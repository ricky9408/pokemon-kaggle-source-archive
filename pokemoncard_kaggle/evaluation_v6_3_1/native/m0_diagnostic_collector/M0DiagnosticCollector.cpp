#include "FrozenTargetDescriptors.h"
#include "RawCborWriter.h"
#include "CollectorReceipt.h"

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/DeclTemplate.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprConcepts.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/FileManager.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Driver/Compilation.h"
#include "clang/Driver/Driver.h"
#include "clang/Driver/Job.h"
#include "clang/Driver/Tool.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/CompilerInvocation.h"
#include "clang/Frontend/TextDiagnosticPrinter.h"
#include "clang/Lex/Lexer.h"
#include "clang/Tooling/ArgumentsAdjusters.h"
#include "clang/Tooling/CompilationDatabase.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/TargetParser/Host.h"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <iostream>
#include <iterator>
#include <map>
#include <numeric>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::m0_diagnostic {
namespace {

constexpr int kFrontendFailure = 65;
constexpr int kProtocolFailure = 66;
constexpr std::string_view kErrorPrefix = "V631302_M0_ERROR:";

enum class Disposition : std::uint8_t {
    kRepresented = 1,
    kNoninstantiatedOrDiscarded = 2,
    kUnsupported = 3,
};

struct Failure final : std::exception {
    explicit Failure(const char* message = "unspecified") : message_(message) {}
    const char* what() const noexcept override { return message_; }

private:
    const char* message_;
};

struct Span {
    std::string path;
    std::uint64_t begin = 0;
    std::uint64_t end = 0;
};

using StructuralPath = std::vector<std::uint32_t>;

struct Occurrence {
    Span span;
    StructuralPath path;
    std::string kind;
    Disposition disposition = Disposition::kRepresented;
};

struct Definition {
    Span span;
    StructuralPath path;
    std::string kind;
    std::string name;
    std::string type;
    std::uint8_t linkage = 0;
    std::vector<std::uint32_t> target_indices;
    bool local = false;
    bool lambda = false;
    bool implicit = false;
    bool template_pattern = false;
    bool specialization = false;
    Disposition disposition = Disposition::kRepresented;
    std::vector<Occurrence> occurrences;
};

struct Global {
    Span span;
    StructuralPath path;
    std::string kind;
    std::string name;
    std::string type;
    std::uint8_t linkage = 0;
    std::uint8_t runtime_class = 0;
};

bool absolute_canonical_path(std::string_view path) {
    if (path.size() < 2 || path.front() != '/' || path.back() == '/') {
        return false;
    }
    std::size_t begin = 1;
    while (begin < path.size()) {
        const std::size_t end = path.find('/', begin);
        const auto component = path.substr(begin, end == std::string_view::npos
                                                       ? path.size() - begin
                                                       : end - begin);
        if (component.empty() || component == "." || component == "..") {
            return false;
        }
        if (end == std::string_view::npos) {
            break;
        }
        begin = end + 1;
    }
    return true;
}

std::optional<Span> source_span(const clang::SourceRange range, clang::ASTContext& context) {
    auto& manager = context.getSourceManager();
    const auto begin = manager.getExpansionLoc(range.getBegin());
    const auto end = manager.getExpansionLoc(range.getEnd());
    if (begin.isInvalid() || end.isInvalid() || begin.isMacroID() || end.isMacroID()) {
        return std::nullopt;
    }
    const auto file_id = manager.getFileID(begin);
    if (file_id != manager.getFileID(end)) {
        return std::nullopt;
    }
    const auto entry = manager.getFileEntryRefForID(file_id);
    if (!entry) {
        return std::nullopt;
    }
    llvm::SmallString<256> path(manager.getFileManager().getCanonicalName(&entry->getFileEntry()));
    if (!llvm::sys::path::is_absolute(path) || llvm::sys::path::remove_dots(path, true)) {
        return std::nullopt;
    }
    const auto after = clang::Lexer::getLocForEndOfToken(end, 0, manager, context.getLangOpts());
    if (after.isInvalid() || manager.getFileID(after) != file_id) {
        return std::nullopt;
    }
    const auto result = path.str().str();
    const auto offset_begin = static_cast<std::uint64_t>(manager.getFileOffset(begin));
    const auto offset_end = static_cast<std::uint64_t>(manager.getFileOffset(after));
    if (!absolute_canonical_path(result) || offset_end <= offset_begin) {
        return std::nullopt;
    }
    return Span{result, offset_begin, offset_end};
}

std::optional<Span> source_span(const clang::Decl& declaration, clang::ASTContext& context) {
    return source_span(declaration.getSourceRange(), context);
}

std::optional<Span> source_span(const clang::Stmt& statement, clang::ASTContext& context) {
    return source_span(statement.getSourceRange(), context);
}

std::string declaration_kind(const clang::Decl& declaration) {
    return std::string(declaration.getDeclKindName()) + "Decl";
}

std::string qualified_type(const clang::ValueDecl& declaration, clang::ASTContext& context) {
    clang::PrintingPolicy policy(context.getPrintingPolicy());
    return declaration.getType().getAsString(policy);
}

struct AstNodeIdentity {
    const clang::Decl* declaration = nullptr;
    const clang::Stmt* statement = nullptr;
};

bool same_ast_identity(const AstNodeIdentity& left, const AstNodeIdentity& right) {
    return left.declaration == right.declaration && left.statement == right.statement;
}

bool null_ast_identity(const AstNodeIdentity& value) {
    return value.declaration == nullptr && value.statement == nullptr;
}

bool contains_ast_identity(const std::vector<AstNodeIdentity>& values,
                           const AstNodeIdentity& target) {
    return std::any_of(values.begin(), values.end(), [&](const AstNodeIdentity& value) {
        return same_ast_identity(value, target);
    });
}

// Observe only the direct Decl/Stmt recursion calls made by the pinned Clang-16
// RecursiveASTVisitor. Non-Decl/Stmt helper traversal remains active, while an
// intercepted child is recorded without descending into that child.
class SupplementalTraversalEdgeCollector final
    : public clang::RecursiveASTVisitor<SupplementalTraversalEdgeCollector> {
public:
    bool shouldVisitImplicitCode() const { return true; }
    bool shouldVisitTemplateInstantiations() const { return true; }
    bool shouldWalkTypesOfTypeLocs() const { return true; }
    bool shouldTraversePostOrder() const { return false; }

    std::vector<AstNodeIdentity> collect(const clang::Decl* root) {
        edges_.clear();
        if (!clang::RecursiveASTVisitor<SupplementalTraversalEdgeCollector>::TraverseDecl(
                const_cast<clang::Decl*>(root))) {
            throw Failure{};
        }
        edges_.erase(std::remove_if(edges_.begin(), edges_.end(), [&](const AstNodeIdentity& edge) {
                         return edge.declaration == root;
                     }),
                     edges_.end());
        return edges_;
    }

    std::vector<AstNodeIdentity> collect(const clang::Stmt* root) {
        edges_.clear();
        if (!clang::RecursiveASTVisitor<SupplementalTraversalEdgeCollector>::TraverseStmt(
                const_cast<clang::Stmt*>(root))) {
            throw Failure{};
        }
        edges_.erase(std::remove_if(edges_.begin(), edges_.end(), [&](const AstNodeIdentity& edge) {
                         return edge.statement == root;
                     }),
                     edges_.end());
        return edges_;
    }

    bool TraverseDecl(clang::Decl* declaration) {
        if (declaration != nullptr) {
            edges_.push_back(AstNodeIdentity{declaration, nullptr});
        }
        return true;
    }

    bool TraverseStmt(clang::Stmt* statement) {
        if (statement != nullptr) {
            edges_.push_back(AstNodeIdentity{nullptr, statement});
        }
        return true;
    }

    // Clang 16 has helper traversals (notably InitListExpr semantic/syntactic
    // forms) which enter a distinct Decl/Stmt without calling TraverseDecl or
    // TraverseStmt. Visit hooks capture those helper-mediated direct entries;
    // the collect() root is removed afterwards.
    bool VisitDecl(clang::Decl* declaration) {
        if (declaration != nullptr) {
            edges_.push_back(AstNodeIdentity{declaration, nullptr});
        }
        return true;
    }

    bool VisitStmt(clang::Stmt* statement) {
        if (statement != nullptr) {
            edges_.push_back(AstNodeIdentity{nullptr, statement});
        }
        return true;
    }

private:
    std::vector<AstNodeIdentity> edges_;
};

class AstMaterializationVisitor final
    : public clang::RecursiveASTVisitor<AstMaterializationVisitor> {
public:
    bool shouldVisitImplicitCode() const { return true; }
    bool shouldVisitTemplateInstantiations() const { return true; }
    bool shouldWalkTypesOfTypeLocs() const { return true; }
    bool shouldTraversePostOrder() const { return false; }

    bool VisitDecl(clang::Decl* declaration) {
        record(AstNodeIdentity{declaration, nullptr});
        return true;
    }

    bool VisitStmt(clang::Stmt* statement) {
        record(AstNodeIdentity{nullptr, statement});
        return true;
    }

    const std::vector<AstNodeIdentity>& nodes() const { return nodes_; }

private:
    void record(const AstNodeIdentity& node) {
        if (!null_ast_identity(node) && !contains_ast_identity(nodes_, node)) {
            nodes_.push_back(node);
        }
    }

    std::vector<AstNodeIdentity> nodes_;
};

struct ParentEdges {
    AstNodeIdentity parent;
    std::vector<AstNodeIdentity> core;
    std::vector<AstNodeIdentity> raw_rav;
};

struct TraversalSnapshot {
    std::vector<AstNodeIdentity> nodes;
    std::vector<ParentEdges> parents;
};

bool same_identity_sequence(const std::vector<AstNodeIdentity>& left,
                            const std::vector<AstNodeIdentity>& right) {
    if (left.size() != right.size()) {
        return false;
    }
    for (std::size_t index = 0; index < left.size(); ++index) {
        if (!same_ast_identity(left[index], right[index])) {
            return false;
        }
    }
    return true;
}

bool same_snapshot(const TraversalSnapshot& left, const TraversalSnapshot& right) {
    if (!same_identity_sequence(left.nodes, right.nodes) ||
        left.parents.size() != right.parents.size()) {
        return false;
    }
    for (std::size_t index = 0; index < left.parents.size(); ++index) {
        const auto& left_parent = left.parents[index];
        const auto& right_parent = right.parents[index];
        if (!same_ast_identity(left_parent.parent, right_parent.parent) ||
            !same_identity_sequence(left_parent.core, right_parent.core) ||
            !same_identity_sequence(left_parent.raw_rav, right_parent.raw_rav)) {
            return false;
        }
    }
    return true;
}

// Clang16StructuralPathV2 wraps the historical V1 core path, then appends the
// first direct-RAV-only edges after global V1 seeding. Pointer equality is used
// only for same-AST-object recognition; pointer values never enter ordering,
// hashing, or the wire.
class StructuralPathIndex final {
public:
    StructuralPathIndex(clang::ASTContext& context, bool force_nonconvergence = false,
                        bool inject_repeated_rav_edge = false)
        : context_(context), force_nonconvergence_(force_nonconvergence),
          inject_repeated_rav_edge_(inject_repeated_rav_edge) {}

    void build() {
        stabilization_passes_ = 0u;
        core_duplicate_edges_ = 0u;
        repeated_raw_edges_ = 0u;
        alias_edges_ = 0u;
        v1_paths_.clear();
        TraversalSnapshot previous;
        bool have_previous = false;
        std::uint32_t passes = 0;
        while (passes < 16u) {
            TraversalSnapshot current = capture_snapshot();
            ++passes;
            stabilization_passes_ = passes;
            if (force_nonconvergence_) {
                previous = std::move(current);
                have_previous = true;
                continue;
            }
            if (!have_previous || !same_snapshot(previous, current)) {
                previous = std::move(current);
                have_previous = true;
                continue;
            }

            build_paths(current);
            if (passes >= 16u) {
                throw Failure{"structural path verification exceeds stabilization bound"};
            }
            TraversalSnapshot verification = capture_snapshot();
            ++passes;
            stabilization_passes_ = passes;
            if (same_snapshot(current, verification)) {
                snapshot_ = std::move(current);
                return;
            }
            paths_.clear();
            previous = std::move(verification);
        }
        throw Failure{"structural path stabilization failed"};
    }

#if defined(V631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS)
    std::vector<RawCborWriter::Byte> encode_test_audit() const {
        RawCborWriter writer;
        writer.array(12u);
        writer.uint(631302u);
        writer.uint(2u);
        writer.array(9u);
        writer.uint(2u);
        writer.uint(16u);
        writer.uint(1u);
        writer.uint(1u);
        writer.uint(1u);
        writer.uint(0u);
        writer.uint(16u);
        writer.uint(1u);
        writer.uint(1u);
        writer.uint(stabilization_passes_);
        writer.uint(v1_paths_.size());
        writer.uint(paths_.size() - v1_paths_.size());
        writer.uint(core_duplicate_edges_);
        writer.uint(repeated_raw_edges_);
        writer.uint(alias_edges_);

        writer.array(v1_paths_.size());
        for (const auto& original : v1_paths_) {
            const auto* final = find_path(original.node);
            if (final == nullptr) {
                throw Failure{"V1 audit identity disappeared"};
            }
            writer.array(5u);
            write_audit_identity(writer, original.node);
            write_audit_path(writer, original.path);
            write_audit_path(writer, final->path);
            writer.uint(original.path == final->path ? 1u : 0u);
            write_audit_span(writer, original.node);
        }

        writer.array(paths_.size() - v1_paths_.size());
        for (const auto& record : paths_) {
            if (record.v1_seeded) {
                continue;
            }
            writer.array(3u);
            write_audit_identity(writer, record.node);
            write_audit_path(writer, record.path);
            write_audit_span(writer, record.node);
        }
        write_edge_audit(writer);
        return std::move(writer).take_bytes();
    }
#endif

    const StructuralPath& declaration(const clang::Decl& value) const {
        const auto* found = find_path(AstNodeIdentity{&value, nullptr});
        if (found == nullptr) {
            throw Failure{"missing declaration path"};
        }
        return found->path;
    }

    const StructuralPath& statement(const clang::Stmt& value) const {
        const auto* found = find_path(AstNodeIdentity{nullptr, &value});
        if (found == nullptr) {
            throw Failure{"missing statement path"};
        }
        return found->path;
    }

    StructuralPath relative_statement(const clang::Decl& definition,
                                      const clang::Stmt& statement) const {
        StructuralPath result;
        std::vector<AstNodeIdentity> seen;
        if (!find_relative_statement(AstNodeIdentity{&definition, nullptr}, statement, {}, seen,
                                     result)) {
            throw Failure{"missing definition-relative statement path"};
        }
        return result;
    }

private:
    struct PathRecord {
        AstNodeIdentity node;
        StructuralPath path;
        bool v1_seeded = false;
    };

#if defined(V631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS)
    static void write_audit_path(RawCborWriter& writer, const StructuralPath& path) {
        writer.array(2u);
        writer.uint(2u);
        writer.array(path.size());
        for (const auto index : path) {
            writer.uint(index);
        }
    }

    void write_audit_span(RawCborWriter& writer, const AstNodeIdentity& node) const {
        std::optional<Span> span;
        if (node.declaration != nullptr) {
            span = source_span(*node.declaration, context_);
        } else if (node.statement != nullptr) {
            span = source_span(*node.statement, context_);
        }
        if (!span) {
            writer.array(0u);
            return;
        }
        writer.array(3u);
        writer.text(span->path);
        writer.uint(span->begin);
        writer.uint(span->end);
    }

    static void write_audit_identity(RawCborWriter& writer, const AstNodeIdentity& node) {
        if (node.declaration != nullptr) {
            writer.text(declaration_kind(*node.declaration));
        } else if (node.statement != nullptr) {
            writer.text(node.statement->getStmtClassName());
        } else {
            throw Failure{"null audit identity"};
        }
    }

    void write_edge_audit(RawCborWriter& writer) const {
        writer.array(2u);

        const auto core_edge_count = static_cast<std::uint64_t>(std::accumulate(
            snapshot_.parents.begin(), snapshot_.parents.end(), std::size_t{0u},
            [](std::size_t count, const ParentEdges& parent) {
                return count + static_cast<std::size_t>(std::count_if(
                                   parent.core.begin(), parent.core.end(),
                                   [](const AstNodeIdentity& edge) {
                                       return !null_ast_identity(edge);
                                   }));
            }));
        writer.array(core_edge_count);
        for (const auto& parent : snapshot_.parents) {
            const auto* parent_path = find_path(parent.parent);
            if (parent_path == nullptr) {
                throw Failure{"edge audit parent has no path"};
            }
            for (std::size_t index = 0; index < parent.core.size(); ++index) {
                const auto& child = parent.core[index];
                if (null_ast_identity(child)) {
                    continue;
                }
                const auto* child_path = find_path(child);
                if (child_path == nullptr) {
                    throw Failure{"edge audit core child has no path"};
                }
                StructuralPath proposed = parent_path->path;
                proposed.push_back(static_cast<std::uint32_t>(index));
                writer.array(7u);
                write_audit_identity(writer, parent.parent);
                write_audit_path(writer, parent_path->path);
                write_audit_identity(writer, child);
                write_audit_path(writer, child_path->path);
                writer.uint(index);
                write_audit_path(writer, proposed);
                writer.uint(child_path->path == proposed ? 1u : 0u);
            }
        }

        const auto raw_edge_count = static_cast<std::uint64_t>(std::accumulate(
            snapshot_.parents.begin(), snapshot_.parents.end(), std::size_t{0u},
            [](std::size_t count, const ParentEdges& parent) {
                return count + static_cast<std::size_t>(std::count_if(
                                   parent.raw_rav.begin(), parent.raw_rav.end(),
                                   [](const AstNodeIdentity& edge) {
                                       return !null_ast_identity(edge);
                                   }));
            }));
        writer.array(raw_edge_count);
        for (const auto& parent : snapshot_.parents) {
            const auto* parent_path = find_path(parent.parent);
            if (parent_path == nullptr) {
                throw Failure{"edge audit RAV parent has no path"};
            }
            std::vector<AstNodeIdentity> observed;
            std::uint32_t supplemental_ordinal = 0u;
            for (std::size_t raw_index = 0; raw_index < parent.raw_rav.size(); ++raw_index) {
                const auto& child = parent.raw_rav[raw_index];
                if (null_ast_identity(child)) {
                    continue;
                }
                const auto* child_path = find_path(child);
                if (child_path == nullptr) {
                    throw Failure{"edge audit RAV child has no path"};
                }
                const bool first_raw = !contains_ast_identity(observed, child);
                if (first_raw) {
                    observed.push_back(child);
                }
                const bool core_duplicate = contains_ast_identity(parent.core, child);
                const bool has_proposal = first_raw && !core_duplicate;
                StructuralPath proposed;
                std::uint32_t ordinal = 0u;
                if (has_proposal) {
                    ordinal = supplemental_ordinal++;
                    proposed = parent_path->path;
                    proposed.push_back(static_cast<std::uint32_t>(parent.core.size()) + ordinal);
                }

                writer.array(10u);
                write_audit_identity(writer, parent.parent);
                write_audit_path(writer, parent_path->path);
                write_audit_identity(writer, child);
                write_audit_path(writer, child_path->path);
                writer.uint(raw_index);
                writer.uint(first_raw ? 1u : 0u);
                writer.uint(core_duplicate ? 1u : 0u);
                writer.array(has_proposal ? 1u : 0u);
                if (has_proposal) {
                    writer.uint(ordinal);
                }
                writer.array(has_proposal ? 1u : 0u);
                if (has_proposal) {
                    write_audit_path(writer, proposed);
                }
                writer.uint(has_proposal && child_path->path == proposed ? 1u : 0u);
            }
        }
    }
#endif

    static std::vector<AstNodeIdentity> core_edges(const clang::Decl* declaration) {
        std::vector<AstNodeIdentity> result;
        if (const auto* context = llvm::dyn_cast<clang::DeclContext>(declaration)) {
            for (const clang::Decl* child : context->decls()) {
                result.push_back(AstNodeIdentity{child, nullptr});
            }
        }
        if (const auto* function_template = llvm::dyn_cast<clang::FunctionTemplateDecl>(declaration)) {
            result.push_back(AstNodeIdentity{function_template->getTemplatedDecl(), nullptr});
            for (const auto* specialization : function_template->specializations()) {
                result.push_back(AstNodeIdentity{specialization, nullptr});
            }
        }
        if (const auto* class_template = llvm::dyn_cast<clang::ClassTemplateDecl>(declaration)) {
            result.push_back(AstNodeIdentity{class_template->getTemplatedDecl(), nullptr});
            for (const auto* specialization : class_template->specializations()) {
                result.push_back(AstNodeIdentity{specialization, nullptr});
            }
        }
        if (const auto* variable_template = llvm::dyn_cast<clang::VarTemplateDecl>(declaration)) {
            result.push_back(AstNodeIdentity{variable_template->getTemplatedDecl(), nullptr});
            for (const auto* specialization : variable_template->specializations()) {
                result.push_back(AstNodeIdentity{specialization, nullptr});
            }
        }
        if (const auto* function = llvm::dyn_cast<clang::FunctionDecl>(declaration)) {
            if (const clang::Stmt* body = function->getBody()) {
                result.push_back(AstNodeIdentity{nullptr, body});
            }
        }
        return result;
    }

    static std::vector<AstNodeIdentity> core_edges(const clang::Stmt* statement) {
        std::vector<AstNodeIdentity> result;
        for (const clang::Stmt* child : statement->children()) {
            result.push_back(AstNodeIdentity{nullptr, child});
        }
        return result;
    }

    static const ParentEdges* find_parent(const TraversalSnapshot& snapshot,
                                          const AstNodeIdentity& node) {
        const auto found = std::find_if(snapshot.parents.begin(), snapshot.parents.end(),
                                        [&](const ParentEdges& parent) {
                                            return same_ast_identity(parent.parent, node);
                                        });
        return found == snapshot.parents.end() ? nullptr : &*found;
    }

    const PathRecord* find_path(const AstNodeIdentity& node) const {
        const auto found = std::find_if(paths_.begin(), paths_.end(), [&](const PathRecord& record) {
            return same_ast_identity(record.node, node);
        });
        return found == paths_.end() ? nullptr : &*found;
    }

    bool assign_path(const AstNodeIdentity& node, const StructuralPath& path, bool v1_seeded) {
        const auto* existing = find_path(node);
        if (existing != nullptr) {
            if (existing->path != path) {
                ++alias_edges_;
            }
            return false;
        }
        if (std::any_of(paths_.begin(), paths_.end(), [&](const PathRecord& record) {
                return record.path == path && !same_ast_identity(record.node, node);
            })) {
            throw Failure{"structural path collision"};
        }
        paths_.push_back(PathRecord{node, path, v1_seeded});
        return true;
    }

    std::vector<AstNodeIdentity> supplemental_edges(const ParentEdges& parent) const {
        std::vector<AstNodeIdentity> result;
        for (const auto& edge : parent.raw_rav) {
            if (null_ast_identity(edge)) {
                continue;
            }
            if (contains_ast_identity(parent.core, edge)) {
                ++core_duplicate_edges_;
                continue;
            }
            if (contains_ast_identity(result, edge)) {
                ++repeated_raw_edges_;
                continue;
            }
            result.push_back(edge);
        }
        return result;
    }

    void observe_node(const AstNodeIdentity& node, TraversalSnapshot& snapshot) const {
        if (null_ast_identity(node) || contains_ast_identity(snapshot.nodes, node)) {
            return;
        }
        snapshot.nodes.push_back(node);
        ParentEdges parent;
        parent.parent = node;
        SupplementalTraversalEdgeCollector collector;
        if (node.declaration != nullptr) {
            parent.core = core_edges(node.declaration);
            parent.raw_rav = collector.collect(node.declaration);
        } else {
            parent.core = core_edges(node.statement);
            parent.raw_rav = collector.collect(node.statement);
        }
        snapshot.parents.push_back(parent);
        for (const auto& edge : parent.core) {
            observe_node(edge, snapshot);
        }
        for (const auto& edge : parent.raw_rav) {
            observe_node(edge, snapshot);
        }
    }

    TraversalSnapshot capture_snapshot() const {
        AstMaterializationVisitor materializer;
        if (!materializer.TraverseDecl(context_.getTranslationUnitDecl())) {
            throw Failure{"AST materialization traversal failed"};
        }
        TraversalSnapshot snapshot;
        observe_node(AstNodeIdentity{context_.getTranslationUnitDecl(), nullptr}, snapshot);
        for (const auto& node : materializer.nodes()) {
            if (!contains_ast_identity(snapshot.nodes, node)) {
                throw Failure{"materialized AST node has no projected edge"};
            }
        }
#if defined(V631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS)
        if (inject_repeated_rav_edge_) {
            bool injected = false;
            for (auto& parent : snapshot.parents) {
                const auto found = std::find_if(
                    parent.raw_rav.begin(), parent.raw_rav.end(), [&](const AstNodeIdentity& edge) {
                        return !null_ast_identity(edge) &&
                               !contains_ast_identity(parent.core, edge);
                    });
                if (found != parent.raw_rav.end()) {
                    parent.raw_rav.push_back(*found);
                    injected = true;
                    break;
                }
            }
            if (!injected) {
                throw Failure{"test fixture has no supplemental edge to repeat"};
            }
        }
#endif
        return snapshot;
    }

    void seed_v1_core(const TraversalSnapshot& snapshot, const AstNodeIdentity& node,
                      const StructuralPath& path) {
        if (!assign_path(node, path, true)) {
            return;
        }
        const auto* parent = find_parent(snapshot, node);
        if (parent == nullptr) {
            throw Failure{};
        }
        for (std::size_t index = 0; index < parent->core.size(); ++index) {
            if (!null_ast_identity(parent->core[index])) {
                StructuralPath child_path = path;
                child_path.push_back(static_cast<std::uint32_t>(index));
                seed_v1_core(snapshot, parent->core[index], child_path);
            }
        }
    }

    void assign_new_subtree(const TraversalSnapshot& snapshot, const AstNodeIdentity& node,
                            const StructuralPath& path) {
        if (!assign_path(node, path, false)) {
            return;
        }
        const auto* parent = find_parent(snapshot, node);
        if (parent == nullptr) {
            throw Failure{};
        }
        for (std::size_t index = 0; index < parent->core.size(); ++index) {
            if (!null_ast_identity(parent->core[index])) {
                StructuralPath child_path = path;
                child_path.push_back(static_cast<std::uint32_t>(index));
                assign_new_subtree(snapshot, parent->core[index], child_path);
            }
        }
        const auto supplemental = supplemental_edges(*parent);
        for (std::size_t index = 0; index < supplemental.size(); ++index) {
            StructuralPath child_path = path;
            child_path.push_back(static_cast<std::uint32_t>(parent->core.size() + index));
            assign_new_subtree(snapshot, supplemental[index], child_path);
        }
    }

    void append_supplemental_for_seeded_parent(const TraversalSnapshot& snapshot,
                                               const AstNodeIdentity& node,
                                               const StructuralPath& path) {
        const auto* parent = find_parent(snapshot, node);
        if (parent == nullptr) {
            throw Failure{};
        }
        const auto supplemental = supplemental_edges(*parent);
        for (std::size_t index = 0; index < supplemental.size(); ++index) {
            StructuralPath child_path = path;
            child_path.push_back(static_cast<std::uint32_t>(parent->core.size() + index));
            assign_new_subtree(snapshot, supplemental[index], child_path);
        }
    }

    void build_paths(const TraversalSnapshot& snapshot) {
        paths_.clear();
        const AstNodeIdentity root{context_.getTranslationUnitDecl(), nullptr};
        seed_v1_core(snapshot, root, {});
        v1_paths_.clear();
        for (const auto& record : paths_) {
            if (record.v1_seeded) {
                v1_paths_.push_back(record);
            }
        }

        std::vector<std::pair<StructuralPath, AstNodeIdentity>> seeded_parents;
        for (const auto& record : paths_) {
            if (record.v1_seeded) {
                seeded_parents.push_back({record.path, record.node});
            }
        }
        std::sort(seeded_parents.begin(), seeded_parents.end(), [](const auto& left, const auto& right) {
            return left.first < right.first;
        });
        for (const auto& [path, node] : seeded_parents) {
            append_supplemental_for_seeded_parent(snapshot, node, path);
        }
        for (const auto& node : snapshot.nodes) {
            if (find_path(node) == nullptr) {
                throw Failure{"stable AST node has no V2 path"};
            }
        }
        for (const auto& original : v1_paths_) {
            const auto* final = find_path(original.node);
            if (final == nullptr || final->path != original.path || !final->v1_seeded) {
                throw Failure{"supplemental traversal moved a V1 identity"};
            }
        }
    }

    bool find_relative_statement(const AstNodeIdentity& node, const clang::Stmt& target,
                                 const StructuralPath& path,
                                 std::vector<AstNodeIdentity>& seen,
                                 StructuralPath& result) const {
        if (null_ast_identity(node) || contains_ast_identity(seen, node)) {
            return false;
        }
        seen.push_back(node);
        if (node.statement == &target) {
            result = path;
            return true;
        }
        const auto* parent = find_parent(snapshot_, node);
        if (parent == nullptr) {
            throw Failure{};
        }
        for (std::size_t index = 0; index < parent->core.size(); ++index) {
            StructuralPath child_path = path;
            child_path.push_back(static_cast<std::uint32_t>(index));
            if (find_relative_statement(parent->core[index], target, child_path, seen, result)) {
                return true;
            }
        }
        const auto supplemental = supplemental_edges(*parent);
        for (std::size_t index = 0; index < supplemental.size(); ++index) {
            StructuralPath child_path = path;
            child_path.push_back(static_cast<std::uint32_t>(parent->core.size() + index));
            if (find_relative_statement(supplemental[index], target, child_path, seen, result)) {
                return true;
            }
        }
        return false;
    }

    clang::ASTContext& context_;
    bool force_nonconvergence_ = false;
    [[maybe_unused]] bool inject_repeated_rav_edge_ = false;
    std::uint32_t stabilization_passes_ = 0;
    mutable std::uint64_t core_duplicate_edges_ = 0;
    mutable std::uint64_t repeated_raw_edges_ = 0;
    std::uint64_t alias_edges_ = 0;
    TraversalSnapshot snapshot_;
    std::vector<PathRecord> paths_;
    std::vector<PathRecord> v1_paths_;
};

bool domain2_storage(const clang::VarDecl& declaration) {
    const auto duration = declaration.getStorageDuration();
    return duration == clang::SD_Static || duration == clang::SD_Thread;
}

bool domain2_candidate(const clang::VarDecl& declaration) {
    if (declaration.isImplicit() || declaration.getParentFunctionOrMethod() != nullptr ||
        !domain2_storage(declaration) ||
        declaration.isThisDeclarationADefinition() == clang::VarDecl::DeclarationOnly) {
        return false;
    }
    // A dependent variable-template pattern is not a concrete specialization.
    // Clang represents a concrete variable-template specialization with its
    // own declaration class, independent of the pattern's metadata fields.
    return declaration.getDescribedVarTemplate() == nullptr ||
           llvm::isa<clang::VarTemplateSpecializationDecl>(&declaration);
}

std::uint8_t global_runtime_class(const clang::VarDecl& declaration) {
    const bool dynamic = declaration.hasInit() && !declaration.hasConstantInitialization();
    const bool destructed = declaration.getType().isDestructedType() != clang::QualType::DK_none;
    if (dynamic && destructed) {
        return 4u;
    }
    if (dynamic) {
        return 2u;
    }
    if (destructed) {
        return 3u;
    }
    return 1u;
}

std::vector<std::uint32_t> target_indices(const clang::FunctionDecl& declaration,
                                          clang::ASTContext& context) {
    const auto name = declaration.getNameAsString();
    const auto type = qualified_type(declaration, context);
    std::vector<std::uint32_t> result;
    for (const auto& descriptor : kFrozenTargetDescriptors) {
        if (descriptor.name == name && descriptor.raw_qual_type == type) {
            result.push_back(descriptor.index);
        }
    }
    return result;
}

class OccurrenceVisitor final : public clang::RecursiveASTVisitor<OccurrenceVisitor> {
public:
    OccurrenceVisitor(clang::ASTContext& context, const StructuralPathIndex& paths,
                      const clang::Decl& definition, std::vector<Occurrence>& output)
        : context_(context), paths_(paths), definition_(definition), output_(output) {}

    bool VisitCallExpr(clang::CallExpr* expression) {
        add(*expression, "CallExpr", Disposition::kRepresented);
        return true;
    }

    bool VisitVAArgExpr(clang::VAArgExpr* expression) {
        add(*expression, "VAArgExpr", Disposition::kUnsupported);
        return true;
    }

    // RequiresExpr is unevaluated.  It is intentionally absent, not a failed
    // occurrence root.  Adjacent runtime calls remain traversed normally.
    bool TraverseRequiresExpr(clang::RequiresExpr*) {
        return true;
    }

private:
    void add(const clang::Stmt& statement, std::string kind, Disposition disposition) {
        const auto span = source_span(statement, context_);
        if (!span) {
            throw Failure{};
        }
        StructuralPath relative_path = paths_.relative_statement(definition_, statement);
        if (relative_path.empty()) {
            throw Failure{};
        }
        output_.push_back(
            Occurrence{*span, std::move(relative_path), std::move(kind), disposition});
    }

    clang::ASTContext& context_;
    const StructuralPathIndex& paths_;
    const clang::Decl& definition_;
    std::vector<Occurrence>& output_;
};

class CandidateVisitor final : public clang::RecursiveASTVisitor<CandidateVisitor> {
public:
#if defined(V631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS)
    struct DefinitionObservation {
        const clang::FunctionDecl* declaration = nullptr;
        std::uint64_t count = 0u;
    };
#endif

    CandidateVisitor(clang::ASTContext& context, StructuralPathIndex& paths)
        : context_(context), paths_(paths) {}

    bool VisitFunctionDecl(clang::FunctionDecl* declaration) {
        record_definition(declaration);
        return true;
    }

    bool VisitFunctionTemplateDecl(clang::FunctionTemplateDecl* declaration) {
        for (auto* specialization : declaration->specializations()) {
            record_definition(specialization);
        }
        return true;
    }

    bool VisitVarDecl(clang::VarDecl* declaration) {
        if (!domain2_candidate(*declaration)) {
            return true;
        }
        const clang::VarDecl* canonical = declaration->getCanonicalDecl();
        const clang::VarDecl* definition = canonical->getDefinition();
        if (definition == nullptr) {
            throw Failure{};
        }
        if (definition != declaration) {
            return true;
        }
        if (std::find(seen_global_definitions_.begin(), seen_global_definitions_.end(), canonical) !=
            seen_global_definitions_.end()) {
            throw Failure{};
        }
        seen_global_definitions_.push_back(canonical);
        const auto span = source_span(*definition, context_);
        if (!span) {
            throw Failure{};
        }
        globals_.push_back(Global{
            *span,
            paths_.declaration(*definition),
            declaration_kind(*definition),
            definition->getQualifiedNameAsString(),
            qualified_type(*definition, context_),
            static_cast<std::uint8_t>(definition->hasExternalFormalLinkage() ? 1u : 2u),
            global_runtime_class(*definition),
        });
        return true;
    }

    std::vector<Definition> take_definitions() && { return std::move(definitions_); }
    std::vector<Global> take_globals() && { return std::move(globals_); }
#if defined(V631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS)
    const std::vector<DefinitionObservation>& definition_observations() const {
        return definition_observations_;
    }
#endif

private:
    void record_definition(clang::FunctionDecl* declaration) {
#if defined(V631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS)
        const auto observation = std::find_if(
            definition_observations_.begin(), definition_observations_.end(),
            [&](const DefinitionObservation& value) {
                return value.declaration == declaration;
            });
        if (observation == definition_observations_.end()) {
            definition_observations_.push_back(DefinitionObservation{declaration, 1u});
        } else {
            ++observation->count;
        }
#endif
        if (std::find(seen_definitions_.begin(), seen_definitions_.end(), declaration) !=
            seen_definitions_.end()) {
            return;
        }
        seen_definitions_.push_back(declaration);
        if (!declaration->isThisDeclarationADefinition()) {
            return;
        }
        const auto span = source_span(*declaration, context_);
        if (!span) {
            throw Failure{};
        }
        Definition definition;
        definition.span = *span;
        definition.path = paths_.declaration(*declaration);
        definition.kind = declaration_kind(*declaration);
        definition.name = declaration->getQualifiedNameAsString();
        definition.type = qualified_type(*declaration, context_);
        definition.linkage =
            static_cast<std::uint8_t>(declaration->hasExternalFormalLinkage() ? 1u : 2u);
        definition.target_indices = target_indices(*declaration, context_);
        definition.local = declaration->getDeclContext()->isFunctionOrMethod();
        if (const auto* method = llvm::dyn_cast<clang::CXXMethodDecl>(declaration)) {
            definition.lambda = method->getParent()->isLambda();
        }
        definition.implicit = declaration->isImplicit() ||
                              declaration->getTemplateSpecializationKind() ==
                                  clang::TSK_ImplicitInstantiation;
        definition.template_pattern = declaration->getDescribedFunctionTemplate() != nullptr;
        definition.specialization = declaration->isFunctionTemplateSpecialization();
        // Level 2 cannot establish the erratum's five exclusion facts.  It
        // therefore records template patterns as unsupported with proof=[];
        // it never synthesizes disposition 2 or a template exclusion proof.
        definition.disposition = definition.template_pattern ? Disposition::kUnsupported
                                                              : Disposition::kRepresented;
        if (const auto* body = declaration->getBody()) {
            OccurrenceVisitor occurrences(
                context_, paths_, *declaration, definition.occurrences);
            occurrences.TraverseStmt(const_cast<clang::Stmt*>(body));
        }
        definitions_.push_back(std::move(definition));
    }

    clang::ASTContext& context_;
    StructuralPathIndex& paths_;
    std::vector<const clang::FunctionDecl*> seen_definitions_;
#if defined(V631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS)
    std::vector<DefinitionObservation> definition_observations_;
#endif
    std::vector<const clang::VarDecl*> seen_global_definitions_;
    std::vector<Definition> definitions_;
    std::vector<Global> globals_;
};

void write_occurrence_path(RawCborWriter& writer, const StructuralPath& path) {
    writer.array(path.size());
    for (const auto value : path) {
        writer.uint(value);
    }
}

void write_structural_path_v2(RawCborWriter& writer, const StructuralPath& path) {
    writer.array(2u);
    writer.uint(2u);
    write_occurrence_path(writer, path);
}

void write_span(RawCborWriter& writer, const Span& span) {
    writer.array(3u);
    writer.text(span.path);
    writer.uint(span.begin);
    writer.uint(span.end);
}

#if defined(V631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS)
std::vector<RawCborWriter::Byte> encode_definition_observation_audit(
    const CandidateVisitor& visitor, clang::ASTContext& context,
    const StructuralPathIndex& paths) {
    struct AuditRow {
        const clang::FunctionDecl* declaration = nullptr;
        Span span;
        StructuralPath path;
        std::uint64_t canonical_group = 0u;
        std::uint64_t observation_count = 0u;
    };

    std::vector<const clang::FunctionDecl*> canonical_families;
    std::vector<AuditRow> rows;
    for (const auto& observation : visitor.definition_observations()) {
        if (observation.declaration == nullptr) {
            throw Failure{"null definition observation"};
        }
        const auto span = source_span(*observation.declaration, context);
        if (!span) {
            continue;
        }
        const auto* canonical = observation.declaration->getCanonicalDecl();
        const auto found = std::find(canonical_families.begin(), canonical_families.end(), canonical);
        std::uint64_t canonical_group = 0u;
        if (found == canonical_families.end()) {
            canonical_group = canonical_families.size();
            canonical_families.push_back(canonical);
        } else {
            canonical_group = static_cast<std::uint64_t>(
                std::distance(canonical_families.begin(), found));
        }
        rows.push_back(AuditRow{observation.declaration, *span,
                                paths.declaration(*observation.declaration), canonical_group,
                                observation.count});
    }

    RawCborWriter writer;
    writer.array(3u);
    writer.uint(631302u);
    writer.uint(3u);
    writer.array(rows.size());
    for (const auto& row : rows) {
        const auto& declaration = *row.declaration;
        writer.array(10u);
        write_structural_path_v2(writer, row.path);
        writer.text(declaration_kind(declaration));
        writer.text(declaration.getQualifiedNameAsString());
        writer.text(qualified_type(declaration, context));
        write_span(writer, row.span);
        writer.uint(declaration.isThisDeclarationADefinition() ? 1u : 0u);
        writer.uint(declaration.isImplicit() ||
                            declaration.getTemplateSpecializationKind() ==
                                clang::TSK_ImplicitInstantiation
                        ? 1u
                        : 0u);
        writer.uint(declaration.isFunctionTemplateSpecialization() ? 1u : 0u);
        writer.uint(row.canonical_group);
        writer.uint(row.observation_count);
    }
    return std::move(writer).take_bytes();
}
#endif

void write_construct_key(RawCborWriter& writer, const StructuralPath& path,
                         std::string_view kind, const Span& span) {
    writer.array(3u);
    write_occurrence_path(writer, path);
    writer.text(kind);
    write_span(writer, span);
}

void write_definition_subject(RawCborWriter& writer, const Definition& definition) {
    writer.array(3u);
    write_structural_path_v2(writer, definition.path);
    writer.text(definition.kind);
    write_span(writer, definition.span);
}

void write_binding3_definition_semantic_key_v1(RawCborWriter& writer,
                                               const Definition& definition) {
    writer.array(8u);
    writer.text(definition.kind);
    writer.text(definition.name);
    writer.text(definition.type);
    writer.uint(definition.linkage);
    writer.array(definition.target_indices.size());
    for (const auto index : definition.target_indices) {
        writer.uint(index);
    }
    writer.text(definition.span.path);
    writer.uint(definition.span.begin);
    writer.uint(definition.span.end);
}

// The V2 instance key embeds the exact Domain-1 subject and the non-unique
// Binding-3 semantic descriptor from the same compiler declaration instance.
void write_binding3_definition_instance_key_v2(RawCborWriter& writer,
                                                const Definition& definition) {
    writer.array(3u);
    writer.uint(2u);
    write_definition_subject(writer, definition);
    write_binding3_definition_semantic_key_v1(writer, definition);
}

void write_global_key(RawCborWriter& writer, const Global& global) {
    writer.array(9u);
    writer.text(global.kind);
    writer.text(global.name);
    writer.text(global.type);
    writer.uint(global.linkage);
    writer.array(0u);
    writer.text(global.span.path);
    writer.uint(global.span.begin);
    writer.uint(global.span.end);
    write_structural_path_v2(writer, global.path);
}

void write_target_descriptors(RawCborWriter& writer) {
    writer.array(kFrozenTargetDescriptors.size());
    for (const auto& descriptor : kFrozenTargetDescriptors) {
        writer.array(3u);
        writer.uint(descriptor.index);
        writer.text(descriptor.name);
        writer.text(descriptor.raw_qual_type);
    }
}

std::vector<RawCborWriter::Byte> encode_definition_subject(const Definition& definition) {
    RawCborWriter writer;
    write_definition_subject(writer, definition);
    return std::move(writer).take_bytes();
}

std::vector<RawCborWriter::Byte> encode_binding3_definition_instance_key_v2(
    const Definition& definition) {
    RawCborWriter writer;
    write_binding3_definition_instance_key_v2(writer, definition);
    return std::move(writer).take_bytes();
}

bool cbor_bytes_less(const std::vector<RawCborWriter::Byte>& left,
                     const std::vector<RawCborWriter::Byte>& right) {
    const auto shared = std::min(left.size(), right.size());
    for (std::size_t index = 0; index < shared; ++index) {
        if (left[index] != right[index]) {
            return left[index] < right[index];
        }
    }
    return left.size() < right.size();
}

struct CborByteVectorLess final {
    bool operator()(const std::vector<RawCborWriter::Byte>& left,
                    const std::vector<RawCborWriter::Byte>& right) const {
        return cbor_bytes_less(left, right);
    }
};

void enforce_definition_key_uniqueness(const std::vector<Definition>& definitions) {
    std::set<std::vector<RawCborWriter::Byte>, CborByteVectorLess> subjects;
    std::set<std::vector<RawCborWriter::Byte>, CborByteVectorLess> instance_keys;
    for (const auto& definition : definitions) {
        if (!subjects.insert(encode_definition_subject(definition)).second ||
            !instance_keys.insert(encode_binding3_definition_instance_key_v2(definition)).second) {
            throw Failure{};
        }
    }
}

void write_counts(RawCborWriter& writer, const std::vector<Definition>& definitions,
                  const std::vector<Global>& globals) {
    std::uint64_t source_represented = 0;
    std::uint64_t source_discarded = 0;
    std::uint64_t source_unsupported = 0;
    std::uint64_t invocation_total = 0;
    std::uint64_t invocation_represented = 0;
    std::uint64_t invocation_unsupported = 0;
    for (const auto& definition : definitions) {
        if (definition.disposition == Disposition::kRepresented) {
            ++source_represented;
        } else if (definition.disposition == Disposition::kNoninstantiatedOrDiscarded) {
            ++source_discarded;
        } else {
            ++source_unsupported;
        }
        if (definition.disposition != Disposition::kRepresented) {
            continue;
        }
        for (const auto& occurrence : definition.occurrences) {
            ++invocation_total;
            if (occurrence.disposition == Disposition::kRepresented) {
                ++invocation_represented;
            } else {
                ++invocation_unsupported;
            }
        }
    }
    const auto counts = [&writer](std::uint64_t total, std::uint64_t represented,
                                  std::uint64_t discarded, std::uint64_t unsupported) {
        writer.array(4u);
        writer.uint(total);
        writer.uint(represented);
        writer.uint(discarded);
        writer.uint(unsupported);
    };
    writer.array(3u);
    counts(definitions.size(), source_represented, source_discarded, source_unsupported);
    counts(globals.size(), globals.size(), 0u, 0u);
    counts(invocation_total, invocation_represented, 0u, invocation_unsupported);
}

std::vector<RawCborWriter::Byte> encode_raw_transport(std::vector<Definition> definitions,
                                                       std::vector<Global> globals) {
    enforce_definition_key_uniqueness(definitions);
    std::sort(definitions.begin(), definitions.end(), [](const Definition& left,
                                                          const Definition& right) {
        return cbor_bytes_less(encode_binding3_definition_instance_key_v2(left),
                               encode_binding3_definition_instance_key_v2(right));
    });
    std::sort(globals.begin(), globals.end(), [](const Global& left, const Global& right) {
        return std::tie(left.path, left.kind, left.span.path, left.span.begin, left.span.end) <
               std::tie(right.path, right.kind, right.span.path, right.span.begin, right.span.end);
    });
    for (auto& definition : definitions) {
        std::sort(definition.occurrences.begin(), definition.occurrences.end(),
                  [](const Occurrence& left, const Occurrence& right) {
                      return std::tie(left.path, left.kind, left.span.path, left.span.begin,
                                      left.span.end) <
                             std::tie(right.path, right.kind, right.span.path, right.span.begin,
                                      right.span.end);
                  });
    }

    RawCborWriter writer;
    // Implementation-internal transport only.  It deliberately contains no
    // DIAGNOSTIC_CENSUS_V1 schema/profile/root and no ordered_blockers array.
    // Python is the later canonicalizer; this collector has zero authority.
    writer.array(5u);
    write_target_descriptors(writer);
    write_counts(writer, definitions, globals);

    writer.array(definitions.size());
    for (const auto& definition : definitions) {
        writer.array(4u);
        write_definition_subject(writer, definition);
        writer.array(6u);
        writer.uint(definition.local ? 1u : 0u);
        writer.uint(definition.lambda ? 1u : 0u);
        writer.uint(definition.implicit ? 1u : 0u);
        writer.uint(definition.template_pattern ? 1u : 0u);
        writer.uint(definition.specialization ? 1u : 0u);
        writer.array(0u);
        writer.uint(static_cast<std::uint8_t>(definition.disposition));
        if (definition.disposition == Disposition::kUnsupported) {
            writer.array(1u);
            writer.array(2u);
            write_construct_key(writer, {}, "FunctionTemplateDecl", definition.span);
            writer.text("M0_TEMPLATE_EMISSION_STATUS_UNPROVEN");
        } else {
            writer.array(0u);
        }
    }

    writer.array(globals.size());
    for (const auto& global : globals) {
        writer.array(4u);
        write_global_key(writer, global);
        writer.uint(global.runtime_class);
        writer.array(3u);
        writer.uint(global.runtime_class == 2u || global.runtime_class == 4u ? 1u : 0u);
        writer.uint(static_cast<std::uint8_t>(Disposition::kRepresented));
        writer.array(0u);
        writer.array(3u);
        writer.uint(global.runtime_class == 3u || global.runtime_class == 4u ? 1u : 0u);
        writer.uint(static_cast<std::uint8_t>(Disposition::kRepresented));
        writer.array(0u);
    }

    // Domain 3 contains exactly the represented Domain-1 definitions. Its V2
    // instance key carries the complete authenticated join.
    const auto represented_definitions = static_cast<std::uint64_t>(std::count_if(
        definitions.begin(), definitions.end(), [](const Definition& definition) {
            return definition.disposition == Disposition::kRepresented;
        }));
    writer.array(represented_definitions);
    for (const auto& definition : definitions) {
        if (definition.disposition != Disposition::kRepresented) {
            continue;
        }
        writer.array(2u);
        write_binding3_definition_instance_key_v2(writer, definition);
        writer.array(definition.occurrences.size());
        for (const auto& occurrence : definition.occurrences) {
            writer.array(3u);
            write_construct_key(writer, occurrence.path, occurrence.kind, occurrence.span);
            writer.uint(static_cast<std::uint8_t>(occurrence.disposition));
            if (occurrence.disposition == Disposition::kUnsupported) {
                writer.array(1u);
                writer.array(2u);
                write_construct_key(writer, occurrence.path, occurrence.kind, occurrence.span);
                writer.text("M0_INVOCATION_INVENTORY_INCOMPLETE");
            } else {
                writer.array(0u);
            }
        }
    }
    return std::move(writer).take_bytes();
}

class CollectorConsumer final : public clang::ASTConsumer {
public:
    CollectorConsumer(std::vector<RawCborWriter::Byte>& output, bool structural_audit,
                      bool definition_observation_audit, bool force_nonconvergence,
                      bool inject_repeated_rav_edge)
        : output_(output), structural_audit_(structural_audit),
          definition_observation_audit_(definition_observation_audit),
          force_nonconvergence_(force_nonconvergence),
          inject_repeated_rav_edge_(inject_repeated_rav_edge) {}

    void HandleTranslationUnit(clang::ASTContext& context) override {
        StructuralPathIndex paths(context, force_nonconvergence_, inject_repeated_rav_edge_);
        paths.build();
#if defined(V631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS)
        if (structural_audit_) {
            output_ = paths.encode_test_audit();
            return;
        }
#endif
        CandidateVisitor visitor(context, paths);
        visitor.TraverseDecl(context.getTranslationUnitDecl());
#if defined(V631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS)
        if (definition_observation_audit_) {
            output_ = encode_definition_observation_audit(visitor, context, paths);
            return;
        }
#endif
        output_ = encode_raw_transport(std::move(visitor).take_definitions(),
                                       std::move(visitor).take_globals());
    }

private:
    std::vector<RawCborWriter::Byte>& output_;
    [[maybe_unused]] bool structural_audit_ = false;
    [[maybe_unused]] bool definition_observation_audit_ = false;
    bool force_nonconvergence_ = false;
    bool inject_repeated_rav_edge_ = false;
};

class CollectorAction final : public clang::ASTFrontendAction {
public:
    CollectorAction(std::vector<RawCborWriter::Byte>& output, bool structural_audit,
                    bool definition_observation_audit, bool force_nonconvergence,
                    bool inject_repeated_rav_edge)
        : output_(output), structural_audit_(structural_audit),
          definition_observation_audit_(definition_observation_audit),
          force_nonconvergence_(force_nonconvergence),
          inject_repeated_rav_edge_(inject_repeated_rav_edge) {}

    std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(clang::CompilerInstance&,
                                                           llvm::StringRef) override {
        return std::make_unique<CollectorConsumer>(output_, structural_audit_,
                                                   definition_observation_audit_,
                                                   force_nonconvergence_,
                                                   inject_repeated_rav_edge_);
    }

private:
    std::vector<RawCborWriter::Byte>& output_;
    bool structural_audit_ = false;
    bool definition_observation_audit_ = false;
    bool force_nonconvergence_ = false;
    bool inject_repeated_rav_edge_ = false;
};

struct CommandLine {
    std::string primary_source;
    std::string capture_context_hex;
    std::vector<std::string> compiler_arguments;
    bool structural_audit = false;
    bool definition_observation_audit = false;
    bool force_nonconvergence = false;
    bool inject_repeated_rav_edge = false;
#if defined(V631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS)
    bool driver_cc1_audit = false;
    bool no_fd3_receipt = false;
#endif
};

std::optional<CommandLine> parse_command_line(int argc, char** argv) {
    constexpr std::string_view kCaptureContextPrefix =
        "--capture-context-v1-cbor-hex=";
    CommandLine command;
    bool separator = false;
    bool capture_context_seen = false;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (separator) {
            command.compiler_arguments.emplace_back(argument);
        } else if (argument == "--") {
            separator = true;
        } else if (argument.starts_with("--primary-source=")) {
            command.primary_source = std::string(argument.substr(17u));
        } else if (argument.starts_with(kCaptureContextPrefix)) {
            if (capture_context_seen) {
                return std::nullopt;
            }
            capture_context_seen = true;
            command.capture_context_hex =
                std::string(argument.substr(kCaptureContextPrefix.size()));
        } else if (argument == "--protocol=631302" || argument == "--level=2") {
            continue;
#if defined(V631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS)
        } else if (argument == "--test-structural-audit") {
            command.structural_audit = true;
        } else if (argument == "--test-definition-observation-audit") {
            command.definition_observation_audit = true;
        } else if (argument == "--test-force-nonconvergence") {
            command.force_nonconvergence = true;
        } else if (argument == "--test-inject-repeated-rav-edge") {
            command.inject_repeated_rav_edge = true;
        } else if (argument == "--test-driver-cc1-audit") {
            command.driver_cc1_audit = true;
        } else if (argument == "--test-no-fd3-receipt") {
            command.no_fd3_receipt = true;
#endif
        } else {
            return std::nullopt;
        }
    }
    if (!separator || command.primary_source.empty() || command.compiler_arguments.empty() ||
        !absolute_canonical_path(command.primary_source)) {
        return std::nullopt;
    }
#if defined(V631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS)
    if (command.no_fd3_receipt) {
        if (capture_context_seen || !command.capture_context_hex.empty()) {
            return std::nullopt;
        }
    } else if (!capture_context_seen || command.capture_context_hex.empty()) {
        return std::nullopt;
    }
    if (command.driver_cc1_audit && !command.no_fd3_receipt) {
        return std::nullopt;
    }
#else
    if (!capture_context_seen || command.capture_context_hex.empty()) {
        return std::nullopt;
    }
#endif
    return command;
}

class FrontendFailure final : public std::exception {};

struct ExpandedInvocation {
    std::vector<std::string> driver_argv;
    std::vector<std::string> cc1_argv;
    llvm::IntrusiveRefCntPtr<llvm::vfs::FileSystem> file_system;
};

void require_receipt_safe_argument(std::string_view argument) {
    if (argument.find('\0') != std::string_view::npos || !llvm::json::isUTF8(argument) ||
        argument.starts_with("@") || argument == "--config" ||
        argument.starts_with("--config=") ||
        argument.starts_with("--config-system-dir=") ||
        argument.starts_with("--config-user-dir=")) {
        throw Failure{};
    }
}

void require_receipt_safe_arguments(const std::vector<std::string>& arguments) {
    if (arguments.empty()) {
        throw Failure{};
    }
    for (const std::string& argument : arguments) {
        require_receipt_safe_argument(argument);
    }
}

ExpandedInvocation expand_driver_once(const CommandLine& command,
                                      clang::DiagnosticConsumer* diagnostic_consumer,
                                      evaluation_v6_3_1::capture_v2::CollectorReceipt* receipt) {
    clang::tooling::FixedCompilationDatabase database("/", command.compiler_arguments);
    std::vector<clang::tooling::CompileCommand> commands =
        database.getCompileCommands(command.primary_source);
    if (commands.size() != 1 || commands.front().Filename != command.primary_source) {
        throw Failure{};
    }
    auto file_system = llvm::vfs::getRealFileSystem();
    if (file_system->setCurrentWorkingDirectory(commands.front().Directory)) {
        throw Failure{};
    }

    std::vector<std::string> driver_argv = commands.front().CommandLine;
    require_receipt_safe_arguments(driver_argv);
    const std::string& primary = commands.front().Filename;
    driver_argv = clang::tooling::getClangStripOutputAdjuster()(driver_argv, primary);
    driver_argv = clang::tooling::getClangSyntaxOnlyAdjuster()(driver_argv, primary);
    driver_argv = clang::tooling::getClangStripDependencyFileAdjuster()(driver_argv, primary);

    // This reproduces ClangTool::run's resource-dir behavior exactly. The
    // static symbol is intentionally local to the collector binary, not argv[0].
    static int resource_directory_anchor;
    bool has_resource_directory = false;
    for (const std::string& argument : driver_argv) {
        if (std::string_view(argument).starts_with("-resource-dir")) {
            has_resource_directory = true;
            break;
        }
    }
    if (!has_resource_directory) {
        const std::string resource_directory =
            "-resource-dir=" + clang::CompilerInvocation::GetResourcesPath(
                                  "clang_tool", &resource_directory_anchor);
        driver_argv = clang::tooling::getInsertArgumentAdjuster(resource_directory.c_str())(
            driver_argv, primary);
    }
    const auto no_default_config_count = static_cast<std::size_t>(
        std::count(driver_argv.begin(), driver_argv.end(), "--no-default-config"));
    if (no_default_config_count > 1) {
        throw Failure{};
    }
    if (no_default_config_count == 0) {
        driver_argv = clang::tooling::getInsertArgumentAdjuster("--no-default-config")(
            driver_argv, primary);
    }
    require_receipt_safe_arguments(driver_argv);
    if (receipt != nullptr) {
        receipt->driver_argv_frozen(driver_argv);
    }

    llvm::opt::ArgStringList raw_driver_argv;
    for (const std::string& argument : driver_argv) {
        raw_driver_argv.push_back(argument.c_str());
    }
    auto options = llvm::IntrusiveRefCntPtr<clang::DiagnosticOptions>(
        new clang::DiagnosticOptions());
    std::unique_ptr<clang::TextDiagnosticPrinter> default_diagnostics;
    if (diagnostic_consumer == nullptr) {
        default_diagnostics = std::make_unique<clang::TextDiagnosticPrinter>(
            llvm::errs(), options.get());
        diagnostic_consumer = default_diagnostics.get();
    }
    auto diagnostics = clang::CompilerInstance::createDiagnostics(
        options.get(), diagnostic_consumer, false);
    clang::driver::Driver driver(driver_argv.front(), llvm::sys::getDefaultTargetTriple(),
                                 *diagnostics, "v631302 m0 diagnostic driver", file_system);
    driver.setCheckInputsExist(true);
    if (receipt != nullptr) {
        receipt->driver_execution_begin();
    }
    std::unique_ptr<clang::driver::Compilation> compilation(
        driver.BuildCompilation(llvm::ArrayRef(raw_driver_argv)));
    if (!compilation || diagnostics->hasErrorOccurred()) {
        throw FrontendFailure{};
    }

    const clang::driver::Command* frontend = nullptr;
    for (const clang::driver::Command& job : compilation->getJobs()) {
        const llvm::opt::ArgStringList& job_arguments = job.getArguments();
        const auto cc1_count = static_cast<std::size_t>(std::count_if(
            job_arguments.begin(), job_arguments.end(), [](const char* argument) {
                return llvm::StringRef(argument) == "-cc1";
            }));
        if (frontend != nullptr || llvm::StringRef(job.getCreator().getName()) != "clang" ||
            job_arguments.empty() || llvm::StringRef(job_arguments.front()) != "-cc1" ||
            cc1_count != 1) {
            throw Failure{};
        }
        frontend = &job;
    }
    if (frontend == nullptr) {
        throw Failure{};
    }

    const llvm::opt::ArgStringList* cc1_arguments =
        clang::tooling::getCC1Arguments(diagnostics.get(), compilation.get());
    if (cc1_arguments == nullptr || diagnostics->hasErrorOccurred()) {
        throw Failure{};
    }
    std::vector<std::string> copied_cc1_argv;
    copied_cc1_argv.reserve(cc1_arguments->size());
    for (const char* argument : *cc1_arguments) {
        copied_cc1_argv.emplace_back(argument);
    }
    if (receipt != nullptr) {
        receipt->cc1_argv_frozen(copied_cc1_argv);
    }
    require_receipt_safe_arguments(copied_cc1_argv);
    if (copied_cc1_argv.front() != "-cc1" ||
        std::count(copied_cc1_argv.begin(), copied_cc1_argv.end(), "-cc1") != 1 ||
        copied_cc1_argv.size() != frontend->getArguments().size()) {
        throw Failure{};
    }
    for (std::size_t index = 0; index < copied_cc1_argv.size(); ++index) {
        if (copied_cc1_argv[index] != frontend->getArguments()[index]) {
            throw Failure{};
        }
    }
    return ExpandedInvocation{std::move(driver_argv), std::move(copied_cc1_argv),
                              std::move(file_system)};
}

#if defined(V631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS)
std::vector<RawCborWriter::Byte> encode_driver_cc1_audit(
    const ExpandedInvocation& expansion) {
    RawCborWriter writer;
    writer.array(4);
    writer.uint(631302);
    writer.uint(4);
    writer.array(expansion.driver_argv.size());
    for (const std::string& argument : expansion.driver_argv) {
        writer.text(argument);
    }
    writer.array(expansion.cc1_argv.size());
    for (const std::string& argument : expansion.cc1_argv) {
        writer.text(argument);
    }
    return std::move(writer).take_bytes();
}
#endif

#if defined(V631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS)
class SilentTestDiagnosticConsumer final : public clang::DiagnosticConsumer {};
#endif

}  // namespace
}  // namespace evaluation_v6_3_1::m0_diagnostic

int main(int argc, char** argv) {
    using namespace evaluation_v6_3_1::m0_diagnostic;
    try {
        const auto command = parse_command_line(argc, argv);
        if (!command) {
            std::cerr << kErrorPrefix << "M0_DIAGNOSTIC_INVENTORY_INCOMPLETE\n";
            return kProtocolFailure;
        }
        std::optional<evaluation_v6_3_1::capture_v2::CollectorReceipt> receipt;
#if defined(V631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS)
        if (!command->no_fd3_receipt) {
#endif
            receipt.emplace(command->capture_context_hex);
            receipt->start();
#if defined(V631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS)
        }
#endif
        clang::DiagnosticConsumer* diagnostic_consumer = nullptr;
#if defined(V631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS)
        SilentTestDiagnosticConsumer silent_diagnostics;
        if (command->definition_observation_audit) {
            diagnostic_consumer = &silent_diagnostics;
        }
#endif
        const ExpandedInvocation expansion =
            expand_driver_once(*command, diagnostic_consumer,
                               receipt ? &*receipt : nullptr);
#if defined(V631302_M0_DIAGNOSTIC_ENABLE_STRUCTURAL_TEST_HOOKS)
        if (command->driver_cc1_audit) {
            const std::vector<RawCborWriter::Byte> audit = encode_driver_cc1_audit(expansion);
            std::cout.write(reinterpret_cast<const char*>(audit.data()),
                            static_cast<std::streamsize>(audit.size()));
            if (!std::cout) {
                throw Failure{};
            }
            return 0;
        }
#endif
        std::vector<std::string> execution_argv;
        execution_argv.reserve(expansion.cc1_argv.size() + 1);
        execution_argv.push_back(expansion.driver_argv.front());
        execution_argv.insert(execution_argv.end(), expansion.cc1_argv.begin(),
                              expansion.cc1_argv.end());
        std::vector<RawCborWriter::Byte> output;
        clang::FileSystemOptions file_options;
        auto files = llvm::IntrusiveRefCntPtr<clang::FileManager>(
            new clang::FileManager(file_options, expansion.file_system));
        clang::tooling::ToolInvocation invocation(
            std::move(execution_argv),
            std::make_unique<CollectorAction>(output, command->structural_audit,
                                              command->definition_observation_audit,
                                              command->force_nonconvergence,
                                              command->inject_repeated_rav_edge),
            files.get());
        if (diagnostic_consumer != nullptr) {
            invocation.setDiagnosticConsumer(diagnostic_consumer);
        }
        if (receipt) {
            receipt->cc1_execution_begin();
        }
        const bool frontend_succeeded = invocation.run();
        if (frontend_succeeded && receipt) {
            receipt->cc1_execution_end();
        }
        if (!frontend_succeeded &&
            !(command->definition_observation_audit && !output.empty())) {
            std::cerr << kErrorPrefix << "M0_FRONTEND_FAILED\n";
            return kFrontendFailure;
        }
        if (output.empty()) {
            throw Failure{};
        }
        if (receipt) {
            receipt->finalize();
        }
        std::cout.write(reinterpret_cast<const char*>(output.data()),
                        static_cast<std::streamsize>(output.size()));
        if (!std::cout) {
            throw Failure{};
        }
        return 0;
    } catch (const FrontendFailure&) {
        std::cerr << kErrorPrefix << "M0_FRONTEND_FAILED\n";
        return kFrontendFailure;
    } catch (const std::exception&) {
        std::cerr << kErrorPrefix << "M0_DIAGNOSTIC_INVENTORY_INCOMPLETE\n";
        return kProtocolFailure;
    }
}
