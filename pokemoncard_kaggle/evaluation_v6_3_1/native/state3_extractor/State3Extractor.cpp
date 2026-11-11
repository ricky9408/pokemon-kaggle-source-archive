#include "Observation.h"

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/ASTDumperUtils.h"
#include "clang/AST/Attr.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/EvaluatedExprVisitor.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/ExprConcepts.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtCXX.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/FileManager.h"
#include "clang/Basic/LangStandard.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Driver/Compilation.h"
#include "clang/Driver/Driver.h"
#include "clang/Driver/Job.h"
#include "clang/Driver/Tool.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Lex/Lexer.h"
#include "clang/Lex/MacroInfo.h"
#include "clang/Lex/PPCallbacks.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/Host.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::native {
namespace {

constexpr std::string_view kCompilerEntry = "/v631302/toolchain/bin/clang++";
constexpr std::string_view kSourceRoot = "/v631302/src";
constexpr std::string_view kRuntimeRoot = "/v631302/toolchain";
constexpr std::string_view kWorkingDirectory = "/v631302/work";
constexpr std::string_view kTargetRoot =
    "e7945c89633e0bf4e4f56ed2830d7126e78055ca280b6e19e69a817b9a48bdde";
constexpr std::string_view kTargetSchema =
    "eval.v6.3.1.compiler-derived-function-registry.v1";

constexpr int kFrontendFailure = 65;
constexpr int kProtocolFailure = 66;
constexpr int kInvariantFailure = 70;

struct Failure final : std::exception {
    int exit_code;
    std::string code;

    Failure(int value, std::string failure_code)
        : exit_code(value), code(std::move(failure_code)) {}

    const char* what() const noexcept override { return code.c_str(); }
};

[[noreturn]] void protocol_failure(std::string code) {
    throw Failure(kProtocolFailure, std::move(code));
}

bool under_root(std::string_view path, std::string_view root) {
    return path.size() > root.size() && path.substr(0, root.size()) == root &&
           path[root.size()] == '/';
}

bool canonical_absolute_path(std::string_view path) {
    if (path.empty() || path.front() != '/' || path.back() == '/' ||
        path.find('\0') != std::string_view::npos) {
        return false;
    }
    std::size_t begin = 1;
    while (begin <= path.size()) {
        const std::size_t end = path.find('/', begin);
        const std::string_view component = path.substr(
            begin, end == std::string_view::npos ? path.size() - begin : end - begin);
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

std::uint32_t parse_canonical_u32(std::string_view value) {
    if (value.empty() || (value.size() > 1 && value.front() == '0')) {
        protocol_failure("M0_TU_ORDINAL_INVALID");
    }
    std::uint64_t parsed = 0;
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (result.ec != std::errc() || result.ptr != value.data() + value.size() ||
        parsed > std::numeric_limits<std::uint32_t>::max()) {
        protocol_failure("M0_TU_ORDINAL_INVALID");
    }
    return static_cast<std::uint32_t>(parsed);
}

void checked_increment(std::uint32_t& value, std::string_view code) {
    if (value == std::numeric_limits<std::uint32_t>::max()) {
        protocol_failure(std::string(code));
    }
    ++value;
}

std::string pointer_id(const void* pointer) {
    return "0x" + llvm::utohexstr(reinterpret_cast<std::uint64_t>(pointer), true);
}

std::string declaration_kind(const clang::FunctionDecl& declaration) {
    return std::string(static_cast<const clang::Decl&>(declaration).getDeclKindName()) +
           "Decl";
}

std::uint8_t linkage_code(const clang::FunctionDecl& declaration) {
    return declaration.hasExternalFormalLinkage() ? 1u : 2u;
}

std::string raw_qual_type(const clang::FunctionDecl& declaration,
                          const clang::ASTContext& context) {
    clang::PrintingPolicy policy(context.getPrintingPolicy());
    return declaration.getType().getAsString(policy);
}

struct SourceSpan {
    std::string path;
    std::uint64_t begin = 0;
    std::uint64_t end = 0;
};

using AttributeMacroKey = std::pair<std::string, std::uint64_t>;
using AttributeMacroIndex = std::map<AttributeMacroKey, bool>;

std::optional<std::string> canonical_file_path(clang::FileManager& files,
                                               clang::FileEntryRef file) {
    llvm::StringRef canonical = files.getCanonicalName(&file.getFileEntry());
    if (canonical.empty()) {
        return std::nullopt;
    }
    llvm::SmallString<256> normalized(canonical);
    if (!llvm::sys::path::is_absolute(normalized)) {
        return std::nullopt;
    }
    if (llvm::sys::path::remove_dots(normalized, true)) {
        return std::nullopt;
    }
    std::string result = normalized.str().str();
    if (!canonical_absolute_path(result)) {
        return std::nullopt;
    }
    return result;
}

std::optional<SourceSpan> source_span(const clang::FunctionDecl& declaration,
                                      clang::ASTContext& context,
                                      const AttributeMacroIndex& attribute_macros) {
    clang::SourceManager& sources = context.getSourceManager();
    clang::SourceLocation begin_location = declaration.getBeginLoc();
    clang::SourceLocation end_location = declaration.getEndLoc();
    const clang::Stmt* body = declaration.getBody();
    const bool macro_prefix = begin_location.isMacroID();
    if (begin_location.isInvalid() || end_location.isInvalid() || body == nullptr ||
        body->getBeginLoc().isInvalid() || body->getEndLoc().isInvalid() ||
        body->getBeginLoc().isMacroID() || body->getEndLoc().isMacroID() ||
        end_location.isMacroID()) {
        return std::nullopt;
    }
    begin_location = sources.getExpansionLoc(begin_location);
    end_location = sources.getExpansionLoc(end_location);
    if (begin_location.isInvalid() || end_location.isInvalid()) {
        return std::nullopt;
    }
    const clang::FileID begin_file = sources.getFileID(begin_location);
    if (begin_file != sources.getFileID(end_location)) {
        return std::nullopt;
    }
    const auto file = sources.getFileEntryRefForID(begin_file);
    if (!file) {
        return std::nullopt;
    }
    auto path = canonical_file_path(sources.getFileManager(), *file);
    if (!path || !under_root(*path, kSourceRoot)) {
        return std::nullopt;
    }
    clang::SourceLocation after_token = clang::Lexer::getLocForEndOfToken(
        end_location, 0, sources, context.getLangOpts());
    if (after_token.isInvalid() || after_token.isMacroID() ||
        sources.getFileID(after_token) != begin_file) {
        return std::nullopt;
    }
    const std::uint64_t begin = sources.getFileOffset(begin_location);
    const std::uint64_t end = sources.getFileOffset(after_token);
    if (end <= begin) {
        return std::nullopt;
    }
    if (macro_prefix) {
        const auto macro = attribute_macros.find(AttributeMacroKey{*path, begin});
        if (macro == attribute_macros.end() || !macro->second) {
            return std::nullopt;
        }
    }
    return SourceSpan{*path, begin, end};
}

bool token_identifier_is(const clang::Token& token, llvm::StringRef expected) {
    const clang::IdentifierInfo* identifier = token.getIdentifierInfo();
    return identifier != nullptr && identifier->getName() == expected;
}

std::optional<std::size_t> consume_balanced(const clang::MacroInfo& macro,
                                            std::size_t begin,
                                            clang::tok::TokenKind open,
                                            clang::tok::TokenKind close) {
    if (begin >= macro.getNumTokens() || !macro.getReplacementToken(begin).is(open)) {
        return std::nullopt;
    }
    std::size_t depth = 0;
    for (std::size_t index = begin; index < macro.getNumTokens(); ++index) {
        const clang::Token& token = macro.getReplacementToken(index);
        if (token.is(open)) {
            ++depth;
        } else if (token.is(close)) {
            if (depth == 0) {
                return std::nullopt;
            }
            --depth;
            if (depth == 0) {
                return index + 1;
            }
        }
    }
    return std::nullopt;
}

bool attribute_only_macro(const clang::MacroInfo* macro) {
    if (macro == nullptr || macro->isBuiltinMacro() || macro->getNumTokens() == 0) {
        return false;
    }
    std::size_t index = 0;
    bool saw_attribute = false;
    while (index < macro->getNumTokens()) {
        const clang::Token& token = macro->getReplacementToken(index);
        if (token_identifier_is(token, "__attribute__") ||
            token_identifier_is(token, "__attribute")) {
            saw_attribute = true;
            ++index;
            if (index + 1 >= macro->getNumTokens() ||
                !macro->getReplacementToken(index).is(clang::tok::l_paren) ||
                !macro->getReplacementToken(index + 1).is(clang::tok::l_paren)) {
                return false;
            }
            const auto end = consume_balanced(
                *macro, index, clang::tok::l_paren, clang::tok::r_paren);
            if (!end || *end < index + 4 ||
                !macro->getReplacementToken(*end - 2).is(clang::tok::r_paren)) {
                return false;
            }
            index = *end;
            continue;
        }
        if (token_identifier_is(token, "__declspec")) {
            saw_attribute = true;
            ++index;
            const auto end = consume_balanced(
                *macro, index, clang::tok::l_paren, clang::tok::r_paren);
            if (!end || *end < index + 2) {
                return false;
            }
            index = *end;
            continue;
        }
        if (token.is(clang::tok::l_square) && index + 1 < macro->getNumTokens() &&
            macro->getReplacementToken(index + 1).is(clang::tok::l_square)) {
            saw_attribute = true;
            const auto end = consume_balanced(
                *macro, index, clang::tok::l_square, clang::tok::r_square);
            if (!end || *end < index + 4 ||
                !macro->getReplacementToken(*end - 2).is(clang::tok::r_square)) {
                return false;
            }
            index = *end;
            continue;
        }
        return false;
    }
    return saw_attribute;
}

bool location_is_source_backed(clang::SourceLocation location,
                               clang::ASTContext& context) {
    if (location.isInvalid()) {
        return false;
    }
    clang::SourceManager& sources = context.getSourceManager();
    const std::array<clang::SourceLocation, 2> candidates = {
        sources.getSpellingLoc(location),
        sources.getExpansionLoc(location),
    };
    for (clang::SourceLocation candidate : candidates) {
        if (candidate.isInvalid()) {
            continue;
        }
        candidate = sources.getFileLoc(candidate);
        const auto file = sources.getFileEntryRefForID(sources.getFileID(candidate));
        if (!file) {
            continue;
        }
        const auto path = canonical_file_path(sources.getFileManager(), *file);
        if (path && under_root(*path, kSourceRoot)) {
            return true;
        }
    }
    return false;
}

bool definition_is_source_backed(const clang::FunctionDecl& declaration,
                                 clang::ASTContext& context) {
    return location_is_source_backed(declaration.getBeginLoc(), context) ||
           location_is_source_backed(declaration.getEndLoc(), context);
}

class InputCollector final : public clang::PPCallbacks {
public:
    InputCollector(clang::FileManager& files, clang::SourceManager& sources,
                   clang::Preprocessor& preprocessor)
        : files_(files), sources_(sources), preprocessor_(preprocessor) {}

    void LexedFileChanged(clang::FileID file_id, LexedFileChangeReason reason,
                          clang::SrcMgr::CharacteristicKind,
                          clang::FileID, clang::SourceLocation) override {
        if (reason != LexedFileChangeReason::EnterFile || !error_.empty()) {
            return;
        }
        if (file_id == preprocessor_.getPredefinesFileID()) {
            return;
        }
        if (const auto file = sources_.getFileEntryRefForID(file_id)) {
            record_physical(*file);
            return;
        }
        record_virtual(file_id);
    }

    void MacroExpands(const clang::Token& token,
                      const clang::MacroDefinition& definition,
                      clang::SourceRange range,
                      const clang::MacroArgs*) override {
        record_attribute_macro(definition, range);
        const clang::IdentifierInfo* identifier = token.getIdentifierInfo();
        if (identifier == nullptr) {
            return;
        }
        const llvm::StringRef name = identifier->getName();
        if (name == "__DATE__" || name == "__TIME__" || name == "__TIMESTAMP__") {
            if (nondeterministic_builtins_ == std::numeric_limits<std::uint32_t>::max()) {
                error_ = "M0_INPUT_COUNTER_OVERFLOW";
            } else {
                ++nondeterministic_builtins_;
            }
        }
    }

    const std::string& error() const { return error_; }
    std::uint32_t compiler_file_activations() const { return file_activations_; }
    std::uint32_t compiler_virtual_activations() const { return virtual_activations_; }
    std::uint32_t nondeterministic_builtins() const { return nondeterministic_builtins_; }
    const std::map<std::string, PhysicalInput>& physical() const { return physical_; }
    const std::map<std::tuple<std::uint8_t, std::string, std::string>, VirtualInput>&
    virtual_inputs() const {
        return virtual_;
    }
    const AttributeMacroIndex& attribute_macros() const { return attribute_macros_; }

private:
    void record_attribute_macro(const clang::MacroDefinition& definition,
                                clang::SourceRange range) {
        clang::SourceLocation begin = sources_.getExpansionLoc(range.getBegin());
        clang::SourceLocation end = sources_.getExpansionLoc(range.getEnd());
        if (begin.isInvalid() || end.isInvalid() ||
            sources_.getFileID(begin) != sources_.getFileID(end)) {
            return;
        }
        const auto file = sources_.getFileEntryRefForID(sources_.getFileID(begin));
        if (!file) {
            return;
        }
        const auto path = canonical_file_path(files_, *file);
        if (!path || !under_root(*path, kSourceRoot)) {
            return;
        }
        const AttributeMacroKey key{*path, sources_.getFileOffset(begin)};
        const bool accepted = attribute_only_macro(definition.getMacroInfo());
        auto [iterator, inserted] = attribute_macros_.try_emplace(key, accepted);
        if (!inserted) {
            iterator->second = iterator->second && accepted;
        }
    }

    void record_physical(clang::FileEntryRef file) {
        auto path = canonical_file_path(files_, file);
        if (!path) {
            error_ = "M0_PHYSICAL_PATH_INVALID";
            return;
        }
        std::uint8_t origin = 0;
        if (under_root(*path, kSourceRoot)) {
            origin = 1;
        } else if (under_root(*path, kRuntimeRoot)) {
            origin = 2;
        } else {
            error_ = "M0_PHYSICAL_INPUT_OUTSIDE_ROOT";
            return;
        }
        auto [iterator, inserted] = physical_.try_emplace(
            *path, PhysicalInput{origin, *path, 0});
        if (!inserted && iterator->second.origin != origin) {
            error_ = "M0_PHYSICAL_ORIGIN_COLLISION";
            return;
        }
        if (iterator->second.activation_count == std::numeric_limits<std::uint32_t>::max() ||
            file_activations_ == std::numeric_limits<std::uint32_t>::max()) {
            error_ = "M0_INPUT_COUNTER_OVERFLOW";
            return;
        }
        ++iterator->second.activation_count;
        ++file_activations_;
    }

    void record_virtual(clang::FileID file_id) {
        bool invalid = false;
        const llvm::StringRef content = sources_.getBufferData(file_id, &invalid);
        if (invalid) {
            error_ = "M0_VIRTUAL_BUFFER_UNAVAILABLE";
            return;
        }
        const clang::SourceLocation start = sources_.getLocForStartOfFile(file_id);
        const llvm::StringRef name = sources_.getBufferName(start, &invalid);
        if (invalid || name.empty()) {
            error_ = "M0_VIRTUAL_NAME_INVALID";
            return;
        }
        std::uint8_t kind = 3;
        if (name == "<built-in>") {
            kind = 1;
        } else if (name == "<command line>") {
            kind = 2;
        }
        const auto key = std::make_tuple(kind, name.str(), content.str());
        auto [iterator, inserted] = virtual_.try_emplace(
            key, VirtualInput{kind, name.str(), content.str(), 0});
        (void)inserted;
        if (iterator->second.activation_count == std::numeric_limits<std::uint32_t>::max() ||
            virtual_activations_ == std::numeric_limits<std::uint32_t>::max()) {
            error_ = "M0_INPUT_COUNTER_OVERFLOW";
            return;
        }
        ++iterator->second.activation_count;
        ++virtual_activations_;
    }

    clang::FileManager& files_;
    clang::SourceManager& sources_;
    clang::Preprocessor& preprocessor_;
    std::map<std::string, PhysicalInput> physical_;
    std::map<std::tuple<std::uint8_t, std::string, std::string>, VirtualInput> virtual_;
    AttributeMacroIndex attribute_macros_;
    std::uint32_t file_activations_ = 0;
    std::uint32_t virtual_activations_ = 0;
    std::uint32_t nondeterministic_builtins_ = 0;
    std::string error_;
};

struct PendingInvocation {
    const clang::Stmt* anchor = nullptr;
    std::uint8_t kind = 0;
    const clang::FunctionDecl* callee = nullptr;
};

class InvocationVisitor final : public clang::EvaluatedExprVisitor<InvocationVisitor> {
public:
    using Base = clang::EvaluatedExprVisitor<InvocationVisitor>;

    explicit InvocationVisitor(clang::ASTContext& context)
        : Base(context), context_(context) {}

    bool shouldVisitDiscardedStmt() const { return false; }

    void ObserveDefinition(const clang::FunctionDecl& declaration) {
        const clang::FunctionDecl::TemplatedKind templated = declaration.getTemplatedKind();
        if (declaration.isDependentContext() ||
            templated == clang::FunctionDecl::TK_FunctionTemplate ||
            templated == clang::FunctionDecl::TK_DependentFunctionTemplateSpecialization ||
            templated == clang::FunctionDecl::TK_DependentNonTemplate ||
            llvm::isa<clang::CoroutineBodyStmt>(declaration.getBody())) {
            inventory_incomplete_ = true;
        }
        if (declaration.hasAttr<clang::ConstructorAttr>() ||
            declaration.hasAttr<clang::DestructorAttr>() ||
            declaration.hasAttr<clang::IFuncAttr>() ||
            declaration.hasAttr<clang::TargetClonesAttr>() ||
            declaration.hasAttr<clang::TargetVersionAttr>()) {
            inventory_incomplete_ = true;
        }

        if (const auto* destructor = llvm::dyn_cast<clang::CXXDestructorDecl>(&declaration)) {
            const clang::CXXRecordDecl* record = destructor->getParent();
            for (const clang::FieldDecl* field : record->fields()) {
                if (needs_destruction(field->getType())) {
                    inventory_incomplete_ = true;
                }
            }
            for (const clang::CXXBaseSpecifier& base : record->bases()) {
                if (needs_destruction(base.getType())) {
                    inventory_incomplete_ = true;
                }
            }
            for (const clang::CXXBaseSpecifier& base : record->vbases()) {
                if (needs_destruction(base.getType())) {
                    inventory_incomplete_ = true;
                }
            }
        }

        if (context_.getLangOpts().CXXExceptions) {
            if (const auto* constructor =
                    llvm::dyn_cast<clang::CXXConstructorDecl>(&declaration)) {
                for (const clang::CXXCtorInitializer* initializer : constructor->inits()) {
                    clang::QualType initialized_type;
                    if (initializer->isMemberInitializer()) {
                        initialized_type = initializer->getMember()->getType();
                    } else if (initializer->isBaseInitializer()) {
                        initialized_type = initializer->getTypeSourceInfo()->getType();
                    }
                    if (!initialized_type.isNull() && needs_destruction(initialized_type)) {
                        inventory_incomplete_ = true;
                    }
                }
            }
        }
    }

    void ObserveParameter(const clang::ParmVarDecl& declaration) {
        const clang::QualType type = context_.getBaseElementType(declaration.getType());
        const auto* record_type = type->getAs<clang::RecordType>();
        const auto* record = record_type == nullptr
                                 ? nullptr
                                 : llvm::dyn_cast<clang::CXXRecordDecl>(
                                       record_type->getDecl());
        if (declaration.getOriginalType()->isVariablyModifiedType() ||
            has_nontrivial_destructor(declaration.getType()) ||
            (record != nullptr &&
             (record->hasNonTrivialCopyConstructorForCall() ||
              record->hasNonTrivialMoveConstructorForCall()))) {
            inventory_incomplete_ = true;
        }
    }

    void VisitExpr(clang::Expr* expression) {
        if (!concrete(expression)) {
            return;
        }
        Base::VisitStmt(expression);
    }

    void VisitCallExpr(clang::CallExpr* expression) {
        if (expression->isUnevaluatedBuiltinCall(context_) || !concrete(expression)) {
            return;
        }
        const clang::FunctionDecl* callee = expression->getDirectCallee();
        if (callee == nullptr) {
            checked_increment(unresolved_, "M0_INVOCATION_COUNTER_OVERFLOW");
        } else if (callee->getBuiltinID(false) != 0) {
            invocations_.push_back(PendingInvocation{expression, 8, callee});
        } else if (llvm::isa<clang::CXXDestructorDecl>(callee) ||
                   llvm::isa<clang::CXXConversionDecl>(callee)) {
            checked_increment(unsupported_, "M0_INVOCATION_COUNTER_OVERFLOW");
        } else if (const auto* method = llvm::dyn_cast<clang::CXXMethodDecl>(callee);
                   method != nullptr && method->isVirtual()) {
            checked_increment(unresolved_, "M0_INVOCATION_COUNTER_OVERFLOW");
        } else {
            invocations_.push_back(PendingInvocation{expression, 1, callee});
        }
        Base::VisitStmt(expression);
    }

    void VisitVAArgExpr(clang::VAArgExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitCXXConstructExpr(clang::CXXConstructExpr* expression) {
        if (!concrete(expression)) {
            return;
        }
        if (expression->isElidable()) {
            inventory_incomplete_ = true;
            return;
        }
        const clang::CXXConstructorDecl* constructor = expression->getConstructor();
        if (constructor == nullptr) {
            checked_increment(unresolved_, "M0_INVOCATION_COUNTER_OVERFLOW");
        } else {
            invocations_.push_back(PendingInvocation{expression, 2, constructor});
        }
        Base::VisitStmt(expression);
    }

    void VisitCXXInheritedCtorInitExpr(clang::CXXInheritedCtorInitExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitArrayInitLoopExpr(clang::ArrayInitLoopExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitReturnStmt(clang::ReturnStmt* statement) {
        if (statement->getNRVOCandidate() != nullptr) {
            inventory_incomplete_ = true;
            return;
        }
        Base::VisitStmt(statement);
    }

    void VisitCXXNewExpr(clang::CXXNewExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitCXXDeleteExpr(clang::CXXDeleteExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitCXXPseudoDestructorExpr(clang::CXXPseudoDestructorExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitCoroutineBodyStmt(clang::CoroutineBodyStmt*) {
        inventory_incomplete_ = true;
    }

    void VisitCoreturnStmt(clang::CoreturnStmt*) {
        inventory_incomplete_ = true;
    }

    void VisitCoawaitExpr(clang::CoawaitExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitDependentCoawaitExpr(clang::DependentCoawaitExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitCoyieldExpr(clang::CoyieldExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitLambdaExpr(clang::LambdaExpr* expression) {
        if (!concrete(expression)) {
            return;
        }
        inventory_incomplete_ = true;
    }

    void VisitCXXBindTemporaryExpr(clang::CXXBindTemporaryExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitMaterializeTemporaryExpr(clang::MaterializeTemporaryExpr* expression) {
        if (!concrete(expression)) {
            return;
        }
        if (has_nontrivial_destructor(expression->getType())) {
            inventory_incomplete_ = true;
            return;
        }
        Base::VisitStmt(expression);
    }

    void VisitExprWithCleanups(clang::ExprWithCleanups* expression) {
        if (!concrete(expression)) {
            return;
        }
        if (expression->cleanupsHaveSideEffects() || expression->getNumObjects() != 0) {
            inventory_incomplete_ = true;
            return;
        }
        Base::VisitStmt(expression);
    }

    void VisitDeclStmt(clang::DeclStmt* statement) {
        for (clang::Decl* declaration : statement->decls()) {
            auto* variable = llvm::dyn_cast<clang::VarDecl>(declaration);
            if (variable == nullptr) {
                if (const auto* alias = llvm::dyn_cast<clang::TypedefNameDecl>(declaration);
                    alias != nullptr && alias->getUnderlyingType()->isVariablyModifiedType()) {
                    inventory_incomplete_ = true;
                }
                continue;
            }
            if (llvm::isa<clang::DecompositionDecl>(variable)) {
                inventory_incomplete_ = true;
                continue;
            }
            const clang::QualType base_element =
                context_.getBaseElementType(variable->getType());
            if (variable->getType()->isInstantiationDependentType() ||
                variable->getType()->isVariablyModifiedType() ||
                (variable->getType()->isArrayType() && base_element->isRecordType()) ||
                variable->hasAttr<clang::CleanupAttr>() ||
                variable->isStaticLocal() || variable->getTLSKind() != clang::VarDecl::TLS_None ||
                variable->needsDestruction(context_) != clang::QualType::DK_none) {
                inventory_incomplete_ = true;
                continue;
            }
            if (variable->hasInit()) {
                this->Visit(variable->getInit());
            }
        }
    }

    void VisitCXXCatchStmt(clang::CXXCatchStmt* statement) {
        const clang::VarDecl* exception = statement->getExceptionDecl();
        if (exception != nullptr && !exception->getType()->isReferenceType() &&
            exception->needsDestruction(context_) != clang::QualType::DK_none) {
            inventory_incomplete_ = true;
            return;
        }
        Base::VisitStmt(statement);
    }

    void VisitCXXForRangeStmt(clang::CXXForRangeStmt*) {
        inventory_incomplete_ = true;
    }

    void VisitIfStmt(clang::IfStmt* statement) {
        if (!statement->isConstexpr()) {
            if (statement->isConsteval()) {
                inventory_incomplete_ = true;
                return;
            }
            Base::VisitStmt(statement);
            return;
        }
        if (statement->getInit() != nullptr) {
            this->Visit(statement->getInit());
        }
        if (statement->getConditionVariable() != nullptr ||
            statement->getCond() == nullptr || dependent(*statement->getCond())) {
            inventory_incomplete_ = true;
            return;
        }
        const std::optional<clang::Stmt*> selected = statement->getNondiscardedCase(context_);
        if (!selected) {
            inventory_incomplete_ = true;
            return;
        }
        if (*selected != nullptr) {
            this->Visit(*selected);
        }
    }

    void VisitChooseExpr(clang::ChooseExpr* expression) {
        if (expression->getCond()->isValueDependent() || expression->getChosenSubExpr() == nullptr) {
            inventory_incomplete_ = true;
            return;
        }
        this->Visit(expression->getChosenSubExpr());
    }

    void VisitGenericSelectionExpr(clang::GenericSelectionExpr* expression) {
        if (expression->isResultDependent() || expression->getResultExpr() == nullptr) {
            inventory_incomplete_ = true;
            return;
        }
        this->Visit(expression->getResultExpr());
    }

    void VisitUnaryExprOrTypeTraitExpr(clang::UnaryExprOrTypeTraitExpr* expression) {
        if (expression->isArgumentType() &&
            expression->getArgumentType()->isVariablyModifiedType()) {
            inventory_incomplete_ = true;
        }
    }
    void VisitExpressionTraitExpr(clang::ExpressionTraitExpr*) {}
    void VisitOffsetOfExpr(clang::OffsetOfExpr*) {}
    void VisitCXXNoexceptExpr(clang::CXXNoexceptExpr*) {}
    void VisitCXXUuidofExpr(clang::CXXUuidofExpr*) {}
    void VisitRequiresExpr(clang::RequiresExpr*) {}
    void VisitConstantExpr(clang::ConstantExpr*) {}

    void VisitCXXTypeidExpr(clang::CXXTypeidExpr* expression) {
        if (expression->isTypeOperand()) {
            return;
        }
        if (dependent(*expression->getExprOperand())) {
            inventory_incomplete_ = true;
            return;
        }
        if (expression->isPotentiallyEvaluated()) {
            inventory_incomplete_ = true;
        }
    }

    void VisitCXXDefaultArgExpr(clang::CXXDefaultArgExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitCXXDefaultInitExpr(clang::CXXDefaultInitExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitCXXThrowExpr(clang::CXXThrowExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitCXXTryStmt(clang::CXXTryStmt*) {
        inventory_incomplete_ = true;
    }

    void VisitCXXDynamicCastExpr(clang::CXXDynamicCastExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitAtomicExpr(clang::AtomicExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitPseudoObjectExpr(clang::PseudoObjectExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitCXXRewrittenBinaryOperator(clang::CXXRewrittenBinaryOperator*) {
        inventory_incomplete_ = true;
    }

    void VisitGCCAsmStmt(clang::GCCAsmStmt*) {
        inventory_incomplete_ = true;
    }

    void VisitMSAsmStmt(clang::MSAsmStmt*) {
        inventory_incomplete_ = true;
    }

    void VisitBlockExpr(clang::BlockExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitCXXUnresolvedConstructExpr(clang::CXXUnresolvedConstructExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitUnresolvedLookupExpr(clang::UnresolvedLookupExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitUnresolvedMemberExpr(clang::UnresolvedMemberExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitCXXDependentScopeMemberExpr(clang::CXXDependentScopeMemberExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitDependentScopeDeclRefExpr(clang::DependentScopeDeclRefExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitPackExpansionExpr(clang::PackExpansionExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitFunctionParmPackExpr(clang::FunctionParmPackExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitCXXFoldExpr(clang::CXXFoldExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitRecoveryExpr(clang::RecoveryExpr*) {
        inventory_incomplete_ = true;
    }

    void VisitTypoExpr(clang::TypoExpr*) {
        inventory_incomplete_ = true;
    }

    const std::vector<PendingInvocation>& invocations() const { return invocations_; }
    std::uint32_t unresolved() const { return unresolved_; }
    std::uint32_t unsupported() const { return unsupported_; }
    bool inventory_incomplete() const { return inventory_incomplete_; }

private:
    bool dependent(const clang::Expr& expression) const {
        return expression.isTypeDependent() || expression.isValueDependent() ||
               expression.isInstantiationDependent() ||
               expression.containsUnexpandedParameterPack();
    }

    bool concrete(const clang::Expr* expression) {
        if (expression == nullptr || dependent(*expression)) {
            inventory_incomplete_ = true;
            return false;
        }
        return true;
    }

    bool needs_destruction(clang::QualType type) const {
        return type.isDestructedType() != clang::QualType::DK_none;
    }

    bool has_nontrivial_destructor(clang::QualType declared_type) const {
        const clang::QualType type = context_.getBaseElementType(declared_type);
        if (const auto* record_type = type->getAs<clang::RecordType>()) {
            if (const auto* record = llvm::dyn_cast<clang::CXXRecordDecl>(record_type->getDecl());
                record != nullptr && record->hasNonTrivialDestructor()) {
                return true;
            }
        }
        return false;
    }
    clang::ASTContext& context_;
    std::vector<PendingInvocation> invocations_;
    std::uint32_t unresolved_ = 0;
    std::uint32_t unsupported_ = 0;
    bool inventory_incomplete_ = false;
};

struct DefinitionCandidate {
    const clang::FunctionDecl* declaration = nullptr;
};

class DefinitionVisitor final : public clang::RecursiveASTVisitor<DefinitionVisitor> {
public:
    explicit DefinitionVisitor(clang::ASTContext& context) : context_(context) {}

    bool shouldVisitTemplateInstantiations() const { return true; }
    bool shouldVisitImplicitCode() const { return true; }

    bool VisitFunctionDecl(clang::FunctionDecl* declaration) {
        if (!declaration->isThisDeclarationADefinition() || declaration->getBody() == nullptr ||
            !seen_.insert(declaration).second) {
            return true;
        }
        if (!definition_is_source_backed(*declaration, context_)) {
            return true;
        }
        if (const auto* method = llvm::dyn_cast<clang::CXXMethodDecl>(declaration)) {
            const clang::CXXRecordDecl* parent = method->getParent();
            if (parent->isLambda() || parent->isLocalClass()) {
                inventory_incomplete_ = true;
                return true;
            }
        }
        candidates_.push_back(DefinitionCandidate{declaration});
        return true;
    }

    const std::vector<DefinitionCandidate>& candidates() const { return candidates_; }
    bool inventory_incomplete() const { return inventory_incomplete_; }

private:
    clang::ASTContext& context_;
    std::set<const clang::FunctionDecl*> seen_;
    std::vector<DefinitionCandidate> candidates_;
    bool inventory_incomplete_ = false;
};

class TranslationUnitRuntimeVisitor final
    : public clang::RecursiveASTVisitor<TranslationUnitRuntimeVisitor> {
public:
    explicit TranslationUnitRuntimeVisitor(clang::ASTContext& context) : context_(context) {}

    bool shouldVisitImplicitCode() const { return true; }
    bool shouldVisitTemplateInstantiations() const { return true; }

    bool VisitVarDecl(clang::VarDecl* declaration) {
        if (!source_backed(*declaration)) {
            return true;
        }
        if (declaration->getType()->isVariablyModifiedType()) {
            inventory_incomplete_ = true;
        }
        if ((!declaration->hasGlobalStorage() &&
             declaration->getTLSKind() == clang::VarDecl::TLS_None) ||
            declaration->isStaticLocal() ||
            declaration->isThisDeclarationADefinition(context_) ==
                clang::VarDecl::DeclarationOnly) {
            return true;
        }
        if (declaration->getTLSKind() != clang::VarDecl::TLS_None ||
            declaration->needsDestruction(context_) != clang::QualType::DK_none ||
            (declaration->hasInit() && !declaration->hasConstantInitialization())) {
            inventory_incomplete_ = true;
        }
        return true;
    }

    bool VisitFileScopeAsmDecl(clang::FileScopeAsmDecl* declaration) {
        if (source_backed(*declaration)) {
            inventory_incomplete_ = true;
        }
        return true;
    }

    bool VisitImportDecl(clang::ImportDecl* declaration) {
        if (source_backed(*declaration)) {
            inventory_incomplete_ = true;
        }
        return true;
    }

    bool inventory_incomplete() const { return inventory_incomplete_; }

private:
    bool source_backed(const clang::Decl& declaration) const {
        return location_is_source_backed(declaration.getBeginLoc(), context_) ||
               location_is_source_backed(declaration.getEndLoc(), context_);
    }

    clang::ASTContext& context_;
    bool inventory_incomplete_ = false;
};

struct TargetEntry {
    std::uint32_t index = 0;
    const clang::FunctionDecl* declaration = nullptr;
    std::uint64_t source_offset = 0;
};

class TargetPushVisitor final : public clang::RecursiveASTVisitor<TargetPushVisitor> {
public:
    explicit TargetPushVisitor(clang::ASTContext& context) : context_(context) {}

    bool VisitCXXMemberCallExpr(clang::CXXMemberCallExpr* call) {
        const clang::FunctionDecl* callee = call->getDirectCallee();
        if (callee == nullptr || callee->getName() != "push_back" || call->getNumArgs() != 1) {
            return true;
        }
        const clang::Expr* object = call->getImplicitObjectArgument();
        if (object == nullptr) {
            return true;
        }
        object = object->IgnoreParenImpCasts();
        const auto* table_ref = llvm::dyn_cast<clang::DeclRefExpr>(object);
        if (table_ref == nullptr || table_ref->getDecl()->getName() != "FunctionTable") {
            return true;
        }
        const clang::Expr* argument = call->getArg(0)->IgnoreParenImpCasts();
        while (const auto* cast = llvm::dyn_cast<clang::CastExpr>(argument)) {
            argument = cast->getSubExpr()->IgnoreParenImpCasts();
        }
        const auto* target_ref = llvm::dyn_cast<clang::DeclRefExpr>(argument);
        const auto* target = target_ref == nullptr
                                 ? nullptr
                                 : llvm::dyn_cast<clang::FunctionDecl>(target_ref->getDecl());
        if (target == nullptr) {
            invalid_ = true;
            return true;
        }
        clang::SourceLocation location = context_.getSourceManager().getFileLoc(call->getBeginLoc());
        if (location.isInvalid()) {
            invalid_ = true;
            return true;
        }
        entries_.push_back(TargetEntry{0, target, context_.getSourceManager().getFileOffset(location)});
        return true;
    }

    std::vector<TargetEntry>& entries() { return entries_; }
    bool invalid() const { return invalid_; }

private:
    clang::ASTContext& context_;
    std::vector<TargetEntry> entries_;
    bool invalid_ = false;
};

struct TargetRegistry {
    bool present = false;
    std::unordered_map<const clang::FunctionDecl*, std::vector<std::uint32_t>> indices;
};

std::string json_quote(llvm::StringRef value) {
    return llvm::formatv("{0}", llvm::json::Value(value)).str();
}

TargetRegistry collect_target_registry(clang::ASTContext& context) {
    std::vector<const clang::FunctionDecl*> initializers;
    class InitializerVisitor final : public clang::RecursiveASTVisitor<InitializerVisitor> {
    public:
        explicit InitializerVisitor(std::vector<const clang::FunctionDecl*>& output)
            : output_(output) {}
        bool VisitFunctionDecl(clang::FunctionDecl* declaration) {
            if (declaration->isThisDeclarationADefinition() && declaration->getBody() != nullptr &&
                declaration->getQualifiedNameAsString() == "InitializeBattleFunction") {
                output_.push_back(declaration);
            }
            return true;
        }
    private:
        std::vector<const clang::FunctionDecl*>& output_;
    } visitor(initializers);
    visitor.TraverseDecl(context.getTranslationUnitDecl());
    if (initializers.empty()) {
        return {};
    }
    if (initializers.size() != 1) {
        protocol_failure("M0_TARGET_REGISTRY_COMPILER_DRIFT");
    }

    TargetPushVisitor pushes(context);
    pushes.TraverseStmt(initializers.front()->getBody());
    auto entries = pushes.entries();
    if (pushes.invalid() || entries.size() != 116) {
        protocol_failure("M0_TARGET_REGISTRY_COMPILER_DRIFT");
    }
    std::sort(entries.begin(), entries.end(), [](const TargetEntry& left, const TargetEntry& right) {
        return left.source_offset < right.source_offset;
    });
    for (std::size_t index = 0; index < entries.size(); ++index) {
        if (index > 0 && entries[index - 1].source_offset == entries[index].source_offset) {
            protocol_failure("M0_TARGET_REGISTRY_COMPILER_DRIFT");
        }
        entries[index].index = static_cast<std::uint32_t>(index);
    }

    std::string projection = "{\"entries\":[";
    for (std::size_t index = 0; index < entries.size(); ++index) {
        if (index != 0) {
            projection.push_back(',');
        }
        const clang::FunctionDecl& declaration = *entries[index].declaration;
        projection += "{\"index\":" + std::to_string(index) +
                      ",\"name\":" + json_quote(declaration.getName()) +
                      ",\"qual_type\":" + json_quote(raw_qual_type(declaration, context)) + "}";
    }
    projection += "],\"schema\":" + json_quote(kTargetSchema) + "}";
    const auto digest = llvm::SHA256::hash(llvm::arrayRefFromStringRef(projection));
    if (llvm::toHex(digest, true) != kTargetRoot) {
        protocol_failure("M0_TARGET_REGISTRY_COMPILER_DRIFT");
    }

    TargetRegistry registry;
    registry.present = true;
    for (const TargetEntry& entry : entries) {
        registry.indices[entry.declaration->getCanonicalDecl()].push_back(entry.index);
    }
    return registry;
}

class JsonAnchorIndex final {
public:
    explicit JsonAnchorIndex(const clang::FunctionDecl& root) {
        std::string dump;
        llvm::raw_string_ostream stream(dump);
        root.dump(stream, false, clang::ADOF_JSON);
        stream.flush();
        llvm::Expected<llvm::json::Value> parsed = llvm::json::parse(dump);
        if (!parsed) {
            llvm::consumeError(parsed.takeError());
            protocol_failure("M0_JSON_AST_GRAPH_INVALID");
        }
        llvm::json::Object* object = parsed->getAsObject();
        if (object == nullptr) {
            protocol_failure("M0_JSON_AST_GRAPH_INVALID");
        }
        std::vector<std::uint32_t> path;
        walk(*object, path);
    }

    std::vector<std::uint32_t> path_for(const clang::Stmt* statement) const {
        const auto iterator = paths_.find(pointer_id(statement));
        if (iterator == paths_.end() || iterator->second.empty()) {
            protocol_failure("M0_AST_ANCHOR_NOT_FOUND");
        }
        const auto& paths = iterator->second;
        return *std::min_element(paths.begin(), paths.end(),
                                 [](const auto& left, const auto& right) {
                                     if (left.size() != right.size()) {
                                         return left.size() > right.size();
                                     }
                                     return left < right;
                                 });
    }

private:
    void walk(llvm::json::Object& object, std::vector<std::uint32_t>& path) {
        if (llvm::json::Value* id_value = object.get("id")) {
            const auto id = id_value->getAsString();
            if (!id) {
                protocol_failure("M0_JSON_AST_GRAPH_INVALID");
            }
            paths_[id->str()].push_back(path);
        }
        llvm::json::Value* inner_value = object.get("inner");
        if (inner_value == nullptr) {
            return;
        }
        llvm::json::Array* inner = inner_value->getAsArray();
        if (inner == nullptr || inner->size() > std::numeric_limits<std::uint32_t>::max()) {
            protocol_failure("M0_JSON_AST_GRAPH_INVALID");
        }
        for (std::size_t index = 0; index < inner->size(); ++index) {
            llvm::json::Object* child = (*inner)[index].getAsObject();
            if (child == nullptr) {
                protocol_failure("M0_JSON_AST_GRAPH_INVALID");
            }
            path.push_back(static_cast<std::uint32_t>(index));
            walk(*child, path);
            path.pop_back();
        }
    }

    std::map<std::string, std::vector<std::vector<std::uint32_t>>> paths_;
};

CalleeDescriptor describe_callee(const clang::FunctionDecl& declaration,
                                  clang::ASTContext& context,
                                  const AttributeMacroIndex& attribute_macros) {
    const clang::FunctionDecl* definition = declaration.getDefinition();
    if (definition == nullptr || !definition_is_source_backed(*definition, context)) {
        protocol_failure("M0_CALLEE_ORIGIN_UNSUPPORTED");
    }
    if (!source_span(*definition, context, attribute_macros)) {
        protocol_failure("M0_DEFINITION_SPAN_UNSUPPORTED");
    }
    return CalleeDescriptor{
        declaration_kind(declaration),
        declaration.getQualifiedNameAsString(),
        raw_qual_type(declaration, context),
        linkage_code(declaration),
        1,
    };
}

struct ExtractorState {
    Observation observation;
    std::vector<std::string> effective_cc1_argv;
    std::string primary_source;
    InputCollector* inputs = nullptr;
    std::string error;
    bool complete = false;
};

struct ClosedDefinitionInvocations {
    const clang::FunctionDecl* declaration = nullptr;
    std::vector<PendingInvocation> invocations;
    std::vector<std::vector<std::uint32_t>> anchor_paths;
};

class ExtractorConsumer final : public clang::ASTConsumer {
public:
    explicit ExtractorConsumer(ExtractorState& state) : state_(state) {}

    void HandleTranslationUnit(clang::ASTContext& context) override {
        try {
            if (state_.inputs == nullptr) {
                protocol_failure("M0_INPUT_COLLECTOR_MISSING");
            }
            if (!state_.inputs->error().empty()) {
                protocol_failure(state_.inputs->error());
            }
            if (context.getModuleForCodeGen() != nullptr) {
                protocol_failure("M0_INVOCATION_INVENTORY_INCOMPLETE");
            }
            DefinitionVisitor definitions(context);
            definitions.TraverseDecl(context.getTranslationUnitDecl());
            TranslationUnitRuntimeVisitor translation_unit_runtime(context);
            translation_unit_runtime.TraverseDecl(context.getTranslationUnitDecl());

            std::uint32_t unresolved = 0;
            std::uint32_t unsupported = 0;
            bool inventory_incomplete = definitions.inventory_incomplete() ||
                                        translation_unit_runtime.inventory_incomplete();
            std::vector<ClosedDefinitionInvocations> closed_definitions;
            closed_definitions.reserve(definitions.candidates().size());
            for (const DefinitionCandidate& candidate : definitions.candidates()) {
                const clang::FunctionDecl& declaration = *candidate.declaration;
                InvocationVisitor visitor(context);
                if (declaration.isConsteval()) {
                    closed_definitions.push_back(ClosedDefinitionInvocations{
                        &declaration,
                        {},
                        {},
                    });
                    continue;
                }
                visitor.ObserveDefinition(declaration);
                for (const clang::ParmVarDecl* parameter : declaration.parameters()) {
                    visitor.ObserveParameter(*parameter);
                }
                if (const auto* constructor = llvm::dyn_cast<clang::CXXConstructorDecl>(&declaration)) {
                    for (const clang::CXXCtorInitializer* initializer : constructor->inits()) {
                        if (initializer->getInit() != nullptr) {
                            visitor.Visit(initializer->getInit());
                        }
                    }
                }
                visitor.Visit(declaration.getBody());
                inventory_incomplete = inventory_incomplete || visitor.inventory_incomplete();
                if (std::numeric_limits<std::uint32_t>::max() - unresolved < visitor.unresolved() ||
                    std::numeric_limits<std::uint32_t>::max() - unsupported < visitor.unsupported()) {
                    protocol_failure("M0_INVOCATION_COUNTER_OVERFLOW");
                }
                unresolved += visitor.unresolved();
                unsupported += visitor.unsupported();
                closed_definitions.push_back(ClosedDefinitionInvocations{
                    &declaration,
                    visitor.invocations(),
                    {},
                });
            }
            if (inventory_incomplete || unresolved != 0 || unsupported != 0) {
                protocol_failure("M0_INVOCATION_INVENTORY_INCOMPLETE");
            }

            for (ClosedDefinitionInvocations& closed : closed_definitions) {
                JsonAnchorIndex anchors(*closed.declaration);
                closed.anchor_paths.reserve(closed.invocations.size());
                for (const PendingInvocation& pending : closed.invocations) {
                    if (pending.callee == nullptr || pending.anchor == nullptr) {
                        protocol_failure("M0_INTERNAL_INVOCATION_INVALID");
                    }
                    closed.anchor_paths.push_back(anchors.path_for(pending.anchor));
                }
            }

            const TargetRegistry targets = collect_target_registry(context);
            std::vector<SourceSpan> definition_spans;
            definition_spans.reserve(closed_definitions.size());
            for (const ClosedDefinitionInvocations& closed : closed_definitions) {
                auto span = source_span(
                    *closed.declaration,
                    context,
                    state_.inputs->attribute_macros());
                if (!span) {
                    protocol_failure("M0_DEFINITION_SPAN_UNSUPPORTED");
                }
                definition_spans.push_back(std::move(*span));
            }

            std::uint32_t emitted = 0;
            for (std::size_t definition_index = 0;
                 definition_index < closed_definitions.size();
                 ++definition_index) {
                const ClosedDefinitionInvocations& closed =
                    closed_definitions[definition_index];
                const clang::FunctionDecl& declaration = *closed.declaration;
                const SourceSpan& span = definition_spans[definition_index];
                DefinitionObservation row;
                row.declaration_kind = declaration_kind(declaration);
                row.qualified_name = declaration.getQualifiedNameAsString();
                row.raw_qual_type = raw_qual_type(declaration, context);
                row.linkage = linkage_code(declaration);
                row.virtual_path = span.path;
                row.begin_offset = span.begin;
                row.end_offset_exclusive = span.end;
                const auto target = targets.indices.find(declaration.getCanonicalDecl());
                if (target != targets.indices.end()) {
                    row.target_indices = target->second;
                }

                for (std::size_t invocation_index = 0;
                     invocation_index < closed.invocations.size();
                     ++invocation_index) {
                    const PendingInvocation& pending = closed.invocations[invocation_index];
                    row.invocations.push_back(InvocationOccurrence{
                        closed.anchor_paths[invocation_index],
                        pending.kind,
                        1,
                        {describe_callee(
                            *pending.callee,
                            context,
                            state_.inputs->attribute_macros())},
                    });
                    checked_increment(emitted, "M0_INVOCATION_COUNTER_OVERFLOW");
                }
                state_.observation.definitions.push_back(std::move(row));
            }

            const auto& physical = state_.inputs->physical();
            const auto primary = physical.find(state_.primary_source);
            if (primary == physical.end() || primary->second.origin != 1 ||
                primary->second.activation_count == 0) {
                protocol_failure("M0_PRIMARY_INPUT_MISSING");
            }
            state_.observation.primary = primary->second;
            for (const auto& [path, input] : physical) {
                if (path != state_.primary_source) {
                    state_.observation.dependencies.push_back(input);
                }
            }
            for (const auto& [key, input] : state_.inputs->virtual_inputs()) {
                (void)key;
                state_.observation.virtual_inputs.push_back(input);
            }
            state_.observation.coverage = {
                state_.inputs->compiler_file_activations(),
                state_.inputs->compiler_file_activations(),
                static_cast<std::uint32_t>(physical.size()),
                static_cast<std::uint32_t>(physical.size()),
                state_.inputs->compiler_virtual_activations(),
                state_.inputs->compiler_virtual_activations(),
                static_cast<std::uint32_t>(state_.observation.definitions.size()),
                static_cast<std::uint32_t>(state_.observation.definitions.size()),
                emitted,
                emitted,
                unresolved,
                unsupported,
                0,
                state_.inputs->nondeterministic_builtins(),
            };
            if (state_.inputs->nondeterministic_builtins() != 0) {
                protocol_failure("M0_NONDETERMINISTIC_BUILTIN_EXPANSION");
            }
            canonicalize(state_.observation);
            state_.complete = true;
        } catch (const Failure& failure) {
            state_.error = failure.code;
        } catch (...) {
            state_.error = "M0_INTERNAL_INVARIANT";
        }
    }

private:
    ExtractorState& state_;
};

class ExtractorAction final : public clang::ASTFrontendAction {
public:
    explicit ExtractorAction(ExtractorState& state) : state_(state) {}

    bool BeginSourceFileAction(clang::CompilerInstance& compiler) override {
        try {
            const clang::LangOptions& language = compiler.getLangOpts();
            if (!language.CPlusPlus || language.ObjC || language.OpenMP != 0 ||
                language.OpenMPSimd || language.CUDA || language.HIP ||
                language.OpenCL || language.OpenCLCPlusPlus || language.SYCLIsDevice ||
                language.SYCLIsHost || language.HLSL || language.Blocks ||
                language.AsmBlocks || language.MicrosoftExt ||
                language.DelayedTemplateParsing || language.ModulesTS ||
                compiler.getFrontendOpts().ProgramAction != clang::frontend::ParseSyntaxOnly) {
                state_.error = "M0_FRONTEND_ACTION_UNSUPPORTED";
                return false;
            }
            state_.observation.frontend.effective_cc1_argv = state_.effective_cc1_argv;
            state_.observation.frontend.target_triple = compiler.getTargetOpts().Triple;
            state_.observation.frontend.language_standard =
                clang::LangStandard::getLangStandardForKind(language.LangStd).getName();
            state_.observation.frontend.resource_directory =
                compiler.getHeaderSearchOpts().ResourceDir;
            state_.observation.frontend.sysroot = compiler.getHeaderSearchOpts().Sysroot;
            state_.observation.predefines_bytes = compiler.getPreprocessor().getPredefines();
            auto inputs = std::make_unique<InputCollector>(
                compiler.getFileManager(), compiler.getSourceManager(),
                compiler.getPreprocessor());
            state_.inputs = inputs.get();
            compiler.getPreprocessor().addPPCallbacks(
                std::move(inputs));
            return true;
        } catch (...) {
            state_.error = "M0_INTERNAL_INVARIANT";
            return false;
        }
    }

    std::unique_ptr<clang::ASTConsumer>
    CreateASTConsumer(clang::CompilerInstance&, llvm::StringRef) override {
        return std::make_unique<ExtractorConsumer>(state_);
    }

private:
    ExtractorState& state_;
};

struct CommandLine {
    std::uint32_t tu_ordinal = 0;
    std::string compiler_entry;
    std::string primary_source;
    std::vector<std::string> compiler_arguments;
};

CommandLine parse_command_line(int argc, char** argv) {
    if (argc < 7) {
        protocol_failure("M0_CLI_INVALID");
    }
    std::optional<std::uint32_t> ordinal;
    std::optional<std::string> compiler;
    std::optional<std::string> primary;
    bool protocol = false;
    bool version = false;
    int separator = -1;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--") {
            separator = index;
            break;
        }
        if (argument == "--protocol=631302" && !protocol) {
            protocol = true;
        } else if (argument == "--observation-version=2" && !version) {
            version = true;
        } else if (argument.starts_with("--tu-ordinal=") && !ordinal) {
            ordinal = parse_canonical_u32(argument.substr(std::string_view("--tu-ordinal=").size()));
        } else if (argument.starts_with("--compiler-entry=") && !compiler) {
            compiler = std::string(argument.substr(std::string_view("--compiler-entry=").size()));
        } else if (argument.starts_with("--primary-source=") && !primary) {
            primary = std::string(argument.substr(std::string_view("--primary-source=").size()));
        } else {
            protocol_failure("M0_CLI_INVALID");
        }
    }
    if (!protocol || !version || !ordinal || !compiler || !primary ||
        separator < 0 || separator + 1 >= argc || *compiler != kCompilerEntry ||
        !canonical_absolute_path(*primary) || !under_root(*primary, kSourceRoot)) {
        protocol_failure("M0_CLI_INVALID");
    }
    CommandLine result{*ordinal, *compiler, *primary, {}};
    for (int index = separator + 1; index < argc; ++index) {
        std::string argument(argv[index]);
        if (argument.empty() || argument == "-" || argument.find('@') != std::string::npos ||
            argument == "-march=native" || argument.starts_with("-march=native=") ||
            argument == "-mcpu=native" || argument.starts_with("-mcpu=native=") ||
            argument == "-mtune=native" || argument.starts_with("-mtune=native=")) {
            protocol_failure("M0_COMPILER_ARGUMENT_FORBIDDEN");
        }
        result.compiler_arguments.push_back(std::move(argument));
    }
    if (std::count(result.compiler_arguments.begin(), result.compiler_arguments.end(),
                   result.primary_source) != 1) {
        protocol_failure("M0_PRIMARY_ARGUMENT_INVALID");
    }
    return result;
}

std::vector<std::string> expand_driver(const CommandLine& command,
                                       clang::DiagnosticConsumer& diagnostics) {
    std::vector<std::string> driver_arguments;
    driver_arguments.push_back(command.compiler_entry);
    driver_arguments.insert(driver_arguments.end(), command.compiler_arguments.begin(),
                            command.compiler_arguments.end());
    llvm::opt::ArgStringList argv;
    for (const std::string& argument : driver_arguments) {
        argv.push_back(argument.c_str());
    }
    auto options = llvm::IntrusiveRefCntPtr<clang::DiagnosticOptions>(
        new clang::DiagnosticOptions());
    auto engine = clang::CompilerInstance::createDiagnostics(
        options.get(), &diagnostics, false);
    clang::driver::Driver driver(command.compiler_entry,
                                 llvm::sys::getDefaultTargetTriple(), *engine,
                                 "v631302 native extractor driver");
    driver.setCheckInputsExist(true);
    std::unique_ptr<clang::driver::Compilation> compilation(
        driver.BuildCompilation(llvm::ArrayRef(argv)));
    if (!compilation || engine->hasErrorOccurred()) {
        throw Failure(kFrontendFailure, "M0_FRONTEND_FAILED");
    }
    const clang::driver::Command* frontend = nullptr;
    for (const clang::driver::Command& job : compilation->getJobs()) {
        if (frontend != nullptr ||
            llvm::StringRef(job.getCreator().getName()) != "clang") {
            protocol_failure("M0_FRONTEND_ACTION_COUNT_INVALID");
        }
        frontend = &job;
    }
    if (frontend == nullptr) {
        protocol_failure("M0_FRONTEND_ACTION_COUNT_INVALID");
    }
    std::vector<std::string> effective{command.compiler_entry};
    for (const char* argument : frontend->getArguments()) {
        effective.emplace_back(argument);
    }
    if (effective.size() < 2 || effective[1] != "-cc1" ||
        std::count(effective.begin(), effective.end(), "-cc1") != 1) {
        protocol_failure("M0_FRONTEND_ACTION_COUNT_INVALID");
    }
    static constexpr std::array<std::string_view, 8> forbidden = {
        "-fmodules", "-include-pch", "-include-pth", "-ivfsoverlay",
        "-load", "-plugin", "-add-plugin", "-fmodule-file",
    };
    for (const std::string& argument : effective) {
        for (std::string_view option : forbidden) {
            if (argument == option || argument.starts_with(std::string(option) + "=")) {
                protocol_failure("M0_IMPLICIT_FRONTEND_STATE_UNSUPPORTED");
            }
        }
    }
    return effective;
}

class SilentCountingDiagnosticConsumer final : public clang::DiagnosticConsumer {
public:
    void HandleDiagnostic(clang::DiagnosticsEngine::Level level,
                          const clang::Diagnostic&) override {
        if (level >= clang::DiagnosticsEngine::Error) {
            if (errors_ == std::numeric_limits<std::uint32_t>::max()) {
                overflowed_ = true;
            } else {
                ++errors_;
            }
        }
    }

    void clear() override {
        clang::DiagnosticConsumer::clear();
        errors_ = 0;
        overflowed_ = false;
    }

    std::uint32_t errors() const { return errors_; }
    bool overflowed() const { return overflowed_; }

private:
    std::uint32_t errors_ = 0;
    bool overflowed_ = false;
};

void verify_working_directory() {
    llvm::SmallString<256> current;
    if (std::error_code error = llvm::sys::fs::current_path(current)) {
        (void)error;
        protocol_failure("M0_WORKING_DIRECTORY_INVALID");
    }
    if (current != kWorkingDirectory) {
        protocol_failure("M0_WORKING_DIRECTORY_INVALID");
    }
}

int run(int argc, char** argv) {
    const CommandLine command = parse_command_line(argc, argv);
    verify_working_directory();

    clang::FileSystemOptions file_options;
    auto files = llvm::IntrusiveRefCntPtr<clang::FileManager>(
        new clang::FileManager(file_options, llvm::vfs::getRealFileSystem()));
    SilentCountingDiagnosticConsumer diagnostics;
    std::vector<std::string> effective = expand_driver(command, diagnostics);
    if (diagnostics.overflowed()) {
        protocol_failure("M0_DIAGNOSTIC_COUNTER_OVERFLOW");
    }
    diagnostics.clear();

    ExtractorState state;
    state.observation.tu_ordinal = command.tu_ordinal;
    state.observation.primary_source_virtual_path = command.primary_source;
    state.primary_source = command.primary_source;
    state.effective_cc1_argv = effective;
    clang::tooling::ToolInvocation invocation(
        effective, std::make_unique<ExtractorAction>(state), files.get());
    invocation.setDiagnosticConsumer(&diagnostics);
    const bool invocation_succeeded = invocation.run();
    if (diagnostics.overflowed()) {
        protocol_failure("M0_DIAGNOSTIC_COUNTER_OVERFLOW");
    }
    if (diagnostics.errors() != 0) {
        throw Failure(kFrontendFailure, "M0_FRONTEND_FAILED");
    }
    if (!invocation_succeeded) {
        if (!state.error.empty() && state.error != "M0_INTERNAL_INVARIANT") {
            protocol_failure(state.error);
        }
        throw Failure(kFrontendFailure, "M0_FRONTEND_FAILED");
    }
    if (!state.error.empty()) {
        if (state.error == "M0_INTERNAL_INVARIANT") {
            throw Failure(kInvariantFailure, state.error);
        }
        protocol_failure(state.error);
    }
    if (!state.complete) {
        throw Failure(kInvariantFailure, "M0_INTERNAL_INVARIANT");
    }
    const std::vector<CborWriter::Byte> bytes = encode_observation(state.observation);
    std::cout.write(reinterpret_cast<const char*>(bytes.data()),
                    static_cast<std::streamsize>(bytes.size()));
    if (!std::cout) {
        throw Failure(kInvariantFailure, "M0_STDOUT_WRITE_FAILED");
    }
    return 0;
}

}  // namespace
}  // namespace evaluation_v6_3_1::native

int main(int argc, char** argv) {
    try {
        return evaluation_v6_3_1::native::run(argc, argv);
    } catch (const evaluation_v6_3_1::native::Failure& failure) {
        std::cerr << "V631302_M0_ERROR:" << failure.code << '\n';
        return failure.exit_code;
    } catch (...) {
        std::cerr << "V631302_M0_ERROR:M0_INTERNAL_INVARIANT\n";
        return 70;
    }
}
