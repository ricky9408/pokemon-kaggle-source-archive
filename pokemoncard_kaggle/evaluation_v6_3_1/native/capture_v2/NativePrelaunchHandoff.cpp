#include "NativePrelaunchHandoff.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/SHA256.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {
namespace {

using Byte = std::uint8_t;

constexpr std::size_t kMaximumOuterHandoffBytes =
    NativePrelaunchHandoff::kRawPrelaunchRequestMaximumBytes + 4096u;
constexpr std::size_t kMaximumCborDepth = 64u;
constexpr std::size_t kMaximumCborItems = 1'000'000u;
constexpr std::size_t kMaximumLabelBytes = 1u * 1024u * 1024u;
constexpr std::size_t kMaximumGnuBuildIdBytes = 65'535u;
constexpr std::size_t kMaximumCollectorProfileBytes = 16u * 1024u * 1024u;
constexpr std::size_t kMaximumPathProfileBytes = 4096u;
constexpr std::size_t kMaximumPathBytes = 4096u;
constexpr std::size_t kMaximumPublicRowsBytes = 48u * 1024u * 1024u;
constexpr std::size_t kMaximumArgvItems = 4096u;
constexpr std::size_t kMaximumArgvItemBytes = 1u * 1024u * 1024u;
constexpr std::size_t kMaximumEncodedArgvBytes = 16u * 1024u * 1024u;
constexpr std::uint64_t kMaximumHarnessComponentBytes = 1u * 1024u * 1024u * 1024u;
constexpr std::uint64_t kCollectorRole = 1u;
constexpr std::uint64_t kPrimarySourceRole = 2u;
constexpr char kValidatedPrelaunchExpectationsV2Domain[] =
    "V631302_VALIDATED_PRELAUNCH_EXPECTATIONS_V2\0";

[[noreturn]] void fail(std::string message) {
    throw SupervisorError(SupervisorFailure::InvalidRequest, std::move(message));
}

bool valid_utf8(std::span<const Byte> bytes) noexcept {
    std::size_t index = 0u;
    while (index < bytes.size()) {
        const Byte first = bytes[index++];
        if (first <= 0x7fu) continue;
        std::size_t continuation_count = 0u;
        std::uint32_t codepoint = 0u;
        if (first >= 0xc2u && first <= 0xdfu) {
            continuation_count = 1u;
            codepoint = static_cast<std::uint32_t>(first & 0x1fu);
        } else if (first >= 0xe0u && first <= 0xefu) {
            continuation_count = 2u;
            codepoint = static_cast<std::uint32_t>(first & 0x0fu);
        } else if (first >= 0xf0u && first <= 0xf4u) {
            continuation_count = 3u;
            codepoint = static_cast<std::uint32_t>(first & 0x07u);
        } else {
            return false;
        }
        if (index + continuation_count > bytes.size()) return false;
        for (std::size_t offset = 0u; offset < continuation_count; ++offset) {
            const Byte continuation = bytes[index++];
            if ((continuation & 0xc0u) != 0x80u) return false;
            codepoint = (codepoint << 6u) | static_cast<std::uint32_t>(continuation & 0x3fu);
        }
        if ((continuation_count == 2u && codepoint < 0x800u) ||
            (continuation_count == 3u && codepoint < 0x10000u) ||
            (codepoint >= 0xd800u && codepoint <= 0xdfffu) || codepoint > 0x10ffffu) {
            return false;
        }
    }
    return true;
}

struct CborHead final {
    Byte major = 0u;
    std::uint64_t argument = 0u;
};

struct CborNode final {
    enum class Kind : std::uint8_t { Uint, Bytes, Text, Array };
    Kind kind = Kind::Uint;
    std::uint64_t uint_value = 0u;
    std::vector<Byte> bytes_value;
    std::string text_value;
    std::vector<CborNode> array_value;
    std::size_t start = 0u;
    std::size_t end = 0u;
};

[[noreturn]] void cbor_fail() { fail("native prelaunch handoff is not canonical arrays-only CBOR"); }

CborHead parse_head(std::span<const Byte> bytes, std::size_t& cursor) {
    if (cursor >= bytes.size()) cbor_fail();
    const Byte initial = bytes[cursor++];
    const Byte major = static_cast<Byte>(initial >> 5u);
    const Byte information = static_cast<Byte>(initial & 0x1fu);
    if (major != 0u && major != 2u && major != 3u && major != 4u) cbor_fail();
    if (information < 24u) return {major, information};
    std::size_t width = 0u;
    if (information == 24u) width = 1u;
    else if (information == 25u) width = 2u;
    else if (information == 26u) width = 4u;
    else if (information == 27u) width = 8u;
    else cbor_fail();
    if (bytes.size() - cursor < width) cbor_fail();
    std::uint64_t argument = 0u;
    for (std::size_t offset = 0u; offset < width; ++offset) {
        argument = (argument << 8u) | bytes[cursor++];
    }
    if ((information == 24u && argument < 24u) ||
        (information == 25u && argument <= 0xffu) ||
        (information == 26u && argument <= 0xffffu) ||
        (information == 27u && argument <= 0xffffffffULL)) {
        cbor_fail();
    }
    return {major, argument};
}

CborNode parse_item(
    std::span<const Byte> bytes,
    std::size_t& cursor,
    std::size_t depth,
    std::size_t& item_count) {
    if (depth > kMaximumCborDepth || item_count == kMaximumCborItems) cbor_fail();
    ++item_count;
    const std::size_t start = cursor;
    const CborHead head = parse_head(bytes, cursor);
    if (head.major == 0u) return {CborNode::Kind::Uint, head.argument, {}, {}, {}, start, cursor};
    if (head.argument > static_cast<std::uint64_t>(bytes.size() - cursor) ||
        head.argument > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        cbor_fail();
    }
    const std::size_t size = static_cast<std::size_t>(head.argument);
    if (head.major == 2u) {
        std::vector<Byte> value(bytes.begin() + static_cast<std::ptrdiff_t>(cursor),
                                bytes.begin() + static_cast<std::ptrdiff_t>(cursor + size));
        cursor += size;
        return {CborNode::Kind::Bytes, 0u, std::move(value), {}, {}, start, cursor};
    }
    if (head.major == 3u) {
        const std::span<const Byte> raw = bytes.subspan(cursor, size);
        if (!valid_utf8(raw)) cbor_fail();
        std::string value(reinterpret_cast<const char*>(raw.data()), raw.size());
        cursor += size;
        return {CborNode::Kind::Text, 0u, {}, std::move(value), {}, start, cursor};
    }
    if (head.argument > static_cast<std::uint64_t>(kMaximumCborItems - item_count) ||
        head.argument > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        cbor_fail();
    }
    std::vector<CborNode> values;
    values.reserve(static_cast<std::size_t>(head.argument));
    for (std::uint64_t index = 0u; index < head.argument; ++index) {
        values.push_back(parse_item(bytes, cursor, depth + 1u, item_count));
    }
    return {CborNode::Kind::Array, 0u, {}, {}, std::move(values), start, cursor};
}

void append_head(std::vector<Byte>& output, Byte major, std::uint64_t value) {
    if (value < 24u) {
        output.push_back(static_cast<Byte>((major << 5u) | static_cast<Byte>(value)));
    } else if (value <= 0xffu) {
        output.push_back(static_cast<Byte>((static_cast<unsigned>(major) << 5u) | 24u));
        output.push_back(static_cast<Byte>(value));
    } else if (value <= 0xffffu) {
        output.push_back(static_cast<Byte>((static_cast<unsigned>(major) << 5u) | 25u));
        output.push_back(static_cast<Byte>(value >> 8u));
        output.push_back(static_cast<Byte>(value));
    } else if (value <= 0xffffffffULL) {
        output.push_back(static_cast<Byte>((static_cast<unsigned>(major) << 5u) | 26u));
        for (int shift = 24; shift >= 0; shift -= 8) output.push_back(static_cast<Byte>(value >> static_cast<unsigned>(shift)));
    } else {
        output.push_back(static_cast<Byte>((static_cast<unsigned>(major) << 5u) | 27u));
        for (int shift = 56; shift >= 0; shift -= 8) output.push_back(static_cast<Byte>(value >> static_cast<unsigned>(shift)));
    }
}

void encode_item(const CborNode& value, std::vector<Byte>& output) {
    if (value.kind == CborNode::Kind::Uint) { append_head(output, 0u, value.uint_value); return; }
    if (value.kind == CborNode::Kind::Bytes) { append_head(output, 2u, value.bytes_value.size()); output.insert(output.end(), value.bytes_value.begin(), value.bytes_value.end()); return; }
    if (value.kind == CborNode::Kind::Text) { append_head(output, 3u, value.text_value.size()); output.insert(output.end(), value.text_value.begin(), value.text_value.end()); return; }
    append_head(output, 4u, value.array_value.size());
    for (const CborNode& child : value.array_value) encode_item(child, output);
}

CborNode parse_canonical_array(std::span<const Byte> bytes, std::size_t maximum_bytes) {
    if (bytes.empty() || bytes.size() > maximum_bytes) cbor_fail();
    std::size_t cursor = 0u;
    std::size_t item_count = 0u;
    CborNode value = parse_item(bytes, cursor, 0u, item_count);
    if (cursor != bytes.size() || value.kind != CborNode::Kind::Array) cbor_fail();
    std::vector<Byte> reencoded;
    reencoded.reserve(bytes.size());
    encode_item(value, reencoded);
    if (reencoded.size() != bytes.size() || !std::equal(reencoded.begin(), reencoded.end(), bytes.begin())) cbor_fail();
    return value;
}

const CborNode& array_at(const CborNode& value, std::size_t index) {
    if (value.kind != CborNode::Kind::Array || index >= value.array_value.size()) cbor_fail();
    return value.array_value[index];
}

void exact_array_width(const CborNode& value, std::size_t width) {
    if (value.kind != CborNode::Kind::Array || value.array_value.size() != width) cbor_fail();
}

std::uint64_t require_uint(const CborNode& value) {
    if (value.kind != CborNode::Kind::Uint) cbor_fail();
    return value.uint_value;
}

std::vector<Byte> require_bytes(const CborNode& value, std::size_t minimum, std::size_t maximum) {
    if (value.kind != CborNode::Kind::Bytes || value.bytes_value.size() < minimum || value.bytes_value.size() > maximum) cbor_fail();
    return value.bytes_value;
}

std::string require_text(const CborNode& value, std::size_t minimum, std::size_t maximum) {
    if (value.kind != CborNode::Kind::Text || value.text_value.size() < minimum || value.text_value.size() > maximum ||
        value.text_value.find('\0') != std::string::npos) cbor_fail();
    return value.text_value;
}

Sha256Digest require_digest(const CborNode& value) {
    const std::vector<Byte> bytes = require_bytes(value, Sha256Digest{}.size(), Sha256Digest{}.size());
    Sha256Digest digest{};
    std::copy(bytes.begin(), bytes.end(), digest.begin());
    return digest;
}

bool canonical_relative(std::string_view path) noexcept {
    if (path.empty() || path.front() == '/' || path.back() == '/' || path.find('\\') != std::string_view::npos || path.find('\0') != std::string_view::npos) return false;
    std::size_t start = 0u;
    for (;;) {
        const std::size_t separator = path.find('/', start);
        const std::size_t end = separator == std::string_view::npos ? path.size() : separator;
        const std::string_view component = path.substr(start, end - start);
        if (component.empty() || component == "." || component == "..") return false;
        if (separator == std::string_view::npos) return true;
        start = separator + 1u;
    }
}

bool printable_ascii(std::string_view text) noexcept {
    return std::all_of(text.begin(), text.end(), [](char value) {
        const Byte byte = static_cast<Byte>(value);
        return byte >= 0x20u && byte <= 0x7eu;
    });
}

bool bytewise_less(const std::string& left, const std::string& right) noexcept {
    return std::lexicographical_compare(left.begin(), left.end(), right.begin(), right.end(),
        [](char l, char r) { return static_cast<Byte>(l) < static_cast<Byte>(r); });
}

struct CollectorProfileFacts final {
    Sha256Digest collector_sha256{};
    Sha256Digest clang_sha256{};
};

CollectorProfileFacts validate_collector_profile(
    const std::vector<Byte>& bytes,
    const std::string& label) {
    const CborNode profile = parse_canonical_array(bytes, kMaximumCollectorProfileBytes);
    exact_array_width(profile, 8u);
    const Sha256Digest collector_sha256 = require_digest(array_at(profile, 0u));
    if (require_text(array_at(profile, 1u), 1u, kMaximumLabelBytes) != label) {
        fail("collector profile differs from raw prelaunch label");
    }
    const Sha256Digest clang_sha256 = require_digest(array_at(profile, 2u));
    if (require_uint(array_at(profile, 3u)) != 16u) {
        fail("collector profile is not pinned to Clang 16");
    }
    // Fields 4-7 are rooted Python-canonicalizer data. Native verifies only
    // their canonical CBOR types and bounds; it deliberately does not attach
    // any canonicalizer semantics to the native execution boundary.
    static_cast<void>(require_uint(array_at(profile, 4u)));
    if (array_at(profile, 5u).kind != CborNode::Kind::Array ||
        array_at(profile, 7u).kind != CborNode::Kind::Array) {
        cbor_fail();
    }
    static_cast<void>(require_digest(array_at(profile, 6u)));
    return {collector_sha256, clang_sha256};
}

void validate_path_profile(const std::vector<Byte>& bytes) {
    static constexpr std::array<Byte, 18u> kPathProfileV2 = {
        0x84u, 0x02u, 0x64u, '/', 's', 'r', 'c', 0x65u, '/', 'w', 'o', 'r', 'k', 0x64u, '/', 'b', 'i', 'n'};
    const CborNode profile = parse_canonical_array(bytes, kMaximumPathProfileBytes);
    exact_array_width(profile, 4u);
    if (!std::equal(bytes.begin(), bytes.end(), kPathProfileV2.begin(), kPathProfileV2.end())) {
        fail("path profile differs from frozen PATH_PROFILE_V2 bytes");
    }
    static_cast<void>(profile);
}

struct PublicRowsFacts final {
    std::string collector_path;
    std::size_t collector_count = 0u;
    Sha256Digest collector_sha256{};
    std::size_t libclang_count = 0u;
    Sha256Digest libclang_sha256{};
    std::string primary_source_path;
    std::size_t primary_source_count = 0u;
};

PublicRowsFacts validate_public_rows(const std::vector<Byte>& bytes) {
    const CborNode rows = parse_canonical_array(bytes, kMaximumPublicRowsBytes);
    static constexpr std::array<std::string_view, 5u> kExpectedPaths = {
        "bin/collector",
        "lib/ld-linux-x86-64.so.2",
        "lib/libc.so.6",
        "lib/libclang-cpp.so.16",
        "src/Export.cpp",
    };
    static constexpr std::array<std::array<std::uint64_t, 2u>, 5u>
        kExpectedRoles = {{
            {1u, 0u},
            {6u, 0u},
            {8u, 0u},
            {7u, 8u},
            {2u, 3u},
        }};
    static constexpr std::array<std::size_t, 5u> kExpectedRoleCounts = {
        1u, 1u, 1u, 2u, 2u};
    static constexpr std::array<std::uint64_t, 5u> kExpectedModes = {
        0555u, 0444u, 0444u, 0444u, 0444u};
    if (rows.array_value.size() != kExpectedPaths.size()) {
        fail("public file rows differ from the exact five-object capture topology");
    }
    std::string prior_path;
    PublicRowsFacts facts;
    for (std::size_t row_index = 0u; row_index < rows.array_value.size(); ++row_index) {
        const CborNode& row = rows.array_value[row_index];
        exact_array_width(row, 5u);
        const std::string path = require_text(array_at(row, 0u), 1u, kMaximumPathBytes);
        if (!canonical_relative(path) || (!prior_path.empty() && !bytewise_less(prior_path, path))) {
            fail("public file rows are not canonical bytewise-sorted relative paths");
        }
        prior_path = path;
        const CborNode& roles = array_at(row, 1u);
        if (roles.kind != CborNode::Kind::Array || roles.array_value.empty()) cbor_fail();
        if (path != kExpectedPaths[row_index] ||
            roles.array_value.size() != kExpectedRoleCounts[row_index]) {
            fail("public file rows differ from the exact five-object capture topology");
        }
        std::uint64_t prior_role = 0u;
        bool collector = false;
        bool primary_source = false;
        for (std::size_t role_index = 0u; role_index < roles.array_value.size(); ++role_index) {
            const CborNode& role_node = roles.array_value[role_index];
            const std::uint64_t role = require_uint(role_node);
            if (role == 0u || role <= prior_role) cbor_fail();
            if (role != kExpectedRoles[row_index][role_index]) {
                fail("public file rows differ from the exact five-object capture topology");
            }
            prior_role = role;
            collector = collector || role == kCollectorRole;
            primary_source = primary_source || role == kPrimarySourceRole;
        }
        if (require_uint(array_at(row, 2u)) != kExpectedModes[row_index]) {
            fail("public file rows differ from the exact five-object capture topology");
        }
        static_cast<void>(require_uint(array_at(row, 3u)));
        const Sha256Digest sha256 = require_digest(array_at(row, 4u));
        if (collector) {
            ++facts.collector_count;
            facts.collector_path = path;
            facts.collector_sha256 = sha256;
        }
        if (path == "lib/libclang-cpp.so.16") {
            ++facts.libclang_count;
            facts.libclang_sha256 = sha256;
        }
        if (primary_source) {
            ++facts.primary_source_count;
            facts.primary_source_path = path;
        }
    }
    if (facts.collector_count != 1u) fail("public file rows must identify exactly one collector role");
    if (facts.collector_path != "bin/collector") {
        fail("public file rows must identify bin/collector as the unique collector executable");
    }
    if (facts.libclang_count != 1u) {
        fail("public file rows must identify exactly one retained libclang-cpp object");
    }
    if (facts.primary_source_count != 1u) {
        fail("public file rows must identify exactly one primary-source role");
    }
    return facts;
}

std::vector<std::string> decode_argv(const CborNode& node) {
    if (node.kind != CborNode::Kind::Array || node.array_value.empty() || node.array_value.size() > kMaximumArgvItems ||
        node.end - node.start > kMaximumEncodedArgvBytes) {
        cbor_fail();
    }
    std::vector<std::string> argv;
    argv.reserve(node.array_value.size());
    for (std::size_t index = 0u; index < node.array_value.size(); ++index) {
        argv.push_back(require_text(node.array_value[index], index == 0u ? 1u : 0u, kMaximumArgvItemBytes));
    }
    return argv;
}

HarnessExpectations decode_harness(const CborNode& node) {
    exact_array_width(node, 3u);
    std::array<ComponentExpectation, 3u> values{};
    for (std::size_t index = 0u; index < values.size(); ++index) {
        const CborNode& row = array_at(node, index);
        exact_array_width(row, 3u);
        const std::uint64_t byte_length = require_uint(array_at(row, 0u));
        if (byte_length == 0u || byte_length > kMaximumHarnessComponentBytes) cbor_fail();
        values[index] = {byte_length, require_digest(array_at(row, 1u)),
                         require_bytes(array_at(row, 2u), 0u, kMaximumGnuBuildIdBytes)};
    }
    return {std::move(values[0]), std::move(values[1]), std::move(values[2])};
}

Sha256Digest32 recompute_validated_prelaunch_expectations_v2_root(
    const CborNode& raw) {
    exact_array_width(raw, 13u);
    CborNode value;
    value.kind = CborNode::Kind::Array;
    value.array_value.reserve(14u);
    value.array_value.push_back(CborNode{
        CborNode::Kind::Uint,
        NativePrelaunchHandoff::kProtocolId,
        {}, {}, {}, 0u, 0u});
    value.array_value.push_back(CborNode{
        CborNode::Kind::Uint, 2u, {}, {}, {}, 0u, 0u});
    value.array_value.push_back(CborNode{
        CborNode::Kind::Uint,
        NativePrelaunchHandoff::kVersionV1,
        {}, {}, {}, 0u, 0u});
    for (std::size_t index = 2u; index < raw.array_value.size(); ++index) {
        value.array_value.push_back(raw.array_value[index]);
    }
    std::vector<Byte> canonical;
    encode_item(value, canonical);
    llvm::SHA256 hasher;
    hasher.update(llvm::ArrayRef<Byte>(
        reinterpret_cast<const Byte*>(kValidatedPrelaunchExpectationsV2Domain),
        sizeof(kValidatedPrelaunchExpectationsV2Domain) - 1u));
    hasher.update(llvm::ArrayRef<Byte>(canonical.data(), canonical.size()));
    return hasher.final();
}

}  // namespace

RawPrelaunchRequest NativePrelaunchHandoff::decode(
    std::span<const std::uint8_t> handoff_cbor) {
    const CborNode handoff = parse_canonical_array(handoff_cbor, kMaximumOuterHandoffBytes);
    exact_array_width(handoff, 4u);
    if (require_uint(array_at(handoff, 0u)) != kProtocolId ||
        require_uint(array_at(handoff, 1u)) != kVersionV1) {
        fail("native prelaunch handoff protocol or version differs from V1");
    }
    const Sha256Digest32 root = require_digest(array_at(handoff, 2u));
    const std::vector<Byte> raw_bytes = require_bytes(
        array_at(handoff, 3u), 1u, kRawPrelaunchRequestMaximumBytes);
    const CborNode raw = parse_canonical_array(raw_bytes, kRawPrelaunchRequestMaximumBytes);
    exact_array_width(raw, 13u);
    if (require_uint(array_at(raw, 0u)) != kProtocolId ||
        require_uint(array_at(raw, 1u)) != kVersionV1) {
        fail("raw prelaunch request protocol or version differs from V1");
    }
    if (recompute_validated_prelaunch_expectations_v2_root(raw) != root) {
        fail("outer handoff root does not bind exact ValidatedPrelaunchExpectationsV2 bytes");
    }

    const std::string label = require_text(array_at(raw, 2u), 1u, kMaximumLabelBytes);
    if (!printable_ascii(label)) fail("collector profile build label is not printable ASCII");
    const std::vector<Byte> descriptor = require_bytes(
        array_at(raw, 3u), 1u, kMaximumGnuBuildIdBytes);
    const std::vector<Byte> collector_profile = require_bytes(
        array_at(raw, 4u), 1u, kMaximumCollectorProfileBytes);
    const std::uint64_t grammar_version = require_uint(array_at(raw, 5u));
    if (grammar_version == 0u || grammar_version > 0xffffffffULL) cbor_fail();
    const Sha256Digest grammar_sha256 = require_digest(array_at(raw, 6u));
    if (grammar_version != ValidatedPrelaunchPlan::kFrozenArgvGrammarVersionV1 ||
        grammar_sha256 != ValidatedPrelaunchPlan::kFrozenArgvGrammarSha256V1) {
        fail("raw prelaunch request does not bind the frozen argv grammar pin");
    }
    const std::vector<Byte> path_profile = require_bytes(
        array_at(raw, 7u), 1u, kMaximumPathProfileBytes);
    const std::string relative_cwd = require_text(array_at(raw, 8u), 1u, kMaximumPathBytes);
    const std::string primary_source = require_text(array_at(raw, 9u), 1u, kMaximumPathBytes);
    const std::vector<Byte> public_rows = require_bytes(
        array_at(raw, 10u), 1u, kMaximumPublicRowsBytes);
    const std::vector<std::string> argv = decode_argv(array_at(raw, 11u));
    HarnessExpectations harness = decode_harness(array_at(raw, 12u));

    const CollectorProfileFacts profile = validate_collector_profile(collector_profile, label);
    validate_path_profile(path_profile);
    if (!canonical_relative(relative_cwd) || !canonical_relative(primary_source) ||
        relative_cwd != "work" || primary_source != "src/Export.cpp") {
        fail("raw prelaunch relative paths differ from frozen PATH_PROFILE_V2 ingress");
    }
    const PublicRowsFacts rows = validate_public_rows(public_rows);
    if (rows.primary_source_path != primary_source ||
        profile.collector_sha256 != rows.collector_sha256 ||
        profile.clang_sha256 != rows.libclang_sha256 ||
        argv.front() != "/bin/clang-tool") {
        fail("native prelaunch security projection cross-leaf binding failed");
    }

    // Python owns full grammar interpretation. Native ingress binds only the
    // already-frozen grammar pin; the plan repeats that exact pin check.
    return RawPrelaunchRequest(
        label, descriptor, root, collector_profile, grammar_version, grammar_sha256,
        path_profile, relative_cwd, primary_source, public_rows, argv, std::move(harness));
}

}  // namespace evaluation_v6_3_1::capture_v2
