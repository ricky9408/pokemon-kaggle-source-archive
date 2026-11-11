#include "PrelaunchContext.h"

#if !defined(__linux__)
#error "PrelaunchContext is a Linux-only Capture V2 component"
#endif

#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/SHA256.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <span>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {
namespace {

using Byte = std::uint8_t;

constexpr std::size_t kMaximumCollectorProfileCborBytes =
    16u * 1024u * 1024u;
constexpr std::size_t kMaximumPathProfileCborBytes = 4096u;
constexpr std::size_t kMaximumPublicFileRowsCborBytes =
    48u * 1024u * 1024u;
constexpr std::size_t kMaximumCborDepth = 64u;
constexpr std::size_t kMaximumCborItems = 1'000'000u;
constexpr std::size_t kMaximumArgvItems = 4096u;
constexpr std::size_t kMaximumArgvItemBytes = 1u * 1024u * 1024u;
constexpr std::size_t kMaximumEncodedArgvBytes = 16u * 1024u * 1024u;
constexpr std::size_t kMaximumHarnessBuildIdBytes = 65'535u;
constexpr std::uint64_t kMaximumHarnessComponentBytes =
    1u * 1024u * 1024u * 1024u;
constexpr std::size_t kMaximumGnuBuildIdDescriptorBytes = 65'535u;

[[noreturn]] void fail(std::string message, int system_errno = 0) {
    throw SupervisorError(SupervisorFailure::InvalidRequest, std::move(message), system_errno);
}

bool is_continuation(Byte value) noexcept { return (value & 0xc0u) == 0x80u; }

bool valid_utf8(std::span<const Byte> value) noexcept {
    std::size_t index = 0u;
    while (index < value.size()) {
        const Byte first = value[index++];
        if (first <= 0x7fu) continue;
        if (first >= 0xc2u && first <= 0xdfu) {
            if (index >= value.size() || !is_continuation(value[index])) return false;
            ++index;
            continue;
        }
        if (first >= 0xe0u && first <= 0xefu) {
            if (index + 1u >= value.size()) return false;
            const Byte second = value[index];
            const bool second_valid = first == 0xe0u ? second >= 0xa0u && second <= 0xbfu
                                      : first == 0xedu ? second >= 0x80u && second <= 0x9fu
                                                       : is_continuation(second);
            if (!second_valid || !is_continuation(value[index + 1u])) return false;
            index += 2u;
            continue;
        }
        if (first >= 0xf0u && first <= 0xf4u) {
            if (index + 2u >= value.size()) return false;
            const Byte second = value[index];
            const bool second_valid = first == 0xf0u ? second >= 0x90u && second <= 0xbfu
                                      : first == 0xf4u ? second >= 0x80u && second <= 0x8fu
                                                       : is_continuation(second);
            if (!second_valid || !is_continuation(value[index + 1u]) ||
                !is_continuation(value[index + 2u])) return false;
            index += 3u;
            continue;
        }
        return false;
    }
    return true;
}

bool valid_collector_profile_build_label(
    std::span<const Byte> value) noexcept {
    if (value.empty() || value.size() > kValidatedCollectorProfileBuildLabelMaximumBytes) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](Byte byte) {
        return byte >= 0x20u && byte <= 0x7eu;
    });
}

struct CborNode final {
    enum class Kind : Byte { Uint, Bytes, Text, Array };
    Kind kind;
    std::uint64_t uint_value = 0u;
    std::vector<Byte> bytes_value;
    std::string text_value;
    std::vector<CborNode> array_value;
};

struct CborHead final { Byte major; std::uint64_t argument; };

[[noreturn]] void cbor_fail() { fail("prelaunch CBOR is not canonical arrays-only CBOR"); }

CborHead parse_head(std::span<const Byte> bytes, std::size_t& cursor) {
    if (cursor >= bytes.size()) cbor_fail();
    const Byte initial = bytes[cursor++];
    const Byte major = static_cast<Byte>(initial >> 5u);
    const Byte additional = static_cast<Byte>(initial & 0x1fu);
    if (major != 0u && major != 2u && major != 3u && major != 4u) cbor_fail();
    std::size_t width = 0u;
    std::uint64_t value = 0u;
    if (additional < 24u) value = additional;
    else if (additional == 24u) width = 1u;
    else if (additional == 25u) width = 2u;
    else if (additional == 26u) width = 4u;
    else if (additional == 27u) width = 8u;
    else cbor_fail();
    if (width == 0u) return {major, value};
    if (width > bytes.size() - cursor) cbor_fail();
    for (std::size_t index = 0u; index < width; ++index) value = (value << 8u) | bytes[cursor++];
    const std::uint64_t minimum = width == 1u ? 24u : width == 2u ? 0x100u
                                  : width == 4u ? 0x10000u : 0x100000000ULL;
    if (value < minimum) cbor_fail();
    return {major, value};
}

CborNode parse_item(std::span<const Byte> bytes, std::size_t& cursor, std::size_t depth,
                    std::size_t& item_count) {
    if (depth > kMaximumCborDepth || ++item_count > kMaximumCborItems) cbor_fail();
    const CborHead head = parse_head(bytes, cursor);
    if (head.major == 0u) return {CborNode::Kind::Uint, head.argument, {}, {}, {}};
    if (head.argument > bytes.size() - cursor) cbor_fail();
    const std::size_t length = static_cast<std::size_t>(head.argument);
    if (head.major == 2u) {
        std::vector<Byte> value(bytes.begin() + static_cast<std::ptrdiff_t>(cursor),
                                bytes.begin() + static_cast<std::ptrdiff_t>(cursor + length));
        cursor += length;
        return {CborNode::Kind::Bytes, 0u, std::move(value), {}, {}};
    }
    if (head.major == 3u) {
        const std::span<const Byte> raw = bytes.subspan(cursor, length);
        if (!valid_utf8(raw)) cbor_fail();
        std::string value(reinterpret_cast<const char*>(raw.data()), raw.size());
        cursor += length;
        return {CborNode::Kind::Text, 0u, {}, std::move(value), {}};
    }
    if (head.argument > kMaximumCborItems - item_count) cbor_fail();
    std::vector<CborNode> value;
    value.reserve(static_cast<std::size_t>(head.argument));
    for (std::uint64_t index = 0u; index < head.argument; ++index) {
        value.push_back(parse_item(bytes, cursor, depth + 1u, item_count));
    }
    return {CborNode::Kind::Array, 0u, {}, {}, std::move(value)};
}

void append_head(std::vector<Byte>& output, Byte major, std::uint64_t value) {
    const auto append = [&output](Byte byte) { output.push_back(byte); };
    if (value < 24u) append(static_cast<Byte>((major << 5u) | static_cast<Byte>(value)));
    else if (value <= 0xffu) { append(static_cast<Byte>((static_cast<unsigned>(major) << 5u) | 24u)); append(static_cast<Byte>(value)); }
    else if (value <= 0xffffu) { append(static_cast<Byte>((static_cast<unsigned>(major) << 5u) | 25u)); append(static_cast<Byte>(value >> 8u)); append(static_cast<Byte>(value)); }
    else if (value <= 0xffffffffULL) { append(static_cast<Byte>((static_cast<unsigned>(major) << 5u) | 26u)); for (int shift = 24; shift >= 0; shift -= 8) append(static_cast<Byte>(value >> static_cast<unsigned>(shift))); }
    else { append(static_cast<Byte>((static_cast<unsigned>(major) << 5u) | 27u)); for (int shift = 56; shift >= 0; shift -= 8) append(static_cast<Byte>(value >> static_cast<unsigned>(shift))); }
}

void encode_item(const CborNode& value, std::vector<Byte>& output) {
    if (value.kind == CborNode::Kind::Uint) { append_head(output, 0u, value.uint_value); return; }
    if (value.kind == CborNode::Kind::Bytes) { append_head(output, 2u, value.bytes_value.size()); output.insert(output.end(), value.bytes_value.begin(), value.bytes_value.end()); return; }
    if (value.kind == CborNode::Kind::Text) { append_head(output, 3u, value.text_value.size()); output.insert(output.end(), value.text_value.begin(), value.text_value.end()); return; }
    append_head(output, 4u, value.array_value.size());
    for (const CborNode& child : value.array_value) encode_item(child, output);
}

CborNode parse_canonical_array(
    std::span<const Byte> bytes,
    std::size_t maximum_total_bytes) {
    if (bytes.empty() || bytes.size() > maximum_total_bytes) cbor_fail();
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

const CborNode& array_at(const CborNode& node, std::size_t index) {
    if (node.kind != CborNode::Kind::Array || index >= node.array_value.size()) cbor_fail();
    return node.array_value[index];
}
void exact_width(const CborNode& node, std::size_t width) {
    if (node.kind != CborNode::Kind::Array || node.array_value.size() != width) cbor_fail();
}
std::uint64_t require_uint(const CborNode& node) { if (node.kind != CborNode::Kind::Uint) cbor_fail(); return node.uint_value; }
std::string require_text(const CborNode& node) { if (node.kind != CborNode::Kind::Text || node.text_value.find('\0') != std::string::npos) cbor_fail(); return node.text_value; }
Sha256Digest require_digest(const CborNode& node) {
    if (node.kind != CborNode::Kind::Bytes || node.bytes_value.size() != Sha256Digest{}.size()) cbor_fail();
    Sha256Digest result{};
    std::copy(node.bytes_value.begin(), node.bytes_value.end(), result.begin());
    return result;
}

bool canonical_absolute(std::string_view path) noexcept {
    if (path.size() <= 1u || path.front() != '/' || path.back() == '/' || path.find('\\') != std::string_view::npos || path.find('\0') != std::string_view::npos) return false;
    std::size_t start = 1u;
    for (;;) {
        const std::size_t separator = path.find('/', start);
        const std::size_t end = separator == std::string_view::npos ? path.size() : separator;
        const std::string_view part = path.substr(start, end - start);
        if (part.empty() || part == "." || part == "..") return false;
        if (separator == std::string_view::npos) return true;
        start = separator + 1u;
    }
}
bool canonical_relative(std::string_view path) noexcept {
    if (path.empty() || path.front() == '/' || path.find('\\') != std::string_view::npos || path.find('\0') != std::string_view::npos) return false;
    std::size_t start = 0u;
    for (;;) {
        const std::size_t separator = path.find('/', start);
        const std::size_t end = separator == std::string_view::npos ? path.size() : separator;
        const std::string_view part = path.substr(start, end - start);
        if (part.empty() || part == "." || part == "..") return false;
        if (separator == std::string_view::npos) return true;
        start = separator + 1u;
    }
}
bool bytewise_less(const std::string& left, const std::string& right) noexcept {
    return std::lexicographical_compare(left.begin(), left.end(), right.begin(), right.end(),
        [](char a, char b) { return static_cast<Byte>(a) < static_cast<Byte>(b); });
}

std::string resolve_argv_path(
    const std::string& token,
    const DecodedPathProfileV2& profile) {
    if (token.find('\\') != std::string::npos ||
        token.find('\0') != std::string::npos || token.rfind("//", 0u) == 0u) {
        fail("requested argv contains a non-POSIX path");
    }
    std::vector<std::string> components;
    if (token.empty() || token.front() != '/') {
        components.emplace_back(profile.work_absolute_prefix.substr(1u));
    }
    std::size_t start = token.empty() || token.front() != '/' ? 0u : 1u;
    while (start <= token.size()) {
        const std::size_t separator = token.find('/', start);
        const std::size_t end = separator == std::string::npos ? token.size() : separator;
        const std::string_view component(token.data() + start, end - start);
        if (!component.empty() && component != ".") {
            if (component == "..") {
                if (!components.empty()) components.pop_back();
            } else {
                components.emplace_back(component);
            }
        }
        if (separator == std::string::npos) break;
        start = separator + 1u;
    }
    if (components.empty()) {
        fail("requested argv path resolves to the namespace root");
    }
    std::string result;
    for (const std::string& component : components) {
        if (!result.empty()) result.push_back('/');
        result.append(component);
    }
    if (!canonical_relative(result)) {
        fail("requested argv path is not canonical after resolution");
    }
    return result;
}

bool allowed_search_directory(std::string_view relative) noexcept {
    static constexpr std::array<std::string_view, 4u> kPrefixes = {
        "src", "work", "bin", "lib"};
    return std::any_of(kPrefixes.begin(), kPrefixes.end(), [relative](std::string_view prefix) {
        return relative == prefix ||
               (relative.size() > prefix.size() &&
                relative.compare(0u, prefix.size(), prefix) == 0 &&
                relative[prefix.size()] == '/');
    });
}

DecodedPathProfileV2 decode_profile(
    const std::vector<Byte>& raw,
    const std::string& relative_cwd) {
    const CborNode node = parse_canonical_array(
        raw, kMaximumPathProfileCborBytes);
    exact_width(node, 4u);
    DecodedPathProfileV2 value{
        require_uint(array_at(node, 0u)),
        require_text(array_at(node, 1u)),
        require_text(array_at(node, 2u)),
        require_text(array_at(node, 3u))};
    if (value.version != 2u || !canonical_absolute(value.source_absolute_prefix) ||
        !canonical_absolute(value.work_absolute_prefix) ||
        !canonical_absolute(value.command_absolute_prefix) ||
        !canonical_relative(relative_cwd)) {
        fail("PATH_PROFILE_V2 contains a noncanonical path");
    }
    if (value.source_absolute_prefix != "/src" ||
        value.work_absolute_prefix != "/work" ||
        value.command_absolute_prefix != "/bin" ||
        relative_cwd != "work") {
        fail("PATH_PROFILE_V2 does not match the frozen process-root mapping");
    }
    return value;
}

std::vector<DecodedPublicFileRow> decode_public_rows(const std::vector<Byte>& raw) {
    const CborNode rows = parse_canonical_array(
        raw, kMaximumPublicFileRowsCborBytes);
    if (rows.array_value.empty()) cbor_fail();
    std::vector<DecodedPublicFileRow> result;
    result.reserve(rows.array_value.size());
    std::string previous;
    for (const CborNode& row : rows.array_value) {
        exact_width(row, 5u);
        const CborNode& roles = array_at(row, 1u);
        if (roles.kind != CborNode::Kind::Array || roles.array_value.empty()) cbor_fail();
        std::vector<std::uint64_t> role_codes;
        role_codes.reserve(roles.array_value.size());
        std::uint64_t prior_role = 0u;
        for (const CborNode& role : roles.array_value) {
            const std::uint64_t code = require_uint(role);
            if (code == 0u || code <= prior_role) cbor_fail();
            role_codes.push_back(code);
            prior_role = code;
        }
        DecodedPublicFileRow decoded{require_text(array_at(row, 0u)), std::move(role_codes),
                                     require_uint(array_at(row, 2u)), require_uint(array_at(row, 3u)),
                                     require_digest(array_at(row, 4u))};
        if (!canonical_relative(decoded.namespace_relative_path) ||
            (!previous.empty() && !bytewise_less(previous, decoded.namespace_relative_path))) {
            fail("public namespace expectation rows are not bytewise strictly sorted");
        }
        previous = decoded.namespace_relative_path;
        result.push_back(std::move(decoded));
    }
    return result;
}

std::string decode_collector_profile_build_label_text(
    const std::vector<Byte>& raw) {
    const CborNode node = parse_canonical_array(
        raw, kMaximumCollectorProfileCborBytes);
    exact_width(node, 8u);
    std::string label = require_text(array_at(node, 1u));
    const std::span<const Byte> label_bytes(
        reinterpret_cast<const Byte*>(label.data()), label.size());
    if (!valid_collector_profile_build_label(label_bytes)) {
        fail("collector profile build label violates the frozen ASCII grammar");
    }
    return label;
}
void validate_argv(
    const std::vector<std::string>& argv,
    const DecodedPathProfileV2& profile,
    const std::string& primary_source) {
    if (argv.empty() || argv.size() > kMaximumArgvItems) fail("requested argv count is invalid");
    const auto head_size = [](std::size_t value) noexcept -> std::size_t {
        if (value <= 23u) return 1u;
        if (value <= 0xffu) return 2u;
        if (value <= 0xffffu) return 3u;
        if (value <= 0xffffffffULL) return 5u;
        return 9u;
    };
    std::size_t encoded_size = head_size(argv.size());
    for (std::size_t index = 0u; index < argv.size(); ++index) {
        const std::string& token = argv[index];
        if (token.empty() ||
            token.find('\0') != std::string::npos ||
            (!token.empty() && token.front() == '@') ||
            token.size() > kMaximumArgvItemBytes ||
            !valid_utf8(std::span<const Byte>(
                reinterpret_cast<const Byte*>(token.data()), token.size()))) {
            fail("requested argv violates frozen V1 ingress constraints");
        }
        const std::size_t header_bytes = head_size(token.size());
        if (header_bytes > kMaximumEncodedArgvBytes - encoded_size ||
            token.size() >
                kMaximumEncodedArgvBytes - encoded_size - header_bytes) {
            fail("requested argv exceeds its frozen canonical-CBOR byte limit");
        }
        encoded_size += header_bytes + token.size();
    }

    // CLANG16_CAPTURE_PROFILE_GRAMMAR_V1, driver phase.  Native does not
    // interpret canonicalizer fields, but it must independently validate the
    // exact rooted invocation that controls the collector's compiler child.
    if (argv.front() != "/bin/clang-tool") {
        fail("requested argv does not name the frozen Clang driver");
    }
    std::size_t std_count = 0u;
    std::size_t syntax_count = 0u;
    std::size_t nostdinc_count = 0u;
    std::size_t no_config_count = 0u;
    std::size_t include_count = 0u;
    std::size_t resource_count = 0u;
    std::size_t primary_count = 0u;
    for (std::size_t index = 1u; index < argv.size(); ++index) {
        const std::string& token = argv[index];
        if (token == "-std=c++20") {
            ++std_count;
        } else if (token == "-fsyntax-only") {
            ++syntax_count;
        } else if (token == "-nostdinc") {
            ++nostdinc_count;
        } else if (token == "--no-default-config") {
            ++no_config_count;
        } else if (token == "-I") {
            if (++index >= argv.size()) {
                fail("requested argv has an invalid -I value");
            }
            if (!allowed_search_directory(resolve_argv_path(argv[index], profile))) {
                fail("requested argv -I value is outside PATH_PROFILE_V2");
            }
            ++include_count;
        } else if (token == "-resource-dir") {
            if (++index >= argv.size()) {
                fail("requested argv has an invalid -resource-dir value");
            }
            if (!allowed_search_directory(resolve_argv_path(argv[index], profile))) {
                fail("requested argv resource directory is outside PATH_PROFILE_V2");
            }
            ++resource_count;
        } else if (token.rfind("-resource-dir=", 0u) == 0u &&
                   token.size() > std::string("-resource-dir=").size()) {
            const std::string resource = token.substr(std::string("-resource-dir=").size());
            if (!allowed_search_directory(resolve_argv_path(resource, profile))) {
                fail("requested argv resource directory is outside PATH_PROFILE_V2");
            }
            ++resource_count;
        } else if (!token.empty() && token.front() != '-') {
            if (resolve_argv_path(token, profile) == primary_source) {
                ++primary_count;
            } else {
                fail("requested argv contains an uncommitted positional input");
            }
        } else {
            fail("requested argv token is not in CLANG16_CAPTURE_PROFILE_GRAMMAR_V1");
        }
    }
    if (std_count != 1u || syntax_count != 1u || nostdinc_count != 1u ||
        no_config_count != 1u || include_count == 0u || include_count > 64u ||
        resource_count > 1u || primary_count != 1u) {
        fail("requested argv violates CLANG16_CAPTURE_PROFILE_GRAMMAR_V1 multiplicity");
    }
}

struct DirectInProcessCollectorLaunchV2 final {
    std::string absolute_primary_source;
    std::vector<Byte> capture_context_cbor_bytes;
    std::vector<std::string> argv;
};

std::string lowercase_hex(std::span<const Byte> bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2u);
    for (const Byte byte : bytes) {
        result.push_back(kDigits[byte >> 4u]);
        result.push_back(kDigits[byte & 0x0fu]);
    }
    return result;
}

DirectInProcessCollectorLaunchV2 derive_collector_launch_v2(
    const std::vector<DecodedPublicFileRow>& rows,
    const std::vector<Byte>& path_profile_cbor_bytes,
    const std::string& primary_source,
    const std::vector<std::string>& requested_argv) {
    static const std::array<std::string, 5u> kExpectedPaths = {
        "bin/collector",
        "lib/ld-linux-x86-64.so.2",
        "lib/libc.so.6",
        "lib/libclang-cpp.so.16",
        "src/Export.cpp",
    };
    static const std::array<std::vector<std::uint64_t>, 5u> kExpectedRoles = {
        std::vector<std::uint64_t>{1u},
        std::vector<std::uint64_t>{6u},
        std::vector<std::uint64_t>{8u},
        std::vector<std::uint64_t>{7u, 8u},
        std::vector<std::uint64_t>{2u, 3u},
    };
    static constexpr std::array<std::uint64_t, 5u> kExpectedModes = {
        0555u, 0444u, 0444u, 0444u, 0444u};
    if (rows.size() != kExpectedPaths.size()) {
        fail("public rows differ from the exact five-object capture topology");
    }
    for (std::size_t index = 0u; index < rows.size(); ++index) {
        if (rows[index].namespace_relative_path != kExpectedPaths[index] ||
            rows[index].role_codes != kExpectedRoles[index] ||
            rows[index].normalized_mode != kExpectedModes[index]) {
            fail("public rows differ from the exact five-object capture topology");
        }
    }
    if (requested_argv.empty() || requested_argv.front() != "/bin/clang-tool") {
        fail("inner Clang driver argv cannot derive the collector launch");
    }

    DirectInProcessCollectorLaunchV2 result;
    result.absolute_primary_source = "/" + primary_source;
    append_head(result.capture_context_cbor_bytes, 4u, 3u);
    append_head(result.capture_context_cbor_bytes, 0u, 1u);
    append_head(result.capture_context_cbor_bytes, 3u, primary_source.size());
    result.capture_context_cbor_bytes.insert(
        result.capture_context_cbor_bytes.end(),
        reinterpret_cast<const Byte*>(primary_source.data()),
        reinterpret_cast<const Byte*>(primary_source.data()) + primary_source.size());
    result.capture_context_cbor_bytes.insert(
        result.capture_context_cbor_bytes.end(),
        path_profile_cbor_bytes.begin(),
        path_profile_cbor_bytes.end());
    const std::string context_hex = lowercase_hex(result.capture_context_cbor_bytes);

    result.argv.reserve(requested_argv.size() + 6u);
    result.argv.emplace_back("/bin/collector");
    result.argv.emplace_back("--protocol=631302");
    result.argv.emplace_back("--level=2");
    result.argv.emplace_back("--primary-source=" + result.absolute_primary_source);
    result.argv.emplace_back("--capture-context-v1-cbor-hex=" + context_hex);
    result.argv.emplace_back("--");
    result.argv.insert(result.argv.end(), requested_argv.begin(), requested_argv.end());
    return result;
}
void validate_primary(const std::string& primary, const DecodedPathProfileV2& profile) {
    const std::string source_prefix = profile.source_absolute_prefix.substr(1u);
    if (!canonical_relative(primary) ||
        (primary != source_prefix &&
         (primary.size() <= source_prefix.size() ||
          primary.compare(0u, source_prefix.size(), source_prefix) != 0 ||
          primary[source_prefix.size()] != '/'))) {
        fail("primary source is outside source prefix");
    }
}
void validate_harness(const HarnessExpectations& expectations) {
    const std::array<const ComponentExpectation*, 3u> rows = {
        &expectations.capture_entry_component,
        &expectations.capture_interpreter_component,
        &expectations.native_supervisor_component,
    };
    for (const ComponentExpectation* row : rows) {
        if (row->byte_length == 0u ||
            row->byte_length > kMaximumHarnessComponentBytes ||
            row->build_id.size() > kMaximumHarnessBuildIdBytes) {
            fail("harness expectation is structurally invalid");
        }
    }
}
void validate_custody_fd(
    int descriptor,
    const WorkDirectoryIdentity& identity) {
    if (descriptor < 0) {
        fail("work-directory custody input is incomplete");
    }
    const int flags = ::fcntl(descriptor, F_GETFL);
    if (flags < 0) fail("work-directory custody descriptor flags unavailable", errno);
    // O_DIRECTORY is not retained by Linux F_GETFL. O_PATH plus fstat directory
    // proof is the checkable O_PATH/O_DIRECTORY descriptor contract.
    if ((flags & O_PATH) == 0) fail("work-directory custody descriptor is not O_PATH");
    struct stat status {};
    if (::fstat(descriptor, &status) != 0) fail("work-directory custody descriptor fstat failed", errno);
    if (!S_ISDIR(status.st_mode) || static_cast<std::uint64_t>(status.st_dev) != identity.device ||
        static_cast<std::uint64_t>(status.st_ino) != identity.inode) {
        fail("work-directory custody descriptor identity differs from receipt");
    }
}

void append_u64(std::vector<Byte>& output, std::uint64_t value) { for (int shift = 56; shift >= 0; shift -= 8) output.push_back(static_cast<Byte>(value >> static_cast<unsigned>(shift))); }
void append_bytes(std::vector<Byte>& output, std::span<const Byte> value) { append_u64(output, value.size()); output.insert(output.end(), value.begin(), value.end()); }
void append_text(std::vector<Byte>& output, const std::string& value) { append_bytes(output, std::span<const Byte>(reinterpret_cast<const Byte*>(value.data()), value.size())); }
Sha256Digest hash_material(const std::vector<Byte>& material) { return llvm::SHA256::hash(llvm::ArrayRef<Byte>(material.data(), material.size())); }

}  // namespace

Sha256Digest ValidatedPrelaunchPlan::plan_binding_digest(const RawPrelaunchRequest& raw) {
    std::vector<Byte> material;
    append_text(material, "V631302_PRELAUNCH_PLAN_V3");
    append_text(material, raw.collector_profile_build_label_text_);
    append_bytes(
        material,
        raw.expected_collector_gnu_build_id_descriptor_bytes_);
    append_bytes(material, raw.validated_prelaunch_expectations_root_);
    append_bytes(material, raw.collector_profile_cbor_bytes_);
    append_u64(material, raw.argv_grammar_version_);
    append_bytes(material, raw.argv_grammar_sha256_);
    append_bytes(material, raw.path_profile_cbor_bytes_);
    append_text(material, raw.namespace_relative_cwd_);
    append_text(material, raw.primary_source_);
    append_bytes(material, raw.public_file_rows_cbor_bytes_);
    append_u64(material, raw.requested_argv_.size());
    for (const std::string& token : raw.requested_argv_) append_text(material, token);
    const std::array<const ComponentExpectation*, 3u> harness_rows = {
        &raw.harness_expectations_.capture_entry_component,
        &raw.harness_expectations_.capture_interpreter_component,
        &raw.harness_expectations_.native_supervisor_component,
    };
    for (const ComponentExpectation* row : harness_rows) {
        append_u64(material, row->byte_length);
        append_bytes(material, row->sha256);
        append_bytes(material, row->build_id);
    }
    return hash_material(material);
}

Sha256Digest ValidatedPrelaunchPlan::context_binding_digest(
    const Sha256Digest& plan_digest,
    const Sha256Digest32& validated_prelaunch_expectations_root,
    WorkDirectoryIdentity identity) {
    std::vector<Byte> material;
    append_text(material, "V631302_WORKDIR_CONTEXT_V3");
    append_bytes(material, plan_digest);
    append_bytes(material, validated_prelaunch_expectations_root);
    append_u64(material, identity.device);
    append_u64(material, identity.inode);
    return hash_material(material);
}

RawPrelaunchRequest::RawPrelaunchRequest(
    std::string profile_build_label,
    std::vector<Byte> expected_gnu_build_id_descriptor,
    Sha256Digest32 validated_prelaunch_expectations_root,
    std::vector<Byte> profile,
    std::uint64_t grammar_version, Sha256Digest grammar_digest, std::vector<Byte> path_profile,
    std::string relative_cwd, std::string primary, std::vector<Byte> public_rows,
    std::vector<std::string> argv, HarnessExpectations harness)
    : collector_profile_build_label_text_(std::move(profile_build_label)),
      expected_collector_gnu_build_id_descriptor_bytes_(
          std::move(expected_gnu_build_id_descriptor)),
      validated_prelaunch_expectations_root_(validated_prelaunch_expectations_root),
      collector_profile_cbor_bytes_(std::move(profile)),
      argv_grammar_version_(grammar_version), argv_grammar_sha256_(grammar_digest),
      path_profile_cbor_bytes_(std::move(path_profile)),
      namespace_relative_cwd_(std::move(relative_cwd)), primary_source_(std::move(primary)),
      public_file_rows_cbor_bytes_(std::move(public_rows)), requested_argv_(std::move(argv)),
      harness_expectations_(std::move(harness)) {}

#if defined(EVALUATION_V631302_NATIVE_PRELAUNCH_HANDOFF_TEST_ONLY)
RawPrelaunchRequest RawPrelaunchRequest::copy_from(
    const std::string& profile_build_label,
    const std::vector<Byte>& expected_gnu_build_id_descriptor,
    const Sha256Digest32& validated_prelaunch_expectations_root,
    const std::vector<Byte>& profile,
    std::uint64_t grammar_version,
    const Sha256Digest& grammar_digest,
    const std::vector<Byte>& path_profile, const std::string& relative_cwd,
    const std::string& primary, const std::vector<Byte>& public_rows, const std::vector<std::string>& argv,
    const HarnessExpectations& harness) {
    return RawPrelaunchRequest(
        profile_build_label,
        expected_gnu_build_id_descriptor,
        validated_prelaunch_expectations_root,
        profile,
        grammar_version,
        grammar_digest,
        path_profile,
        relative_cwd,
        primary,
        public_rows,
        argv,
        harness);
}

RawPrelaunchRequest RawPrelaunchRequest::copy_from(
    const std::string& profile_build_label,
    const std::vector<Byte>& expected_gnu_build_id_descriptor,
    const Sha256Digest32& validated_prelaunch_expectations_root,
    const std::vector<Byte>& profile,
    std::uint64_t grammar_version,
    const Sha256Digest& grammar_digest,
    const std::vector<Byte>& path_profile,
    const std::string& legacy_working_directory_absolute,
    const std::string& relative_cwd,
    const std::string& primary,
    const std::vector<Byte>& public_rows,
    const std::vector<std::string>& argv,
    const HarnessExpectations& harness) {
    static_cast<void>(legacy_working_directory_absolute);
    return copy_from(
        profile_build_label,
        expected_gnu_build_id_descriptor,
        validated_prelaunch_expectations_root,
        profile,
        grammar_version,
        grammar_digest,
        path_profile,
        relative_cwd,
        primary,
        public_rows,
        argv,
        harness);
}
#endif

ValidatedPrelaunchPlan::ValidatedPrelaunchPlan(RawPrelaunchRequest&& raw, DecodedPathProfileV2 profile,
    std::vector<DecodedPublicFileRow> public_rows,
    std::string absolute_primary_source,
    std::vector<Byte> capture_context_cbor_bytes,
    std::vector<std::string> collector_launch_argv,
    Sha256Digest digest) noexcept
    : collector_profile_build_label_text_(
          ValidatedCollectorProfileBuildLabelText(
              std::move(raw.collector_profile_build_label_text_))),
      expected_collector_gnu_build_id_descriptor_bytes_(
          ExactGnuBuildIdDescriptorBytes(
              std::move(raw.expected_collector_gnu_build_id_descriptor_bytes_))),
      validated_prelaunch_expectations_root_(raw.validated_prelaunch_expectations_root_),
      collector_profile_cbor_bytes_(std::move(raw.collector_profile_cbor_bytes_)),
      argv_grammar_version_(raw.argv_grammar_version_), argv_grammar_sha256_(raw.argv_grammar_sha256_),
      path_profile_cbor_bytes_(std::move(raw.path_profile_cbor_bytes_)),
      namespace_relative_cwd_(std::move(raw.namespace_relative_cwd_)), primary_source_(std::move(raw.primary_source_)),
      public_file_rows_cbor_bytes_(std::move(raw.public_file_rows_cbor_bytes_)), requested_argv_(std::move(raw.requested_argv_)),
      absolute_primary_source_(std::move(absolute_primary_source)),
      capture_context_cbor_bytes_(std::move(capture_context_cbor_bytes)),
      collector_launch_argv_(std::move(collector_launch_argv)),
      harness_expectations_(std::move(raw.harness_expectations_)), path_profile_(std::move(profile)),
      public_file_rows_(std::move(public_rows)), private_plan_binding_digest_(digest) {}

ValidatedPrelaunchPlan ValidatedPrelaunchPlan::validate(RawPrelaunchRequest&& raw) {
    const std::span<const Byte> profile_build_label_bytes(
        reinterpret_cast<const Byte*>(raw.collector_profile_build_label_text_.data()),
        raw.collector_profile_build_label_text_.size());
    if (!valid_collector_profile_build_label(profile_build_label_bytes)) {
        fail("collector profile build label must satisfy the frozen ASCII grammar");
    }
    if (raw.expected_collector_gnu_build_id_descriptor_bytes_.empty() ||
        raw.expected_collector_gnu_build_id_descriptor_bytes_.size() >
            kMaximumGnuBuildIdDescriptorBytes) {
        fail("expected collector GNU build-ID descriptor is outside 1..65535 bytes");
    }
    if (raw.argv_grammar_version_ != kFrozenArgvGrammarVersionV1 || raw.argv_grammar_sha256_ != kFrozenArgvGrammarSha256V1) fail("argv grammar pin differs from frozen V1");
    const std::string profile_label = decode_collector_profile_build_label_text(
        raw.collector_profile_cbor_bytes_);
    if (profile_label != raw.collector_profile_build_label_text_) {
        fail("collector profile field 1 differs from its expected build label");
    }
    DecodedPathProfileV2 profile = decode_profile(raw.path_profile_cbor_bytes_, raw.namespace_relative_cwd_);
    validate_primary(raw.primary_source_, profile);
    std::vector<DecodedPublicFileRow> rows = decode_public_rows(raw.public_file_rows_cbor_bytes_);
    validate_argv(raw.requested_argv_, profile, raw.primary_source_);
    validate_harness(raw.harness_expectations_);
    DirectInProcessCollectorLaunchV2 launch = derive_collector_launch_v2(
        rows,
        raw.path_profile_cbor_bytes_,
        raw.primary_source_,
        raw.requested_argv_);
    const Sha256Digest digest = plan_binding_digest(raw);
    return ValidatedPrelaunchPlan(
        std::move(raw), std::move(profile), std::move(rows),
        std::move(launch.absolute_primary_source),
        std::move(launch.capture_context_cbor_bytes),
        std::move(launch.argv),
        digest);
}

ValidatedPrelaunchContext ValidatedPrelaunchPlan::bind_work_directory_custody(
    WorkDirectoryCustodyParentEndpoint&& parent_endpoint) && {
    ValidatedPrelaunchContextSlot destination;
    WorkDirectoryCustody custody =
        parent_endpoint.receive_handoff_and_confirm_peer_eof();
    const WorkDirectoryIdentity identity = custody.identity();
    validate_custody_fd(custody.retained_directory_fd(), identity);
    const Sha256Digest digest = context_binding_digest(
        private_plan_binding_digest_, validated_prelaunch_expectations_root_, identity);
    destination.commit(ValidatedPrelaunchContext(
        std::move(*this),
        std::move(custody).take_retained_directory_fd(),
        identity,
        digest));
    try {
        parent_endpoint.acknowledge_after_context_commit();
    } catch (...) {
        destination.abort();
        throw;
    }
    return std::move(destination).take_committed();
}

ValidatedPrelaunchContext::ValidatedPrelaunchContext(
    ValidatedPrelaunchPlan&& plan,
    OwnedFd retained_working_directory_fd,
    WorkDirectoryIdentity retained_working_directory_identity,
    Sha256Digest digest) noexcept
    : collector_profile_build_label_text_(
          std::move(plan.collector_profile_build_label_text_)),
      expected_collector_gnu_build_id_descriptor_bytes_(
          std::move(plan.expected_collector_gnu_build_id_descriptor_bytes_)),
      validated_prelaunch_expectations_root_(plan.validated_prelaunch_expectations_root_),
      collector_profile_cbor_bytes_(std::move(plan.collector_profile_cbor_bytes_)),
      argv_grammar_version_(plan.argv_grammar_version_), argv_grammar_sha256_(plan.argv_grammar_sha256_),
      path_profile_cbor_bytes_(std::move(plan.path_profile_cbor_bytes_)),
      namespace_relative_cwd_(std::move(plan.namespace_relative_cwd_)), primary_source_(std::move(plan.primary_source_)),
      public_file_rows_cbor_bytes_(std::move(plan.public_file_rows_cbor_bytes_)), requested_argv_(std::move(plan.requested_argv_)),
      absolute_primary_source_(std::move(plan.absolute_primary_source_)),
      capture_context_cbor_bytes_(std::move(plan.capture_context_cbor_bytes_)),
      collector_launch_argv_(std::move(plan.collector_launch_argv_)),
      harness_expectations_(std::move(plan.harness_expectations_)), path_profile_(std::move(plan.path_profile_)),
      public_file_rows_(std::move(plan.public_file_rows_)),
      retained_working_directory_fd_(std::move(retained_working_directory_fd)),
      retained_working_directory_identity_(retained_working_directory_identity),
      private_context_binding_digest_(digest) {}

bool ValidatedPrelaunchContext::has_same_private_binding(const ValidatedPrelaunchContext& other) const noexcept {
    return private_context_binding_digest_ == other.private_context_binding_digest_;
}

void ValidatedPrelaunchContextSlot::commit(ValidatedPrelaunchContext&& context) {
    if (state_ != ValidatedPrelaunchContextSlotState::Empty || context_.has_value()) {
        fail("validated prelaunch context slot cannot be committed twice");
    }
    context_.emplace(std::move(context));
    state_ = ValidatedPrelaunchContextSlotState::Committed;
}

void ValidatedPrelaunchContextSlot::abort() noexcept {
    context_.reset();
    state_ = ValidatedPrelaunchContextSlotState::Aborted;
}

ValidatedPrelaunchContext ValidatedPrelaunchContextSlot::take_committed() && {
    if (state_ != ValidatedPrelaunchContextSlotState::Committed || !context_.has_value()) {
        fail("validated prelaunch context slot is not committed");
    }
    ValidatedPrelaunchContext context = std::move(*context_);
    context_.reset();
    state_ = ValidatedPrelaunchContextSlotState::MovedFrom;
    return context;
}

}  // namespace evaluation_v6_3_1::capture_v2
