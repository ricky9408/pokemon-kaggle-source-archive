#include "ExecutionOriginRelaxed.h"

#include "ExecutionOriginRelaxedBuildConfig.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/SHA256.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <optional>
#include <poll.h>
#include <signal.h>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::m0_diagnostic_relaxed {
namespace {

using Bytes = std::vector<std::uint8_t>;
using Digest = std::array<std::uint8_t, 32u>;

constexpr std::string_view kInputMagic = "V631DI01";
constexpr std::string_view kOutputMagic = "V631DO01";
constexpr std::string_view kBundleDomain = "V631302_CANONICALIZER_BUNDLE_V1";
constexpr std::string_view kBundleRootHex =
    "b5a5c7cefe1fc55db01a94516fc1a3068672a4f95d61f6a911b86d86d53fe6e6";
constexpr std::string_view kManifestDigestHex =
    "ce53f596ccc0563a2efee169a6e330924f8b3e57726f448fec19f4ac44581e35";
constexpr std::size_t kManifestLength = 357u;
constexpr std::string_view kWrapperLabel =
    "B9_FIXTURE_TU_A4_RETIRED_CAPTURE_V1_EMULATED_RELAXED_FD_FUNCTIONAL_ONLY";
constexpr std::string_view kEntryPath = "evaluation_v6_3_1/m0_diagnostic_census.py";
constexpr std::string_view kWorkerPath = "worker/v631302_diagnostic_worker_v1.py";
constexpr std::size_t kMaximumSelfBytes = 4u * 1024u * 1024u;
constexpr std::size_t kMaximumPinnedFileBytes = 256u * 1024u * 1024u;
constexpr std::uint64_t kMaximumCapturedRawCollectorBytes = 67108864ULL;
constexpr std::uint64_t kMaximumRawTransportBytes = 1073741824ULL;
constexpr std::uint64_t kMaximumInputPayloadBytes = 1074790400ULL;
constexpr std::uint64_t kMaximumCandidateBytes = 1073741824ULL;
constexpr std::size_t kMaximumStderrBytes = 65536u;
constexpr std::size_t kFrameHeaderBytes = 16u;

struct FileDescriptor final {
    explicit FileDescriptor(int descriptor = -1) : descriptor(descriptor) {}
    ~FileDescriptor() {
        if (descriptor >= 0) {
            close(descriptor);
        }
    }
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    FileDescriptor(FileDescriptor&& other) noexcept
        : descriptor(std::exchange(other.descriptor, -1)) {}
    FileDescriptor& operator=(FileDescriptor&& other) noexcept {
        if (this != &other) {
            if (descriptor >= 0) {
                close(descriptor);
            }
            descriptor = std::exchange(other.descriptor, -1);
        }
        return *this;
    }
    int release() noexcept { return std::exchange(descriptor, -1); }
    int descriptor;
};

struct PinnedFile final {
    FileDescriptor descriptor;
    std::uint64_t length = 0;
    Digest digest{};
    Bytes bytes;
};

enum class CborKind : std::uint8_t { Uint = 0u, Bytes = 2u, Text = 3u, Array = 4u };

struct CborValue final {
    CborKind kind = CborKind::Uint;
    std::uint64_t integer = 0;
    Bytes string;
    std::vector<CborValue> children;
    Bytes raw;
};

struct BundleMember final {
    std::string_view logical_path;
    std::string_view physical_path;
    std::uint64_t expected_length;
    std::string_view expected_digest;
};

struct ProcessOutput final {
    Bytes stdout_bytes;
    Bytes stderr_bytes;
    int status = -1;
    int inherited_interpreter_fd = -1;
    bool timed_out = false;
};

struct PreparedInput final {
    PinnedFile self;
    PinnedFile clang;
    PinnedFile interpreter;
    std::array<PinnedFile, 4u> bundle;
    Bytes profile;
    Bytes input_frame;
};

Bytes text_bytes(std::string_view value) {
    return Bytes(value.begin(), value.end());
}

Bytes digest_bytes(const Digest& digest) {
    return Bytes(digest.begin(), digest.end());
}

Digest sha256(const Bytes& bytes) {
    llvm::SHA256 hasher;
    hasher.update(llvm::ArrayRef<std::uint8_t>(bytes.data(), bytes.size()));
    return hasher.final();
}

std::optional<Digest> decode_hex_digest(std::string_view text) {
    if (text.size() != 64u) {
        return std::nullopt;
    }
    Digest result{};
    const auto nibble = [](char value) -> int {
        if (value >= '0' && value <= '9') return value - '0';
        if (value >= 'a' && value <= 'f') return value - 'a' + 10;
        if (value >= 'A' && value <= 'F') return value - 'A' + 10;
        return -1;
    };
    for (std::size_t index = 0; index < result.size(); ++index) {
        const int high = nibble(text[index * 2u]);
        const int low = nibble(text[index * 2u + 1u]);
        if (high < 0 || low < 0) return std::nullopt;
        result[index] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return result;
}

bool valid_utf8(const Bytes& value) {
    std::size_t index = 0;
    while (index < value.size()) {
        const auto first = value[index++];
        if (first <= 0x7Fu) continue;

        std::uint32_t code_point = 0;
        std::size_t continuation = 0;
        std::uint32_t minimum = 0;
        if (first >= 0xC2u && first <= 0xDFu) {
            code_point = first & 0x1Fu;
            continuation = 1;
            minimum = 0x80u;
        } else if (first >= 0xE0u && first <= 0xEFu) {
            code_point = first & 0x0Fu;
            continuation = 2;
            minimum = 0x800u;
        } else if (first >= 0xF0u && first <= 0xF4u) {
            code_point = first & 0x07u;
            continuation = 3;
            minimum = 0x10000u;
        } else {
            return false;
        }
        if (continuation > value.size() - index) return false;
        for (std::size_t offset = 0; offset < continuation; ++offset) {
            const auto next = value[index + offset];
            if ((next & 0xC0u) != 0x80u) return false;
            code_point = (code_point << 6u) | (next & 0x3Fu);
        }
        index += continuation;
        if (code_point < minimum || code_point > 0x10FFFFu ||
            (code_point >= 0xD800u && code_point <= 0xDFFFu)) {
            return false;
        }
    }
    return true;
}

void cbor_head(Bytes& output, std::uint8_t major, std::uint64_t argument) {
    if (major != 0u && major != 2u && major != 3u && major != 4u) {
        throw std::logic_error("unsupported CBOR type");
    }
    if (argument < 24u) {
        output.push_back(static_cast<std::uint8_t>((major << 5u) | argument));
    } else if (argument <= 0xffu) {
        output.push_back(static_cast<std::uint8_t>((major << 5u) | 24u));
        output.push_back(static_cast<std::uint8_t>(argument));
    } else if (argument <= 0xffffu) {
        output.push_back(static_cast<std::uint8_t>((major << 5u) | 25u));
        output.push_back(static_cast<std::uint8_t>(argument >> 8u));
        output.push_back(static_cast<std::uint8_t>(argument));
    } else if (argument <= 0xffffffffu) {
        output.push_back(static_cast<std::uint8_t>((major << 5u) | 26u));
        for (int shift = 24; shift >= 0; shift -= 8) output.push_back(argument >> shift);
    } else {
        output.push_back(static_cast<std::uint8_t>((major << 5u) | 27u));
        for (int shift = 56; shift >= 0; shift -= 8) output.push_back(argument >> shift);
    }
}

void cbor_uint(Bytes& output, std::uint64_t value) { cbor_head(output, 0u, value); }
void cbor_bytes(Bytes& output, const Bytes& value) {
    cbor_head(output, 2u, value.size());
    output.insert(output.end(), value.begin(), value.end());
}
void cbor_text(Bytes& output, std::string_view value) {
    const auto bytes = text_bytes(value);
    if (!valid_utf8(bytes)) throw std::logic_error("invalid UTF-8");
    cbor_head(output, 3u, bytes.size());
    output.insert(output.end(), bytes.begin(), bytes.end());
}
void cbor_array(Bytes& output, std::size_t count) { cbor_head(output, 4u, count); }

std::optional<std::pair<std::uint8_t, std::uint64_t>> parse_head(
    std::span<const std::uint8_t> bytes, std::size_t& cursor) {
    if (cursor >= bytes.size()) return std::nullopt;
    const auto first = bytes[cursor++];
    const auto major = static_cast<std::uint8_t>(first >> 5u);
    const auto additional = static_cast<std::uint8_t>(first & 31u);
    if (major != 0u && major != 2u && major != 3u && major != 4u) return std::nullopt;
    std::size_t width = 0;
    if (additional < 24u) return std::pair{major, static_cast<std::uint64_t>(additional)};
    if (additional == 24u) width = 1u;
    else if (additional == 25u) width = 2u;
    else if (additional == 26u) width = 4u;
    else if (additional == 27u) width = 8u;
    else return std::nullopt;
    if (width > bytes.size() - cursor) return std::nullopt;
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < width; ++index) value = (value << 8u) | bytes[cursor++];
    const auto minimum = width == 1u ? 24u : width == 2u ? 0x100u :
                         width == 4u ? 0x10000u : 0x100000000ULL;
    if (value < minimum) return std::nullopt;
    return std::pair{major, value};
}

std::optional<CborValue> parse_value(std::span<const std::uint8_t> bytes,
                                     std::size_t& cursor, std::size_t depth) {
    if (depth > 128u) return std::nullopt;
    const auto start = cursor;
    const auto head = parse_head(bytes, cursor);
    if (!head) return std::nullopt;
    CborValue result;
    result.kind = static_cast<CborKind>(head->first);
    result.integer = head->second;
    if (result.kind == CborKind::Uint) {
        // nothing
    } else if (result.kind == CborKind::Bytes || result.kind == CborKind::Text) {
        if (head->second > bytes.size() - cursor) return std::nullopt;
        const auto end = cursor + static_cast<std::size_t>(head->second);
        result.string.assign(bytes.begin() + static_cast<std::ptrdiff_t>(cursor),
                             bytes.begin() + static_cast<std::ptrdiff_t>(end));
        if (result.kind == CborKind::Text && !valid_utf8(result.string)) return std::nullopt;
        cursor = end;
    } else {
        if (head->second > 200000u) return std::nullopt;
        result.children.reserve(static_cast<std::size_t>(head->second));
        for (std::uint64_t index = 0; index < head->second; ++index) {
            auto child = parse_value(bytes, cursor, depth + 1u);
            if (!child) return std::nullopt;
            result.children.push_back(std::move(*child));
        }
    }
    result.raw.assign(bytes.begin() + static_cast<std::ptrdiff_t>(start),
                      bytes.begin() + static_cast<std::ptrdiff_t>(cursor));
    return result;
}

void encode_value(Bytes& output, const CborValue& value) {
    if (value.kind == CborKind::Uint) cbor_uint(output, value.integer);
    else if (value.kind == CborKind::Bytes) cbor_bytes(output, value.string);
    else if (value.kind == CborKind::Text) {
        cbor_head(output, 3u, value.string.size());
        output.insert(output.end(), value.string.begin(), value.string.end());
    } else if (value.kind == CborKind::Array) {
        cbor_array(output, value.children.size());
        for (const auto& child : value.children) encode_value(output, child);
    } else {
        throw std::logic_error("unknown CBOR node");
    }
}

std::optional<CborValue> parse_canonical_cbor(const Bytes& bytes) {
    std::size_t cursor = 0;
    auto value = parse_value(bytes, cursor, 0u);
    if (!value || cursor != bytes.size()) return std::nullopt;
    Bytes reencoded;
    encode_value(reencoded, *value);
    if (reencoded != bytes) return std::nullopt;
    return value;
}

bool cbor_uint_equals(const CborValue& value, std::uint64_t expected) {
    return value.kind == CborKind::Uint && value.integer == expected;
}

bool cbor_bytes_equal(const CborValue& value, const Bytes& expected) {
    return value.kind == CborKind::Bytes && value.string == expected;
}

bool cbor_text_equals(const CborValue& value, std::string_view expected) {
    return value.kind == CborKind::Text &&
           value.string == Bytes(expected.begin(), expected.end());
}

bool promote(FileDescriptor& file) {
    if (file.descriptor >= 3) return true;
    const int duplicate = fcntl(file.descriptor, F_DUPFD_CLOEXEC, 3);
    if (duplicate < 0) return false;
    close(file.descriptor);
    file.descriptor = duplicate;
    return true;
}

std::optional<PinnedFile> open_regular(std::string_view path, std::uint64_t expected_length,
                                       const Digest& expected_digest, bool retain_fd,
                                       std::uint64_t maximum_length = kMaximumPinnedFileBytes) {
    const std::string native_path(path);
    FileDescriptor file(open(native_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (file.descriptor < 0 || !promote(file)) return std::nullopt;
    struct stat status {};
    if (fstat(file.descriptor, &status) != 0 || !S_ISREG(status.st_mode) || status.st_size < 0 ||
        static_cast<std::uint64_t>(status.st_size) != expected_length ||
        expected_length > maximum_length) {
        return std::nullopt;
    }
    Bytes bytes;
    bytes.reserve(static_cast<std::size_t>(expected_length));
    std::array<std::uint8_t, 4096u> buffer{};
    for (;;) {
        const auto count = read(file.descriptor, buffer.data(), buffer.size());
        if (count == 0) break;
        if (count < 0) {
            if (errno == EINTR) continue;
            return std::nullopt;
        }
        if (bytes.size() > expected_length - static_cast<std::size_t>(count)) return std::nullopt;
        bytes.insert(bytes.end(), buffer.begin(), buffer.begin() + count);
    }
    if (bytes.size() != expected_length || sha256(bytes) != expected_digest) return std::nullopt;
    if (lseek(file.descriptor, 0, SEEK_SET) != 0) return std::nullopt;
    PinnedFile result{std::move(file), expected_length, expected_digest, std::move(bytes)};
    if (!retain_fd) result.descriptor = FileDescriptor{};
    return result;
}

std::optional<PinnedFile> open_self() {
    FileDescriptor file(open("/proc/self/exe", O_RDONLY | O_CLOEXEC));
    if (file.descriptor < 0 || !promote(file)) return std::nullopt;
    struct stat status {};
    if (fstat(file.descriptor, &status) != 0 || !S_ISREG(status.st_mode) || status.st_size < 0 ||
        static_cast<std::uint64_t>(status.st_size) > kMaximumSelfBytes) return std::nullopt;
    const auto length = static_cast<std::uint64_t>(status.st_size);
    Bytes bytes;
    bytes.reserve(static_cast<std::size_t>(length));
    std::array<std::uint8_t, 4096u> buffer{};
    for (;;) {
        const auto count = read(file.descriptor, buffer.data(), buffer.size());
        if (count == 0) break;
        if (count < 0) {
            if (errno == EINTR) continue;
            return std::nullopt;
        }
        bytes.insert(bytes.end(), buffer.begin(), buffer.begin() + count);
    }
    if (bytes.size() != length || lseek(file.descriptor, 0, SEEK_SET) != 0) return std::nullopt;
    return PinnedFile{std::move(file), length, sha256(bytes), std::move(bytes)};
}

std::optional<Bytes> read_raw_collector(std::string_view path) {
    const auto digest = decode_hex_digest(V631302_RELAXED_RAW_COLLECTOR_SHA256);
    if (!digest || V631302_RELAXED_RAW_COLLECTOR_SIZE == 0u ||
        V631302_RELAXED_RAW_COLLECTOR_SIZE > kMaximumCapturedRawCollectorBytes) {
        return std::nullopt;
    }
    auto raw = open_regular(path, V631302_RELAXED_RAW_COLLECTOR_SIZE, *digest, false,
                            kMaximumCapturedRawCollectorBytes);
    if (!raw || !parse_canonical_cbor(raw->bytes)) return std::nullopt;
    return std::move(raw->bytes);
}

void append_u64(Bytes& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) output.push_back(value >> shift);
}

Bytes make_interpreter_pin(const PinnedFile& interpreter) {
    Bytes value;
    cbor_array(value, 7u);
    cbor_uint(value, 1u);
    cbor_uint(value, 1u);
    cbor_uint(value, V631302_RELAXED_PYTHON_VERSION_HEX);
    cbor_text(value, V631302_RELAXED_PYTHON_CACHE_TAG);
    cbor_text(value, V631302_RELAXED_PYTHON_ABI_FLAGS);
    cbor_uint(value, interpreter.length);
    cbor_bytes(value, digest_bytes(interpreter.digest));
    return value;
}

Bytes make_manifest(const std::array<PinnedFile, 4u>& bundle) {
    constexpr std::array<std::string_view, 4u> paths = {
        "evaluation_v6_3_1/__init__.py", "evaluation_v6_3_1/m0_diagnostic_census.py",
        "evaluation_v6_3_1/m0_diagnostic_primitives.py", "worker/v631302_diagnostic_worker_v1.py"};
    Bytes files;
    cbor_array(files, paths.size());
    for (std::size_t index = 0; index < paths.size(); ++index) {
        cbor_array(files, 3u);
        cbor_text(files, paths[index]);
        cbor_uint(files, bundle[index].length);
        cbor_bytes(files, digest_bytes(bundle[index].digest));
    }
    Bytes manifest;
    cbor_array(manifest, 3u);
    cbor_uint(manifest, 1u);
    cbor_text(manifest, kEntryPath);
    manifest.insert(manifest.end(), files.begin(), files.end());
    return manifest;
}

Bytes make_bundle_bytes(const std::array<PinnedFile, 4u>& bundle) {
    constexpr std::array<std::string_view, 4u> paths = {
        "evaluation_v6_3_1/__init__.py", "evaluation_v6_3_1/m0_diagnostic_census.py",
        "evaluation_v6_3_1/m0_diagnostic_primitives.py", "worker/v631302_diagnostic_worker_v1.py"};
    Bytes value;
    cbor_array(value, paths.size());
    for (std::size_t index = 0; index < paths.size(); ++index) {
        cbor_array(value, 2u);
        cbor_text(value, paths[index]);
        cbor_bytes(value, bundle[index].bytes);
    }
    return value;
}

Bytes make_bundle_root(const Bytes& manifest) {
    Bytes preimage;
    cbor_array(preimage, 5u);
    cbor_bytes(preimage, text_bytes(kBundleDomain));
    cbor_uint(preimage, 631302u);
    cbor_uint(preimage, 1u);
    cbor_uint(preimage, 1u);
    preimage.insert(preimage.end(), manifest.begin(), manifest.end());
    return digest_bytes(sha256(preimage));
}

Bytes make_execution_profile(const PinnedFile& interpreter, const PinnedFile& worker) {
    Bytes value;
    cbor_array(value, 8u);
    cbor_uint(value, 1u);
    const auto pin = make_interpreter_pin(interpreter);
    value.insert(value.end(), pin.begin(), pin.end());
    cbor_text(value, kWorkerPath);
    cbor_bytes(value, digest_bytes(worker.digest));
    cbor_uint(value, 1u);
    cbor_uint(value, 1u);
    cbor_uint(value, 1u);
    cbor_uint(value, 1u);
    return value;
}

Bytes make_profile(const PinnedFile& self, const PinnedFile& clang, const PinnedFile& interpreter,
                   const std::array<PinnedFile, 4u>& bundle) {
    const auto manifest = make_manifest(bundle);
    const auto execution = make_execution_profile(interpreter, bundle[3]);
    const auto root = make_bundle_root(manifest);
    Bytes value;
    cbor_array(value, 8u);
    cbor_bytes(value, digest_bytes(self.digest));
    cbor_text(value, V631302_RELAXED_BUILD_ID);
    cbor_bytes(value, digest_bytes(clang.digest));
    cbor_uint(value, 16u);
    cbor_uint(value, 1u);
    value.insert(value.end(), execution.begin(), execution.end());
    cbor_bytes(value, root);
    value.insert(value.end(), manifest.begin(), manifest.end());
    return value;
}

bool verify_prelaunch_profile(const PreparedInput& prepared) {
    const auto profile = parse_canonical_cbor(prepared.profile);
    const auto expected_bundle_root = decode_hex_digest(kBundleRootHex);
    const auto expected_manifest_digest = decode_hex_digest(kManifestDigestHex);
    if (!profile || !expected_bundle_root || !expected_manifest_digest ||
        profile->kind != CborKind::Array || profile->children.size() != 8u) {
        return false;
    }
    const auto manifest = make_manifest(prepared.bundle);
    const auto execution = make_execution_profile(prepared.interpreter, prepared.bundle[3]);
    const auto bundle_root = make_bundle_root(manifest);
    return manifest.size() == kManifestLength && sha256(manifest) == *expected_manifest_digest &&
           bundle_root == digest_bytes(*expected_bundle_root) &&
           cbor_bytes_equal(profile->children[0], digest_bytes(prepared.self.digest)) &&
           cbor_text_equals(profile->children[1], V631302_RELAXED_BUILD_ID) &&
           cbor_bytes_equal(profile->children[2], digest_bytes(prepared.clang.digest)) &&
           cbor_uint_equals(profile->children[3], 16u) &&
           cbor_uint_equals(profile->children[4], 1u) &&
           profile->children[5].raw == execution &&
           cbor_bytes_equal(profile->children[6], bundle_root) &&
           profile->children[7].raw == manifest;
}

std::size_t cbor_head_size(std::uint64_t argument) {
    if (argument < 24u) return 1u;
    if (argument <= 0xffu) return 2u;
    if (argument <= 0xffffu) return 3u;
    if (argument <= 0xffffffffu) return 5u;
    return 9u;
}

bool checked_add(std::uint64_t& total, std::uint64_t value, std::uint64_t limit) {
    if (value > limit || total > limit - value) return false;
    total += value;
    return true;
}

std::optional<Bytes> make_input_frame(const Bytes& profile,
                                      const std::array<PinnedFile, 4u>& bundle,
                                      const Bytes& raw_collector) {
    if (raw_collector.size() > kMaximumCapturedRawCollectorBytes ||
        raw_collector.size() > kMaximumRawTransportBytes) {
        return std::nullopt;
    }
    const auto bundle_bytes = make_bundle_bytes(bundle);
    std::uint64_t payload_length = 0;
    if (!checked_add(payload_length, 1u, kMaximumInputPayloadBytes) ||
        !checked_add(payload_length, cbor_head_size(631302u) + 1u,
                     kMaximumInputPayloadBytes) ||
        !checked_add(payload_length, profile.size(), kMaximumInputPayloadBytes) ||
        !checked_add(payload_length, bundle_bytes.size(), kMaximumInputPayloadBytes) ||
        !checked_add(payload_length, cbor_head_size(raw_collector.size()),
                     kMaximumInputPayloadBytes) ||
        !checked_add(payload_length, raw_collector.size(), kMaximumInputPayloadBytes) ||
        payload_length > std::numeric_limits<std::size_t>::max() - kFrameHeaderBytes) {
        return std::nullopt;
    }
    Bytes input;
    input.reserve(static_cast<std::size_t>(payload_length));
    cbor_array(input, 5u);
    cbor_uint(input, 631302u);
    cbor_uint(input, 1u);
    input.insert(input.end(), profile.begin(), profile.end());
    input.insert(input.end(), bundle_bytes.begin(), bundle_bytes.end());
    cbor_bytes(input, raw_collector);
    if (input.size() != payload_length) return std::nullopt;
    Bytes frame(kInputMagic.begin(), kInputMagic.end());
    frame.reserve(kFrameHeaderBytes + input.size());
    append_u64(frame, input.size());
    frame.insert(frame.end(), input.begin(), input.end());
    return frame;
}

std::optional<Bytes> parse_frame(const Bytes& frame, std::string_view magic,
                                 std::uint64_t payload_limit) {
    if (frame.size() < magic.size() + 8u ||
        !std::equal(magic.begin(), magic.end(), frame.begin())) return std::nullopt;
    std::uint64_t length = 0;
    for (std::size_t index = 0; index < 8u; ++index) length = (length << 8u) | frame[magic.size() + index];
    const auto header = magic.size() + 8u;
    if (length > payload_limit || length != frame.size() - header) return std::nullopt;
    return Bytes(frame.begin() + static_cast<std::ptrdiff_t>(header), frame.end());
}

bool close_except_standard_and_interpreter(int interpreter) {
#ifdef SYS_close_range
    const auto close_range = [](unsigned int first, unsigned int last) {
        return syscall(SYS_close_range, first, last, 0u) == 0;
    };
    const bool lower = interpreter == 3 || close_range(3u, static_cast<unsigned int>(interpreter - 1));
    const bool upper = interpreter == std::numeric_limits<int>::max() ||
                       close_range(static_cast<unsigned int>(interpreter + 1),
                                   std::numeric_limits<unsigned int>::max());
    if (lower && upper) return true;
#endif
    const auto maximum = sysconf(_SC_OPEN_MAX);
    if (maximum < 3) return false;
    for (long descriptor = 3; descriptor < maximum; ++descriptor) {
        if (descriptor != interpreter) close(static_cast<int>(descriptor));
    }
    return true;
}

[[noreturn]] void relaxed_child_exec(int input, int output, int error, int interpreter,
                                     const Bytes& worker_source) {
    if (interpreter <= STDERR_FILENO || dup2(input, STDIN_FILENO) < 0 ||
        dup2(output, STDOUT_FILENO) < 0 || dup2(error, STDERR_FILENO) < 0 || chdir("/") != 0) {
        _exit(127);
    }
    umask(0077);
    if (!close_except_standard_and_interpreter(interpreter)) _exit(127);

    // The sole intentional divergence from strict: preserve only the already
    // pinned interpreter descriptor through exec for the emulation fixture.
    const int descriptor_flags = fcntl(interpreter, F_GETFD);
    if (descriptor_flags < 0 || fcntl(interpreter, F_SETFD, descriptor_flags & ~FD_CLOEXEC) != 0) {
        _exit(127);
    }
    std::string worker(worker_source.begin(), worker_source.end());
    char argv0[] = "v631302-canonicalizer";
    char arg1[] = "-I";
    char arg2[] = "-S";
    char arg3[] = "-E";
    char arg4[] = "-s";
    char arg5[] = "-P";
    char arg6[] = "-B";
    char arg7[] = "-u";
    char arg8[] = "-X";
    char arg9[] = "utf8";
    char argc[] = "-c";
    char arg12[] = "V631302_DIAGNOSTIC_WORKER_V1";
    char arg13[] = "worker/v631302_diagnostic_worker_v1.py";
    char* argv[] = {argv0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, argc,
                    worker.data(), arg12, arg13, nullptr};
    char* environment[] = {nullptr};
#ifdef SYS_execveat
    syscall(SYS_execveat, interpreter, "", argv, environment, AT_EMPTY_PATH);
#endif
    _exit(127);
}

bool set_nonblocking(int descriptor) {
    const int flags = fcntl(descriptor, F_GETFL);
    return flags >= 0 && fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0;
}

std::optional<int> kill_and_reap(pid_t child) {
    if (kill(child, SIGKILL) != 0 && errno != ESRCH) {
        return std::nullopt;
    }
    int status = 0;
    for (;;) {
        if (waitpid(child, &status, 0) == child) return status;
        if (errno != EINTR) return std::nullopt;
    }
}

struct SigpipeGuard final {
    SigpipeGuard() {
        struct sigaction ignored {};
        ignored.sa_handler = SIG_IGN;
        sigemptyset(&ignored.sa_mask);
        ignored.sa_flags = 0;
        active = sigaction(SIGPIPE, &ignored, &previous) == 0;
    }
    ~SigpipeGuard() {
        if (active) sigaction(SIGPIPE, &previous, nullptr);
    }
    SigpipeGuard(const SigpipeGuard&) = delete;
    SigpipeGuard& operator=(const SigpipeGuard&) = delete;
    struct sigaction previous {};
    bool active = false;
};

std::optional<ProcessOutput> launch_until(
    std::chrono::steady_clock::time_point monotonic_deadline,
    PinnedFile interpreter,
    const Bytes& worker,
    const Bytes& input) {
    if (interpreter.descriptor.descriptor <= STDERR_FILENO ||
        input.size() > kMaximumInputPayloadBytes + kFrameHeaderBytes) {
        return std::nullopt;
    }
    const int inherited_fd = interpreter.descriptor.descriptor;
    int input_pipe[2] = {-1, -1};
    int output_pipe[2] = {-1, -1};
    int error_pipe[2] = {-1, -1};
    if (pipe2(input_pipe, O_CLOEXEC) != 0 || pipe2(output_pipe, O_CLOEXEC) != 0 ||
        pipe2(error_pipe, O_CLOEXEC) != 0) return std::nullopt;
    FileDescriptor input_read(input_pipe[0]);
    FileDescriptor input_write(input_pipe[1]);
    FileDescriptor output_read(output_pipe[0]);
    FileDescriptor output_write(output_pipe[1]);
    FileDescriptor error_read(error_pipe[0]);
    FileDescriptor error_write(error_pipe[1]);
    const pid_t child = fork();
    if (child < 0) return std::nullopt;
    if (child == 0) {
        relaxed_child_exec(input_read.release(), output_write.release(), error_write.release(),
                           interpreter.descriptor.release(), worker);
    }
    input_read = FileDescriptor{};
    output_write = FileDescriptor{};
    error_write = FileDescriptor{};
    if (!set_nonblocking(input_write.descriptor) || !set_nonblocking(output_read.descriptor) ||
        !set_nonblocking(error_read.descriptor)) {
        kill_and_reap(child);
        return std::nullopt;
    }
    SigpipeGuard sigpipe;
    if (!sigpipe.active) {
        kill_and_reap(child);
        return std::nullopt;
    }
    ProcessOutput result;
    result.inherited_interpreter_fd = inherited_fd;
    std::size_t written = 0;
    bool input_open = true;
    bool output_open = true;
    bool error_open = true;
    const auto consume_stdout = [](int descriptor, Bytes& destination, bool& open) -> bool {
        std::array<std::uint8_t, 4096u> buffer{};
        for (;;) {
            const auto count = read(descriptor, buffer.data(), buffer.size());
            if (count > 0) {
                constexpr auto kMaximumOutputFrameBytes =
                    kMaximumCandidateBytes + static_cast<std::uint64_t>(kFrameHeaderBytes);
                if (static_cast<std::uint64_t>(count) > kMaximumOutputFrameBytes ||
                    destination.size() >
                        kMaximumOutputFrameBytes - static_cast<std::uint64_t>(count)) {
                    return false;
                }
                destination.insert(destination.end(), buffer.begin(), buffer.begin() + count);
            } else if (count == 0) {
                open = false;
                return true;
            } else if (errno != EINTR) {
                return errno == EAGAIN || errno == EWOULDBLOCK;
            }
        }
    };
    const auto consume_stderr = [](int descriptor, bool& open) -> bool {
        std::array<std::uint8_t, 1u> byte{};
        static_assert(kMaximumStderrBytes >= byte.size());
        for (;;) {
            const auto count = read(descriptor, byte.data(), byte.size());
            if (count > 0) return false;
            if (count == 0) {
                open = false;
                return true;
            }
            if (errno == EINTR) continue;
            return errno == EAGAIN || errno == EWOULDBLOCK;
        }
    };
    while (input_open || output_open || error_open) {
        if (std::chrono::steady_clock::now() >= monotonic_deadline) {
            const auto status = kill_and_reap(child);
            if (!status) return std::nullopt;
            result.status = *status;
            result.timed_out = true;
            return result;
        }
        std::array<pollfd, 3u> descriptors{};
        nfds_t count = 0;
        std::optional<std::size_t> input_index;
        std::optional<std::size_t> output_index;
        std::optional<std::size_t> error_index;
        if (input_open) {
            input_index = count;
            descriptors[count++] = pollfd{input_write.descriptor, POLLOUT, 0};
        }
        if (output_open) {
            output_index = count;
            descriptors[count++] = pollfd{output_read.descriptor, POLLIN | POLLHUP, 0};
        }
        if (error_open) {
            error_index = count;
            descriptors[count++] = pollfd{error_read.descriptor, POLLIN | POLLHUP, 0};
        }
        const auto poll_status = poll(descriptors.data(), count, 100);
        if (poll_status < 0) {
            if (errno == EINTR) continue;
            kill_and_reap(child);
            return std::nullopt;
        }

        if (error_index) {
            const auto events = descriptors[*error_index].revents;
            if ((events & POLLNVAL) != 0 ||
                ((events & (POLLIN | POLLHUP | POLLERR)) != 0 &&
                 !consume_stderr(error_read.descriptor, error_open))) {
                kill_and_reap(child);
                return std::nullopt;
            }
        }
        if (output_index) {
            const auto events = descriptors[*output_index].revents;
            if ((events & POLLNVAL) != 0 ||
                ((events & (POLLIN | POLLHUP | POLLERR)) != 0 &&
                 !consume_stdout(output_read.descriptor, result.stdout_bytes, output_open))) {
                kill_and_reap(child);
                return std::nullopt;
            }
        }
        if (input_index) {
            const auto events = descriptors[*input_index].revents;
            if ((events & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                kill_and_reap(child);
                return std::nullopt;
            }
            if ((events & POLLOUT) != 0) {
                const auto count_written =
                    write(input_write.descriptor, input.data() + written, input.size() - written);
                if (count_written > 0) {
                    written += static_cast<std::size_t>(count_written);
                    if (written == input.size()) {
                        input_write = FileDescriptor{};
                        input_open = false;
                    }
                } else if (count_written < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    kill_and_reap(child);
                    return std::nullopt;
                }
            }
        }
    }
    for (;;) {
        const auto waited = waitpid(child, &result.status, WNOHANG);
        if (waited == child) break;
        if (waited < 0) {
            if (errno == EINTR) continue;
            return std::nullopt;
        }
        if (std::chrono::steady_clock::now() >= monotonic_deadline) {
            const auto status = kill_and_reap(child);
            if (!status) return std::nullopt;
            result.status = *status;
            result.timed_out = true;
            return result;
        }
        if (poll(nullptr, 0, 10) < 0 && errno != EINTR) {
            kill_and_reap(child);
            return std::nullopt;
        }
    }
    return result;
}

std::optional<ProcessOutput> launch_relaxed_worker(PinnedFile interpreter, const Bytes& worker,
                                                    const Bytes& input) {
    auto result = launch_until(
        std::chrono::steady_clock::now() + std::chrono::milliseconds(300000),
        std::move(interpreter), worker, input);
    if (!result || result->timed_out) return std::nullopt;
    return result;
}

bool verify_candidate(const Bytes& candidate, const Bytes& expected_profile) {
    const auto value = parse_canonical_cbor(candidate);
    if (!value || value->kind != CborKind::Array || value->children.size() != 9u ||
        value->children[0].kind != CborKind::Uint || value->children[0].integer != 631302u ||
        value->children[1].kind != CborKind::Uint || value->children[1].integer != 1u ||
        value->children[2].kind != CborKind::Array ||
        value->children[2].children.size() != 8u ||
        value->children[2].raw != expected_profile ||
        value->children[3].kind != CborKind::Array ||
        value->children[3].children.size() != 3u ||
        value->children[4].kind != CborKind::Array ||
        value->children[4].children.size() != 4u) {
        return false;
    }
    return std::all_of(value->children.begin() + 5, value->children.end(),
                       [](const CborValue& field) { return field.kind == CborKind::Array; });
}

Bytes make_wrapper(const PinnedFile& self, int inherited_fd, const Bytes& candidate) {
    Bytes wrapper;
    cbor_array(wrapper, 6u);
    cbor_uint(wrapper, 631302u);
    cbor_uint(wrapper, 1u);
    cbor_text(wrapper, kWrapperLabel);
    cbor_bytes(wrapper, digest_bytes(self.digest));
    cbor_uint(wrapper, static_cast<std::uint64_t>(inherited_fd));
    cbor_bytes(wrapper, candidate);
    return wrapper;
}

std::optional<PreparedInput> prepare(std::string_view raw_collector_path) {
    const auto interpreter_digest = decode_hex_digest(V631302_RELAXED_INTERPRETER_SHA256);
    const auto clang_digest = decode_hex_digest(V631302_RELAXED_CLANG_SHA256);
    const auto capture_root = decode_hex_digest(V631302_RELAXED_RAW_COLLECTOR_CAPTURE_ROOT);
    const std::array<BundleMember, 4u> members = {{
        {"evaluation_v6_3_1/__init__.py", V631302_RELAXED_BUNDLE_INIT_PATH,
         V631302_RELAXED_INIT_SIZE, V631302_RELAXED_INIT_SHA256},
        {"evaluation_v6_3_1/m0_diagnostic_census.py", V631302_RELAXED_BUNDLE_ENTRY_PATH,
         V631302_RELAXED_ENTRY_SIZE, V631302_RELAXED_ENTRY_SHA256},
        {"evaluation_v6_3_1/m0_diagnostic_primitives.py", V631302_RELAXED_BUNDLE_PRIMITIVES_PATH,
         V631302_RELAXED_PRIMITIVES_SIZE, V631302_RELAXED_PRIMITIVES_SHA256},
        {"worker/v631302_diagnostic_worker_v1.py", V631302_RELAXED_BUNDLE_WORKER_PATH,
         V631302_RELAXED_WORKER_SIZE, V631302_RELAXED_WORKER_SHA256},
    }};
    if (!interpreter_digest || !clang_digest || !capture_root ||
        std::all_of(capture_root->begin(), capture_root->end(),
                    [](std::uint8_t value) { return value == 0u; }) ||
        members[0].expected_length != 0u) {
        return std::nullopt;
    }
    auto self = open_self();
    auto clang = open_regular(V631302_RELAXED_PINNED_CLANG_PATH, V631302_RELAXED_CLANG_SIZE,
                              *clang_digest, false);
    auto interpreter = open_regular(V631302_RELAXED_PINNED_INTERPRETER_PATH,
                                    V631302_RELAXED_INTERPRETER_SIZE, *interpreter_digest, true);
    if (!self || !clang || !interpreter) return std::nullopt;
    std::array<PinnedFile, 4u> bundle;
    for (std::size_t index = 0; index < members.size(); ++index) {
        const auto digest = decode_hex_digest(members[index].expected_digest);
        if (!digest) return std::nullopt;
        auto member = open_regular(members[index].physical_path, members[index].expected_length,
                                   *digest, false);
        if (!member) return std::nullopt;
        bundle[index] = std::move(*member);
    }
    const auto raw_collector = read_raw_collector(raw_collector_path);
    if (!raw_collector) return std::nullopt;
    PreparedInput result{std::move(*self), std::move(*clang), std::move(*interpreter),
                         std::move(bundle), {}, {}};
    result.profile = make_profile(result.self, result.clang, result.interpreter, result.bundle);
    if (!verify_prelaunch_profile(result)) return std::nullopt;
    auto input_frame = make_input_frame(result.profile, result.bundle, *raw_collector);
    if (!input_frame || !parse_frame(*input_frame, kInputMagic, kMaximumInputPayloadBytes)) {
        return std::nullopt;
    }
    result.input_frame = std::move(*input_frame);
    return result;
}

}  // namespace

bool run_relaxed_fixture(const char* raw_collector_path, std::vector<std::uint8_t>* wrapper) {
    if (raw_collector_path == nullptr || wrapper == nullptr || raw_collector_path[0] == '\0') return false;
    auto prepared = prepare(raw_collector_path);
    if (!prepared) return false;
    const auto process = launch_relaxed_worker(std::move(prepared->interpreter),
                                               prepared->bundle[3].bytes, prepared->input_frame);
    if (!process || !WIFEXITED(process->status) || WEXITSTATUS(process->status) != 0 ||
        !process->stderr_bytes.empty() || process->inherited_interpreter_fd <= STDERR_FILENO) return false;
    const auto candidate = parse_frame(process->stdout_bytes, kOutputMagic, kMaximumCandidateBytes);
    const bool candidate_valid = candidate && verify_candidate(*candidate, prepared->profile);
    if (!candidate_valid) return false;
    *wrapper = make_wrapper(prepared->self, process->inherited_interpreter_fd, *candidate);
    return parse_canonical_cbor(*wrapper).has_value();
}

}  // namespace evaluation_v6_3_1::m0_diagnostic_relaxed
