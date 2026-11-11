#include "ExecutionOrigin.h"

#include "ExecutionOriginBuildConfig.h"

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

namespace evaluation_v6_3_1::m0_diagnostic {
namespace {

constexpr std::size_t kDigestBytes = 32u;
constexpr std::size_t kMaximumWorkerBytes = 65535u;
constexpr std::size_t kMaximumFrameBytes = 4u * 1024u * 1024u;
constexpr std::chrono::seconds kWorkerTimeout(5);
constexpr std::string_view kInputMagic = "V631DI01";
constexpr std::string_view kOutputMagic = "V631DO01";
constexpr std::string_view kLogicalWorkerPath = "worker/v631302_diagnostic_worker_v1.py";

using Bytes = std::vector<std::uint8_t>;
using Digest = std::array<std::uint8_t, kDigestBytes>;

struct FileDescriptor final {
    explicit FileDescriptor(int value = -1) : value(value) {}
    ~FileDescriptor() {
        if (value >= 0) {
            close(value);
        }
    }
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    FileDescriptor(FileDescriptor&& other) noexcept : value(std::exchange(other.value, -1)) {}
    FileDescriptor& operator=(FileDescriptor&& other) noexcept {
        if (this != &other) {
            if (value >= 0) {
                close(value);
            }
            value = std::exchange(other.value, -1);
        }
        return *this;
    }
    int release() noexcept { return std::exchange(value, -1); }
    int value;
};

struct PinnedFile {
    FileDescriptor descriptor;
    std::uint64_t byte_length = 0;
    Digest digest{};
};

struct ProcessOutput {
    Bytes stdout_bytes;
    Bytes stderr_bytes;
    int status = -1;
};

enum class CborKind : std::uint8_t { kUint = 0u, kBytes = 2u, kText = 3u, kArray = 4u };

struct CborValue {
    CborKind kind = CborKind::kUint;
    std::uint64_t integer = 0;
    Bytes string;
    std::vector<CborValue> children;
    Bytes raw;
};

struct PrelaunchProfile {
    PinnedFile collector;
    PinnedFile clang;
    PinnedFile interpreter;
    Bytes worker;
    Bytes worker_digest;
    Bytes execution_profile;
    Bytes bundle_root;
    Bytes bundle_manifest;
    Bytes profile;
    Bytes bundle_file_bytes;
};

Bytes byte_string(const Digest& digest) {
    return Bytes(digest.begin(), digest.end());
}

Bytes byte_string(std::string_view value) {
    return Bytes(value.begin(), value.end());
}

Digest digest_bytes(const Bytes& bytes) {
    llvm::SHA256 hasher;
    hasher.update(llvm::ArrayRef<std::uint8_t>(bytes.data(), bytes.size()));
    return hasher.final();
}

void append_cbor_head(Bytes& output, std::uint8_t major, std::uint64_t argument) {
    if (major != 0u && major != 2u && major != 3u && major != 4u) {
        throw std::logic_error("unsupported diagnostic CBOR major type");
    }
    if (argument < 24u) {
        output.push_back(static_cast<std::uint8_t>((major << 5u) | argument));
    } else if (argument <= 0xFFu) {
        output.push_back(static_cast<std::uint8_t>((major << 5u) | 24u));
        output.push_back(static_cast<std::uint8_t>(argument));
    } else if (argument <= 0xFFFFu) {
        output.push_back(static_cast<std::uint8_t>((major << 5u) | 25u));
        output.push_back(static_cast<std::uint8_t>(argument >> 8u));
        output.push_back(static_cast<std::uint8_t>(argument));
    } else if (argument <= 0xFFFFFFFFu) {
        output.push_back(static_cast<std::uint8_t>((major << 5u) | 26u));
        for (int shift = 24; shift >= 0; shift -= 8) {
            output.push_back(static_cast<std::uint8_t>(argument >> shift));
        }
    } else {
        output.push_back(static_cast<std::uint8_t>((major << 5u) | 27u));
        for (int shift = 56; shift >= 0; shift -= 8) {
            output.push_back(static_cast<std::uint8_t>(argument >> shift));
        }
    }
}

void append_cbor_uint(Bytes& output, std::uint64_t value) {
    append_cbor_head(output, 0u, value);
}

void append_cbor_bytes(Bytes& output, const Bytes& value) {
    append_cbor_head(output, 2u, value.size());
    output.insert(output.end(), value.begin(), value.end());
}

bool valid_utf8(const Bytes& value) {
    std::size_t index = 0;
    while (index < value.size()) {
        const auto first = value[index++];
        if (first <= 0x7Fu) {
            continue;
        }
        std::size_t tail = 0;
        if (first >= 0xC2u && first <= 0xDFu) {
            tail = 1;
        } else if (first >= 0xE0u && first <= 0xEFu) {
            tail = 2;
        } else if (first >= 0xF0u && first <= 0xF4u) {
            tail = 3;
        } else {
            return false;
        }
        if (index + tail > value.size()) {
            return false;
        }
        for (std::size_t offset = 0; offset < tail; ++offset) {
            if ((value[index + offset] & 0xC0u) != 0x80u) {
                return false;
            }
        }
        index += tail;
    }
    return true;
}

void append_cbor_text(Bytes& output, std::string_view value) {
    const Bytes bytes = byte_string(value);
    if (!valid_utf8(bytes)) {
        throw std::logic_error("non-UTF-8 diagnostic text");
    }
    append_cbor_head(output, 3u, bytes.size());
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void append_cbor_array(Bytes& output, std::size_t count) {
    append_cbor_head(output, 4u, count);
}

void append_cbor_item(Bytes& output, const Bytes& item) {
    output.insert(output.end(), item.begin(), item.end());
}

std::optional<std::pair<std::uint8_t, std::uint64_t>> parse_cbor_head(
    std::span<const std::uint8_t> bytes, std::size_t& cursor) {
    if (cursor >= bytes.size()) {
        return std::nullopt;
    }
    const auto first = bytes[cursor++];
    const auto major = static_cast<std::uint8_t>(first >> 5u);
    const auto additional = static_cast<std::uint8_t>(first & 0x1Fu);
    if (major != 0u && major != 2u && major != 3u && major != 4u) {
        return std::nullopt;
    }
    std::size_t width = 0;
    if (additional < 24u) {
        return std::pair{major, static_cast<std::uint64_t>(additional)};
    }
    if (additional == 24u) {
        width = 1u;
    } else if (additional == 25u) {
        width = 2u;
    } else if (additional == 26u) {
        width = 4u;
    } else if (additional == 27u) {
        width = 8u;
    } else {
        return std::nullopt;
    }
    if (cursor > bytes.size() || bytes.size() - cursor < width) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < width; ++index) {
        value = (value << 8u) | bytes[cursor++];
    }
    const auto minimum = width == 1u ? 24u : width == 2u ? 0x100u :
                         width == 4u ? 0x10000u : 0x100000000ULL;
    if (value < minimum) {
        return std::nullopt;
    }
    return std::pair{major, value};
}

std::optional<CborValue> parse_cbor_item(std::span<const std::uint8_t> bytes,
                                          std::size_t& cursor, std::size_t depth) {
    if (depth > 128u) {
        return std::nullopt;
    }
    const std::size_t start = cursor;
    const auto head = parse_cbor_head(bytes, cursor);
    if (!head) {
        return std::nullopt;
    }
    CborValue result;
    result.kind = static_cast<CborKind>(head->first);
    result.integer = head->second;
    if (result.kind == CborKind::kUint) {
        result.raw.assign(bytes.begin() + static_cast<std::ptrdiff_t>(start),
                          bytes.begin() + static_cast<std::ptrdiff_t>(cursor));
        return result;
    }
    if (result.kind == CborKind::kBytes || result.kind == CborKind::kText) {
        if (head->second > bytes.size() - cursor) {
            return std::nullopt;
        }
        const auto end = cursor + static_cast<std::size_t>(head->second);
        result.string.assign(bytes.begin() + static_cast<std::ptrdiff_t>(cursor),
                             bytes.begin() + static_cast<std::ptrdiff_t>(end));
        if (result.kind == CborKind::kText && !valid_utf8(result.string)) {
            return std::nullopt;
        }
        cursor = end;
    } else {
        if (head->second > 65536u) {
            return std::nullopt;
        }
        result.children.reserve(static_cast<std::size_t>(head->second));
        for (std::uint64_t index = 0; index < head->second; ++index) {
            auto child = parse_cbor_item(bytes, cursor, depth + 1u);
            if (!child) {
                return std::nullopt;
            }
            result.children.push_back(std::move(*child));
        }
    }
    result.raw.assign(bytes.begin() + static_cast<std::ptrdiff_t>(start),
                      bytes.begin() + static_cast<std::ptrdiff_t>(cursor));
    return result;
}

void encode_cbor_value(Bytes& output, const CborValue& value) {
    switch (value.kind) {
        case CborKind::kUint:
            append_cbor_uint(output, value.integer);
            return;
        case CborKind::kBytes:
            append_cbor_bytes(output, value.string);
            return;
        case CborKind::kText:
            if (!valid_utf8(value.string)) {
                throw std::logic_error("invalid text in diagnostic value");
            }
            append_cbor_head(output, 3u, value.string.size());
            output.insert(output.end(), value.string.begin(), value.string.end());
            return;
        case CborKind::kArray:
            append_cbor_array(output, value.children.size());
            for (const auto& child : value.children) {
                encode_cbor_value(output, child);
            }
            return;
    }
    throw std::logic_error("unknown diagnostic CBOR kind");
}

std::optional<CborValue> parse_exact_canonical_cbor(const Bytes& bytes) {
    std::size_t cursor = 0;
    auto value = parse_cbor_item(bytes, cursor, 0u);
    if (!value || cursor != bytes.size()) {
        return std::nullopt;
    }
    Bytes encoded;
    encode_cbor_value(encoded, *value);
    if (encoded != bytes) {
        return std::nullopt;
    }
    return value;
}

bool promote_to_nonstandard_descriptor(FileDescriptor& descriptor) {
    if (descriptor.value >= 3) {
        return true;
    }
    const int duplicate = fcntl(descriptor.value, F_DUPFD_CLOEXEC, 3);
    if (duplicate < 0) {
        return false;
    }
    close(descriptor.value);
    descriptor.value = duplicate;
    return true;
}

std::optional<Digest> decode_digest(std::string_view hex) {
    if (hex.size() != kDigestBytes * 2u) {
        return std::nullopt;
    }
    const auto decode_nibble = [](char value) -> std::optional<std::uint8_t> {
        if (value >= '0' && value <= '9') {
            return static_cast<std::uint8_t>(value - '0');
        }
        if (value >= 'a' && value <= 'f') {
            return static_cast<std::uint8_t>(value - 'a' + 10);
        }
        return std::nullopt;
    };
    Digest result{};
    for (std::size_t index = 0; index < result.size(); ++index) {
        const auto high = decode_nibble(hex[index * 2u]);
        const auto low = decode_nibble(hex[index * 2u + 1u]);
        if (!high || !low) {
            return std::nullopt;
        }
        result[index] = static_cast<std::uint8_t>((*high << 4u) | *low);
    }
    return result;
}

std::optional<PinnedFile> open_and_hash_regular_executable(std::string_view pathname,
                                                            std::uint64_t expected_length,
                                                            const Digest& expected_digest) {
    const std::string path(pathname);
    FileDescriptor descriptor(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (descriptor.value < 0 || !promote_to_nonstandard_descriptor(descriptor)) {
        return std::nullopt;
    }
    struct stat status {};
    if (fstat(descriptor.value, &status) != 0 || !S_ISREG(status.st_mode) ||
        (status.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0 || status.st_size < 0 ||
        static_cast<std::uint64_t>(status.st_size) != expected_length) {
        return std::nullopt;
    }
    llvm::SHA256 hasher;
    std::array<std::uint8_t, 8192u> buffer{};
    std::uint64_t observed = 0;
    for (;;) {
        const auto count = read(descriptor.value, buffer.data(), buffer.size());
        if (count > 0) {
            observed += static_cast<std::uint64_t>(count);
            if (observed > expected_length) {
                return std::nullopt;
            }
            hasher.update(llvm::ArrayRef<std::uint8_t>(buffer.data(),
                                                        static_cast<std::size_t>(count)));
            continue;
        }
        if (count == 0) {
            break;
        }
        if (errno != EINTR) {
            return std::nullopt;
        }
    }
    const Digest digest = hasher.final();
    if (observed != expected_length || digest != expected_digest) {
        return std::nullopt;
    }
    return PinnedFile{std::move(descriptor), observed, digest};
}

std::optional<PinnedFile> open_and_hash_retained_executable(std::string_view pathname) {
    const std::string path(pathname);
    // /proc/self/exe is the kernel-provided identity of this running process,
    // not an attacker-selected filesystem link.  O_NOFOLLOW would reject that
    // mandatory procfs handle, so this function is intentionally private to
    // native self-identity; all configured pathname opens retain O_NOFOLLOW.
    FileDescriptor descriptor(open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (descriptor.value < 0 || !promote_to_nonstandard_descriptor(descriptor)) {
        return std::nullopt;
    }
    struct stat status {};
    if (fstat(descriptor.value, &status) != 0 || !S_ISREG(status.st_mode) ||
        (status.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0 || status.st_size < 0) {
        return std::nullopt;
    }
    llvm::SHA256 hasher;
    std::array<std::uint8_t, 8192u> buffer{};
    std::uint64_t observed = 0;
    for (;;) {
        const auto count = read(descriptor.value, buffer.data(), buffer.size());
        if (count > 0) {
            observed += static_cast<std::uint64_t>(count);
            hasher.update(llvm::ArrayRef<std::uint8_t>(buffer.data(),
                                                        static_cast<std::size_t>(count)));
            continue;
        }
        if (count == 0) {
            break;
        }
        if (errno != EINTR) {
            return std::nullopt;
        }
    }
    if (observed != static_cast<std::uint64_t>(status.st_size)) {
        return std::nullopt;
    }
    return PinnedFile{std::move(descriptor), observed, hasher.final()};
}

std::optional<Bytes> open_and_read_verified_worker(std::string_view pathname,
                                                    std::uint64_t expected_length,
                                                    const Digest& expected_digest) {
    if (expected_length == 0 || expected_length > kMaximumWorkerBytes) {
        return std::nullopt;
    }
    const std::string path(pathname);
    FileDescriptor descriptor(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (descriptor.value < 0 || !promote_to_nonstandard_descriptor(descriptor)) {
        return std::nullopt;
    }
    struct stat status {};
    if (fstat(descriptor.value, &status) != 0 || !S_ISREG(status.st_mode) || status.st_size < 0 ||
        static_cast<std::uint64_t>(status.st_size) != expected_length) {
        return std::nullopt;
    }
    Bytes bytes;
    bytes.reserve(static_cast<std::size_t>(expected_length));
    std::array<std::uint8_t, 4096u> buffer{};
    llvm::SHA256 hasher;
    for (;;) {
        const auto count = read(descriptor.value, buffer.data(), buffer.size());
        if (count > 0) {
            const auto size = static_cast<std::size_t>(count);
            if (bytes.size() > expected_length - size) {
                return std::nullopt;
            }
            bytes.insert(bytes.end(), buffer.begin(), buffer.begin() + size);
            hasher.update(llvm::ArrayRef<std::uint8_t>(buffer.data(), size));
            continue;
        }
        if (count == 0) {
            break;
        }
        if (errno != EINTR) {
            return std::nullopt;
        }
    }
    if (bytes.size() != expected_length || hasher.final() != expected_digest ||
        (bytes.size() >= 3u && bytes[0] == 0xEFu && bytes[1] == 0xBBu && bytes[2] == 0xBFu)) {
        return std::nullopt;
    }
    for (const auto value : bytes) {
        if (value == 0u || value > 0x7Fu || value == static_cast<std::uint8_t>('\r')) {
            return std::nullopt;
        }
    }
    return bytes;
}

void append_u64_be(Bytes& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

std::optional<Bytes> parse_exact_frame(const Bytes& bytes, std::string_view magic) {
    if (bytes.size() < magic.size() + sizeof(std::uint64_t) ||
        !std::equal(magic.begin(), magic.end(), bytes.begin())) {
        return std::nullopt;
    }
    std::uint64_t size = 0;
    for (std::size_t index = 0; index < sizeof(std::uint64_t); ++index) {
        size = (size << 8u) | bytes[magic.size() + index];
    }
    const auto header = magic.size() + sizeof(std::uint64_t);
    if (size > kMaximumFrameBytes || size != bytes.size() - header) {
        return std::nullopt;
    }
    return Bytes(bytes.begin() + static_cast<std::ptrdiff_t>(header), bytes.end());
}

bool set_nonblocking(int descriptor) {
    const auto flags = fcntl(descriptor, F_GETFL);
    return flags >= 0 && fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0;
}

bool close_everything_except_standard_and_interpreter(int interpreter_descriptor) {
#ifdef SYS_close_range
    const auto close_range = [](unsigned int first, unsigned int last) {
        return syscall(SYS_close_range, first, last, 0u) == 0;
    };
    const bool lower_closed = interpreter_descriptor == 3 ||
                              close_range(3u, static_cast<unsigned int>(interpreter_descriptor - 1));
    const bool upper_closed = interpreter_descriptor == std::numeric_limits<int>::max() ||
                              close_range(static_cast<unsigned int>(interpreter_descriptor + 1),
                                          std::numeric_limits<unsigned int>::max());
    if (lower_closed && upper_closed) {
        return true;
    }
#endif
    const auto maximum = sysconf(_SC_OPEN_MAX);
    if (maximum < 3) {
        return false;
    }
    for (long descriptor = 3; descriptor < maximum; ++descriptor) {
        if (descriptor != interpreter_descriptor) {
            close(static_cast<int>(descriptor));
        }
    }
    return true;
}

[[noreturn]] void child_exec(int input, int output, int error, int interpreter,
                             const Bytes& worker_source) {
    if (dup2(input, STDIN_FILENO) < 0 || dup2(output, STDOUT_FILENO) < 0 ||
        dup2(error, STDERR_FILENO) < 0 || chdir("/") != 0) {
        _exit(127);
    }
    umask(0077);
    // The retained interpreter descriptor was opened O_CLOEXEC.  fexecve uses
    // it to select the already verified ELF image, then the kernel closes it as
    // part of the successful exec transition.  Thus only descriptors 0, 1,
    // and 2 remain once the interpreter begins.
    if (!close_everything_except_standard_and_interpreter(interpreter)) {
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

std::optional<ProcessOutput> launch_worker(PinnedFile interpreter, const Bytes& worker,
                                           const Bytes& input) {
    int input_pipe[2] = {-1, -1};
    int output_pipe[2] = {-1, -1};
    int error_pipe[2] = {-1, -1};
    if (pipe2(input_pipe, O_CLOEXEC) != 0 || pipe2(output_pipe, O_CLOEXEC) != 0 ||
        pipe2(error_pipe, O_CLOEXEC) != 0) {
        return std::nullopt;
    }
    FileDescriptor input_read(input_pipe[0]);
    FileDescriptor input_write(input_pipe[1]);
    FileDescriptor output_read(output_pipe[0]);
    FileDescriptor output_write(output_pipe[1]);
    FileDescriptor error_read(error_pipe[0]);
    FileDescriptor error_write(error_pipe[1]);
    const pid_t child = fork();
    if (child < 0) {
        return std::nullopt;
    }
    if (child == 0) {
        child_exec(input_read.release(), output_write.release(), error_write.release(),
                   interpreter.descriptor.release(), worker);
    }
    input_read = FileDescriptor{};
    output_write = FileDescriptor{};
    error_write = FileDescriptor{};
    if (!set_nonblocking(input_write.value) || !set_nonblocking(output_read.value) ||
        !set_nonblocking(error_read.value)) {
        kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        return std::nullopt;
    }
    ProcessOutput result;
    std::size_t written = 0;
    bool input_open = true;
    bool output_open = true;
    bool error_open = true;
    const auto deadline = std::chrono::steady_clock::now() + kWorkerTimeout;
    const auto consume = [](int descriptor, Bytes& destination, bool& open) -> bool {
        std::array<std::uint8_t, 4096u> buffer{};
        for (;;) {
            const auto count = read(descriptor, buffer.data(), buffer.size());
            if (count > 0) {
                const auto size = static_cast<std::size_t>(count);
                if (destination.size() > kMaximumFrameBytes - size) {
                    return false;
                }
                destination.insert(destination.end(), buffer.begin(), buffer.begin() + size);
                continue;
            }
            if (count == 0) {
                open = false;
                return true;
            }
            if (errno == EINTR) {
                continue;
            }
            return errno == EAGAIN || errno == EWOULDBLOCK;
        }
    };
    while (input_open || output_open || error_open) {
        if (std::chrono::steady_clock::now() >= deadline) {
            kill(child, SIGKILL);
            waitpid(child, nullptr, 0);
            return std::nullopt;
        }
        std::array<pollfd, 3u> descriptors{};
        nfds_t count = 0;
        if (input_open) {
            descriptors[count++] = pollfd{input_write.value, POLLOUT, 0};
        }
        if (output_open) {
            descriptors[count++] = pollfd{output_read.value, POLLIN | POLLHUP, 0};
        }
        if (error_open) {
            descriptors[count++] = pollfd{error_read.value, POLLIN | POLLHUP, 0};
        }
        const auto polled = poll(descriptors.data(), count, 100);
        if (polled < 0 && errno != EINTR) {
            kill(child, SIGKILL);
            waitpid(child, nullptr, 0);
            return std::nullopt;
        }
        std::size_t index = 0;
        if (input_open) {
            const auto events = descriptors[index++].revents;
            if ((events & POLLOUT) != 0) {
                const auto count_written = write(input_write.value, input.data() + written,
                                                 input.size() - written);
                if (count_written > 0) {
                    written += static_cast<std::size_t>(count_written);
                    if (written == input.size()) {
                        input_write = FileDescriptor{};
                        input_open = false;
                    }
                } else if (count_written < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
                           errno != EINTR) {
                    kill(child, SIGKILL);
                    waitpid(child, nullptr, 0);
                    return std::nullopt;
                }
            }
        }
        if (output_open) {
            const auto events = descriptors[index++].revents;
            if ((events & (POLLIN | POLLHUP | POLLERR)) != 0 &&
                !consume(output_read.value, result.stdout_bytes, output_open)) {
                kill(child, SIGKILL);
                waitpid(child, nullptr, 0);
                return std::nullopt;
            }
        }
        if (error_open) {
            const auto events = descriptors[index++].revents;
            if ((events & (POLLIN | POLLHUP | POLLERR)) != 0 &&
                !consume(error_read.value, result.stderr_bytes, error_open)) {
                kill(child, SIGKILL);
                waitpid(child, nullptr, 0);
                return std::nullopt;
            }
        }
    }
    if (waitpid(child, &result.status, 0) != child) {
        return std::nullopt;
    }
    return result;
}

Bytes test_input_frame() {
    Bytes result(kInputMagic.begin(), kInputMagic.end());
    append_u64_be(result, 1u);
    result.push_back(0x80u);  // canonical CBOR empty array, opaque to this substrate.
    return result;
}

Bytes make_interpreter_pin(const PinnedFile& interpreter) {
    Bytes result;
    append_cbor_array(result, 7u);
    append_cbor_uint(result, 1u);  // CPYTHON
    append_cbor_uint(result, 1u);  // LINUX_PROC_SELF_EXE
    append_cbor_uint(result, V631302_M0_PINNED_PYTHON_VERSION_HEX);
    append_cbor_text(result, V631302_M0_PINNED_PYTHON_CACHE_TAG);
    append_cbor_text(result, V631302_M0_PINNED_PYTHON_ABI_FLAGS);
    append_cbor_uint(result, interpreter.byte_length);
    append_cbor_bytes(result, byte_string(interpreter.digest));
    return result;
}

Bytes make_execution_profile(const PinnedFile& interpreter, const Bytes& worker_digest) {
    Bytes result;
    append_cbor_array(result, 8u);
    append_cbor_uint(result, 1u);
    append_cbor_item(result, make_interpreter_pin(interpreter));
    append_cbor_text(result, kLogicalWorkerPath);
    append_cbor_bytes(result, worker_digest);
    append_cbor_uint(result, 1u);  // FRESH_FEXECVE_ARGV_V1
    append_cbor_uint(result, 1u);  // EMPTY_ENVIRONMENT_V1
    append_cbor_uint(result, 1u);  // VERIFIED_BUNDLE_IMPORT_V1
    append_cbor_uint(result, 1u);  // PIPE_CBOR_FRAME_V1
    return result;
}

Bytes make_bundle_manifest(const Bytes& worker, const Bytes& worker_digest) {
    Bytes file_row;
    append_cbor_array(file_row, 3u);
    append_cbor_text(file_row, kLogicalWorkerPath);
    append_cbor_uint(file_row, worker.size());
    append_cbor_bytes(file_row, worker_digest);

    Bytes files;
    append_cbor_array(files, 1u);
    append_cbor_item(files, file_row);

    Bytes result;
    append_cbor_array(result, 3u);
    append_cbor_uint(result, 1u);
    append_cbor_text(result, kLogicalWorkerPath);
    append_cbor_item(result, files);
    return result;
}

Bytes make_bundle_root(const Bytes& manifest) {
    Bytes preimage;
    append_cbor_array(preimage, 5u);
    append_cbor_bytes(preimage, byte_string("V631302_CANONICALIZER_BUNDLE_V1"));
    append_cbor_uint(preimage, 631302u);
    append_cbor_uint(preimage, 1u);
    append_cbor_uint(preimage, 1u);
    append_cbor_item(preimage, manifest);
    return byte_string(digest_bytes(preimage));
}

Bytes make_bundle_file_bytes(const Bytes& worker) {
    Bytes row;
    append_cbor_array(row, 2u);
    append_cbor_text(row, kLogicalWorkerPath);
    append_cbor_bytes(row, worker);
    Bytes result;
    append_cbor_array(result, 1u);
    append_cbor_item(result, row);
    return result;
}

Bytes make_prelaunch_profile(const PinnedFile& collector, const PinnedFile& clang,
                             const Bytes& execution_profile, const Bytes& bundle_root,
                             const Bytes& bundle_manifest) {
    Bytes result;
    append_cbor_array(result, 8u);
    append_cbor_bytes(result, byte_string(collector.digest));
    append_cbor_text(result, V631302_M0_COLLECTOR_BUILD_ID);
    append_cbor_bytes(result, byte_string(clang.digest));
    append_cbor_uint(result, V631302_M0_PINNED_CLANG_MAJOR);
    append_cbor_uint(result, 1u);
    append_cbor_item(result, execution_profile);
    append_cbor_bytes(result, bundle_root);
    append_cbor_item(result, bundle_manifest);
    return result;
}

std::optional<PrelaunchProfile> construct_prelaunch_profile() {
    const auto interpreter_digest = decode_digest(V631302_M0_PINNED_INTERPRETER_SHA256);
    const auto clang_digest = decode_digest(V631302_M0_PINNED_CLANG_SHA256);
    const auto worker_digest = decode_digest(V631302_M0_TEST_BOOTSTRAP_SHA256);
    if (!interpreter_digest || !clang_digest || !worker_digest) {
        return std::nullopt;
    }
    auto collector = open_and_hash_retained_executable("/proc/self/exe");
    auto clang = open_and_hash_regular_executable(V631302_M0_PINNED_CLANG_PATH,
                                                  V631302_M0_PINNED_CLANG_SIZE, *clang_digest);
    auto interpreter = open_and_hash_regular_executable(
        V631302_M0_PINNED_INTERPRETER_PATH, V631302_M0_PINNED_INTERPRETER_SIZE,
        *interpreter_digest);
    auto worker = open_and_read_verified_worker(V631302_M0_TEST_BOOTSTRAP_PATH,
                                                V631302_M0_TEST_BOOTSTRAP_SIZE, *worker_digest);
    if (!collector || !clang || !interpreter || !worker) {
        return std::nullopt;
    }
    PrelaunchProfile result{std::move(*collector), std::move(*clang), std::move(*interpreter),
                            std::move(*worker), byte_string(*worker_digest), {}, {}, {}, {}, {}};
    result.execution_profile = make_execution_profile(result.interpreter, result.worker_digest);
    result.bundle_manifest = make_bundle_manifest(result.worker, result.worker_digest);
    result.bundle_root = make_bundle_root(result.bundle_manifest);
    result.bundle_file_bytes = make_bundle_file_bytes(result.worker);
    result.profile = make_prelaunch_profile(result.collector, result.clang,
                                            result.execution_profile, result.bundle_root,
                                            result.bundle_manifest);
    if (!parse_exact_canonical_cbor(result.profile)) {
        return std::nullopt;
    }
    return result;
}

std::optional<Bytes> mutate_prelaunch_profile(const Bytes& profile, std::string_view field) {
    auto value = parse_exact_canonical_cbor(profile);
    if (!value || value->kind != CborKind::kArray || value->children.size() != 8u) {
        return std::nullopt;
    }
    if (field.empty() || field == "none" || field == "worker-rewrite") {
        return profile;
    }
    const auto mutate_byte = [](CborValue& target) -> bool {
        if (target.kind != CborKind::kBytes || target.string.empty()) {
            return false;
        }
        target.string.front() ^= 0x01u;
        return true;
    };
    if (field == "collector-sha") {
        if (!mutate_byte(value->children[0])) {
            return std::nullopt;
        }
    } else if (field == "collector-build-id") {
        if (value->children[1].kind != CborKind::kText) {
            return std::nullopt;
        }
        value->children[1].string.push_back(static_cast<std::uint8_t>('X'));
    } else if (field == "clang-sha") {
        if (!mutate_byte(value->children[2])) {
            return std::nullopt;
        }
    } else if (field == "clang-major") {
        if (value->children[3].kind != CborKind::kUint) {
            return std::nullopt;
        }
        ++value->children[3].integer;
    } else if (field == "execution-profile") {
        auto& execution = value->children[5];
        if (execution.kind != CborKind::kArray || execution.children.size() != 8u ||
            execution.children[4].kind != CborKind::kUint) {
            return std::nullopt;
        }
        execution.children[4].integer = 9u;
    } else if (field == "bundle-root") {
        if (!mutate_byte(value->children[6])) {
            return std::nullopt;
        }
    } else if (field == "bundle-manifest") {
        auto& manifest = value->children[7];
        if (manifest.kind != CborKind::kArray || manifest.children.size() != 3u ||
            manifest.children[2].kind != CborKind::kArray) {
            return std::nullopt;
        }
        manifest.children[2].children.clear();
    } else {
        return std::nullopt;
    }
    Bytes result;
    encode_cbor_value(result, *value);
    return result;
}

Bytes make_worker_input(const Bytes& profile, const Bytes& bundle_file_bytes,
                        const Bytes& raw_collector_bytes) {
    Bytes result;
    append_cbor_array(result, 5u);
    append_cbor_uint(result, 631302u);
    append_cbor_uint(result, 1u);
    append_cbor_item(result, profile);
    append_cbor_item(result, bundle_file_bytes);
    append_cbor_bytes(result, raw_collector_bytes);
    return result;
}

Bytes prelaunch_input_frame(const Bytes& payload) {
    Bytes result(kInputMagic.begin(), kInputMagic.end());
    append_u64_be(result, payload.size());
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

bool has_expected_profile(const CborValue& profile, const PrelaunchProfile& expected) {
    if (profile.kind != CborKind::kArray || profile.children.size() != 8u ||
        profile.children[0].kind != CborKind::kBytes ||
        profile.children[0].string != byte_string(expected.collector.digest) ||
        profile.children[1].kind != CborKind::kText ||
        profile.children[1].string != byte_string(V631302_M0_COLLECTOR_BUILD_ID) ||
        profile.children[2].kind != CborKind::kBytes ||
        profile.children[2].string != byte_string(expected.clang.digest) ||
        profile.children[3].kind != CborKind::kUint ||
        profile.children[3].integer != V631302_M0_PINNED_CLANG_MAJOR ||
        profile.children[4].kind != CborKind::kUint || profile.children[4].integer != 1u) {
        return false;
    }
    return profile.children[5].raw == expected.execution_profile &&
           profile.children[6].kind == CborKind::kBytes &&
           profile.children[6].string == expected.bundle_root &&
           profile.children[7].raw == expected.bundle_manifest;
}

bool verify_worker_artifact(const Bytes& artifact, const PrelaunchProfile& expected) {
    const auto result = parse_exact_canonical_cbor(artifact);
    if (!result || result->kind != CborKind::kArray || result->children.size() != 9u ||
        result->children[0].kind != CborKind::kUint || result->children[0].integer != 631302u ||
        result->children[1].kind != CborKind::kUint || result->children[1].integer != 1u) {
        return false;
    }
    const auto& profile = result->children[2];
    // Amendment 4 is exact-byte equality, followed by independent retained-FD
    // identity checks.  This verifier deliberately has no repair/re-encoding path.
    return profile.raw == expected.profile && has_expected_profile(profile, expected);
}

}  // namespace

bool run_fresh_worker_substrate_test() {
#if V631302_M0_TEST_BOOTSTRAP_ENABLED != 1
    return false;
#else
    const auto interpreter_digest = decode_digest(V631302_M0_PINNED_INTERPRETER_SHA256);
    const auto worker_digest = decode_digest(V631302_M0_TEST_BOOTSTRAP_SHA256);
    if (!interpreter_digest || !worker_digest) {
        return false;
    }
    auto interpreter = open_and_hash_regular_executable(
        V631302_M0_PINNED_INTERPRETER_PATH, V631302_M0_PINNED_INTERPRETER_SIZE,
        *interpreter_digest);
    auto worker = open_and_read_verified_worker(
        V631302_M0_TEST_BOOTSTRAP_PATH, V631302_M0_TEST_BOOTSTRAP_SIZE, *worker_digest);
    if (!interpreter || !worker) {
        return false;
    }
    // The logical path is deliberately fixed even though the fixture pathname
    // is build-local.  The missing entry-module/stdlib ruling prevents this
    // substrate from constructing a real manifest or final worker input.
    if (kLogicalWorkerPath != "worker/v631302_diagnostic_worker_v1.py") {
        return false;
    }
    const auto input = test_input_frame();
    if (!parse_exact_frame(input, kInputMagic)) {
        return false;
    }
    const auto process = launch_worker(std::move(*interpreter), *worker, input);
    if (!process) {
        return false;
    }
    if (!WIFEXITED(process->status)) {
        return false;
    }
    if (WEXITSTATUS(process->status) != 0) {
        return false;
    }
    if (!process->stderr_bytes.empty()) {
        return false;
    }
    const auto artifact = parse_exact_frame(process->stdout_bytes, kOutputMagic);
    if (!artifact || *artifact != Bytes{0x80u}) {
        return false;
    }
    return true;
#endif
}

bool run_prelaunch_profile_dataflow_test(const char* tamper_field) {
#if V631302_M0_TEST_BOOTSTRAP_ENABLED != 1
    static_cast<void>(tamper_field);
    return false;
#else
    if (tamper_field == nullptr) {
        return false;
    }
    auto expected = construct_prelaunch_profile();
    if (!expected) {
        return false;
    }
    const auto profile = mutate_prelaunch_profile(expected->profile, tamper_field);
    if (!profile) {
        return false;
    }
    // The opaque raw value deliberately contains a profile-shaped conflicting
    // value.  It is a byte string only; it cannot influence the prelaunch
    // profile, which was retained before the frame was assembled.
    Bytes conflicting_raw;
    if (std::string_view(tamper_field) == "worker-rewrite") {
        conflicting_raw = Bytes{0xF6u};  // test-only signal; it has no profile authority.
    } else {
        append_cbor_array(conflicting_raw, 1u);
        append_cbor_bytes(conflicting_raw, byte_string("conflicting-profile-like-value"));
    }
    const auto input = prelaunch_input_frame(
        make_worker_input(*profile, expected->bundle_file_bytes, conflicting_raw));
    const auto input_payload = parse_exact_frame(input, kInputMagic);
    if (!input_payload || !parse_exact_canonical_cbor(*input_payload)) {
        return false;
    }
    const auto process = launch_worker(std::move(expected->interpreter), expected->worker, input);
    if (!process || !WIFEXITED(process->status) || !process->stderr_bytes.empty()) {
        return false;
    }
    if (WEXITSTATUS(process->status) != 0) {
        // A production collector would map this to the public incomplete
        // diagnostic.  The test binary exposes only pass/fail and never treats
        // a worker failure as a successful test result.
        return false;
    }
    const auto artifact = parse_exact_frame(process->stdout_bytes, kOutputMagic);
    if (!artifact) {
        return false;
    }
    return verify_worker_artifact(*artifact, *expected);
#endif
}

}  // namespace evaluation_v6_3_1::m0_diagnostic
