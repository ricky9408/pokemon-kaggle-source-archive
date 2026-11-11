#include "CollectorReceipt.h"

#include "RawCborWriter.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {
namespace {

using Byte = std::uint8_t;
using evaluation_v6_3_1::m0_diagnostic::RawCborWriter;

constexpr int kReceiptFd = 3;
constexpr std::uint64_t kProtocol = 631302;
constexpr std::uint64_t kEventVersion = 1;
constexpr std::size_t kReceiptStreamMaxBytes = 16777216;
constexpr std::array<Byte, 8> kFrameMagic = {'V', '6', '3', '1', 'C', 'R', '0', '1'};

[[noreturn]] void invalid_context() {
    throw std::invalid_argument("invalid capture context");
}

struct CborHead final {
    Byte major;
    std::uint64_t argument;
};

CborHead parse_head(const std::vector<Byte>& bytes, std::size_t& cursor) {
    if (cursor >= bytes.size()) {
        invalid_context();
    }
    const Byte initial = bytes[cursor++];
    const Byte major = static_cast<Byte>(initial >> 5u);
    const Byte additional = static_cast<Byte>(initial & 0x1Fu);
    if (major != 0u && major != 2u && major != 3u && major != 4u) {
        invalid_context();
    }

    std::uint64_t argument = 0;
    std::size_t width = 0;
    if (additional < 24u) {
        argument = additional;
    } else if (additional == 24u) {
        width = 1;
    } else if (additional == 25u) {
        width = 2;
    } else if (additional == 26u) {
        width = 4;
    } else if (additional == 27u) {
        width = 8;
    } else {
        invalid_context();
    }
    if (width != 0u) {
        if (width > bytes.size() - cursor) {
            invalid_context();
        }
        for (std::size_t index = 0; index < width; ++index) {
            argument = (argument << 8u) | bytes[cursor++];
        }
        const std::uint64_t minimum =
            width == 1u   ? 24u
            : width == 2u ? 0x100u
            : width == 4u ? 0x10000u
                          : 0x100000000ULL;
        if (argument < minimum) {
            invalid_context();
        }
    }
    return CborHead{major, argument};
}

bool continuation(Byte value) {
    return (value & 0xC0u) == 0x80u;
}

bool valid_utf8(std::string_view value) {
    const auto* bytes = reinterpret_cast<const Byte*>(value.data());
    std::size_t index = 0;
    while (index < value.size()) {
        const Byte first = bytes[index++];
        if (first <= 0x7Fu) {
            continue;
        }
        if (first >= 0xC2u && first <= 0xDFu) {
            if (index >= value.size() || !continuation(bytes[index])) {
                return false;
            }
            ++index;
            continue;
        }
        if (first >= 0xE0u && first <= 0xEFu) {
            if (index + 1u >= value.size()) {
                return false;
            }
            const Byte second = bytes[index];
            const Byte third = bytes[index + 1u];
            const bool second_valid =
                first == 0xE0u   ? second >= 0xA0u && second <= 0xBFu
                : first == 0xEDu ? second >= 0x80u && second <= 0x9Fu
                                 : continuation(second);
            if (!second_valid || !continuation(third)) {
                return false;
            }
            index += 2u;
            continue;
        }
        if (first >= 0xF0u && first <= 0xF4u) {
            if (index + 2u >= value.size()) {
                return false;
            }
            const Byte second = bytes[index];
            const bool second_valid =
                first == 0xF0u   ? second >= 0x90u && second <= 0xBFu
                : first == 0xF4u ? second >= 0x80u && second <= 0x8Fu
                                 : continuation(second);
            if (!second_valid || !continuation(bytes[index + 1u]) ||
                !continuation(bytes[index + 2u])) {
                return false;
            }
            index += 3u;
            continue;
        }
        return false;
    }
    return true;
}

std::size_t consume_item(const std::vector<Byte>& bytes, std::size_t start) {
    std::size_t cursor = start;
    std::vector<std::uint64_t> pending{1u};
    while (!pending.empty()) {
        if (pending.back() == 0u) {
            pending.pop_back();
            continue;
        }
        --pending.back();
        const CborHead head = parse_head(bytes, cursor);
        if (head.major == 0u) {
            continue;
        }
        if (head.major == 2u || head.major == 3u) {
            if (head.argument > bytes.size() - cursor) {
                invalid_context();
            }
            const std::size_t length = static_cast<std::size_t>(head.argument);
            if (head.major == 3u) {
                const std::string_view text(
                    reinterpret_cast<const char*>(bytes.data() + cursor), length);
                if (!valid_utf8(text)) {
                    invalid_context();
                }
            }
            cursor += length;
            continue;
        }
        pending.push_back(head.argument);
    }
    return cursor;
}

std::string read_text(const std::vector<Byte>& bytes, std::size_t& cursor) {
    const CborHead head = parse_head(bytes, cursor);
    if (head.major != 3u || head.argument > bytes.size() - cursor) {
        invalid_context();
    }
    const std::size_t length = static_cast<std::size_t>(head.argument);
    const std::string_view text(reinterpret_cast<const char*>(bytes.data() + cursor), length);
    if (!valid_utf8(text)) {
        invalid_context();
    }
    cursor += length;
    return std::string(text);
}

void validate_relative_path(std::string_view path) {
    if (path.empty() || path.front() == '/' || path.find('\\') != std::string_view::npos ||
        path.find('\0') != std::string_view::npos) {
        invalid_context();
    }
    std::size_t start = 0;
    while (start <= path.size()) {
        const std::size_t separator = path.find('/', start);
        const std::size_t end = separator == std::string_view::npos ? path.size() : separator;
        const std::string_view component = path.substr(start, end - start);
        if (component.empty() || component == "." || component == "..") {
            invalid_context();
        }
        if (separator == std::string_view::npos) {
            break;
        }
        start = separator + 1u;
    }
}

Byte decode_nibble(char value) {
    if (value >= '0' && value <= '9') {
        return static_cast<Byte>(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return static_cast<Byte>(value - 'a' + 10);
    }
    invalid_context();
}

std::vector<Byte> decode_lowercase_hex(std::string_view text) {
    if (text.empty() || text.size() % 2u != 0u) {
        invalid_context();
    }
    std::vector<Byte> bytes;
    bytes.reserve(text.size() / 2u);
    for (std::size_t index = 0; index < text.size(); index += 2u) {
        const Byte high = decode_nibble(text[index]);
        const Byte low = decode_nibble(text[index + 1u]);
        bytes.push_back(static_cast<Byte>((high << 4u) | low));
    }
    return bytes;
}

void append(std::vector<Byte>& destination, const std::vector<Byte>& source) {
    destination.insert(destination.end(), source.begin(), source.end());
}

void write_argv(RawCborWriter& writer, const std::vector<std::string>& argv) {
    if (argv.empty()) {
        throw std::runtime_error("empty receipt argv");
    }
    writer.array(argv.size());
    for (const std::string& argument : argv) {
        if (argument.find('\0') != std::string::npos || !valid_utf8(argument)) {
            throw std::runtime_error("invalid receipt argv");
        }
        writer.text(argument);
    }
}

std::vector<Byte> event_prefix(std::uint64_t sequence, std::uint64_t code) {
    RawCborWriter writer;
    writer.array(5);
    writer.uint(kProtocol);
    writer.uint(kEventVersion);
    writer.uint(sequence);
    writer.uint(code);
    return std::move(writer).take_bytes();
}

std::vector<Byte> encode_phase_event(std::uint64_t sequence, std::uint64_t phase) {
    std::vector<Byte> payload = event_prefix(sequence, 2u);
    RawCborWriter writer;
    writer.array(2);
    writer.uint(phase);
    writer.uint(phase);
    append(payload, std::move(writer).take_bytes());
    return payload;
}

std::vector<Byte> encode_argv_event(std::uint64_t sequence, std::uint64_t code,
                                    const std::vector<std::string>& argv) {
    std::vector<Byte> payload = event_prefix(sequence, code);
    RawCborWriter writer;
    write_argv(writer, argv);
    append(payload, std::move(writer).take_bytes());
    return payload;
}

std::vector<Byte> encode_binding_event(std::uint64_t device, std::uint64_t inode) {
    std::vector<Byte> payload = event_prefix(0u, 1u);
    RawCborWriter writer;
    writer.array(3);
    writer.uint(3u);
    writer.uint(device);
    writer.uint(inode);
    append(payload, std::move(writer).take_bytes());
    return payload;
}

void write_phase_transitions(RawCborWriter& writer) {
    constexpr std::array<std::uint64_t, 7> event_sequences = {1u, 3u, 4u, 6u, 7u, 8u, 9u};
    writer.array(event_sequences.size());
    for (std::size_t phase = 0; phase < event_sequences.size(); ++phase) {
        writer.array(3);
        writer.uint(phase);
        writer.uint(phase);
        writer.uint(event_sequences[phase]);
    }
}

std::vector<Byte> encode_final_receipt(const CaptureContextV1& context,
                                       std::uint64_t device, std::uint64_t inode,
                                       const std::vector<std::string>& driver_argv,
                                       const std::vector<std::string>& cc1_argv) {
    RawCborWriter prefix;
    prefix.array(8);
    prefix.uint(kProtocol);
    prefix.uint(1u);
    prefix.array(3);
    prefix.uint(3u);
    prefix.uint(device);
    prefix.uint(inode);
    prefix.text(context.primary_source_relative_path);
    std::vector<Byte> receipt = std::move(prefix).take_bytes();
    append(receipt, context.path_profile_cbor);

    RawCborWriter suffix;
    write_argv(suffix, driver_argv);
    write_argv(suffix, cc1_argv);
    write_phase_transitions(suffix);
    append(receipt, std::move(suffix).take_bytes());
    return receipt;
}

std::vector<Byte> encode_final_event(const CaptureContextV1& context,
                                     std::uint64_t device, std::uint64_t inode,
                                     const std::vector<std::string>& driver_argv,
                                     const std::vector<std::string>& cc1_argv) {
    std::vector<Byte> event = event_prefix(10u, 5u);
    append(event, encode_final_receipt(context, device, inode, driver_argv, cc1_argv));
    return event;
}

}  // namespace

CaptureContextV1 decode_capture_context_v1_hex(std::string_view lowercase_hex) {
    const std::vector<Byte> bytes = decode_lowercase_hex(lowercase_hex);
    std::size_t cursor = 0;
    const CborHead top = parse_head(bytes, cursor);
    if (top.major != 4u || top.argument != 3u) {
        invalid_context();
    }
    const CborHead version = parse_head(bytes, cursor);
    if (version.major != 0u || version.argument != 1u) {
        invalid_context();
    }
    std::string primary = read_text(bytes, cursor);
    validate_relative_path(primary);

    const std::size_t profile_start = cursor;
    std::size_t profile_header_cursor = cursor;
    const CborHead profile_head = parse_head(bytes, profile_header_cursor);
    if (profile_head.major != 4u) {
        invalid_context();
    }
    cursor = consume_item(bytes, profile_start);
    if (cursor != bytes.size()) {
        invalid_context();
    }
    std::vector<Byte> profile(bytes.begin() + static_cast<std::ptrdiff_t>(profile_start),
                              bytes.end());

    RawCborWriter prefix;
    prefix.array(3);
    prefix.uint(1u);
    prefix.text(primary);
    std::vector<Byte> recomputed = std::move(prefix).take_bytes();
    append(recomputed, profile);
    if (recomputed != bytes) {
        invalid_context();
    }
    return CaptureContextV1{std::move(primary), std::move(profile)};
}

CollectorReceipt::CollectorReceipt(std::string_view lowercase_context_hex)
    : context_(decode_capture_context_v1_hex(lowercase_context_hex)) {}

CollectorReceipt::~CollectorReceipt() noexcept {
    abort();
}

[[noreturn]] void CollectorReceipt::fail() {
    failed_ = true;
    if (fd_open_) {
        fd_open_ = false;
        static_cast<void>(::close(kReceiptFd));
    }
    throw std::runtime_error("collector receipt failure");
}

void CollectorReceipt::abort() noexcept {
    if (!finalized_) {
        failed_ = true;
    }
    if (fd_open_) {
        fd_open_ = false;
        static_cast<void>(::close(kReceiptFd));
    }
}

void CollectorReceipt::require_sequence(std::uint64_t expected) {
    if (failed_ || finalized_ || !started_ || next_sequence_ != expected) {
        fail();
    }
}

void CollectorReceipt::start() {
    try {
        if (started_ || failed_ || finalized_) {
            fail();
        }
        const int descriptor_flags = ::fcntl(kReceiptFd, F_GETFD);
        if (descriptor_flags < 0) {
            fail();
        }
        fd_open_ = true;
        const int status_flags = ::fcntl(kReceiptFd, F_GETFL);
        struct stat status {};
        if (status_flags < 0 || ::fstat(kReceiptFd, &status) != 0 ||
            !S_ISFIFO(status.st_mode) || (status_flags & O_ACCMODE) != O_WRONLY ||
            (descriptor_flags & FD_CLOEXEC) != 0) {
            fail();
        }
        errno = 0;
        pipe_buf_ = ::fpathconf(kReceiptFd, _PC_PIPE_BUF);
        if (pipe_buf_ <= 0 || pipe_buf_ > std::numeric_limits<int>::max()) {
            fail();
        }
        pipe_st_dev_ = static_cast<std::uint64_t>(status.st_dev);
        pipe_st_ino_ = static_cast<std::uint64_t>(status.st_ino);
        started_ = true;
        emit_binding();
        emit_phase(0u);
    } catch (...) {
        abort();
        throw;
    }
}

void CollectorReceipt::emit_frame(std::vector<Byte> payload, bool phase_frame) {
    if (failed_ || finalized_ || !fd_open_) {
        fail();
    }
    std::vector<Byte> frame;
    frame.reserve(16u + payload.size());
    frame.insert(frame.end(), kFrameMagic.begin(), kFrameMagic.end());
    const std::uint64_t length = static_cast<std::uint64_t>(payload.size());
    for (int shift = 56; shift >= 0; shift -= 8) {
        frame.push_back(static_cast<Byte>(length >> shift));
    }
    append(frame, payload);
    if (frame.size() > kReceiptStreamMaxBytes - stream_bytes_) {
        fail();
    }

    if (phase_frame) {
        const std::size_t effective_pipe_buf =
            std::min<std::size_t>(PIPE_BUF, static_cast<std::size_t>(pipe_buf_));
        if (frame.size() > effective_pipe_buf) {
            fail();
        }
        const ssize_t written = ::write(kReceiptFd, frame.data(), frame.size());
        if (written < 0 || static_cast<std::size_t>(written) != frame.size()) {
            fail();
        }
    } else {
        std::size_t offset = 0;
        while (offset < frame.size()) {
            const ssize_t written =
                ::write(kReceiptFd, frame.data() + offset, frame.size() - offset);
            if (written < 0 && errno == EINTR) {
                continue;
            }
            if (written <= 0) {
                fail();
            }
            offset += static_cast<std::size_t>(written);
        }
    }
    stream_bytes_ += frame.size();
    ++next_sequence_;
}

void CollectorReceipt::emit_binding() {
    require_sequence(0u);
    emit_frame(encode_binding_event(pipe_st_dev_, pipe_st_ino_), false);
}

void CollectorReceipt::emit_phase(std::uint64_t phase) {
    static constexpr std::array<std::uint64_t, 7> sequences = {1u, 3u, 4u, 6u, 7u, 8u, 9u};
    if (phase >= sequences.size()) {
        fail();
    }
    require_sequence(sequences[phase]);
    emit_frame(encode_phase_event(next_sequence_, phase), true);
}

void CollectorReceipt::emit_argv(std::uint64_t event_code,
                                 const std::vector<std::string>& argv) {
    const std::uint64_t expected = event_code == 3u ? 2u : event_code == 4u ? 5u : 11u;
    if (expected == 11u) {
        fail();
    }
    require_sequence(expected);
    emit_frame(encode_argv_event(next_sequence_, event_code, argv), false);
}

void CollectorReceipt::driver_argv_frozen(const std::vector<std::string>& driver_argv) {
    try {
        require_sequence(2u);
        driver_argv_ = driver_argv;
        emit_argv(3u, driver_argv_);
        emit_phase(1u);
    } catch (...) {
        abort();
        throw;
    }
}

void CollectorReceipt::driver_execution_begin() {
    try {
        emit_phase(2u);
    } catch (...) {
        abort();
        throw;
    }
}

void CollectorReceipt::cc1_argv_frozen(const std::vector<std::string>& cc1_argv) {
    try {
        require_sequence(5u);
        cc1_argv_ = cc1_argv;
        emit_argv(4u, cc1_argv_);
        emit_phase(3u);
    } catch (...) {
        abort();
        throw;
    }
}

void CollectorReceipt::cc1_execution_begin() {
    try {
        emit_phase(4u);
    } catch (...) {
        abort();
        throw;
    }
}

void CollectorReceipt::cc1_execution_end() {
    try {
        emit_phase(5u);
    } catch (...) {
        abort();
        throw;
    }
}

void CollectorReceipt::emit_final_receipt() {
    require_sequence(10u);
    if (driver_argv_.empty() || cc1_argv_.empty()) {
        fail();
    }
    emit_frame(encode_final_event(context_, pipe_st_dev_, pipe_st_ino_, driver_argv_, cc1_argv_),
               false);
}

void CollectorReceipt::close_receipt_fd() {
    if (!fd_open_) {
        fail();
    }
    fd_open_ = false;
    if (::close(kReceiptFd) != 0) {
        fail();
    }
}

void CollectorReceipt::finalize() {
    try {
        require_sequence(9u);
        emit_phase(6u);
        emit_final_receipt();
        if (next_sequence_ != 11u) {
            fail();
        }
        close_receipt_fd();
        finalized_ = true;
    } catch (...) {
        abort();
        throw;
    }
}

}  // namespace evaluation_v6_3_1::capture_v2
