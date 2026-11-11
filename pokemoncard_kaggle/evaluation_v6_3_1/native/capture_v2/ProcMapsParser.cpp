#include "ProcMapsParser.h"

#if !defined(__linux__)
#error "ProcMapsParser is a Linux-only Capture V2 component"
#endif

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {
namespace {

constexpr std::uint64_t kProtRead = 1u;
constexpr std::uint64_t kProtWrite = 2u;
constexpr std::uint64_t kProtExec = 4u;

[[noreturn]] void fail(SupervisorFailure failure, std::string message) {
    throw SupervisorError(failure, std::move(message));
}

std::uint64_t parse_unsigned(
    std::string_view text, int base, const char* field) {
    if (text.empty()) {
        fail(SupervisorFailure::ProtocolViolation, std::string(field) + " is empty");
    }
    std::uint64_t value = 0u;
    const auto [end, error] = std::from_chars(
        text.data(), text.data() + text.size(), value, base);
    if (error != std::errc{} || end != text.data() + text.size()) {
        fail(SupervisorFailure::ProtocolViolation, std::string(field) + " is malformed");
    }
    return value;
}

std::string_view take_token(std::string_view& line, const char* field) {
    while (!line.empty() && line.front() == ' ') {
        line.remove_prefix(1u);
    }
    if (line.empty()) {
        fail(SupervisorFailure::ProtocolViolation, std::string(field) + " is missing");
    }
    const std::size_t end = line.find(' ');
    const std::string_view token = line.substr(0u, end);
    line = end == std::string_view::npos ? std::string_view{} : line.substr(end);
    return token;
}

std::pair<std::uint64_t, std::uint64_t> parse_pair(
    std::string_view token, char separator, int base, const char* field) {
    const std::size_t location = token.find(separator);
    if (location == std::string_view::npos || location == 0u ||
        token.find(separator, location + 1u) != std::string_view::npos) {
        fail(SupervisorFailure::ProtocolViolation, std::string(field) + " is malformed");
    }
    return {
        parse_unsigned(token.substr(0u, location), base, field),
        parse_unsigned(token.substr(location + 1u), base, field),
    };
}

std::uint64_t parse_protection(std::string_view permissions) {
    if (permissions.size() != 4u ||
        (permissions[0] != 'r' && permissions[0] != '-') ||
        (permissions[1] != 'w' && permissions[1] != '-') ||
        (permissions[2] != 'x' && permissions[2] != '-') ||
        (permissions[3] != 'p' && permissions[3] != 's')) {
        fail(SupervisorFailure::ProtocolViolation, "proc maps permissions are malformed");
    }
    std::uint64_t flags = 0u;
    if (permissions[0] == 'r') {
        flags |= kProtRead;
    }
    if (permissions[1] == 'w') {
        flags |= kProtWrite;
    }
    if (permissions[2] == 'x') {
        flags |= kProtExec;
    }
    return flags;
}

unsigned int octal_digit(char value) {
    if (value < '0' || value > '7') {
        fail(SupervisorFailure::ProtocolViolation, "proc maps pathname escape is malformed");
    }
    return static_cast<unsigned int>(value - '0');
}

std::string decode_proc_path(std::string_view encoded) {
    if (encoded.empty() || encoded.front() != '/') {
        fail(SupervisorFailure::ProtocolViolation, "file-backed proc maps pathname is not absolute");
    }
    constexpr std::string_view deleted_suffix = " (deleted)";
    if (encoded.ends_with(deleted_suffix)) {
        fail(SupervisorFailure::ProtocolViolation, "sealed runtime mapping is marked deleted");
    }
    std::string decoded;
    decoded.reserve(encoded.size());
    for (std::size_t index = 0u; index < encoded.size(); ++index) {
        const char value = encoded[index];
        if (value != '\\') {
            if (value == '\0' || value == '\n' || value == '\r') {
                fail(SupervisorFailure::ProtocolViolation, "proc maps pathname contains control bytes");
            }
            decoded.push_back(value);
            continue;
        }
        if (encoded.size() - index < 4u) {
            fail(SupervisorFailure::ProtocolViolation, "proc maps pathname escape is truncated");
        }
        const unsigned int first = octal_digit(encoded[index + 1u]);
        const unsigned int second = octal_digit(encoded[index + 2u]);
        const unsigned int third = octal_digit(encoded[index + 3u]);
        const unsigned int byte = (first << 6u) | (second << 3u) | third;
        if (byte == 0u || byte > std::numeric_limits<unsigned char>::max()) {
            fail(SupervisorFailure::ProtocolViolation, "proc maps pathname escape is invalid");
        }
        decoded.push_back(static_cast<char>(byte));
        index += 3u;
    }
    return decoded;
}

}  // namespace

std::vector<ExecutableFileMapping> ProcMapsParser::parse_executable_file_mappings(
    std::span<const std::uint8_t> maps_bytes,
    std::size_t positive_maximum_rows,
    std::size_t positive_maximum_line_bytes) {
    if (maps_bytes.empty() || positive_maximum_rows == 0u ||
        positive_maximum_line_bytes == 0u) {
        fail(SupervisorFailure::InvalidRequest, "proc maps parse request is invalid");
    }
    if (maps_bytes.back() != static_cast<std::uint8_t>('\n')) {
        fail(SupervisorFailure::ProtocolViolation, "proc maps snapshot lacks final newline");
    }

    const std::string_view snapshot(
        reinterpret_cast<const char*>(maps_bytes.data()), maps_bytes.size());
    std::vector<ExecutableFileMapping> result;
    std::uint64_t previous_finish = 0u;
    bool have_previous = false;
    std::size_t offset = 0u;
    while (offset < snapshot.size()) {
        const std::size_t end = snapshot.find('\n', offset);
        if (end == std::string_view::npos) {
            fail(SupervisorFailure::ProtocolViolation, "proc maps line is unterminated");
        }
        std::string_view line = snapshot.substr(offset, end - offset);
        if (line.empty() || line.size() > positive_maximum_line_bytes) {
            fail(SupervisorFailure::ResourceLimit, "proc maps line is empty or oversized");
        }
        offset = end + 1u;

        const auto [start, finish] = parse_pair(
            take_token(line, "proc maps address"), '-', 16, "proc maps address");
        if (start >= finish || (have_previous && start < previous_finish)) {
            fail(SupervisorFailure::ProtocolViolation, "proc maps address order is invalid");
        }
        previous_finish = finish;
        have_previous = true;
        const std::uint64_t protection = parse_protection(
            take_token(line, "proc maps permissions"));
        const std::uint64_t file_offset = parse_unsigned(
            take_token(line, "proc maps file offset"), 16, "proc maps file offset");
        const auto [device_major, device_minor] = parse_pair(
            take_token(line, "proc maps device"), ':', 16, "proc maps device");
        const std::uint64_t inode = parse_unsigned(
            take_token(line, "proc maps inode"), 10, "proc maps inode");
        while (!line.empty() && line.front() == ' ') {
            line.remove_prefix(1u);
        }

        if ((protection & kProtExec) == 0u || inode == 0u) {
            continue;
        }
        if (line.empty()) {
            fail(SupervisorFailure::ProtocolViolation, "file-backed executable map lacks pathname");
        }
        if (result.size() >= positive_maximum_rows) {
            fail(SupervisorFailure::ResourceLimit, "executable proc maps row cap exceeded");
        }
        result.push_back(ExecutableFileMapping{
            start,
            finish,
            file_offset,
            device_major,
            device_minor,
            inode,
            protection,
            decode_proc_path(line),
        });
    }
    return result;
}

}  // namespace evaluation_v6_3_1::capture_v2
