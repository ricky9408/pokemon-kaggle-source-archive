#include "LaunchHandshake.h"

#if !defined(__linux__)
#error "LaunchHandshake is a Linux-only Capture V2 component"
#endif

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <unistd.h>

namespace evaluation_v6_3_1::capture_v2 {
namespace {

constexpr std::array<std::uint8_t, 8> kMagic = {'V', '6', '3', '1', 'L', 'C', 'H', '1'};
constexpr std::uint32_t kVersion = 1u;

[[noreturn]] void invalid(const char* message, int error = 0) {
    throw SupervisorError(SupervisorFailure::ProtocolViolation, message, error);
}

void append_u32(std::array<std::uint8_t, LaunchHandshake::kWireBytes>& bytes,
                std::size_t& cursor, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        bytes[cursor++] = static_cast<std::uint8_t>(value >> shift);
    }
}

void append_u64(std::array<std::uint8_t, LaunchHandshake::kWireBytes>& bytes,
                std::size_t& cursor, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        bytes[cursor++] = static_cast<std::uint8_t>(value >> shift);
    }
}

std::uint32_t read_u32(std::span<const std::uint8_t> bytes, std::size_t& cursor) {
    std::uint32_t value = 0u;
    for (std::size_t index = 0u; index < 4u; ++index) {
        value = static_cast<std::uint32_t>((value << 8u) | bytes[cursor++]);
    }
    return value;
}

std::uint64_t read_u64(std::span<const std::uint8_t> bytes, std::size_t& cursor) {
    std::uint64_t value = 0u;
    for (std::size_t index = 0u; index < 8u; ++index) {
        value = (value << 8u) | bytes[cursor++];
    }
    return value;
}

bool digest_is_zero(const Sha256Digest& digest) noexcept {
    return std::all_of(digest.begin(), digest.end(), [](std::uint8_t value) { return value == 0u; });
}

void validate(const LaunchReadyRecord& record) {
    if (record.status == LaunchReadyStatus::Ready) {
        if (record.failure_code != 0u || record.root_device == 0u || record.root_inode == 0u ||
            record.working_directory_device == 0u || record.working_directory_inode == 0u ||
            record.collector_byte_length == 0u || digest_is_zero(record.collector_sha256)) {
            invalid("launch-ready success record is incomplete");
        }
        return;
    }
    if (record.status != LaunchReadyStatus::Failed || record.failure_code == 0u ||
        record.root_device != 0u || record.root_inode != 0u ||
        record.working_directory_device != 0u || record.working_directory_inode != 0u ||
        record.collector_byte_length != 0u || !digest_is_zero(record.collector_sha256)) {
        invalid("launch-ready failure record is not canonical");
    }
}

}  // namespace

std::array<LaunchHandshake::Byte, LaunchHandshake::kWireBytes> LaunchHandshake::encode(
    const LaunchReadyRecord& record) {
    validate(record);
    std::array<Byte, kWireBytes> bytes{};
    std::copy(kMagic.begin(), kMagic.end(), bytes.begin());
    std::size_t cursor = kMagic.size();
    append_u32(bytes, cursor, kVersion);
    append_u32(bytes, cursor, static_cast<std::uint32_t>(record.status));
    append_u32(bytes, cursor, record.failure_code);
    append_u32(bytes, cursor, 0u);
    append_u64(bytes, cursor, record.root_device);
    append_u64(bytes, cursor, record.root_inode);
    append_u64(bytes, cursor, record.working_directory_device);
    append_u64(bytes, cursor, record.working_directory_inode);
    append_u64(bytes, cursor, record.collector_byte_length);
    std::copy(record.collector_sha256.begin(), record.collector_sha256.end(),
              bytes.begin() + static_cast<std::ptrdiff_t>(cursor));
    cursor += record.collector_sha256.size();
    if (cursor != bytes.size()) {
        invalid("launch-ready encoder length mismatch");
    }
    return bytes;
}

LaunchReadyRecord LaunchHandshake::decode(std::span<const Byte> bytes) {
    if (bytes.size() != kWireBytes ||
        !std::equal(kMagic.begin(), kMagic.end(), bytes.begin())) {
        invalid("launch-ready wire magic or length is invalid");
    }
    std::size_t cursor = kMagic.size();
    if (read_u32(bytes, cursor) != kVersion) {
        invalid("launch-ready wire version is invalid");
    }
    const std::uint32_t raw_status = read_u32(bytes, cursor);
    if (raw_status > static_cast<std::uint32_t>(LaunchReadyStatus::Failed)) {
        invalid("launch-ready wire status is invalid");
    }
    LaunchReadyRecord record{};
    record.status = static_cast<LaunchReadyStatus>(raw_status);
    record.failure_code = read_u32(bytes, cursor);
    if (read_u32(bytes, cursor) != 0u) {
        invalid("launch-ready wire reserved field is nonzero");
    }
    record.root_device = read_u64(bytes, cursor);
    record.root_inode = read_u64(bytes, cursor);
    record.working_directory_device = read_u64(bytes, cursor);
    record.working_directory_inode = read_u64(bytes, cursor);
    record.collector_byte_length = read_u64(bytes, cursor);
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(cursor), record.collector_sha256.size(),
                record.collector_sha256.begin());
    cursor += record.collector_sha256.size();
    if (cursor != bytes.size()) {
        invalid("launch-ready decoder length mismatch");
    }
    validate(record);
    return record;
}

void LaunchHandshake::write_one(int descriptor, const LaunchReadyRecord& record) {
    if (descriptor < 0) {
        invalid("launch-ready write descriptor is invalid");
    }
    const auto bytes = encode(record);
    ssize_t written = -1;
    do {
        written = ::write(descriptor, bytes.data(), bytes.size());
    } while (written < 0 && errno == EINTR);
    if (written < 0 || static_cast<std::size_t>(written) != bytes.size()) {
        invalid("launch-ready record was not one complete write", errno);
    }
}

LaunchReadyRecord LaunchHandshake::read_one(int descriptor) {
    if (descriptor < 0) {
        invalid("launch-ready read descriptor is invalid");
    }
    std::array<Byte, kWireBytes> bytes{};
    std::size_t offset = 0u;
    while (offset < bytes.size()) {
        const ssize_t count = ::read(descriptor, bytes.data() + offset, bytes.size() - offset);
        if (count > 0) {
            offset += static_cast<std::size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        invalid("launch-ready record ended before the exact wire length", errno);
    }
    return decode(bytes);
}

}  // namespace evaluation_v6_3_1::capture_v2
