#ifndef EVALUATION_V6_3_1_CAPTURE_V2_LAUNCH_HANDSHAKE_H
#define EVALUATION_V6_3_1_CAPTURE_V2_LAUNCH_HANDSHAKE_H

#include "SupervisorTypes.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {

enum class LaunchReadyStatus : std::uint32_t {
    Ready = 0u,
    Failed = 1u,
};

struct LaunchReadyRecord final {
    LaunchReadyStatus status = LaunchReadyStatus::Failed;
    std::uint32_t failure_code = 0u;
    std::uint64_t root_device = 0u;
    std::uint64_t root_inode = 0u;
    std::uint64_t working_directory_device = 0u;
    std::uint64_t working_directory_inode = 0u;
    std::uint64_t collector_byte_length = 0u;
    Sha256Digest collector_sha256{};

    friend bool operator==(const LaunchReadyRecord&, const LaunchReadyRecord&) = default;
};

class LaunchHandshake final {
public:
    using Byte = std::uint8_t;
    static constexpr std::size_t kWireBytes = 96u;

    static std::array<Byte, kWireBytes> encode(const LaunchReadyRecord& record);
    static LaunchReadyRecord decode(std::span<const Byte> bytes);

    // The ready record is smaller than PIPE_BUF and is committed by one
    // complete successful write. Reads may be fragmented but never overlong.
    static void write_one(int descriptor, const LaunchReadyRecord& record);
    static LaunchReadyRecord read_one(int descriptor);
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_LAUNCH_HANDSHAKE_H
