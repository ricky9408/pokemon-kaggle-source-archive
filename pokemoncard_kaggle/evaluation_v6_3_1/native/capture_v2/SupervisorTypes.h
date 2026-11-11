#ifndef EVALUATION_V6_3_1_CAPTURE_V2_SUPERVISOR_TYPES_H
#define EVALUATION_V6_3_1_CAPTURE_V2_SUPERVISOR_TYPES_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>

namespace evaluation_v6_3_1::capture_v2 {

using Sha256Digest32 = std::array<std::uint8_t, 32>;
using Sha256Digest = Sha256Digest32;
inline constexpr std::size_t kRawCollectorCaptureMaxBytesV1 =
    64u * 1024u * 1024u;

enum class SupervisorFailure : std::uint32_t {
    InvalidRequest = 1,
    UnsafePath = 2,
    OriginalInputOpen = 3,
    OriginalInputIdentity = 4,
    OriginalInputChanged = 5,
    DestinationInvalid = 6,
    CopyFailure = 7,
    ResourceLimit = 8,
    ProtocolViolation = 9,
    SystemFailure = 10,
    NamespaceSetup = 11,
    NamespaceSeal = 12,
    NamespaceEnter = 13,
    ProcessLaunch = 14,
    HandshakeTimeout = 15,
    ChildFailure = 16,
    TraceFailure = 17,
    TraceTimeout = 18,
};

class SupervisorError final : public std::runtime_error {
public:
    SupervisorError(SupervisorFailure failure, std::string message, int system_errno = 0)
        : std::runtime_error(std::move(message)), failure_(failure), system_errno_(system_errno) {}

    [[nodiscard]] SupervisorFailure failure() const noexcept { return failure_; }
    [[nodiscard]] int system_errno() const noexcept { return system_errno_; }

private:
    SupervisorFailure failure_;
    int system_errno_;
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_SUPERVISOR_TYPES_H
