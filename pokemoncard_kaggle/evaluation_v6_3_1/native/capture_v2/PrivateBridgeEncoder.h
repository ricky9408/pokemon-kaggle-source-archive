#ifndef EVALUATION_V6_3_1_CAPTURE_V2_PRIVATE_BRIDGE_ENCODER_H
#define EVALUATION_V6_3_1_CAPTURE_V2_PRIVATE_BRIDGE_ENCODER_H

#include "CaptureOutcome.h"
#include "PrivateBridgeResult.h"

#include <cstdint>

namespace evaluation_v6_3_1::capture_v2::private_bridge_v3 {

inline constexpr std::uint64_t kProtocol = 631302u;
inline constexpr std::uint64_t kPrivateBridgeVersion = 3u;

// The sole production encoder boundary. It consumes one completed success,
// owns exactly one output vector on success, and never lets an exception cross
// the native-to-Python handoff.
[[nodiscard]] EncodeResult encode_private_capture_bridge_v3(
    ::evaluation_v6_3_1::capture_v2::CompletedNativeCaptureSuccess success) noexcept;

#if defined(EVALUATION_V631302_PRIVATE_BRIDGE_V3_TEST_ONLY)
enum class EncodeTestFault : std::uint8_t {
    kNone = 0u,
    kEncodedSizeOverflow = 1u,
    kInternalEncodingFailure = 2u,
};

// This symbol exists only in a separately linked, ODR-consistent fixture
// target. It is absent from every production object and binary.
void set_encode_test_fault(EncodeTestFault fault) noexcept;
#endif

}  // namespace evaluation_v6_3_1::capture_v2::private_bridge_v3

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_PRIVATE_BRIDGE_ENCODER_H
