#ifndef EVALUATION_V6_3_1_CAPTURE_V2_PRODUCTION_CAPTURE_BRIDGE_H
#define EVALUATION_V6_3_1_CAPTURE_V2_PRODUCTION_CAPTURE_BRIDGE_H

#include "CaptureSession.h"
#include "PrivateBridgeEncoder.h"

#include <type_traits>
#include <variant>

namespace evaluation_v6_3_1::capture_v2 {

using private_bridge_v3::EncodeResult;

using ProductionCaptureBridgeResult =
    std::variant<NativeCaptureFailure, EncodeResult>;

// Sole production run/move boundary. This is zero-authority orchestration: it
// cannot issue a permit, access a holdout, or authorize an upload.
[[nodiscard]] ProductionCaptureBridgeResult
run_production_capture_bridge_v3(CaptureSession&& session) noexcept;

static_assert(!std::is_copy_constructible_v<ProductionCaptureBridgeResult>);
static_assert(std::is_nothrow_move_constructible_v<ProductionCaptureBridgeResult>);

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_PRODUCTION_CAPTURE_BRIDGE_H
