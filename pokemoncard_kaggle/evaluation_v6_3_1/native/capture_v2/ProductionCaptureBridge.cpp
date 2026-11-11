#include "ProductionCaptureBridge.h"

#include <utility>
#include <variant>

namespace evaluation_v6_3_1::capture_v2 {

ProductionCaptureBridgeResult
run_production_capture_bridge_v3(CaptureSession&& session) noexcept {
    CaptureSessionOutcome outcome = std::move(session).run();
    if (std::holds_alternative<NativeCaptureFailure>(outcome)) {
        return ProductionCaptureBridgeResult(
            std::in_place_index<0u>,
            std::get<NativeCaptureFailure>(std::move(outcome)));
    }
    return ProductionCaptureBridgeResult(
        std::in_place_index<1u>,
        private_bridge_v3::encode_private_capture_bridge_v3(
            std::get<CompletedNativeCaptureSuccess>(std::move(outcome))));
}

}  // namespace evaluation_v6_3_1::capture_v2
