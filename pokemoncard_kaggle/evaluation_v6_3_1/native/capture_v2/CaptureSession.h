#ifndef EVALUATION_V6_3_1_CAPTURE_V2_CAPTURE_SESSION_H
#define EVALUATION_V6_3_1_CAPTURE_V2_CAPTURE_SESSION_H

#include "CaptureOutcome.h"
#include "LaunchEngine.h"
#include "PrelaunchContext.h"
#include "PtraceOpenSupervisor.h"
#include "RetainedInputs.h"

#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {

struct CaptureSessionLimits final {
    LaunchRuntimeConfiguration launch;
    std::uint64_t harness_timeout_milliseconds = 0u;
    HarnessObserverLimits harness_observer{};
    std::uint64_t exec_authentication_timeout_milliseconds = 0u;
    PtraceOpenLimits ptrace_open{};
};

// Single-owner native orchestration. The only public terminal operation is an
// rvalue-only noexcept run returning success or bounded diagnostics. It has no
// public-protocol, manifest, permit, holdout, agent, or upload authority.
class CaptureSession final {
public:
    CaptureSession(
        std::vector<std::uint8_t> native_prelaunch_handoff_cbor,
        RetainedInputSet retained_inputs,
        CaptureSessionLimits limits)
        : native_prelaunch_handoff_cbor_(std::move(native_prelaunch_handoff_cbor)),
          retained_inputs_(std::move(retained_inputs)),
          limits_(std::move(limits)),
          failure_builder_() {}

    CaptureSession(const CaptureSession&) = delete;
    CaptureSession& operator=(const CaptureSession&) = delete;
    CaptureSession(CaptureSession&&) = delete;
    CaptureSession& operator=(CaptureSession&&) = delete;
    ~CaptureSession() noexcept = default;

    [[nodiscard]] CaptureSessionOutcome run() && noexcept;

private:
#if defined(EVALUATION_V631302_PRIVATE_BRIDGE_V3_TEST_ONLY)
    friend class PrivateBridgeV3FixtureAccess;
#endif

    std::vector<std::uint8_t> native_prelaunch_handoff_cbor_;
    RetainedInputSet retained_inputs_;
    CaptureSessionLimits limits_;
    NativeCaptureFailureBuilder failure_builder_;
#if defined(EVALUATION_V631302_PRIVATE_BRIDGE_V3_TEST_ONLY)
    std::optional<CaptureSessionOutcome> fixture_outcome_;
    std::size_t* fixture_run_count_ = nullptr;
#endif
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_CAPTURE_SESSION_H
