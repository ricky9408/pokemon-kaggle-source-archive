#ifndef EVALUATION_V6_3_1_CAPTURE_V2_PTRACE_OPEN_SUPERVISOR_H
#define EVALUATION_V6_3_1_CAPTURE_V2_PTRACE_OPEN_SUPERVISOR_H

#include "PtraceExecAuthenticator.h"
#include "ReceiptStreamParser.h"
#include "RuntimeObserver.h"
#include "SupervisorTypes.h"
#include "SyscallPairTracker.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {

class CaptureSession;
class CompletedNativeCaptureSuccess;
#if defined(EVALUATION_V631302_PRIVATE_BRIDGE_V3_TEST_ONLY)
class PrivateBridgeV3FixtureAccess;
#endif

struct ActualOpenObservation final {
    std::uint64_t observation_sequence = 0u;
    Amendment8OpenPhase phase = Amendment8OpenPhase::PreDriver;
    std::string namespace_relative_path;
    std::uint64_t open_flags = 0u;
    std::uint64_t device = 0u;
    std::uint64_t inode = 0u;
    std::uint32_t normalized_mode = 0u;
    std::uint64_t byte_length = 0u;
    Sha256Digest sha256{};

    friend bool operator==(const ActualOpenObservation&, const ActualOpenObservation&) = default;
};

struct PtraceOpenLimits final {
    std::uint64_t total_timeout_milliseconds = 0u;
    std::size_t maximum_path_bytes = 0u;
    std::uint64_t maximum_opened_file_bytes = 0u;
    std::size_t maximum_actual_open_rows = 0u;
    std::uint64_t maximum_syscall_events = 0u;
    RuntimeObserverLimits runtime_observer{};
};

// This legacy component result is intentionally not RAW_COLLECTOR_CAPTURE_V2.
// It can be returned only by the explicitly test-only method below.
struct CompletedOpenTraceSlice final {
    std::vector<ActualOpenObservation> actual_open_rows;
    SyscallPairTracker::Snapshot syscall_pairs;
    ReceiptFinalValues final_receipt;
    std::vector<std::uint8_t> exact_receipt_stream;
    std::vector<std::uint8_t> stdout_bytes;
};

struct CompletedNamespaceObservation final {
    LaunchReadyRecord ready_record;
    std::vector<NamespaceIdentityObservation> namespace_identity_rows;
};

struct CompletedExecStopObservation final {
    pid_t pid = -1;
    std::vector<std::string> argv;
    std::uint64_t proc_exe_byte_length = 0u;
    Sha256Digest proc_exe_sha256{};
    std::uint64_t cwd_device = 0u;
    std::uint64_t cwd_inode = 0u;
    std::string cwd_proc_link;
    bool zero_capability_sets = false;
    bool no_new_privileges = false;
    std::uint32_t user_id = 0u;
    std::uint32_t group_id = 0u;
    bool empty_supplementary_groups = false;
};

struct CompletedTerminationObservation final {
    int raw_wait_status = 0;
    std::uint32_t exit_status = 0u;
    std::vector<std::uint8_t> stderr_bytes;
};

// Deep-owned native observations captured before launch, inspector, runtime,
// and pipe owners are destroyed. This is deliberately not the final
// CompletedNativeCaptureSuccess from the binding ruling: validated prelaunch
// context, natively observed harness components, and retained CWD object
// provenance remain required before any private bridge encoder may accept a
// result. cwd_proc_link is bounded diagnostic text only.
class CompletedNativeCaptureObservations final {
public:
    CompletedNativeCaptureObservations(const CompletedNativeCaptureObservations&) = delete;
    CompletedNativeCaptureObservations& operator=(const CompletedNativeCaptureObservations&) = delete;
    CompletedNativeCaptureObservations(CompletedNativeCaptureObservations&&) noexcept = default;
    CompletedNativeCaptureObservations& operator=(CompletedNativeCaptureObservations&&) = delete;

    [[nodiscard]] const CompletedNamespaceObservation& namespace_observation() const noexcept {
        return namespace_observation_;
    }
    [[nodiscard]] const CompletedExecStopObservation& exec_stop_observation() const noexcept {
        return exec_stop_observation_;
    }
    [[nodiscard]] const CompletedOpenTraceSlice& open_receipt() const noexcept {
        return open_receipt_;
    }
    [[nodiscard]] const CompletedRuntimeObservation& runtime_observation() const noexcept {
        return runtime_observation_;
    }
    [[nodiscard]] const CompletedTerminationObservation& termination_observation() const noexcept {
        return termination_observation_;
    }

private:
    friend class CaptureSession;
    friend class CompletedNativeCaptureSuccess;
    friend class PtraceOpenSupervisor;
#if defined(EVALUATION_V631302_PRIVATE_BRIDGE_V3_TEST_ONLY)
    friend class PrivateBridgeV3FixtureAccess;
#endif

    CompletedNativeCaptureObservations(
        CompletedNamespaceObservation namespace_observation,
        CompletedExecStopObservation exec_stop_observation,
        CompletedOpenTraceSlice open_receipt,
        CompletedRuntimeObservation runtime_observation,
        CompletedTerminationObservation termination_observation,
        Sha256Digest private_context_binding_digest)
        : private_context_binding_digest_(private_context_binding_digest),
          namespace_observation_(std::move(namespace_observation)),
          exec_stop_observation_(std::move(exec_stop_observation)),
          open_receipt_(std::move(open_receipt)),
          runtime_observation_(std::move(runtime_observation)),
          termination_observation_(std::move(termination_observation)) {}

    [[nodiscard]] const Sha256Digest& private_context_binding_digest() const noexcept {
        return private_context_binding_digest_;
    }

    Sha256Digest private_context_binding_digest_{};
    CompletedNamespaceObservation namespace_observation_;
    CompletedExecStopObservation exec_stop_observation_;
    CompletedOpenTraceSlice open_receipt_;
    CompletedRuntimeObservation runtime_observation_;
    CompletedTerminationObservation termination_observation_;
};

class PtraceOpenSupervisor final {
public:
    // Explicitly zero-authority component harness. It consumes and destroys the
    // launch context, so no returned value can become a native success.
    static CompletedNativeCaptureObservations run_completed_observations_for_testing(
        std::unique_ptr<ExecStoppedLaunch> exec_stopped,
        ReceiptContextExpectation receipt_expectation,
        PtraceOpenLimits limits);

    // Zero-authority legacy component harness only. Production and Capture V2
    // assembly code must never call this method.
    static CompletedOpenTraceSlice run_open_receipt_slice_for_testing(
        std::unique_ptr<ExecStoppedLaunch> exec_stopped,
        ReceiptContextExpectation receipt_expectation,
        PtraceOpenLimits limits);

private:
    friend class CaptureSession;

    static CompletedNativeCaptureObservations run(
        ExecStoppedLaunch& exec_stopped,
        ReceiptContextExpectation receipt_expectation,
        PtraceOpenLimits limits);
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_PTRACE_OPEN_SUPERVISOR_H
