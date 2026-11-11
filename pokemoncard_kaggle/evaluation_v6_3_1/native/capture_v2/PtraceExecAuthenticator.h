#ifndef EVALUATION_V6_3_1_CAPTURE_V2_PTRACE_EXEC_AUTHENTICATOR_H
#define EVALUATION_V6_3_1_CAPTURE_V2_PTRACE_EXEC_AUTHENTICATOR_H

#include "LaunchEngine.h"
#include "ProcInspector.h"

#include <cstdint>
#include <memory>

namespace evaluation_v6_3_1::capture_v2 {

// Owns a PreparedLaunch stopped at its single authenticated PTRACE_EVENT_EXEC.
// Destruction without a later handoff kills and reaps through the launch's
// pidfd guard; no partial observation can become a capture.
class ExecStoppedLaunch final {
public:
    ~ExecStoppedLaunch() noexcept = default;

    ExecStoppedLaunch(const ExecStoppedLaunch&) = delete;
    ExecStoppedLaunch& operator=(const ExecStoppedLaunch&) = delete;
    ExecStoppedLaunch(ExecStoppedLaunch&&) = delete;
    ExecStoppedLaunch& operator=(ExecStoppedLaunch&&) = delete;

    [[nodiscard]] PreparedLaunch& launch() noexcept { return *launch_; }
    [[nodiscard]] const PreparedLaunch& launch() const noexcept { return *launch_; }
    [[nodiscard]] const StoppedProcessObservation& observation() const {
        return inspector_->observation();
    }

private:
    friend class PtraceExecAuthenticator;

    ExecStoppedLaunch(
        std::unique_ptr<PreparedLaunch> launch,
        std::unique_ptr<ProcInspector> inspector)
        : launch_(std::move(launch)), inspector_(std::move(inspector)) {}

    std::unique_ptr<PreparedLaunch> launch_;
    std::unique_ptr<ProcInspector> inspector_;
};

// Zero-authority ptrace attachment and exec-stop authentication only.  It does
// not supervise post-exec syscalls, parse receipts, assemble Capture V2, or
// authorize any campaign, holdout, agent modification, or upload action.
class PtraceExecAuthenticator final {
public:
    static std::unique_ptr<ExecStoppedLaunch> reach_authenticated_exec(
        std::unique_ptr<PreparedLaunch> prepared,
        std::uint64_t positive_timeout_milliseconds);
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_PTRACE_EXEC_AUTHENTICATOR_H
