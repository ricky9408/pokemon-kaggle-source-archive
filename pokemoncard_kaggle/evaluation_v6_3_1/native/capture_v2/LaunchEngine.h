#ifndef EVALUATION_V6_3_1_CAPTURE_V2_LAUNCH_ENGINE_H
#define EVALUATION_V6_3_1_CAPTURE_V2_LAUNCH_ENGINE_H

#include "LaunchHandshake.h"
#include "MountSandbox.h"
#include "NamespaceIdentityObserver.h"
#include "OwnedFd.h"
#include "PipePump.h"
#include "PrelaunchContext.h"
#include "RetainedInputs.h"
#include "Timeout.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {

struct NamespaceFileExpectation final {
    std::string namespace_relative_path;
    std::vector<std::uint32_t> role_codes;
    std::uint32_t normalized_mode = 0u;
    std::uint64_t byte_length = 0u;
    Sha256Digest sha256{};

    friend bool operator==(const NamespaceFileExpectation&, const NamespaceFileExpectation&) = default;
};

// Mechanical resource bounds and private staging storage only.  Execution
// identity is deliberately absent: argv, cwd, namespace rows, collector facts,
// and harness expectations come exclusively from ValidatedPrelaunchPlan.
struct LaunchRuntimeConfiguration final {
    std::string staging_root_absolute_path;
    std::uint64_t tmpfs_byte_limit = 0u;
    std::size_t stdout_byte_cap = 0u;
    std::size_t stderr_byte_cap = 0u;
    std::size_t receipt_byte_cap = 0u;
    std::uint64_t custody_timeout_milliseconds = 0u;
    std::uint64_t ready_timeout_milliseconds = 0u;
    std::uint64_t namespace_identity_timeout_milliseconds = 0u;
    std::uint64_t namespace_identity_total_byte_cap = 0u;
};

// A child that has completed namespace materialization and the exact ready
// handshake, but is still blocked before exec.  Releasing it is intentionally
// separate so a ptrace supervisor can seize and interrupt it first.
class PreparedLaunch final {
public:
    ~PreparedLaunch() noexcept = default;

    PreparedLaunch(const PreparedLaunch&) = delete;
    PreparedLaunch& operator=(const PreparedLaunch&) = delete;
    PreparedLaunch(PreparedLaunch&&) = delete;
    PreparedLaunch& operator=(PreparedLaunch&&) = delete;

    [[nodiscard]] pid_t child_pid() const noexcept { return termination_->child_pid(); }
    [[nodiscard]] int pidfd() const noexcept { return termination_->pidfd(); }
    [[nodiscard]] const LaunchReadyRecord& ready_record() const noexcept { return ready_record_; }
    [[nodiscard]] const ValidatedPrelaunchContext& context() const noexcept { return context_; }
    [[nodiscard]] const std::vector<std::string>& expected_argv() const noexcept {
        return context_.collector_launch_argv();
    }
    [[nodiscard]] const std::string& working_directory_relative_path() const noexcept {
        return context_.namespace_relative_cwd();
    }
    [[nodiscard]] const std::vector<NamespaceFileExpectation>& expected_namespace_files() const noexcept {
        return expected_namespace_files_;
    }
    [[nodiscard]] const std::vector<NamespaceIdentityObservation>& namespace_identity_rows() const noexcept {
        return namespace_identity_rows_;
    }
    [[nodiscard]] bool released() const noexcept { return released_; }

    [[nodiscard]] PipePump& pipe_pump() noexcept { return *pipe_pump_; }
    [[nodiscard]] const PipePump& pipe_pump() const noexcept { return *pipe_pump_; }
    [[nodiscard]] ChildTerminationGuard& termination_guard() noexcept { return *termination_; }

    // Exactly one eventfd value of one releases the child.  The descriptor is
    // closed immediately afterward.  Repeated release is terminal misuse.
    void release_child();

private:
    friend class CaptureSession;
    friend class LaunchEngine;

    [[nodiscard]] ValidatedPrelaunchContext take_completed_context();

    PreparedLaunch(
        ValidatedPrelaunchContext context,
        std::unique_ptr<ChildTerminationGuard> termination,
        std::unique_ptr<PipePump> pipe_pump,
        OwnedFd release_writer,
        LaunchReadyRecord ready_record,
        std::vector<NamespaceFileExpectation> expected_namespace_files,
        std::vector<NamespaceIdentityObservation> namespace_identity_rows)
        : context_(std::move(context)),
          termination_(std::move(termination)),
          pipe_pump_(std::move(pipe_pump)),
          release_writer_(std::move(release_writer)),
          ready_record_(ready_record),
          expected_namespace_files_(std::move(expected_namespace_files)),
          namespace_identity_rows_(std::move(namespace_identity_rows)) {}

    // Declaration order keeps the context alive until every child-facing
    // resource and the termination guard have been destroyed.
    ValidatedPrelaunchContext context_;
    std::unique_ptr<ChildTerminationGuard> termination_;
    std::unique_ptr<PipePump> pipe_pump_;
    OwnedFd release_writer_;
    LaunchReadyRecord ready_record_{};
    std::vector<NamespaceFileExpectation> expected_namespace_files_;
    std::vector<NamespaceIdentityObservation> namespace_identity_rows_;
    bool released_ = false;
    bool context_taken_ = false;
};

// Linux-only, zero-authority launch mechanics.  This component does not attach
// ptrace, parse receipts, assemble a Capture V2 object, issue permits, access a
// holdout, modify an agent, or authorize an upload.
class LaunchEngine final {
public:
    static std::unique_ptr<PreparedLaunch> prepare(
        RetainedInputSet retained_inputs,
        ValidatedPrelaunchPlan validated_plan,
        LaunchRuntimeConfiguration runtime);
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_LAUNCH_ENGINE_H
