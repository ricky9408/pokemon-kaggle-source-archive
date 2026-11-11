#ifndef EVALUATION_V6_3_1_CAPTURE_V2_CAPTURE_OUTCOME_H
#define EVALUATION_V6_3_1_CAPTURE_V2_CAPTURE_OUTCOME_H

#include "PrelaunchContext.h"
#include "PrivateBridgeResult.h"
#include "PtraceOpenSupervisor.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <variant>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {

class CaptureSession;
class CompletedNativeCaptureSuccess;
namespace private_bridge_v3 {
[[nodiscard]] EncodeResult encode_private_capture_bridge_v3(
    CompletedNativeCaptureSuccess success) noexcept;
}
#if defined(EVALUATION_V631302_PRIVATE_BRIDGE_V3_TEST_ONLY)
class PrivateBridgeV3FixtureAccess;
#endif

class CaptureSessionSuccessAuthority final {
public:
    CaptureSessionSuccessAuthority(const CaptureSessionSuccessAuthority&) = delete;
    CaptureSessionSuccessAuthority& operator=(const CaptureSessionSuccessAuthority&) = delete;
    CaptureSessionSuccessAuthority(CaptureSessionSuccessAuthority&&) noexcept = default;
    CaptureSessionSuccessAuthority& operator=(CaptureSessionSuccessAuthority&&) = delete;

private:
    friend class CaptureSession;
#if defined(EVALUATION_V631302_PRIVATE_BRIDGE_V3_TEST_ONLY)
    friend class PrivateBridgeV3FixtureAccess;
#endif
    CaptureSessionSuccessAuthority() noexcept = default;
};

// These values are intentionally small and closed.  More detailed failure
// causes belong in a later binding; cleanup errno is kept separately below.
enum class FailureStage : std::uint8_t {
    Validate = 0u,
    Namespace = 1u,
    Harness = 2u,
    Launch = 3u,
    ExecAuthentication = 4u,
    ReceiptOpenRuntime = 5u,
    Termination = 6u,
    SuccessInvalid = 7u,
};

enum class FailureCode : std::uint8_t {
    Validate = 0u,
    Namespace = 1u,
    Harness = 2u,
    Launch = 3u,
    ExecAuthentication = 4u,
    ReceiptOpenRuntime = 5u,
    Termination = 6u,
    SuccessInvalid = 7u,
};

// A bounded, deterministic first/last-byte view of a stderr stream.  The
// accumulator never owns more than prefix_capacity + suffix_capacity bytes.
class StderrAccumulator final {
public:
    static constexpr std::size_t kMaximumRetainedBytes = 64u * 1024u;

    StderrAccumulator(std::size_t prefix_capacity, std::size_t suffix_capacity);

    StderrAccumulator(const StderrAccumulator&) = delete;
    StderrAccumulator& operator=(const StderrAccumulator&) = delete;
    StderrAccumulator(StderrAccumulator&&) noexcept = default;
    StderrAccumulator& operator=(StderrAccumulator&&) = delete;
    ~StderrAccumulator() noexcept = default;

    // Returns false on a uint64 total-byte overflow and leaves the accumulator
    // unchanged.  Normal appends are allocation-free after construction.
    [[nodiscard]] bool append(std::span<const std::uint8_t> bytes) noexcept;

    [[nodiscard]] std::uint64_t total_bytes() const noexcept { return total_bytes_; }
    [[nodiscard]] const std::vector<std::uint8_t>& prefix() const noexcept { return prefix_; }
    [[nodiscard]] const std::vector<std::uint8_t>& suffix() const noexcept { return suffix_; }
    [[nodiscard]] bool truncated() const noexcept { return truncated_; }

private:
    friend class NativeCaptureFailure;

    [[nodiscard]] std::vector<std::uint8_t> take_prefix() && noexcept {
        return std::move(prefix_);
    }
    [[nodiscard]] std::vector<std::uint8_t> take_suffix() && noexcept {
        return std::move(suffix_);
    }

    std::size_t prefix_capacity_;
    std::size_t suffix_capacity_;
    std::uint64_t total_bytes_ = 0u;
    std::vector<std::uint8_t> prefix_;
    std::vector<std::uint8_t> suffix_;
    bool truncated_ = false;
};

// The sole immutable success ownership boundary. Only CaptureSession can pair
// one final context with observations captured under that same hidden binding.
class CompletedNativeCaptureSuccess final {
public:
    static constexpr std::size_t kMaximumCollectorStdoutBytes =
        kRawCollectorCaptureMaxBytesV1;

    CompletedNativeCaptureSuccess(const CompletedNativeCaptureSuccess&) = delete;
    CompletedNativeCaptureSuccess& operator=(const CompletedNativeCaptureSuccess&) = delete;
    CompletedNativeCaptureSuccess(CompletedNativeCaptureSuccess&&) noexcept = default;
    CompletedNativeCaptureSuccess& operator=(CompletedNativeCaptureSuccess&&) = delete;
    ~CompletedNativeCaptureSuccess() noexcept = default;

    [[nodiscard]] const ValidatedPrelaunchContext&
    validated_prelaunch_context() const& noexcept {
        return context_;
    }
    const ValidatedPrelaunchContext&
    validated_prelaunch_context() const&& = delete;

private:
    friend class CaptureSession;
    friend private_bridge_v3::EncodeResult
    private_bridge_v3::encode_private_capture_bridge_v3(
        CompletedNativeCaptureSuccess success) noexcept;
#if defined(EVALUATION_V631302_PRIVATE_BRIDGE_V3_TEST_ONLY)
    friend class PrivateBridgeV3FixtureAccess;
#endif

    CompletedNativeCaptureSuccess(
        CaptureSessionSuccessAuthority authority,
        ValidatedPrelaunchContext context,
        CompletedNativeCaptureObservations observations,
        HarnessObservation harness_observation);

    static void validate_preconstruction(
        const ValidatedPrelaunchContext& context,
        const CompletedNativeCaptureObservations& observations,
        const HarnessObservation& harness_observation);

    [[nodiscard]] const RuntimeObjectEvidence&
    observed_collector_runtime_object() const;
    [[nodiscard]] const Sha256Digest32&
    validated_prelaunch_expectations_root() const noexcept {
        return context_.validated_prelaunch_expectations_root();
    }
    ValidatedPrelaunchContext context_;
    CompletedNativeCaptureObservations observations_;
    HarnessObservation harness_observation_;
};

// Diagnostics only.  This object deliberately has no observation, protocol,
// context, manifest, root, or bridge fields.
class NativeCaptureFailure final {
public:
    NativeCaptureFailure(const NativeCaptureFailure&) = delete;
    NativeCaptureFailure& operator=(const NativeCaptureFailure&) = delete;
    NativeCaptureFailure(NativeCaptureFailure&&) noexcept = default;
    NativeCaptureFailure& operator=(NativeCaptureFailure&&) = delete;
    ~NativeCaptureFailure() noexcept = default;

    [[nodiscard]] FailureStage stage() const noexcept { return stage_; }
    [[nodiscard]] FailureCode code() const noexcept { return code_; }
    [[nodiscard]] int primary_errno() const noexcept { return primary_errno_; }
    [[nodiscard]] int cleanup_errno() const noexcept { return cleanup_errno_; }
    [[nodiscard]] bool has_raw_wait_status() const noexcept {
        return raw_wait_status_present_;
    }
    [[nodiscard]] bool raw_wait_status_present() const noexcept {
        return raw_wait_status_present_;
    }
    [[nodiscard]] int raw_wait_status_value() const noexcept { return raw_wait_status_; }
    [[nodiscard]] std::optional<int> raw_wait_status() const noexcept {
        if (!raw_wait_status_present_) {
            return std::nullopt;
        }
        return raw_wait_status_;
    }
    [[nodiscard]] std::uint64_t stderr_total_bytes() const noexcept {
        return stderr_total_bytes_;
    }
    [[nodiscard]] const std::vector<std::uint8_t>& stderr_prefix() const noexcept {
        return stderr_prefix_;
    }
    [[nodiscard]] const std::vector<std::uint8_t>& stderr_suffix() const noexcept {
        return stderr_suffix_;
    }
    [[nodiscard]] bool stderr_truncated() const noexcept { return stderr_truncated_; }

private:
    friend class NativeCaptureFailureBuilder;

    NativeCaptureFailure(
        FailureStage stage,
        FailureCode code,
        int primary_errno,
        int cleanup_errno,
        bool raw_wait_status_present,
        int raw_wait_status,
        StderrAccumulator&& stderr) noexcept;

    FailureStage stage_;
    FailureCode code_;
    int primary_errno_;
    int cleanup_errno_;
    bool raw_wait_status_present_;
    int raw_wait_status_;
    std::uint64_t stderr_total_bytes_;
    std::vector<std::uint8_t> stderr_prefix_;
    std::vector<std::uint8_t> stderr_suffix_;
    bool stderr_truncated_;
};

// Latches the first primary failure and records the first nonzero cleanup
// errno without ever replacing the primary stage, code, or errno.
class NativeCaptureFailureBuilder final {
public:
    explicit NativeCaptureFailureBuilder(
        std::size_t stderr_prefix_capacity = 256u,
        std::size_t stderr_suffix_capacity = 256u);
    NativeCaptureFailureBuilder(
        FailureStage stage,
        FailureCode code,
        int primary_errno,
        std::size_t stderr_prefix_capacity = 256u,
        std::size_t stderr_suffix_capacity = 256u);

    NativeCaptureFailureBuilder(const NativeCaptureFailureBuilder&) = delete;
    NativeCaptureFailureBuilder& operator=(const NativeCaptureFailureBuilder&) = delete;
    NativeCaptureFailureBuilder(NativeCaptureFailureBuilder&&) noexcept = default;
    NativeCaptureFailureBuilder& operator=(NativeCaptureFailureBuilder&&) = delete;
    ~NativeCaptureFailureBuilder() noexcept = default;

    void latch_primary(
        FailureStage stage,
        FailureCode code,
        int primary_errno) noexcept;
    void record_cleanup_errno(int cleanup_errno) noexcept;
    [[nodiscard]] bool set_raw_wait_status(int raw_wait_status) noexcept;
    [[nodiscard]] bool append_stderr(std::span<const std::uint8_t> bytes) noexcept {
        return stderr_.append(bytes);
    }

    [[nodiscard]] NativeCaptureFailure finish() && noexcept;

private:
    FailureStage stage_;
    FailureCode code_;
    int primary_errno_;
    bool primary_latched_ = false;
    int cleanup_errno_ = 0;
    bool raw_wait_status_present_ = false;
    int raw_wait_status_ = 0;
    StderrAccumulator stderr_;
};

using CaptureSessionOutcome =
    std::variant<CompletedNativeCaptureSuccess, NativeCaptureFailure>;

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_CAPTURE_OUTCOME_H
