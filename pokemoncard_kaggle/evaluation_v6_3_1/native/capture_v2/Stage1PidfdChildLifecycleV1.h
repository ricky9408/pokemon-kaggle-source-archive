#pragma once

#if !defined(__linux__)
#error "Stage1PidfdChildLifecycleV1 is Linux-only"
#endif

#include <array>
#include <cstdint>
#include <ctime>

namespace pokemon::evaluation_v631302 {

// This candidate is a zero-authority Stage-1 primitive. It neither creates a
// child nor grants any launch, receipt, campaign, or upload authority.
inline constexpr bool kStage1PidfdChildLifecycleV1ZeroAuthority = true;
inline constexpr bool kStage1PidfdChildLifecycleV1UploadAuthority = false;

enum class Stage1PidfdTerminalExpectationV1 : std::uint8_t {
    NormalExitZero = 1,
    KilledBySigkill = 2,
};

enum class Stage1PidfdLifecycleStepV1 : std::uint8_t {
    KillSent = 1,
    KillEsrch = 2,
    PollReadable = 3,
    Inspect = 4,
    Reap = 5,
    Close = 6,
};

struct Stage1PidfdTerminalInfoV1 final {
    std::int64_t pid = 0;
    std::uint64_t uid = 0;
    std::int32_t code = 0;
    std::int32_t status = 0;

    [[nodiscard]] bool operator==(const Stage1PidfdTerminalInfoV1&) const noexcept = default;
};

struct Stage1PidfdLifecycleTraceV1 final {
    std::array<Stage1PidfdLifecycleStepV1, 5u> steps{};
    std::uint8_t step_count = 0;
    std::uint32_t inspection_options = 0;
    std::uint32_t reap_options = 0;
    Stage1PidfdTerminalInfoV1 inspected{};
    Stage1PidfdTerminalInfoV1 reaped{};
};

struct Stage1PidfdChildLifecycleRequestV1 final {
    int pidfd = -1;
    std::int64_t expected_pid = 0;
    timespec absolute_deadline{};
    Stage1PidfdTerminalExpectationV1 expectation =
        Stage1PidfdTerminalExpectationV1::NormalExitZero;
    bool send_sigkill = false;
};

struct Stage1PidfdChildLifecycleResultV1 final {
    Stage1PidfdTerminalInfoV1 terminal{};
    bool sigkill_returned_esrch = false;
    bool inspected = false;
    bool reaped = false;
    bool pidfd_closed = false;
    bool requires_immediate_pid1_exit = true;
};

// Validates the exact Stage-1 terminal-state contract without invoking the
// kernel. This mutation-test seam has no callbacks and no authority.
[[nodiscard]] bool validate_stage1_pidfd_lifecycle_trace_v1(
    const Stage1PidfdLifecycleTraceV1& trace,
    Stage1PidfdTerminalExpectationV1 expectation,
    std::int64_t expected_pid,
    const char** error_code) noexcept;

// Produces an absolute CLOCK_MONOTONIC deadline for a positive bounded budget.
[[nodiscard]] bool make_stage1_pidfd_monotonic_deadline_v1(
    std::uint64_t positive_milliseconds,
    timespec* absolute_deadline,
    const char** error_code) noexcept;

// Direct syscall-only lifecycle for a pidfd already returned by clone3 with
// CLONE_PIDFD. It polls to terminal readability, observes with WNOWAIT, reaps
// once, compares both observations, and closes the descriptor only after reaping.
// Once a valid request transfers child ownership into this function, any false
// result requires the caller to exit PID 1 immediately; ordinary pipeline work
// may never continue with a possibly live or unreaped namespace child.
[[nodiscard]] bool run_stage1_pidfd_child_lifecycle_v1(
    const Stage1PidfdChildLifecycleRequestV1& request,
    Stage1PidfdChildLifecycleResultV1* result,
    const char** error_code) noexcept;

}  // namespace pokemon::evaluation_v631302
