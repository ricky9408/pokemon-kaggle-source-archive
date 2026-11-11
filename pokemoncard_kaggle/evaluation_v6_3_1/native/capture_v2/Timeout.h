#ifndef EVALUATION_V6_3_1_CAPTURE_V2_TIMEOUT_H
#define EVALUATION_V6_3_1_CAPTURE_V2_TIMEOUT_H

#if !defined(__linux__)
#error "Timeout is a Linux-only Capture V2 component"
#endif

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <time.h>
#include <utility>

namespace evaluation_v6_3_1::capture_v2 {

enum class TimeoutFailure : std::uint32_t {
    InvalidBudget = 1,
    ClockFailure = 2,
    DeadlineOverflow = 3,
    InvalidPid = 4,
    InvalidPidfd = 5,
    PidfdPidMismatch = 6,
    NotDirectChild = 7,
    AlreadyTerminated = 8,
    InvalidState = 9,
    InvalidWaitStatus = 10,
    DoubleMarkReaped = 11,
    SignalFailure = 12,
    ReapFailure = 13,
    CloseFailure = 14,
};

class TimeoutError final : public std::runtime_error {
public:
    TimeoutError(TimeoutFailure failure, std::string message, int system_errno = 0)
        : std::runtime_error(std::move(message)), failure_(failure), system_errno_(system_errno) {}

    [[nodiscard]] TimeoutFailure failure() const noexcept { return failure_; }
    [[nodiscard]] int system_errno() const noexcept { return system_errno_; }

private:
    TimeoutFailure failure_;
    int system_errno_;
};

// A CLOCK_MONOTONIC deadline.  The budget is an explicit, positive millisecond
// value; it is never derived from wall-clock time or a floating-point duration.
class MonotonicDeadline final {
public:
    explicit MonotonicDeadline(std::uint64_t positive_milliseconds);

    [[nodiscard]] static MonotonicDeadline from_milliseconds(
        std::uint64_t positive_milliseconds) {
        return MonotonicDeadline(positive_milliseconds);
    }

    [[nodiscard]] bool expired() const;

    // poll(2)/ppoll-adjacent timeout in milliseconds.  A live sub-millisecond
    // remainder rounds up to one, while a large remainder saturates at INT_MAX.
    [[nodiscard]] int remaining_poll_timeout_ms() const;

    [[nodiscard]] timespec deadline() const noexcept { return deadline_; }

private:
    timespec deadline_{};
};

using Timeout = MonotonicDeadline;

enum class ChildTerminationState : std::uint8_t {
    Armed,
    Reaped,
    MovedFrom,
    Indeterminate,
};

// Owns one already-created pidfd for one validated direct child.  This is a
// termination/reaping primitive only; it does not launch, trace, or authorize
// any higher-level Capture V2 operation.
class ChildTerminationGuard final {
public:
    ChildTerminationGuard(pid_t direct_child_pid, int pidfd);
    ~ChildTerminationGuard() noexcept;

    ChildTerminationGuard(const ChildTerminationGuard&) = delete;
    ChildTerminationGuard& operator=(const ChildTerminationGuard&) = delete;

    ChildTerminationGuard(ChildTerminationGuard&& other) noexcept;
    ChildTerminationGuard& operator=(ChildTerminationGuard&& other) noexcept;

    [[nodiscard]] pid_t child_pid() const noexcept { return child_pid_; }
    [[nodiscard]] int pidfd() const noexcept { return pidfd_; }
    [[nodiscard]] ChildTerminationState state() const noexcept { return state_; }
    [[nodiscard]] bool reaped() const noexcept {
        return state_ == ChildTerminationState::Reaped;
    }
    [[nodiscard]] std::optional<int> terminal_wait_status() const noexcept {
        return terminal_wait_status_;
    }

    // The caller must pass the pid and terminal status returned by its own
    // waitpid(..., __WALL) observation.  The guard never infers this state.
    void mark_reaped(pid_t observed_pid, int observed_wait_status);
    void mark_reaped(int observed_wait_status) {
        mark_reaped(child_pid_, observed_wait_status);
    }

    // Abort sends SIGKILL through the owned pidfd and then reaps the direct
    // child with waitpid(..., __WALL).  It never falls back to a numeric PID.
    void abort();
    void terminate_and_reap() { abort(); }

private:
    void require_armed() const;
    void close_pidfd();
    void complete_reap(int wait_status);
    void abort_noexcept() noexcept;

    pid_t child_pid_ = -1;
    int pidfd_ = -1;
    ChildTerminationState state_ = ChildTerminationState::MovedFrom;
    std::optional<int> terminal_wait_status_;
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_TIMEOUT_H
