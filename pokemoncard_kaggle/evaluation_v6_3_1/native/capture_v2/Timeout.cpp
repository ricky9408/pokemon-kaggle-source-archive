#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "Timeout.h"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <climits>
#include <cstdint>
#include <fcntl.h>
#include <limits>
#include <signal.h>
#include <string>
#include <string_view>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace evaluation_v6_3_1::capture_v2 {
namespace {

constexpr std::uint64_t kNanosecondsPerSecond = 1'000'000'000ULL;
constexpr std::uint64_t kNanosecondsPerMillisecond = 1'000'000ULL;
constexpr std::uint64_t kMillisecondsPerSecond = 1'000ULL;

[[noreturn]] void fail(TimeoutFailure failure, std::string message, int system_errno = 0) {
    throw TimeoutError(failure, std::move(message), system_errno);
}

timespec monotonic_now() {
    timespec value{};
    if (::clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
        fail(TimeoutFailure::ClockFailure, "CLOCK_MONOTONIC read failed", errno);
    }
    if (value.tv_sec < 0 || value.tv_nsec < 0 ||
        static_cast<std::uint64_t>(value.tv_nsec) >= kNanosecondsPerSecond) {
        fail(TimeoutFailure::ClockFailure, "CLOCK_MONOTONIC returned an invalid value");
    }
    return value;
}

std::uint64_t time_t_max_as_u64() {
    if constexpr (std::numeric_limits<time_t>::is_signed) {
        return static_cast<std::uint64_t>(std::numeric_limits<time_t>::max());
    }
    return std::numeric_limits<time_t>::max();
}

timespec make_deadline(std::uint64_t positive_milliseconds) {
    if (positive_milliseconds == 0u) {
        fail(TimeoutFailure::InvalidBudget, "timeout budget must be positive");
    }

    const timespec now = monotonic_now();
    const std::uint64_t now_seconds = static_cast<std::uint64_t>(now.tv_sec);
    const std::uint64_t budget_seconds = positive_milliseconds / kMillisecondsPerSecond;
    const std::uint64_t budget_milliseconds = positive_milliseconds % kMillisecondsPerSecond;
    const std::uint64_t budget_nanoseconds =
        budget_milliseconds * kNanosecondsPerMillisecond;

    std::uint64_t deadline_seconds = now_seconds;
    if (budget_seconds > time_t_max_as_u64() - deadline_seconds) {
        fail(TimeoutFailure::DeadlineOverflow, "timeout deadline overflows time_t");
    }
    deadline_seconds += budget_seconds;

    std::uint64_t deadline_nanoseconds =
        static_cast<std::uint64_t>(now.tv_nsec) + budget_nanoseconds;
    if (deadline_nanoseconds >= kNanosecondsPerSecond) {
        deadline_nanoseconds -= kNanosecondsPerSecond;
        if (deadline_seconds == time_t_max_as_u64()) {
            fail(TimeoutFailure::DeadlineOverflow, "timeout deadline overflows time_t");
        }
        ++deadline_seconds;
    }

    timespec deadline{};
    deadline.tv_sec = static_cast<time_t>(deadline_seconds);
    deadline.tv_nsec = static_cast<long>(deadline_nanoseconds);
    return deadline;
}

int saturating_poll_timeout(std::uint64_t seconds, std::uint64_t nanoseconds) {
    const std::uint64_t rounded_nanoseconds =
        (nanoseconds + kNanosecondsPerMillisecond - 1u) /
        kNanosecondsPerMillisecond;
    if (seconds > (static_cast<std::uint64_t>(INT_MAX) - 1u) /
                       kMillisecondsPerSecond) {
        return INT_MAX;
    }
    const std::uint64_t milliseconds =
        seconds * kMillisecondsPerSecond + rounded_nanoseconds;
    return milliseconds > static_cast<std::uint64_t>(INT_MAX)
               ? INT_MAX
               : static_cast<int>(milliseconds);
}

bool deadline_reached(const timespec& now, const timespec& deadline) noexcept {
    return now.tv_sec > deadline.tv_sec ||
           (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec);
}

std::uint64_t pidfd_target_pid(int pidfd) {
    const std::string path = "/proc/self/fdinfo/" + std::to_string(pidfd);
    const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        fail(TimeoutFailure::InvalidPidfd, "pidfd fdinfo cannot be opened", errno);
    }

    std::string contents;
    char buffer[512]{};
    for (;;) {
        const ssize_t count = ::read(descriptor, buffer, sizeof(buffer));
        if (count > 0) {
            contents.append(buffer, static_cast<std::size_t>(count));
            if (contents.size() > 16u * 1024u) {
                static_cast<void>(::close(descriptor));
                fail(TimeoutFailure::InvalidPidfd, "pidfd fdinfo is unexpectedly large");
            }
            continue;
        }
        if (count == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        const int error = errno;
        static_cast<void>(::close(descriptor));
        fail(TimeoutFailure::InvalidPidfd, "pidfd fdinfo read failed", error);
    }
    if (::close(descriptor) != 0) {
        fail(TimeoutFailure::InvalidPidfd, "pidfd fdinfo close failed", errno);
    }

    constexpr std::string_view kPidPrefix = "Pid:";
    std::size_t line_start = 0u;
    while (line_start < contents.size()) {
        const std::size_t line_end = contents.find('\n', line_start);
        const std::size_t end = line_end == std::string::npos ? contents.size() : line_end;
        const std::string_view line(contents.data() + line_start, end - line_start);
        if (line.substr(0u, kPidPrefix.size()) == kPidPrefix) {
            std::string_view digits = line.substr(kPidPrefix.size());
            while (!digits.empty() && (digits.front() == ' ' || digits.front() == '\t')) {
                digits.remove_prefix(1u);
            }
            std::uint64_t value = 0u;
            const auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), value);
            if (parsed.ec != std::errc{} || parsed.ptr != digits.data() + digits.size() ||
                value == 0u) {
                fail(TimeoutFailure::InvalidPidfd, "pidfd fdinfo contains an invalid Pid");
            }
            return value;
        }
        if (line_end == std::string::npos) {
            break;
        }
        line_start = line_end + 1u;
    }
    fail(TimeoutFailure::InvalidPidfd, "pidfd fdinfo has no Pid entry");
}

void validate_direct_child(pid_t child_pid, int pidfd) {
    const int descriptor_flags = ::fcntl(pidfd, F_GETFD);
    if (descriptor_flags < 0) {
        fail(TimeoutFailure::InvalidPidfd, "pidfd is not an open descriptor", errno);
    }
    if (pidfd_target_pid(pidfd) != static_cast<std::uint64_t>(child_pid)) {
        fail(TimeoutFailure::PidfdPidMismatch, "pidfd does not identify the supplied PID");
    }

    siginfo_t info{};
    if (::waitid(P_PIDFD, static_cast<id_t>(pidfd), &info, WEXITED | WNOHANG | WNOWAIT) != 0) {
        const int error = errno;
        if (error == ECHILD) {
            fail(TimeoutFailure::NotDirectChild, "pidfd target is not the caller's direct child", error);
        }
        fail(TimeoutFailure::InvalidPidfd, "pidfd direct-child validation failed", error);
    }
    // A terminal-but-unreaped direct child is still valid guard input.  The
    // pidfd remains stable and abort() will observe ESRCH, then reap it through
    // waitpid(..., __WALL).  Rejecting this state would create a launch/exit
    // race between atomic pidfd creation and guard construction.
}

void send_sigkill(int pidfd) {
    for (;;) {
        if (::syscall(SYS_pidfd_send_signal, pidfd, SIGKILL, nullptr, 0u) == 0) {
            return;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == ESRCH) {
            return;
        }
        fail(TimeoutFailure::SignalFailure, "pidfd_send_signal(SIGKILL) failed", errno);
    }
}

pid_t reap_with_wall(pid_t child_pid, int& wait_status) {
    for (;;) {
        const pid_t result = ::waitpid(child_pid, &wait_status, __WALL);
        if (result == child_pid) {
            return result;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result < 0) {
            fail(TimeoutFailure::ReapFailure, "waitpid(..., __WALL) failed", errno);
        }
        fail(TimeoutFailure::ReapFailure, "waitpid returned an unexpected child");
    }
}

bool is_terminal_wait_status(int wait_status) noexcept {
    return WIFEXITED(wait_status) || WIFSIGNALED(wait_status);
}

}  // namespace

MonotonicDeadline::MonotonicDeadline(std::uint64_t positive_milliseconds)
    : deadline_(make_deadline(positive_milliseconds)) {}

bool MonotonicDeadline::expired() const {
    return deadline_reached(monotonic_now(), deadline_);
}

int MonotonicDeadline::remaining_poll_timeout_ms() const {
    const timespec now = monotonic_now();
    if (deadline_reached(now, deadline_)) {
        return 0;
    }
    const std::uint64_t seconds =
        static_cast<std::uint64_t>(deadline_.tv_sec - now.tv_sec);
    if (deadline_.tv_nsec < now.tv_nsec) {
        const std::uint64_t nanoseconds =
            kNanosecondsPerSecond + static_cast<std::uint64_t>(deadline_.tv_nsec) -
            static_cast<std::uint64_t>(now.tv_nsec);
        return saturating_poll_timeout(seconds - 1u, nanoseconds);
    }
    const std::uint64_t nanoseconds =
        static_cast<std::uint64_t>(deadline_.tv_nsec) -
        static_cast<std::uint64_t>(now.tv_nsec);
    return saturating_poll_timeout(seconds, nanoseconds);
}

ChildTerminationGuard::ChildTerminationGuard(pid_t direct_child_pid, int pidfd)
    : child_pid_(direct_child_pid), pidfd_(pidfd), state_(ChildTerminationState::Armed) {
    if (direct_child_pid <= 0) {
        child_pid_ = -1;
        pidfd_ = -1;
        state_ = ChildTerminationState::MovedFrom;
        fail(TimeoutFailure::InvalidPid, "direct child PID must be positive");
    }
    if (pidfd < 0) {
        child_pid_ = -1;
        pidfd_ = -1;
        state_ = ChildTerminationState::MovedFrom;
        fail(TimeoutFailure::InvalidPidfd, "pidfd must be non-negative");
    }
    try {
        validate_direct_child(direct_child_pid, pidfd);
    } catch (...) {
        child_pid_ = -1;
        pidfd_ = -1;
        state_ = ChildTerminationState::MovedFrom;
        throw;
    }
}

ChildTerminationGuard::~ChildTerminationGuard() noexcept {
    abort_noexcept();
}

ChildTerminationGuard::ChildTerminationGuard(ChildTerminationGuard&& other) noexcept
    : child_pid_(other.child_pid_),
      pidfd_(other.pidfd_),
      state_(other.state_),
      terminal_wait_status_(other.terminal_wait_status_) {
    other.child_pid_ = -1;
    other.pidfd_ = -1;
    other.state_ = ChildTerminationState::MovedFrom;
    other.terminal_wait_status_.reset();
}

ChildTerminationGuard& ChildTerminationGuard::operator=(ChildTerminationGuard&& other) noexcept {
    if (this != &other) {
        abort_noexcept();
        child_pid_ = other.child_pid_;
        pidfd_ = other.pidfd_;
        state_ = other.state_;
        terminal_wait_status_ = other.terminal_wait_status_;
        other.child_pid_ = -1;
        other.pidfd_ = -1;
        other.state_ = ChildTerminationState::MovedFrom;
        other.terminal_wait_status_.reset();
    }
    return *this;
}

void ChildTerminationGuard::require_armed() const {
    if (state_ == ChildTerminationState::Reaped) {
        fail(TimeoutFailure::DoubleMarkReaped, "child termination guard is already reaped");
    }
    if (state_ != ChildTerminationState::Armed || child_pid_ <= 0 || pidfd_ < 0) {
        fail(TimeoutFailure::InvalidState, "child termination guard is not armed");
    }
}

void ChildTerminationGuard::close_pidfd() {
    if (pidfd_ < 0) {
        fail(TimeoutFailure::InvalidState, "pidfd was already closed");
    }
    const int descriptor = pidfd_;
    pidfd_ = -1;
    if (::close(descriptor) != 0) {
        state_ = ChildTerminationState::Indeterminate;
        fail(TimeoutFailure::CloseFailure, "pidfd close failed", errno);
    }
}

void ChildTerminationGuard::complete_reap(int wait_status) {
    if (!is_terminal_wait_status(wait_status)) {
        fail(TimeoutFailure::InvalidWaitStatus, "wait status is not terminal");
    }
    terminal_wait_status_ = wait_status;
    close_pidfd();
    state_ = ChildTerminationState::Reaped;
}

void ChildTerminationGuard::mark_reaped(pid_t observed_pid, int observed_wait_status) {
    require_armed();
    if (observed_pid != child_pid_) {
        fail(TimeoutFailure::InvalidWaitStatus, "wait status belongs to another PID");
    }
    complete_reap(observed_wait_status);
}

void ChildTerminationGuard::abort() {
    require_armed();
    send_sigkill(pidfd_);
    int wait_status = 0;
    static_cast<void>(reap_with_wall(child_pid_, wait_status));
    complete_reap(wait_status);
}

void ChildTerminationGuard::abort_noexcept() noexcept {
    if (state_ != ChildTerminationState::Armed || child_pid_ <= 0 || pidfd_ < 0) {
        return;
    }

    for (;;) {
        if (::syscall(SYS_pidfd_send_signal, pidfd_, SIGKILL, nullptr, 0u) == 0 ||
            errno == ESRCH) {
            break;
        }
        if (errno != EINTR) {
            break;
        }
    }

    int wait_status = 0;
    bool reaped_child = false;
    for (;;) {
        const pid_t result = ::waitpid(child_pid_, &wait_status, __WALL);
        if (result == child_pid_) {
            reaped_child = true;
            break;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        break;
    }

    const int descriptor = pidfd_;
    pidfd_ = -1;
    const bool closed = ::close(descriptor) == 0;
    if (reaped_child && is_terminal_wait_status(wait_status)) {
        terminal_wait_status_ = wait_status;
    }
    state_ = reaped_child && is_terminal_wait_status(wait_status) && closed
                 ? ChildTerminationState::Reaped
                 : ChildTerminationState::Indeterminate;
}

}  // namespace evaluation_v6_3_1::capture_v2
