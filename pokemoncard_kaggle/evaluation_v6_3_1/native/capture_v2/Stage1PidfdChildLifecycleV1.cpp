#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "Stage1PidfdChildLifecycleV1.h"

#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace pokemon::evaluation_v631302 {
namespace {

constexpr std::uint64_t kNanosecondsPerSecond = 1'000'000'000u;
constexpr std::uint64_t kNanosecondsPerMillisecond = 1'000'000u;
constexpr std::uint64_t kMillisecondsPerSecond = 1'000u;
static_assert(sizeof(time_t) == 8u);

void set_error(const char* value, const char** error_code) noexcept {
    if (error_code != nullptr) {
        *error_code = value;
    }
}

bool valid_deadline(const timespec& value) noexcept {
    return value.tv_sec >= 0 && value.tv_nsec >= 0 &&
           static_cast<std::uint64_t>(value.tv_nsec) < kNanosecondsPerSecond;
}

int compare_timespec(const timespec& left, const timespec& right) noexcept {
    if (left.tv_sec != right.tv_sec) {
        return left.tv_sec < right.tv_sec ? -1 : 1;
    }
    if (left.tv_nsec != right.tv_nsec) {
        return left.tv_nsec < right.tv_nsec ? -1 : 1;
    }
    return 0;
}

bool remaining_until_deadline(
    const timespec& absolute_deadline,
    timespec* remaining,
    const char** error_code) noexcept {
    timespec now{};
    if (::clock_gettime(CLOCK_MONOTONIC, &now) != 0 || !valid_deadline(now)) {
        set_error("STAGE1_PIDFD_CLOCK_MONOTONIC_FAILED", error_code);
        return false;
    }
    if (compare_timespec(now, absolute_deadline) >= 0) {
        set_error("STAGE1_PIDFD_DEADLINE_EXPIRED", error_code);
        return false;
    }

    remaining->tv_sec = absolute_deadline.tv_sec - now.tv_sec;
    remaining->tv_nsec = absolute_deadline.tv_nsec - now.tv_nsec;
    if (remaining->tv_nsec < 0) {
        --remaining->tv_sec;
        remaining->tv_nsec += static_cast<long>(kNanosecondsPerSecond);
    }
    if (remaining->tv_sec < 0 || !valid_deadline(*remaining)) {
        set_error("STAGE1_PIDFD_DEADLINE_INVALID", error_code);
        return false;
    }
    return true;
}

bool poll_pidfd_readable(
    int pidfd,
    const timespec& absolute_deadline,
    const char** error_code) noexcept {
    for (;;) {
        timespec remaining{};
        if (!remaining_until_deadline(absolute_deadline, &remaining, error_code)) {
            return false;
        }

        pollfd descriptor{};
        descriptor.fd = pidfd;
        descriptor.events = POLLIN;
        const int poll_result = ::ppoll(&descriptor, 1u, &remaining, nullptr);
        if (poll_result > 0) {
            if ((descriptor.revents & POLLIN) == 0 ||
                (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                set_error("STAGE1_PIDFD_POLL_REVENTS_INVALID", error_code);
                return false;
            }
            return true;
        }
        if (poll_result == 0) {
            set_error("STAGE1_PIDFD_DEADLINE_EXPIRED", error_code);
            return false;
        }
        if (errno == EINTR) {
            continue;
        }
        set_error("STAGE1_PIDFD_POLL_FAILED", error_code);
        return false;
    }
}

bool send_sigkill_by_pidfd(int pidfd, bool* saw_esrch, const char** error_code) noexcept {
    for (;;) {
        if (::syscall(SYS_pidfd_send_signal, pidfd, SIGKILL, nullptr, 0u) == 0) {
            *saw_esrch = false;
            return true;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == ESRCH) {
            // ESRCH means only that terminal state may already be observable.
            *saw_esrch = true;
            return true;
        }
        set_error("STAGE1_PIDFD_SEND_SIGKILL_FAILED", error_code);
        return false;
    }
}

bool convert_siginfo(
    const siginfo_t& source,
    Stage1PidfdTerminalInfoV1* target,
    const char** error_code) noexcept {
    if (source.si_pid <= 0) {
        set_error("STAGE1_PIDFD_SIGINFO_PID_INVALID", error_code);
        return false;
    }
    target->pid = static_cast<std::int64_t>(source.si_pid);
    target->uid = static_cast<std::uint64_t>(source.si_uid);
    target->code = static_cast<std::int32_t>(source.si_code);
    target->status = static_cast<std::int32_t>(source.si_status);
    return true;
}

bool waitid_pidfd_once(
    int pidfd,
    int options,
    Stage1PidfdTerminalInfoV1* target,
    const char** error_code) noexcept {
    for (;;) {
        siginfo_t info{};
        if (::waitid(P_PIDFD, static_cast<id_t>(pidfd), &info, options) == 0) {
            return convert_siginfo(info, target, error_code);
        }
        if (errno == EINTR) {
            continue;
        }
        set_error("STAGE1_PIDFD_WAITID_FAILED", error_code);
        return false;
    }
}

bool terminal_matches_expectation(
    const Stage1PidfdTerminalInfoV1& value,
    Stage1PidfdTerminalExpectationV1 expectation) noexcept {
    switch (expectation) {
        case Stage1PidfdTerminalExpectationV1::NormalExitZero:
            return value.code == CLD_EXITED && value.status == 0;
        case Stage1PidfdTerminalExpectationV1::KilledBySigkill:
            return value.code == CLD_KILLED && value.status == SIGKILL;
    }
    return false;
}

bool has_exact_steps(
    const Stage1PidfdLifecycleTraceV1& trace,
    bool sent_sigkill) noexcept {
    const std::uint8_t expected_count = sent_sigkill ? 5u : 4u;
    if (trace.step_count != expected_count) {
        return false;
    }
    std::size_t offset = 0u;
    if (sent_sigkill) {
        if (trace.steps[0] != Stage1PidfdLifecycleStepV1::KillSent &&
            trace.steps[0] != Stage1PidfdLifecycleStepV1::KillEsrch) {
            return false;
        }
        offset = 1u;
    }
    return trace.steps[offset] == Stage1PidfdLifecycleStepV1::PollReadable &&
           trace.steps[offset + 1u] == Stage1PidfdLifecycleStepV1::Inspect &&
           trace.steps[offset + 2u] == Stage1PidfdLifecycleStepV1::Reap &&
           trace.steps[offset + 3u] == Stage1PidfdLifecycleStepV1::Close;
}

}  // namespace

bool validate_stage1_pidfd_lifecycle_trace_v1(
    const Stage1PidfdLifecycleTraceV1& trace,
    Stage1PidfdTerminalExpectationV1 expectation,
    const std::int64_t expected_pid,
    const char** error_code) noexcept {
    set_error(nullptr, error_code);
    const bool sent_sigkill = trace.step_count == 5u;
    if (!has_exact_steps(trace, sent_sigkill)) {
        set_error("STAGE1_PIDFD_TRACE_ORDER_INVALID", error_code);
        return false;
    }
    if (trace.inspection_options != static_cast<std::uint32_t>(WEXITED | WNOWAIT) ||
        trace.reap_options != static_cast<std::uint32_t>(WEXITED)) {
        set_error("STAGE1_PIDFD_WAIT_OPTIONS_INVALID", error_code);
        return false;
    }
    if (trace.inspected != trace.reaped) {
        set_error("STAGE1_PIDFD_WAIT_OBSERVATIONS_DIFFER", error_code);
        return false;
    }
    if (expected_pid <= 0 || trace.inspected.pid != expected_pid) {
        set_error("STAGE1_PIDFD_TERMINAL_PID_INVALID", error_code);
        return false;
    }
    if (!terminal_matches_expectation(trace.inspected, expectation)) {
        set_error("STAGE1_PIDFD_TERMINAL_EXPECTATION_FAILED", error_code);
        return false;
    }
    return true;
}

bool make_stage1_pidfd_monotonic_deadline_v1(
    std::uint64_t positive_milliseconds,
    timespec* absolute_deadline,
    const char** error_code) noexcept {
    set_error(nullptr, error_code);
    if (positive_milliseconds == 0u || absolute_deadline == nullptr) {
        set_error("STAGE1_PIDFD_DEADLINE_ARGUMENT_INVALID", error_code);
        return false;
    }

    timespec now{};
    if (::clock_gettime(CLOCK_MONOTONIC, &now) != 0 || !valid_deadline(now)) {
        set_error("STAGE1_PIDFD_CLOCK_MONOTONIC_FAILED", error_code);
        return false;
    }
    const std::uint64_t seconds = positive_milliseconds / kMillisecondsPerSecond;
    const std::uint64_t nanoseconds =
        (positive_milliseconds % kMillisecondsPerSecond) * kNanosecondsPerMillisecond;
    if (seconds > static_cast<std::uint64_t>(LLONG_MAX) -
                      static_cast<std::uint64_t>(now.tv_sec)) {
        set_error("STAGE1_PIDFD_DEADLINE_OVERFLOW", error_code);
        return false;
    }
    std::uint64_t deadline_seconds = static_cast<std::uint64_t>(now.tv_sec) + seconds;
    std::uint64_t deadline_nanoseconds = static_cast<std::uint64_t>(now.tv_nsec) + nanoseconds;
    if (deadline_nanoseconds >= kNanosecondsPerSecond) {
        deadline_nanoseconds -= kNanosecondsPerSecond;
        if (deadline_seconds == static_cast<std::uint64_t>(LLONG_MAX)) {
            set_error("STAGE1_PIDFD_DEADLINE_OVERFLOW", error_code);
            return false;
        }
        ++deadline_seconds;
    }
    absolute_deadline->tv_sec = static_cast<time_t>(deadline_seconds);
    absolute_deadline->tv_nsec = static_cast<long>(deadline_nanoseconds);
    return true;
}

bool run_stage1_pidfd_child_lifecycle_v1(
    const Stage1PidfdChildLifecycleRequestV1& request,
    Stage1PidfdChildLifecycleResultV1* result,
    const char** error_code) noexcept {
    set_error(nullptr, error_code);
    if (result == nullptr || request.pidfd < 0 || request.expected_pid <= 0 ||
        !valid_deadline(request.absolute_deadline)) {
        set_error("STAGE1_PIDFD_REQUEST_INVALID", error_code);
        return false;
    }
    *result = Stage1PidfdChildLifecycleResultV1{};
    if (::fcntl(request.pidfd, F_GETFD) < 0) {
        set_error("STAGE1_PIDFD_DESCRIPTOR_INVALID", error_code);
        return false;
    }

    Stage1PidfdLifecycleTraceV1 trace{};
    if (request.send_sigkill) {
        bool saw_esrch = false;
        if (!send_sigkill_by_pidfd(request.pidfd, &saw_esrch, error_code)) {
            return false;
        }
        result->sigkill_returned_esrch = saw_esrch;
        trace.steps[trace.step_count++] = saw_esrch ? Stage1PidfdLifecycleStepV1::KillEsrch
                                                     : Stage1PidfdLifecycleStepV1::KillSent;
    }

    if (!poll_pidfd_readable(request.pidfd, request.absolute_deadline, error_code)) {
        return false;
    }
    trace.steps[trace.step_count++] = Stage1PidfdLifecycleStepV1::PollReadable;

    trace.inspection_options = static_cast<std::uint32_t>(WEXITED | WNOWAIT);
    if (!waitid_pidfd_once(
            request.pidfd,
            static_cast<int>(trace.inspection_options),
            &trace.inspected,
            error_code)) {
        return false;
    }
    result->inspected = true;
    trace.steps[trace.step_count++] = Stage1PidfdLifecycleStepV1::Inspect;

    const bool inspection_pid_valid =
        trace.inspected.pid == request.expected_pid;
    const bool inspection_terminal_valid =
        terminal_matches_expectation(trace.inspected, request.expectation);

    trace.reap_options = static_cast<std::uint32_t>(WEXITED);
    if (!waitid_pidfd_once(
            request.pidfd,
            static_cast<int>(trace.reap_options),
            &trace.reaped,
            error_code)) {
        return false;
    }
    result->reaped = true;
    result->terminal = trace.reaped;
    trace.steps[trace.step_count++] = Stage1PidfdLifecycleStepV1::Reap;
    const bool observations_match = trace.inspected == trace.reaped;
    if (::close(request.pidfd) != 0) {
        set_error("STAGE1_PIDFD_CLOSE_FAILED", error_code);
        return false;
    }
    result->pidfd_closed = true;
    trace.steps[trace.step_count++] = Stage1PidfdLifecycleStepV1::Close;

    if (!inspection_pid_valid) {
        set_error("STAGE1_PIDFD_TERMINAL_PID_INVALID", error_code);
        return false;
    }
    if (!inspection_terminal_valid) {
        set_error("STAGE1_PIDFD_TERMINAL_EXPECTATION_FAILED", error_code);
        return false;
    }
    if (!observations_match) {
        set_error("STAGE1_PIDFD_WAIT_OBSERVATIONS_DIFFER", error_code);
        return false;
    }

    const char* trace_error = nullptr;
    const bool trace_valid = validate_stage1_pidfd_lifecycle_trace_v1(
        trace, request.expectation, request.expected_pid, &trace_error);
    if (!trace_valid) {
        set_error(trace_error, error_code);
        return false;
    }
    result->requires_immediate_pid1_exit = false;
    return true;
}

}  // namespace pokemon::evaluation_v631302
