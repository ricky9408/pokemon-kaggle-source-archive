#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "Stage1PidfdChildLifecycleV1.h"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <linux/sched.h>
#include <signal.h>
#include <string_view>
#include <sys/syscall.h>
#include <unistd.h>

namespace {

using pokemon::evaluation_v631302::Stage1PidfdChildLifecycleRequestV1;
using pokemon::evaluation_v631302::Stage1PidfdChildLifecycleResultV1;
using pokemon::evaluation_v631302::Stage1PidfdLifecycleStepV1;
using pokemon::evaluation_v631302::Stage1PidfdLifecycleTraceV1;
using pokemon::evaluation_v631302::Stage1PidfdTerminalExpectationV1;
using pokemon::evaluation_v631302::Stage1PidfdTerminalInfoV1;

Stage1PidfdTerminalInfoV1 normal_terminal() {
    return Stage1PidfdTerminalInfoV1{42, 1000u, CLD_EXITED, 0};
}

Stage1PidfdTerminalInfoV1 killed_terminal() {
    return Stage1PidfdTerminalInfoV1{42, 1000u, CLD_KILLED, SIGKILL};
}

int run_trace(std::string_view scenario) {
    Stage1PidfdLifecycleTraceV1 trace{};
    Stage1PidfdTerminalExpectationV1 expectation =
        Stage1PidfdTerminalExpectationV1::NormalExitZero;
    trace.steps = {
        Stage1PidfdLifecycleStepV1::PollReadable,
        Stage1PidfdLifecycleStepV1::Inspect,
        Stage1PidfdLifecycleStepV1::Reap,
        Stage1PidfdLifecycleStepV1::Close,
        Stage1PidfdLifecycleStepV1::Close,
    };
    trace.step_count = 4u;
    trace.inspection_options = static_cast<std::uint32_t>(WEXITED | WNOWAIT);
    trace.reap_options = static_cast<std::uint32_t>(WEXITED);
    trace.inspected = normal_terminal();
    trace.reaped = normal_terminal();

    if (scenario == "valid") {
        // Exact normal-exit trace above.
    } else if (scenario == "valid-kill-esrch") {
        trace.steps = {
            Stage1PidfdLifecycleStepV1::KillEsrch,
            Stage1PidfdLifecycleStepV1::PollReadable,
            Stage1PidfdLifecycleStepV1::Inspect,
            Stage1PidfdLifecycleStepV1::Reap,
            Stage1PidfdLifecycleStepV1::Close,
        };
        trace.step_count = 5u;
        trace.inspected = killed_terminal();
        trace.reaped = killed_terminal();
        expectation = Stage1PidfdTerminalExpectationV1::KilledBySigkill;
    } else if (scenario == "reap-before-inspect") {
        trace.steps[1] = Stage1PidfdLifecycleStepV1::Reap;
        trace.steps[2] = Stage1PidfdLifecycleStepV1::Inspect;
    } else if (scenario == "close-before-reap") {
        trace.steps[2] = Stage1PidfdLifecycleStepV1::Close;
        trace.steps[3] = Stage1PidfdLifecycleStepV1::Reap;
    } else if (scenario == "wnohang") {
        trace.inspection_options |= static_cast<std::uint32_t>(WNOHANG);
    } else if (scenario == "mismatch") {
        trace.reaped.status = 1;
    } else if (scenario == "pid-mismatch") {
        trace.reaped.pid = 43;
        trace.inspected.pid = 43;
    } else if (scenario == "exit-127") {
        trace.inspected.status = 127;
        trace.reaped.status = 127;
    } else if (scenario == "missing-reap") {
        trace.step_count = 3u;
    } else {
        return 64;
    }

    const char* error = nullptr;
    const bool accepted = pokemon::evaluation_v631302::validate_stage1_pidfd_lifecycle_trace_v1(
        trace, expectation, 42, &error);
    if (!accepted) {
        std::cerr << (error == nullptr ? "STAGE1_PIDFD_TRACE_REJECTED" : error) << '\n';
        return 65;
    }
    std::cout << "STAGE1_PIDFD_TRACE_VALID\n";
    return 0;
}

bool make_deadline(timespec* value) {
    const char* error = nullptr;
    if (!pokemon::evaluation_v631302::make_stage1_pidfd_monotonic_deadline_v1(
            5'000u, value, &error)) {
        std::cerr << (error == nullptr ? "STAGE1_PIDFD_DEADLINE_FAILED" : error) << '\n';
        return false;
    }
    return true;
}

int run_direct(std::string_view scenario) {
    const bool deliberate_kill = scenario == "kill";
    if (!deliberate_kill && scenario != "normal") {
        return 64;
    }

    int pidfd = -1;
    clone_args arguments{};
    arguments.flags = CLONE_PIDFD;
    arguments.pidfd = static_cast<std::uint64_t>(
        reinterpret_cast<std::uintptr_t>(&pidfd));
    arguments.exit_signal = static_cast<std::uint64_t>(SIGCHLD);
    errno = 0;
    const long clone_result = ::syscall(SYS_clone3, &arguments, sizeof(arguments));
    if (clone_result < 0) {
        if (errno == ENOSYS) {
            std::cerr << "STAGE1_PIDFD_CLONE3_UNSUPPORTED_ENOSYS\n";
            return 77;
        }
        if (errno == EINVAL) {
            std::cerr << "STAGE1_PIDFD_CLONE_PIDFD_UNSUPPORTED_EINVAL\n";
            return 78;
        }
        std::cerr << "STAGE1_PIDFD_CLONE3_FAILED_" << errno << '\n';
        return 65;
    }
    if (clone_result == 0) {
        if (!deliberate_kill) {
            static_cast<void>(::syscall(SYS_exit_group, 0));
        }
        for (;;) {
            static_cast<void>(::syscall(SYS_pause));
        }
    }
    if (pidfd < 0 || pidfd == std::numeric_limits<int>::max()) {
        std::cerr << "STAGE1_PIDFD_CLONE_RESULT_INVALID\n";
        return 65;
    }

    timespec deadline{};
    if (!make_deadline(&deadline)) {
        return 65;
    }
    Stage1PidfdChildLifecycleRequestV1 request{};
    request.pidfd = pidfd;
    request.expected_pid = clone_result;
    request.absolute_deadline = deadline;
    request.send_sigkill = deliberate_kill;
    request.expectation = deliberate_kill
                              ? Stage1PidfdTerminalExpectationV1::KilledBySigkill
                              : Stage1PidfdTerminalExpectationV1::NormalExitZero;
    Stage1PidfdChildLifecycleResultV1 result{};
    const char* error = nullptr;
    if (!pokemon::evaluation_v631302::run_stage1_pidfd_child_lifecycle_v1(
            request, &result, &error)) {
        std::cerr << (error == nullptr ? "STAGE1_PIDFD_DIRECT_FAILED" : error) << '\n';
        return 65;
    }
    if (!result.inspected || !result.reaped || !result.pidfd_closed ||
        result.requires_immediate_pid1_exit || result.terminal.pid != clone_result ||
        (deliberate_kill && result.terminal.code != CLD_KILLED) ||
        (!deliberate_kill && result.terminal.code != CLD_EXITED)) {
        std::cerr << "STAGE1_PIDFD_DIRECT_RESULT_INVALID\n";
        return 65;
    }
    std::cout << "STAGE1_PIDFD_DIRECT_VALID " << result.terminal.pid << ' '
              << result.terminal.uid << ' ' << result.terminal.code << ' '
              << result.terminal.status << ' ' << result.sigkill_returned_esrch << '\n';
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        return 64;
    }
    const std::string_view mode(argv[1]);
    if (mode == "trace") {
        return run_trace(argv[2]);
    }
    if (mode == "direct") {
        return run_direct(argv[2]);
    }
    return 64;
}
