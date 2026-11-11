#include "Timeout.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <signal.h>
#include <stdexcept>
#include <system_error>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace capture = evaluation_v6_3_1::capture_v2;

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

int open_pidfd(pid_t pid) {
    const long descriptor = ::syscall(SYS_pidfd_open, pid, 0u);
    if (descriptor < 0 && (errno == ENOSYS || errno == EPERM)) {
        throw std::system_error(errno, std::generic_category(), "pidfd_open unavailable");
    }
    require(descriptor >= 0, "pidfd_open failed");
    return static_cast<int>(descriptor);
}

bool pidfd_available() {
    const long descriptor = ::syscall(SYS_pidfd_open, ::getpid(), 0u);
    if (descriptor >= 0) {
        require(::close(static_cast<int>(descriptor)) == 0, "pidfd probe close failed");
        return true;
    }
    if (errno == ENOSYS || errno == EPERM) {
        return false;
    }
    require(false, "pidfd probe failed");
    return false;
}

void send_signal_via_pidfd(int pidfd, int signal_number) {
    require(
        ::syscall(SYS_pidfd_send_signal, pidfd, signal_number, nullptr, 0u) == 0,
        "pidfd_send_signal failed");
}

pid_t sleeping_child() {
    const pid_t child = ::fork();
    require(child >= 0, "fork failed");
    if (child == 0) {
        for (;;) {
            ::pause();
        }
    }
    return child;
}

void require_no_zombie(pid_t child) {
    int status = 0;
    errno = 0;
    require(::waitpid(child, &status, WNOHANG | __WALL) == -1, "child was still waitable");
    require(errno == ECHILD, "reaped child was not released from the wait set");
}

void test_deadline_arithmetic() {
    capture::MonotonicDeadline deadline(3u);
    require(!deadline.expired(), "fresh deadline expired early");
    require(deadline.remaining_poll_timeout_ms() >= 1, "live deadline returned zero timeout");
    std::this_thread::sleep_for(std::chrono::milliseconds(8));
    require(deadline.expired(), "deadline did not expire");
    require(deadline.remaining_poll_timeout_ms() == 0, "expired deadline was pollable");

    bool zero_rejected = false;
    try {
        capture::MonotonicDeadline invalid(0u);
    } catch (const capture::TimeoutError& error) {
        zero_rejected = error.failure() == capture::TimeoutFailure::InvalidBudget;
    }
    require(zero_rejected, "zero timeout budget was accepted");

    capture::MonotonicDeadline maximum(std::numeric_limits<std::uint64_t>::max());
    require(
        maximum.remaining_poll_timeout_ms() == std::numeric_limits<int>::max(),
        "large timeout did not saturate poll timeout");
}

void test_abort_kills_and_reaps() {
    const pid_t child = sleeping_child();
    const int pidfd = open_pidfd(child);
    {
        capture::ChildTerminationGuard guard(child, pidfd);
        guard.abort();
        require(guard.reaped(), "abort did not mark guard reaped");
        require(guard.pidfd() == -1, "abort did not close pidfd");
        require(
            guard.terminal_wait_status().has_value() &&
                WIFSIGNALED(*guard.terminal_wait_status()) &&
                WTERMSIG(*guard.terminal_wait_status()) == SIGKILL,
            "abort did not retain the terminal SIGKILL wait status");
    }
    require_no_zombie(child);
}

void test_destructor_kills_and_reaps() {
    const pid_t child = sleeping_child();
    const int pidfd = open_pidfd(child);
    {
        capture::ChildTerminationGuard guard(child, pidfd);
    }
    require_no_zombie(child);
}

void test_normal_mark_reaped() {
    const pid_t child = sleeping_child();
    const int pidfd = open_pidfd(child);
    capture::ChildTerminationGuard guard(child, pidfd);
    send_signal_via_pidfd(pidfd, SIGTERM);
    int status = 0;
    require(::waitpid(child, &status, __WALL) == child, "caller waitpid failed");
    require(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM, "unexpected caller status");
    guard.mark_reaped(child, status);
    require(guard.reaped(), "normal mark did not mark guard reaped");

    bool double_mark_rejected = false;
    try {
        guard.mark_reaped(child, status);
    } catch (const capture::TimeoutError& error) {
        double_mark_rejected = error.failure() == capture::TimeoutFailure::DoubleMarkReaped;
    }
    require(double_mark_rejected, "double mark was accepted");
    require_no_zombie(child);
}

void test_already_exited_child_is_still_reaped() {
    const pid_t child = ::fork();
    require(child >= 0, "fork for exited child failed");
    if (child == 0) {
        _exit(0);
    }
    const int pidfd = open_pidfd(child);
    siginfo_t info{};
    require(
        ::waitid(P_PIDFD, static_cast<id_t>(pidfd), &info, WEXITED | WNOWAIT) == 0,
        "waitid for exited child failed");
    require(info.si_pid == child, "waitid did not observe exited child");
    capture::ChildTerminationGuard guard(child, pidfd);
    guard.abort();
    require(guard.reaped(), "exited child was not reaped by guard");
    require_no_zombie(child);
}

void test_failure_cases() {
    bool invalid_pid_rejected = false;
    try {
        capture::ChildTerminationGuard invalid(0, -1);
    } catch (const capture::TimeoutError& error) {
        invalid_pid_rejected = error.failure() == capture::TimeoutFailure::InvalidPid;
    }
    require(invalid_pid_rejected, "invalid PID was accepted");

    bool invalid_pidfd_rejected = false;
    try {
        capture::ChildTerminationGuard invalid(::getpid(), -1);
    } catch (const capture::TimeoutError& error) {
        invalid_pidfd_rejected = error.failure() == capture::TimeoutFailure::InvalidPidfd;
    }
    require(invalid_pidfd_rejected, "invalid pidfd was accepted");

    const pid_t first = sleeping_child();
    const pid_t second = sleeping_child();
    const int first_pidfd = open_pidfd(first);
    const int second_pidfd = open_pidfd(second);
    bool mismatch_rejected = false;
    try {
        capture::ChildTerminationGuard invalid(first, second_pidfd);
    } catch (const capture::TimeoutError& error) {
        mismatch_rejected = error.failure() == capture::TimeoutFailure::PidfdPidMismatch;
    }
    require(mismatch_rejected, "pidfd/PID mismatch was accepted");
    send_signal_via_pidfd(first_pidfd, SIGKILL);
    send_signal_via_pidfd(second_pidfd, SIGKILL);
    int status = 0;
    require(::waitpid(first, &status, __WALL) == first, "first cleanup wait failed");
    require(::waitpid(second, &status, __WALL) == second, "second cleanup wait failed");
    require(::close(first_pidfd) == 0, "first pidfd close failed");
    require(::close(second_pidfd) == 0, "second pidfd close failed");

    const int self_pidfd = open_pidfd(::getpid());
    bool non_child_rejected = false;
    try {
        capture::ChildTerminationGuard invalid(::getpid(), self_pidfd);
    } catch (const capture::TimeoutError& error) {
        non_child_rejected = error.failure() == capture::TimeoutFailure::NotDirectChild;
    }
    require(non_child_rejected, "non-child pidfd was accepted");
    require(::close(self_pidfd) == 0, "self pidfd close failed");

    int pipe_pair[2]{};
    require(::pipe(pipe_pair) == 0, "pipe setup failed");
    bool non_pidfd_rejected = false;
    try {
        capture::ChildTerminationGuard invalid(::getpid(), pipe_pair[0]);
    } catch (const capture::TimeoutError& error) {
        non_pidfd_rejected = error.failure() == capture::TimeoutFailure::InvalidPidfd;
    }
    require(non_pidfd_rejected, "non-pidfd descriptor was accepted");
    require(::close(pipe_pair[0]) == 0, "pipe read close failed");
    require(::close(pipe_pair[1]) == 0, "pipe write close failed");

    const pid_t child = sleeping_child();
    const int pidfd = open_pidfd(child);
    capture::ChildTerminationGuard guard(child, pidfd);
    bool indeterminate_rejected = false;
    try {
        guard.mark_reaped(child, 0x7f);
    } catch (const capture::TimeoutError& error) {
        indeterminate_rejected = error.failure() == capture::TimeoutFailure::InvalidWaitStatus;
    }
    require(indeterminate_rejected, "non-terminal wait status was accepted");
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view(argv[1]) == "deadline") {
        try {
            test_deadline_arithmetic();
        } catch (const std::exception& error) {
            std::cerr << "timeout deadline harness failure: " << error.what() << '\n';
            return EXIT_FAILURE;
        }
        std::cout << "timeout_deadline_harness_ok zero_authority=1\n";
        return EXIT_SUCCESS;
    }
    if (argc != 1) {
        return EXIT_FAILURE;
    }
    if (!pidfd_available()) {
        std::cout << "timeout_harness_skipped pidfd_unavailable=1\n";
        return 77;
    }
    try {
        test_abort_kills_and_reaps();
        test_destructor_kills_and_reaps();
        test_normal_mark_reaped();
        test_already_exited_child_is_still_reaped();
        test_failure_cases();
    } catch (const std::system_error& error) {
        if (std::string(error.what()).find("pidfd_open unavailable") != std::string::npos) {
            std::cout << "timeout_harness_skipped pidfd_unavailable=1\n";
            return 77;
        }
        std::cerr << "timeout harness failure: " << error.what() << '\n';
        return EXIT_FAILURE;
    } catch (const std::exception& error) {
        std::cerr << "timeout harness failure: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "timeout_harness_ok zero_authority=1\n";
    return EXIT_SUCCESS;
}
