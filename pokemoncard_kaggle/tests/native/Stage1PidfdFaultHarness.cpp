#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "Stage1PidfdChildLifecycleV1.h"

#include <cerrno>
#include <cstdarg>
#include <cstring>
#include <iostream>
#include <poll.h>
#include <signal.h>
#include <string>
#include <string_view>
#include <sys/syscall.h>
#include <sys/wait.h>

namespace {

enum class Scenario {
    Valid,
    KillEsrch,
    FcntlFailure,
    SignalFailure,
    PollFailure,
    InspectFailure,
    WrongPid,
    Exit127,
    ReapFailure,
    ObservationMismatch,
    CloseFailure,
};

Scenario scenario = Scenario::Valid;
std::string events;

void record(const std::string_view value) {
    events.append(value);
    events.push_back(';');
}

bool select_scenario(const std::string_view value) {
    if (value == "valid") {
        scenario = Scenario::Valid;
    } else if (value == "kill-esrch") {
        scenario = Scenario::KillEsrch;
    } else if (value == "fcntl-failure") {
        scenario = Scenario::FcntlFailure;
    } else if (value == "signal-failure") {
        scenario = Scenario::SignalFailure;
    } else if (value == "poll-failure") {
        scenario = Scenario::PollFailure;
    } else if (value == "inspect-failure") {
        scenario = Scenario::InspectFailure;
    } else if (value == "wrong-pid") {
        scenario = Scenario::WrongPid;
    } else if (value == "exit-127") {
        scenario = Scenario::Exit127;
    } else if (value == "reap-failure") {
        scenario = Scenario::ReapFailure;
    } else if (value == "observation-mismatch") {
        scenario = Scenario::ObservationMismatch;
    } else if (value == "close-failure") {
        scenario = Scenario::CloseFailure;
    } else {
        return false;
    }
    return true;
}

}  // namespace

extern "C" int __wrap_fcntl(int, int, ...) {
    record("fcntl");
    if (scenario == Scenario::FcntlFailure) {
        errno = EBADF;
        return -1;
    }
    return 0;
}

extern "C" int __wrap_clock_gettime(clockid_t, timespec* value) {
    record("clock");
    value->tv_sec = 1;
    value->tv_nsec = 0;
    return 0;
}

extern "C" long __wrap_syscall(long number, ...) {
    record("pidfd-signal");
    if (number != SYS_pidfd_send_signal) {
        errno = ENOSYS;
        return -1;
    }
    if (scenario == Scenario::KillEsrch) {
        errno = ESRCH;
        return -1;
    }
    if (scenario == Scenario::SignalFailure) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

extern "C" int __wrap_ppoll(
    pollfd* descriptors,
    nfds_t count,
    const timespec*,
    const sigset_t*) {
    record("poll");
    if (scenario == Scenario::PollFailure) {
        errno = EIO;
        return -1;
    }
    if (descriptors == nullptr || count != 1u) {
        errno = EINVAL;
        return -1;
    }
    descriptors[0].revents = POLLIN;
    return 1;
}

extern "C" int __wrap_waitid(
    idtype_t type,
    id_t identifier,
    siginfo_t* information,
    int options) {
    const bool inspection = (options & WNOWAIT) != 0;
    record(inspection ? "inspect" : "reap");
    if (type != P_PIDFD || identifier != 9u || information == nullptr) {
        errno = EINVAL;
        return -1;
    }
    if ((inspection && scenario == Scenario::InspectFailure) ||
        (!inspection && scenario == Scenario::ReapFailure)) {
        errno = EINVAL;
        return -1;
    }

    std::memset(information, 0, sizeof(*information));
    information->si_pid = scenario == Scenario::WrongPid ? 43 : 42;
    information->si_uid = 1000u;
    information->si_code = CLD_KILLED;
    information->si_status = SIGKILL;
    if (scenario == Scenario::Exit127) {
        information->si_code = CLD_EXITED;
        information->si_status = 127;
    } else if (!inspection && scenario == Scenario::ObservationMismatch) {
        information->si_status = SIGTERM;
    }
    return 0;
}

extern "C" int __wrap_close(int descriptor) {
    record("close");
    if (descriptor != 9 || scenario == Scenario::CloseFailure) {
        errno = EIO;
        return -1;
    }
    return 0;
}

int main(int argc, char** argv) {
    if (argc != 2 || !select_scenario(argv[1])) {
        return 64;
    }

    pokemon::evaluation_v631302::Stage1PidfdChildLifecycleRequestV1 request{};
    request.pidfd = 9;
    request.expected_pid = 42;
    request.absolute_deadline.tv_sec = 10;
    request.absolute_deadline.tv_nsec = 0;
    request.expectation =
        pokemon::evaluation_v631302::Stage1PidfdTerminalExpectationV1::KilledBySigkill;
    request.send_sigkill = true;

    pokemon::evaluation_v631302::Stage1PidfdChildLifecycleResultV1 result{};
    const char* error = nullptr;
    const bool accepted = pokemon::evaluation_v631302::run_stage1_pidfd_child_lifecycle_v1(
        request, &result, &error);
    std::cout << "accepted=" << accepted
              << " immediate=" << result.requires_immediate_pid1_exit
              << " inspected=" << result.inspected
              << " reaped=" << result.reaped
              << " closed=" << result.pidfd_closed
              << " esrch=" << result.sigkill_returned_esrch
              << " error=" << (error == nullptr ? "none" : error)
              << " events=" << events << '\n';
    return 0;
}
