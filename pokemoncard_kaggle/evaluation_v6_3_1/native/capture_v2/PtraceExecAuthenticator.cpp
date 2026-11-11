#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "PtraceExecAuthenticator.h"

#if !defined(__linux__)
#error "PtraceExecAuthenticator is a Linux-only Capture V2 component"
#endif

#include "SupervisorTypes.h"
#include "Timeout.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <memory>
#include <poll.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <utility>

namespace evaluation_v6_3_1::capture_v2 {
namespace {

constexpr int kMaximumPollSliceMilliseconds = 10;

[[noreturn]] void fail(SupervisorFailure failure, const char* message, int error = 0) {
    throw SupervisorError(failure, message, error);
}

long ptrace_call(enum __ptrace_request request, pid_t pid, std::uintptr_t data = 0u) {
    errno = 0;
    const long result = ::ptrace(
        request,
        pid,
        nullptr,
        reinterpret_cast<void*>(data));
    if (result < 0) {
        fail(SupervisorFailure::TraceFailure, "ptrace operation failed", errno);
    }
    return result;
}

void drain_ready_channels(PipePump& pump, pollfd* descriptors) {
    constexpr PipePump::ChannelId ids[3] = {
        PipePump::ChannelId::Stdout,
        PipePump::ChannelId::Stderr,
        PipePump::ChannelId::Receipt,
    };
    for (std::size_t index = 0u; index < 3u; ++index) {
        if ((descriptors[index].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
            pump.drain_ready(ids[index]);
        }
        if ((descriptors[index].revents & POLLNVAL) != 0) {
            fail(SupervisorFailure::TraceFailure, "ptrace poll observed an invalid channel");
        }
    }
}

void require_no_preexec_output(const PipePump& pump) {
    for (PipePump::ChannelId id : {
             PipePump::ChannelId::Stdout,
             PipePump::ChannelId::Stderr,
             PipePump::ChannelId::Receipt}) {
        if (!pump.channel_snapshot(id).bytes.empty()) {
            fail(SupervisorFailure::ProtocolViolation, "child emitted bytes before exec authentication");
        }
    }
}

int wait_for_trace_event(PreparedLaunch& launch, const MonotonicDeadline& deadline) {
    for (;;) {
        int status = 0;
        const pid_t waited = ::waitpid(
            launch.child_pid(), &status, WNOHANG | __WALL);
        if (waited == launch.child_pid()) {
            require_no_preexec_output(launch.pipe_pump());
            return status;
        }
        if (waited < 0 && errno != EINTR) {
            fail(SupervisorFailure::TraceFailure, "waitpid for ptrace event failed", errno);
        }

        PipePump& pump = launch.pipe_pump();
        pollfd descriptors[4] = {
            {pump.read_descriptor(PipePump::ChannelId::Stdout), POLLIN | POLLHUP | POLLERR, 0},
            {pump.read_descriptor(PipePump::ChannelId::Stderr), POLLIN | POLLHUP | POLLERR, 0},
            {pump.read_descriptor(PipePump::ChannelId::Receipt), POLLIN | POLLHUP | POLLERR, 0},
            {launch.pidfd(), POLLIN | POLLHUP | POLLERR, 0},
        };
        const int remaining = deadline.remaining_poll_timeout_ms();
        if (remaining == 0) {
            fail(SupervisorFailure::TraceTimeout, "ptrace event timed out");
        }
        const int timeout = std::min(remaining, kMaximumPollSliceMilliseconds);
        int polled = -1;
        do {
            polled = ::poll(descriptors, 4u, timeout);
        } while (polled < 0 && errno == EINTR);
        if (polled < 0) {
            fail(SupervisorFailure::TraceFailure, "ptrace channel poll failed", errno);
        }
        if (polled > 0) {
            drain_ready_channels(pump, descriptors);
            require_no_preexec_output(pump);
            if ((descriptors[3].revents & POLLNVAL) != 0) {
                fail(SupervisorFailure::TraceFailure, "ptrace poll observed an invalid pidfd");
            }
        }
    }
}

std::uint32_t ptrace_event(int status) noexcept {
    return static_cast<std::uint32_t>(status) >> 16u;
}

void require_initial_interrupt_stop(int status) {
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP ||
        ptrace_event(status) != static_cast<std::uint32_t>(PTRACE_EVENT_STOP)) {
        fail(SupervisorFailure::TraceFailure, "child did not enter the exact ptrace interrupt stop");
    }
}

bool forbidden_process_creation_event(std::uint32_t event) noexcept {
    return event == static_cast<std::uint32_t>(PTRACE_EVENT_CLONE) ||
           event == static_cast<std::uint32_t>(PTRACE_EVENT_FORK) ||
           event == static_cast<std::uint32_t>(PTRACE_EVENT_VFORK);
}

}  // namespace

std::unique_ptr<ExecStoppedLaunch> PtraceExecAuthenticator::reach_authenticated_exec(
    std::unique_ptr<PreparedLaunch> prepared,
    std::uint64_t positive_timeout_milliseconds) {
    if (prepared == nullptr || prepared->released() || positive_timeout_milliseconds == 0u) {
        fail(SupervisorFailure::InvalidRequest, "ptrace exec authentication request is invalid");
    }
    MonotonicDeadline deadline(positive_timeout_milliseconds);
    constexpr unsigned long options =
        PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE |
        PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_EXITKILL;
    static_cast<void>(ptrace_call(
        PTRACE_SEIZE,
        prepared->child_pid(),
        static_cast<std::uintptr_t>(options)));
    static_cast<void>(ptrace_call(PTRACE_INTERRUPT, prepared->child_pid()));
    require_initial_interrupt_stop(wait_for_trace_event(*prepared, deadline));

    prepared->release_child();
    static_cast<void>(ptrace_call(PTRACE_SYSCALL, prepared->child_pid()));
    for (;;) {
        const int status = wait_for_trace_event(*prepared, deadline);
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            fail(SupervisorFailure::ChildFailure, "child terminated before authenticated exec");
        }
        if (!WIFSTOPPED(status)) {
            fail(SupervisorFailure::TraceFailure, "ptrace wait status is not a stop");
        }
        const std::uint32_t event = ptrace_event(status);
        if (forbidden_process_creation_event(event)) {
            fail(SupervisorFailure::TraceFailure, "child created a forbidden task before exec");
        }
        if (event == static_cast<std::uint32_t>(PTRACE_EVENT_EXEC)) {
            if (WSTOPSIG(status) != SIGTRAP) {
                fail(SupervisorFailure::TraceFailure, "exec event has the wrong stop signal");
            }
            const ValidatedPrelaunchContext& context = prepared->context();
            const WorkDirectoryIdentity& working_directory =
                context.retained_working_directory_identity();
            auto inspector = std::make_unique<ProcInspector>(StoppedProcessRequirement{
                prepared->child_pid(),
                context.collector_launch_argv(),
                true,
                prepared->ready_record().collector_byte_length,
                prepared->ready_record().collector_sha256,
                working_directory.device,
                working_directory.inode,
                {},
                true,
                true,
                0u,
                0u,
                true,
            });
            static_cast<void>(inspector->authenticate());
            return std::unique_ptr<ExecStoppedLaunch>(new ExecStoppedLaunch(
                std::move(prepared), std::move(inspector)));
        }
        if (event != 0u || WSTOPSIG(status) != (SIGTRAP | 0x80)) {
            fail(SupervisorFailure::TraceFailure, "unexpected stop before exec authentication");
        }
        // Attachment deliberately occurred in the middle of the blocked
        // release read.  Pre-exec syscall stops are not paired or interpreted.
        static_cast<void>(ptrace_call(PTRACE_SYSCALL, prepared->child_pid()));
    }
}

}  // namespace evaluation_v6_3_1::capture_v2
