#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "PtraceOpenSupervisor.h"

#if !defined(__linux__)
#error "PtraceOpenSupervisor is a Linux-only Capture V2 component"
#endif

#include "FdTracker.h"
#include "OpenPathResolver.h"
#include "PidfdOpenedFile.h"
#include "PipePump.h"
#include "TraceeMemory.h"
#include "Timeout.h"

#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <dirent.h>
#include <fcntl.h>
#include <limits>
#include <linux/audit.h>
#include <linux/openat2.h>
#include <map>
#include <memory>
#include <optional>
#include <poll.h>
#include <signal.h>
#include <span>
#include <string>
#include <string_view>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {
namespace {

constexpr int kMaximumPollSliceMilliseconds = 10;
constexpr std::uint64_t kFirstObservedOpenObjectId = 5u;
constexpr std::uint64_t kReceiptOpenObjectId = 4u;
constexpr std::uint64_t kProtExec = 4u;
constexpr std::uint32_t kCollectorRole = 1u;

[[noreturn]] void fail(SupervisorFailure failure, const char* message, int error = 0) {
    throw SupervisorError(failure, message, error);
}

void require_transition(
    FdTracker::TransitionResult result,
    FdTracker::TransitionResult expected,
    const char* message) {
    if (result != expected) {
        fail(SupervisorFailure::ProtocolViolation, message);
    }
}

void require_pair_transition(
    SyscallPairTracker::TransitionResult result,
    const char* message) {
    if (result != SyscallPairTracker::TransitionResult::Applied) {
        fail(SupervisorFailure::ProtocolViolation, message);
    }
}

long ptrace_resume(pid_t pid) {
    errno = 0;
    const long result = ::ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr);
    if (result < 0) {
        fail(SupervisorFailure::TraceFailure, "PTRACE_SYSCALL resume failed", errno);
    }
    return result;
}

std::int64_t signed_argument(std::uint64_t value) noexcept {
    return std::bit_cast<std::int64_t>(value);
}

bool syscall_number(std::int64_t observed, long expected) noexcept {
    return observed == static_cast<std::int64_t>(expected);
}

bool terminal_syscall(std::int64_t number) noexcept {
    return syscall_number(number, SYS_exit) || syscall_number(number, SYS_exit_group);
}

bool forbidden_process_creation(std::int64_t number) noexcept {
    return syscall_number(number, SYS_clone) || syscall_number(number, SYS_fork) ||
           syscall_number(number, SYS_vfork) || syscall_number(number, SYS_clone3);
}

bool forbidden_unmodeled_fd_creation(std::int64_t number) noexcept {
    bool forbidden = false;
#ifdef SYS_pipe
    forbidden = forbidden || syscall_number(number, SYS_pipe);
#endif
#ifdef SYS_pipe2
    forbidden = forbidden || syscall_number(number, SYS_pipe2);
#endif
#ifdef SYS_socket
    forbidden = forbidden || syscall_number(number, SYS_socket);
#endif
#ifdef SYS_socketpair
    forbidden = forbidden || syscall_number(number, SYS_socketpair);
#endif
#ifdef SYS_eventfd
    forbidden = forbidden || syscall_number(number, SYS_eventfd);
#endif
#ifdef SYS_eventfd2
    forbidden = forbidden || syscall_number(number, SYS_eventfd2);
#endif
#ifdef SYS_memfd_create
    forbidden = forbidden || syscall_number(number, SYS_memfd_create);
#endif
#ifdef SYS_signalfd
    forbidden = forbidden || syscall_number(number, SYS_signalfd);
#endif
#ifdef SYS_signalfd4
    forbidden = forbidden || syscall_number(number, SYS_signalfd4);
#endif
#ifdef SYS_timerfd_create
    forbidden = forbidden || syscall_number(number, SYS_timerfd_create);
#endif
#ifdef SYS_epoll_create
    forbidden = forbidden || syscall_number(number, SYS_epoll_create);
#endif
#ifdef SYS_epoll_create1
    forbidden = forbidden || syscall_number(number, SYS_epoll_create1);
#endif
#ifdef SYS_accept
    forbidden = forbidden || syscall_number(number, SYS_accept);
#endif
#ifdef SYS_accept4
    forbidden = forbidden || syscall_number(number, SYS_accept4);
#endif
#ifdef SYS_inotify_init
    forbidden = forbidden || syscall_number(number, SYS_inotify_init);
#endif
#ifdef SYS_inotify_init1
    forbidden = forbidden || syscall_number(number, SYS_inotify_init1);
#endif
#ifdef SYS_fanotify_init
    forbidden = forbidden || syscall_number(number, SYS_fanotify_init);
#endif
#ifdef SYS_userfaultfd
    forbidden = forbidden || syscall_number(number, SYS_userfaultfd);
#endif
#ifdef SYS_perf_event_open
    forbidden = forbidden || syscall_number(number, SYS_perf_event_open);
#endif
#ifdef SYS_bpf
    forbidden = forbidden || syscall_number(number, SYS_bpf);
#endif
#ifdef SYS_io_uring_setup
    forbidden = forbidden || syscall_number(number, SYS_io_uring_setup);
#endif
#ifdef SYS_open_by_handle_at
    forbidden = forbidden || syscall_number(number, SYS_open_by_handle_at);
#endif
#ifdef SYS_open_tree
    forbidden = forbidden || syscall_number(number, SYS_open_tree);
#endif
#ifdef SYS_fsopen
    forbidden = forbidden || syscall_number(number, SYS_fsopen);
#endif
#ifdef SYS_fspick
    forbidden = forbidden || syscall_number(number, SYS_fspick);
#endif
#ifdef SYS_fsmount
    forbidden = forbidden || syscall_number(number, SYS_fsmount);
#endif
#ifdef SYS_pidfd_open
    forbidden = forbidden || syscall_number(number, SYS_pidfd_open);
#endif
#ifdef SYS_pidfd_getfd
    forbidden = forbidden || syscall_number(number, SYS_pidfd_getfd);
#endif
#ifdef SYS_landlock_create_ruleset
    forbidden = forbidden || syscall_number(number, SYS_landlock_create_ruleset);
#endif
#ifdef SYS_memfd_secret
    forbidden = forbidden || syscall_number(number, SYS_memfd_secret);
#endif
#ifdef SYS_mq_open
    forbidden = forbidden || syscall_number(number, SYS_mq_open);
#endif
#ifdef SYS_creat
    forbidden = forbidden || syscall_number(number, SYS_creat);
#endif
    return forbidden;
}

bool forbidden_execution_state_mutation(
    std::int64_t number,
    const std::array<std::uint64_t, 6>& arguments) noexcept {
    bool forbidden = false;
#ifdef SYS_chdir
    forbidden = forbidden || syscall_number(number, SYS_chdir);
#endif
#ifdef SYS_fchdir
    forbidden = forbidden || syscall_number(number, SYS_fchdir);
#endif
#ifdef SYS_chroot
    forbidden = forbidden || syscall_number(number, SYS_chroot);
#endif
#ifdef SYS_pivot_root
    forbidden = forbidden || syscall_number(number, SYS_pivot_root);
#endif
#ifdef SYS_unshare
    forbidden = forbidden || syscall_number(number, SYS_unshare);
#endif
#ifdef SYS_setns
    forbidden = forbidden || syscall_number(number, SYS_setns);
#endif
#ifdef SYS_mount
    forbidden = forbidden || syscall_number(number, SYS_mount);
#endif
#ifdef SYS_umount2
    forbidden = forbidden || syscall_number(number, SYS_umount2);
#endif
#ifdef SYS_move_mount
    forbidden = forbidden || syscall_number(number, SYS_move_mount);
#endif
#ifdef SYS_fsconfig
    forbidden = forbidden || syscall_number(number, SYS_fsconfig);
#endif
#ifdef SYS_mount_setattr
    forbidden = forbidden || syscall_number(number, SYS_mount_setattr);
#endif
#ifdef SYS_seccomp
    forbidden = forbidden || syscall_number(number, SYS_seccomp);
#endif
#ifdef SYS_capset
    forbidden = forbidden || syscall_number(number, SYS_capset);
#endif
#ifdef SYS_personality
    forbidden = forbidden || syscall_number(number, SYS_personality);
#endif
#ifdef SYS_setuid
    forbidden = forbidden || syscall_number(number, SYS_setuid);
#endif
#ifdef SYS_setgid
    forbidden = forbidden || syscall_number(number, SYS_setgid);
#endif
#ifdef SYS_setreuid
    forbidden = forbidden || syscall_number(number, SYS_setreuid);
#endif
#ifdef SYS_setregid
    forbidden = forbidden || syscall_number(number, SYS_setregid);
#endif
#ifdef SYS_setresuid
    forbidden = forbidden || syscall_number(number, SYS_setresuid);
#endif
#ifdef SYS_setresgid
    forbidden = forbidden || syscall_number(number, SYS_setresgid);
#endif
#ifdef SYS_setfsuid
    forbidden = forbidden || syscall_number(number, SYS_setfsuid);
#endif
#ifdef SYS_setfsgid
    forbidden = forbidden || syscall_number(number, SYS_setfsgid);
#endif
#ifdef SYS_setgroups
    forbidden = forbidden || syscall_number(number, SYS_setgroups);
#endif
    if (syscall_number(number, SYS_prctl)) {
        const std::uint64_t command = arguments[0];
        forbidden = command == static_cast<std::uint64_t>(PR_SET_SECCOMP) ||
                    command == static_cast<std::uint64_t>(PR_SET_DUMPABLE) ||
                    command == static_cast<std::uint64_t>(PR_SET_SECUREBITS) ||
                    command == static_cast<std::uint64_t>(PR_SET_NO_NEW_PRIVS) ||
                    command == static_cast<std::uint64_t>(PR_CAP_AMBIENT) ||
                    command == static_cast<std::uint64_t>(PR_SET_PDEATHSIG);
    }
    return forbidden;
}

bool receipt_descriptor_alias_or_rebind(
    std::int64_t number,
    const std::array<std::uint64_t, 6>& arguments) noexcept {
    const std::int64_t receipt = ReceiptStreamParser::kReceiptDescriptor;
    if (syscall_number(number, SYS_dup)) {
        return signed_argument(arguments[0]) == receipt;
    }
    if (syscall_number(number, SYS_dup2) || syscall_number(number, SYS_dup3)) {
        return signed_argument(arguments[0]) == receipt ||
               signed_argument(arguments[1]) == receipt;
    }
    if (syscall_number(number, SYS_fcntl)) {
        const std::int64_t command = signed_argument(arguments[1]);
        return signed_argument(arguments[0]) == receipt &&
               (command == F_DUPFD || command == F_DUPFD_CLOEXEC);
    }
    return false;
}

struct PendingOpen final {
    std::string namespace_relative_path;
    std::uint64_t flags = 0u;
};

struct PendingEntry final {
    std::int64_t number = 0;
    std::array<std::uint64_t, 6> arguments{};
    std::optional<PendingOpen> open;
    std::optional<std::vector<std::uint8_t>> fd3_write_bytes;
};

struct LiveState final {
    explicit LiveState(
        pid_t pid,
        ReceiptContextExpectation expectation,
        const std::vector<NamespaceFileExpectation>& namespace_files,
        std::uint64_t maximum_events)
        : memory(pid), receipt(std::move(expectation)), maximum_syscall_events(maximum_events) {
        for (const NamespaceFileExpectation& row : namespace_files) {
            const auto [iterator, inserted] = expected_namespace.emplace(row.namespace_relative_path, row);
            (void)iterator;
            if (!inserted) {
                fail(SupervisorFailure::InvalidRequest, "expected namespace paths are duplicated");
            }
        }
        for (int descriptor = 0; descriptor <= ReceiptStreamParser::kReceiptDescriptor; ++descriptor) {
            require_transition(
                fds.install_open(
                    descriptor,
                    FdTracker::OpenDescriptionIdentity{
                        static_cast<std::uint64_t>(descriptor) + 1u, 0u, 0u},
                    false),
                FdTracker::TransitionResult::Applied,
                "initial collector descriptor state was rejected");
        }
    }

    TraceeMemory memory;
    ReceiptStreamParser receipt;
    SyscallPairTracker pairs;
    FdTracker fds;
    std::map<std::string, NamespaceFileExpectation> expected_namespace;
    std::map<std::uint64_t, std::string> opened_object_paths;
    std::optional<PendingEntry> pending;
    std::vector<ActualOpenObservation> actual_open_rows;
    std::size_t receipt_drain_offset = 0u;
    std::uint64_t global_event_sequence = 0u;
    std::uint64_t next_object_id = kFirstObservedOpenObjectId;
    std::uint64_t maximum_syscall_events = 0u;
    bool initial_exec_exit_allowed = true;
    bool terminal_entry_seen = false;
    bool receipt_fd_closed = false;
};

struct PipeObjectIdentity final {
    std::uint64_t device = 0u;
    std::uint64_t inode = 0u;

    friend bool operator==(const PipeObjectIdentity&, const PipeObjectIdentity&) = default;
};

PipeObjectIdentity inspect_pipe_identity(int descriptor) {
    struct stat status {};
    if (::fstat(descriptor, &status) != 0) {
        fail(SupervisorFailure::SystemFailure, "receipt pipe identity lookup failed", errno);
    }
    if (!S_ISFIFO(status.st_mode)) {
        fail(SupervisorFailure::ProtocolViolation, "receipt channel is not a pipe");
    }
    return PipeObjectIdentity{
        static_cast<std::uint64_t>(status.st_dev),
        static_cast<std::uint64_t>(status.st_ino),
    };
}

std::vector<int> observed_child_descriptors(pid_t pid) {
    const std::string path = "/proc/" + std::to_string(pid) + "/fd";
    DIR* raw_directory = ::opendir(path.c_str());
    if (raw_directory == nullptr) {
        fail(SupervisorFailure::TraceFailure, "open stopped-child FD table failed", errno);
    }
    std::unique_ptr<DIR, decltype(&::closedir)> directory(raw_directory, &::closedir);
    std::vector<int> descriptors;
    errno = 0;
    for (;;) {
        dirent* entry = ::readdir(directory.get());
        if (entry == nullptr) {
            if (errno != 0) {
                fail(SupervisorFailure::TraceFailure, "read stopped-child FD table failed", errno);
            }
            break;
        }
        const std::string_view name(entry->d_name);
        if (name == "." || name == "..") {
            continue;
        }
        int descriptor = -1;
        const auto [end, error] = std::from_chars(
            name.data(), name.data() + name.size(), descriptor);
        if (error != std::errc{} || end != name.data() + name.size() || descriptor < 0) {
            fail(SupervisorFailure::TraceFailure, "stopped-child FD table has an invalid entry");
        }
        descriptors.push_back(descriptor);
        errno = 0;
    }
    std::sort(descriptors.begin(), descriptors.end());
    if (std::adjacent_find(descriptors.begin(), descriptors.end()) != descriptors.end()) {
        fail(SupervisorFailure::TraceFailure, "stopped-child FD table is duplicated");
    }
    return descriptors;
}

void require_complete_fd_universe(pid_t pid, const FdTracker& tracker) {
    std::vector<int> expected;
    for (const FdTracker::DescriptorState& row : tracker.snapshot().descriptors) {
        if (row.is_open()) {
            expected.push_back(row.descriptor);
        }
    }
    if (observed_child_descriptors(pid) != expected) {
        fail(SupervisorFailure::ProtocolViolation, "tracked descriptor universe differs from stopped child");
    }
}

void require_original_receipt_descriptor(const LiveState& state) {
    const std::optional<FdTracker::DescriptorState> descriptor =
        state.fds.lookup_open(ReceiptStreamParser::kReceiptDescriptor);
    if (!descriptor.has_value() || !descriptor->identity.has_value() ||
        descriptor->identity->object_id != kReceiptOpenObjectId || state.receipt_fd_closed) {
        fail(SupervisorFailure::ProtocolViolation, "receipt write is not bound to the original FD3 object");
    }
}

void append_receipt_delta(PipePump& pump, LiveState& state) {
    const std::span<const std::uint8_t> bytes =
        pump.channel_bytes(PipePump::ChannelId::Receipt);
    if (state.receipt_drain_offset > bytes.size()) {
        fail(SupervisorFailure::ProtocolViolation, "receipt pipe buffer shrank");
    }
    if (state.receipt_drain_offset < bytes.size()) {
        state.receipt.append_drained_fd3_bytes(bytes.subspan(state.receipt_drain_offset));
        state.receipt_drain_offset = bytes.size();
    }
}

void drain_all_available(PreparedLaunch& launch, LiveState& state) {
    PipePump& pump = launch.pipe_pump();
    pump.drain_ready(PipePump::ChannelId::Stdout);
    pump.drain_ready(PipePump::ChannelId::Stderr);
    pump.drain_ready(PipePump::ChannelId::Receipt);
    append_receipt_delta(pump, state);
}

int wait_for_event(
    PreparedLaunch& launch,
    LiveState& state,
    const MonotonicDeadline& deadline) {
    for (;;) {
        int status = 0;
        const pid_t waited = ::waitpid(launch.child_pid(), &status, WNOHANG | __WALL);
        if (waited == launch.child_pid()) {
            drain_all_available(launch, state);
            return status;
        }
        if (waited < 0 && errno != EINTR) {
            fail(SupervisorFailure::TraceFailure, "waitpid during live trace failed", errno);
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
            fail(SupervisorFailure::TraceTimeout, "live trace timed out");
        }
        int result = -1;
        do {
            result = ::poll(
                descriptors,
                4u,
                std::min(remaining, kMaximumPollSliceMilliseconds));
        } while (result < 0 && errno == EINTR);
        if (result < 0) {
            fail(SupervisorFailure::TraceFailure, "live trace poll failed", errno);
        }
        for (const pollfd& descriptor : descriptors) {
            if ((descriptor.revents & POLLNVAL) != 0) {
                fail(SupervisorFailure::TraceFailure, "live trace poll observed invalid fd");
            }
        }
        if (result > 0) {
            drain_all_available(launch, state);
        }
    }
}

void drain_to_all_eof(
    PreparedLaunch& launch,
    LiveState& state,
    const MonotonicDeadline& deadline) {
    PipePump& pump = launch.pipe_pump();
    while (!pump.all_eof()) {
        drain_all_available(launch, state);
        if (pump.all_eof()) {
            break;
        }
        pollfd descriptors[3] = {
            {pump.read_descriptor(PipePump::ChannelId::Stdout), POLLIN | POLLHUP | POLLERR, 0},
            {pump.read_descriptor(PipePump::ChannelId::Stderr), POLLIN | POLLHUP | POLLERR, 0},
            {pump.read_descriptor(PipePump::ChannelId::Receipt), POLLIN | POLLHUP | POLLERR, 0},
        };
        const int remaining = deadline.remaining_poll_timeout_ms();
        if (remaining == 0) {
            fail(SupervisorFailure::TraceTimeout, "channel EOF drain timed out");
        }
        int result = -1;
        do {
            result = ::poll(descriptors, 3u, remaining);
        } while (result < 0 && errno == EINTR);
        if (result <= 0) {
            fail(
                result == 0 ? SupervisorFailure::TraceTimeout : SupervisorFailure::TraceFailure,
                result == 0 ? "channel EOF drain timed out" : "channel EOF poll failed",
                result < 0 ? errno : 0);
        }
        for (const pollfd& descriptor : descriptors) {
            if ((descriptor.revents & POLLNVAL) != 0) {
                fail(SupervisorFailure::TraceFailure, "channel EOF poll observed invalid fd");
            }
        }
    }
}

__ptrace_syscall_info syscall_info(pid_t pid) {
    __ptrace_syscall_info info{};
    errno = 0;
    const long length = ::ptrace(
        PTRACE_GET_SYSCALL_INFO,
        pid,
        reinterpret_cast<void*>(sizeof(info)),
        &info);
    if (length < 0) {
        fail(SupervisorFailure::TraceFailure, "PTRACE_GET_SYSCALL_INFO failed", errno);
    }
    const std::size_t available = static_cast<std::size_t>(length);
    const std::size_t common_bytes = offsetof(__ptrace_syscall_info, entry);
    if (available < common_bytes) {
        fail(SupervisorFailure::TraceFailure, "ptrace syscall-info common fields are truncated");
    }
    std::size_t required = common_bytes;
    if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
        required += sizeof(info.entry.nr) + sizeof(info.entry.args);
    } else if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
        required += sizeof(info.exit.rval) + sizeof(info.exit.is_error);
    }
    if (available < required) {
        fail(SupervisorFailure::TraceFailure, "ptrace syscall-info operation fields are truncated");
    }
    if (info.arch != AUDIT_ARCH_X86_64) {
        fail(SupervisorFailure::TraceFailure, "syscall stop is not Linux x86_64");
    }
    return info;
}

std::uint64_t next_event_sequence(LiveState& state) {
    const std::uint64_t result = state.global_event_sequence;
    if (result == std::numeric_limits<std::uint64_t>::max() ||
        result >= state.maximum_syscall_events) {
        fail(SupervisorFailure::ResourceLimit, "syscall event cap or sequence limit reached");
    }
    ++state.global_event_sequence;
    return result;
}

SyscallPairTracker::ReceiptPhase current_receipt_phase(const LiveState& state) {
    const std::optional<OpenPhaseMapping> mapping = state.receipt.current_open_phase_mapping();
    if (!mapping.has_value()) {
        return SyscallPairTracker::ReceiptPhase{0u, 1u};
    }
    if (mapping->effective_event_sequence == std::numeric_limits<std::uint64_t>::max()) {
        fail(SupervisorFailure::ResourceLimit, "receipt phase generation overflow");
    }
    return SyscallPairTracker::ReceiptPhase{
        mapping->receipt_phase_ordinal,
        mapping->effective_event_sequence + 1u,
    };
}

std::int64_t checked_syscall_number(std::uint64_t number) {
    if (number > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        fail(SupervisorFailure::TraceFailure, "syscall number is out of range");
    }
    return static_cast<std::int64_t>(number);
}

std::array<std::uint64_t, 6> syscall_arguments(const __ptrace_syscall_info& info) {
    std::array<std::uint64_t, 6> result{};
    std::copy(std::begin(info.entry.args), std::end(info.entry.args), result.begin());
    return result;
}

std::int64_t checked_dirfd(std::uint64_t raw) {
    const std::int64_t value = signed_argument(raw);
    if (value < static_cast<std::int64_t>(std::numeric_limits<int>::min()) ||
        value > static_cast<std::int64_t>(std::numeric_limits<int>::max())) {
        fail(SupervisorFailure::ProtocolViolation, "openat dirfd is out of range");
    }
    return value;
}

PendingOpen read_open_entry(
    const PendingEntry& pending,
    PreparedLaunch& launch,
    LiveState& state,
    const PtraceOpenLimits& limits) {
    std::uintptr_t path_pointer = 0u;
    std::uint64_t flags = 0u;
    std::int64_t dirfd = OpenPathResolver::kAtFdcwd;
    OpenPathResolver::SyscallFamily family = OpenPathResolver::SyscallFamily::Open;
    if (syscall_number(pending.number, SYS_open)) {
        path_pointer = static_cast<std::uintptr_t>(pending.arguments[0]);
        flags = pending.arguments[1];
    } else if (syscall_number(pending.number, SYS_openat)) {
        family = OpenPathResolver::SyscallFamily::OpenAt;
        dirfd = checked_dirfd(pending.arguments[0]);
        path_pointer = static_cast<std::uintptr_t>(pending.arguments[1]);
        flags = pending.arguments[2];
    } else if (syscall_number(pending.number, SYS_openat2)) {
        family = OpenPathResolver::SyscallFamily::OpenAt2;
        dirfd = checked_dirfd(pending.arguments[0]);
        path_pointer = static_cast<std::uintptr_t>(pending.arguments[1]);
        if (pending.arguments[3] != sizeof(open_how)) {
            fail(SupervisorFailure::ProtocolViolation, "openat2 open_how size is not exact");
        }
        const std::vector<std::uint8_t> bytes = state.memory.exact_bytes(
            static_cast<std::uintptr_t>(pending.arguments[2]),
            sizeof(open_how),
            sizeof(open_how));
        open_how how{};
        std::copy(bytes.begin(), bytes.end(), reinterpret_cast<std::uint8_t*>(&how));
        if (how.resolve != 0u) {
            fail(
                SupervisorFailure::ProtocolViolation,
                "openat2 resolution modes are outside the normalized-path model");
        }
        flags = how.flags;
    } else {
        fail(SupervisorFailure::ProtocolViolation, "pending syscall is not an open family");
    }
    const std::string raw_path = state.memory.nul_terminated_string(
        path_pointer, limits.maximum_path_bytes);
    return PendingOpen{
        OpenPathResolver::resolve(
            raw_path,
            family,
            dirfd,
            launch.working_directory_relative_path()),
        flags,
    };
}

bool open_family(std::int64_t number) noexcept {
    return syscall_number(number, SYS_open) || syscall_number(number, SYS_openat) ||
           syscall_number(number, SYS_openat2);
}

bool mmap_family(std::int64_t number) noexcept {
    bool matches = syscall_number(number, SYS_mmap);
#ifdef SYS_mmap2
    matches = matches || syscall_number(number, SYS_mmap2);
#endif
    return matches;
}

bool executable_protection_change(
    std::int64_t number,
    const std::array<std::uint64_t, 6>& arguments) noexcept {
    bool matches = syscall_number(number, SYS_mprotect);
#ifdef SYS_pkey_mprotect
    matches = matches || syscall_number(number, SYS_pkey_mprotect);
#endif
    return matches && (arguments[2] & kProtExec) != 0u;
}

std::uint64_t mmap_file_offset(const PendingEntry& pending) {
#ifdef SYS_mmap2
    if (syscall_number(pending.number, SYS_mmap2)) {
        const long page_size = ::sysconf(_SC_PAGESIZE);
        if (page_size <= 0) {
            fail(SupervisorFailure::SystemFailure, "mmap2 page size lookup failed", errno);
        }
        const std::uint64_t multiplier = static_cast<std::uint64_t>(page_size);
        if (pending.arguments[5] > std::numeric_limits<std::uint64_t>::max() / multiplier) {
            fail(SupervisorFailure::ProtocolViolation, "mmap2 file offset overflowed");
        }
        return pending.arguments[5] * multiplier;
    }
#endif
    return pending.arguments[5];
}

void observe_successful_executable_mmap(
    const PendingEntry& pending,
    LiveState& state,
    RuntimeObserver& runtime,
    const MonotonicDeadline& deadline) {
    const std::uint64_t mapping_length = pending.arguments[1];
    const std::uint64_t protection_flags = pending.arguments[2];
    const std::uint64_t mapping_flags = pending.arguments[3];
    if (mapping_length == 0u || (protection_flags & kProtExec) == 0u ||
        (mapping_flags & static_cast<std::uint64_t>(MAP_ANONYMOUS)) != 0u) {
        return;
    }
    const std::int64_t descriptor_value = signed_argument(pending.arguments[4]);
    if (descriptor_value < 0 || descriptor_value > std::numeric_limits<int>::max()) {
        fail(SupervisorFailure::ProtocolViolation, "executable mmap descriptor is invalid");
    }
    const int descriptor = static_cast<int>(descriptor_value);
    const std::optional<FdTracker::DescriptorState> tracked = state.fds.lookup_open(descriptor);
    if (!tracked.has_value() || !tracked->identity.has_value()) {
        fail(SupervisorFailure::ProtocolViolation, "executable mmap descriptor is not tracked");
    }
    const FdTracker::OpenDescriptionIdentity& identity = *tracked->identity;
    const auto path = state.opened_object_paths.find(identity.object_id);
    if (path == state.opened_object_paths.end()) {
        fail(SupervisorFailure::ProtocolViolation, "executable mmap object has no frozen namespace path");
    }
    runtime.observe_mmap_fd(
        descriptor,
        path->second,
        identity.device,
        identity.inode,
        mmap_file_offset(pending),
        mapping_length,
        protection_flags,
        deadline);
}

void process_entry(
    const __ptrace_syscall_info& info,
    PreparedLaunch& launch,
    LiveState& state,
    const PtraceOpenLimits& limits,
    RuntimeObserver* runtime,
    const MonotonicDeadline& deadline) {
    if (state.pending.has_value() || state.terminal_entry_seen) {
        fail(SupervisorFailure::ProtocolViolation, "syscall entry arrived while another entry is active");
    }
    const std::int64_t number = checked_syscall_number(info.entry.nr);
    const std::array<std::uint64_t, 6> arguments = syscall_arguments(info);
    if (terminal_syscall(number)) {
        if (!state.receipt_fd_closed) {
            fail(SupervisorFailure::ProtocolViolation, "collector entered terminal syscall before closing FD3");
        }
        if (runtime != nullptr) {
            runtime->rescan_proc_map_files(deadline);
        }
        state.terminal_entry_seen = true;
        static_cast<void>(next_event_sequence(state));
        return;
    }
    if (forbidden_process_creation(number)) {
        fail(SupervisorFailure::ProtocolViolation, "collector attempted task or process creation");
    }
    if (forbidden_unmodeled_fd_creation(number) || syscall_number(number, SYS_close_range)) {
        fail(SupervisorFailure::ProtocolViolation, "collector attempted unmodeled descriptor creation or closure");
    }
    if (forbidden_execution_state_mutation(number, arguments)) {
        fail(SupervisorFailure::ProtocolViolation, "collector attempted frozen execution-state mutation");
    }
    if (receipt_descriptor_alias_or_rebind(number, arguments)) {
        fail(SupervisorFailure::ProtocolViolation, "collector attempted to alias or rebind receipt FD3");
    }
    if (syscall_number(number, SYS_execve) || syscall_number(number, SYS_execveat)) {
        fail(SupervisorFailure::ProtocolViolation, "collector attempted a second exec");
    }

    PendingEntry pending{};
    pending.number = number;
    pending.arguments = arguments;
    const std::uint64_t sequence = next_event_sequence(state);
    require_pair_transition(
        state.pairs.record_entry(
            launch.child_pid(),
            SyscallPairTracker::EntryRecord{
                number,
                pending.arguments,
                sequence,
                current_receipt_phase(state),
            }),
        "syscall entry pairing failed");

    if (open_family(number)) {
        pending.open = read_open_entry(pending, launch, state, limits);
    }
    if (syscall_number(number, SYS_write) &&
        signed_argument(pending.arguments[0]) == ReceiptStreamParser::kReceiptDescriptor) {
        require_original_receipt_descriptor(state);
        const std::uint64_t requested = pending.arguments[2];
        if (requested == 0u || requested > ReceiptStreamParser::kReceiptStreamMaxBytes) {
            fail(SupervisorFailure::ResourceLimit, "FD3 write request is empty or oversized");
        }
        pending.fd3_write_bytes = state.memory.exact_bytes(
            static_cast<std::uintptr_t>(pending.arguments[1]),
            static_cast<std::size_t>(requested),
            ReceiptStreamParser::kReceiptStreamMaxBytes);
    }
    if (syscall_number(number, SYS_writev) &&
        signed_argument(pending.arguments[0]) == ReceiptStreamParser::kReceiptDescriptor) {
        require_original_receipt_descriptor(state);
        fail(SupervisorFailure::ProtocolViolation, "writev to receipt descriptor is forbidden");
    }
    state.pending = std::move(pending);
}

bool restarted_return(std::int64_t value) noexcept {
    return value == -512 || value == -513 || value == -514 || value == -516;
}

void record_actual_open(
    const PendingOpen& pending,
    int child_fd,
    PreparedLaunch& launch,
    LiveState& state,
    const PtraceOpenLimits& limits,
    const MonotonicDeadline& deadline) {
    if (child_fd == ReceiptStreamParser::kReceiptDescriptor) {
        fail(SupervisorFailure::ProtocolViolation, "an open rebound the closed receipt descriptor");
    }
    if (state.actual_open_rows.size() >= limits.maximum_actual_open_rows) {
        fail(SupervisorFailure::ResourceLimit, "actual-open row cap exceeded");
    }
    const auto expected = state.expected_namespace.find(pending.namespace_relative_path);
    if (expected == state.expected_namespace.end()) {
        fail(SupervisorFailure::ProtocolViolation, "successful open is outside the sealed namespace manifest");
    }
    PidfdOpenedFile opened = PidfdOpenedFile::duplicate_stopped_child_file(
        launch.pidfd(), child_fd, limits.maximum_opened_file_bytes, deadline);
    const PidfdOpenedFileObservation& observation = opened.observation();
    if (observation.byte_length != expected->second.byte_length ||
        observation.sha256 != expected->second.sha256 ||
        (observation.mode & static_cast<std::uint32_t>(07777u)) !=
            expected->second.normalized_mode) {
        fail(
            SupervisorFailure::ProtocolViolation,
            "opened file bytes or normalized mode differ from sealed namespace row");
    }
    if (state.next_object_id == std::numeric_limits<std::uint64_t>::max()) {
        fail(SupervisorFailure::ResourceLimit, "open-description identity overflow");
    }
    const std::uint64_t object_id = state.next_object_id++;
    require_transition(
        state.fds.install_open(
            child_fd,
            FdTracker::OpenDescriptionIdentity{
                object_id, observation.device, observation.inode},
            (pending.flags & static_cast<std::uint64_t>(O_CLOEXEC)) != 0u),
        FdTracker::TransitionResult::Applied,
        "opened descriptor generation transition failed");
    const auto [path_iterator, path_inserted] = state.opened_object_paths.emplace(
        object_id, pending.namespace_relative_path);
    (void)path_iterator;
    if (!path_inserted) {
        fail(SupervisorFailure::ProtocolViolation, "open-description path identity was reused");
    }
    const std::optional<OpenPhaseMapping> mapping = state.receipt.current_open_phase_mapping();
    const Amendment8OpenPhase phase =
        mapping.has_value() ? mapping->phase : Amendment8OpenPhase::PreDriver;
    if (!state.actual_open_rows.empty() &&
        static_cast<std::uint64_t>(phase) <
            static_cast<std::uint64_t>(state.actual_open_rows.back().phase)) {
        fail(SupervisorFailure::ProtocolViolation, "actual-open phases regressed");
    }
    state.actual_open_rows.push_back(ActualOpenObservation{
        static_cast<std::uint64_t>(state.actual_open_rows.size()),
        phase,
        pending.namespace_relative_path,
        pending.flags,
        observation.device,
        observation.inode,
        observation.mode & static_cast<std::uint32_t>(07777u),
        observation.byte_length,
        observation.sha256,
    });
}

void process_close(
    const PendingEntry& pending,
    std::int64_t result,
    PreparedLaunch& launch,
    LiveState& state) {
    const std::int64_t descriptor_value = signed_argument(pending.arguments[0]);
    if (descriptor_value < 0 || descriptor_value > std::numeric_limits<int>::max()) {
        fail(SupervisorFailure::ProtocolViolation, "close descriptor is out of range");
    }
    FdTracker::CloseDisposition disposition = FdTracker::CloseDisposition::Closed;
    if (result == -EBADF) {
        disposition = FdTracker::CloseDisposition::DidNotClose;
    } else if (result == -EINTR) {
        disposition = FdTracker::CloseDisposition::Indeterminate;
    }
    const FdTracker::TransitionResult transition =
        state.fds.close(static_cast<int>(descriptor_value), disposition);
    if (disposition == FdTracker::CloseDisposition::DidNotClose) {
        require_transition(
            transition, FdTracker::TransitionResult::NoOp, "failed close changed descriptor state");
    } else {
        require_transition(
            transition, FdTracker::TransitionResult::Applied, "close descriptor transition failed");
    }
    if (descriptor_value == ReceiptStreamParser::kReceiptDescriptor) {
        if (state.receipt_fd_closed || disposition != FdTracker::CloseDisposition::Closed) {
            fail(SupervisorFailure::ProtocolViolation, "receipt FD3 did not close exactly once");
        }
        drain_all_available(launch, state);
        if (!state.receipt.final_frame_parsed()) {
            fail(SupervisorFailure::ProtocolViolation, "receipt FD3 closed before the final frame");
        }
        state.receipt_fd_closed = true;
    }
}

int successful_descriptor(std::int64_t value, const char* message) {
    if (value < 0 || value > std::numeric_limits<int>::max()) {
        fail(SupervisorFailure::ProtocolViolation, message);
    }
    return static_cast<int>(value);
}

void process_duplication(const PendingEntry& pending, std::int64_t result, LiveState& state) {
    const int source = successful_descriptor(signed_argument(pending.arguments[0]), "dup source is invalid");
    const int target = successful_descriptor(result, "dup result is invalid");
    if (target == ReceiptStreamParser::kReceiptDescriptor) {
        fail(SupervisorFailure::ProtocolViolation, "duplication rebound receipt FD3");
    }
    FdTracker::TransitionResult transition = FdTracker::TransitionResult::Rejected;
    if (syscall_number(pending.number, SYS_dup)) {
        transition = state.fds.dup(source, target);
    } else if (syscall_number(pending.number, SYS_dup2)) {
        transition = state.fds.dup2(source, target);
    } else if (syscall_number(pending.number, SYS_dup3)) {
        transition = state.fds.dup3(
            source,
            target,
            (pending.arguments[2] & static_cast<std::uint64_t>(O_CLOEXEC)) != 0u);
    }
    if (transition != FdTracker::TransitionResult::Applied &&
        transition != FdTracker::TransitionResult::NoOp) {
        fail(SupervisorFailure::ProtocolViolation, "dup descriptor transition failed");
    }
}

void process_fcntl(const PendingEntry& pending, std::int64_t result, LiveState& state) {
    const std::int64_t command = signed_argument(pending.arguments[1]);
    if (command == F_DUPFD || command == F_DUPFD_CLOEXEC) {
        const int source = successful_descriptor(
            signed_argument(pending.arguments[0]), "fcntl duplicate source is invalid");
        const int target = successful_descriptor(result, "fcntl duplicate result is invalid");
        if (target == ReceiptStreamParser::kReceiptDescriptor) {
            fail(SupervisorFailure::ProtocolViolation, "fcntl duplication rebound receipt FD3");
        }
        const FdTracker::TransitionResult transition =
            command == F_DUPFD
                ? state.fds.dup(source, target)
                : state.fds.dup3(source, target, true);
        require_transition(
            transition, FdTracker::TransitionResult::Applied, "fcntl duplicate transition failed");
        return;
    }
    if (command == F_SETFD) {
        fail(SupervisorFailure::ProtocolViolation, "F_SETFD is not modeled by this open slice");
    }
}

void process_exit(
    const __ptrace_syscall_info& info,
    PreparedLaunch& launch,
    LiveState& state,
    const PtraceOpenLimits& limits,
    std::size_t receipt_pipe_buf,
    RuntimeObserver* runtime,
    const MonotonicDeadline& deadline) {
    if (!state.pending.has_value()) {
        if (state.initial_exec_exit_allowed) {
            state.initial_exec_exit_allowed = false;
            static_cast<void>(next_event_sequence(state));
            return;
        }
        fail(SupervisorFailure::ProtocolViolation, "syscall exit has no paired entry");
    }
    state.initial_exec_exit_allowed = false;
    PendingEntry pending = std::move(*state.pending);
    state.pending.reset();
    if (info.exit.is_error > 1u) {
        fail(SupervisorFailure::TraceFailure, "ptrace syscall-exit error flag is invalid");
    }
    const std::int64_t result = static_cast<std::int64_t>(info.exit.rval);
    if (restarted_return(result)) {
        static_cast<void>(state.pairs.record_restart(launch.child_pid(), next_event_sequence(state)));
        fail(SupervisorFailure::ProtocolViolation, "restarted syscall is forbidden");
    }
    require_pair_transition(
        state.pairs.record_exit(
            launch.child_pid(),
            SyscallPairTracker::ExitRecord{next_event_sequence(state), result, false}),
        "syscall exit pairing failed");

    if (pending.fd3_write_bytes.has_value()) {
        state.receipt.observe_fd3_write(
            *pending.fd3_write_bytes, result, receipt_pipe_buf, false);
        drain_all_available(launch, state);
    }
    if (pending.open.has_value() && result >= 0) {
        record_actual_open(
            *pending.open,
            successful_descriptor(result, "open returned an invalid descriptor"),
            launch,
            state,
            limits,
            deadline);
    }
    if (runtime != nullptr && result >= 0 && mmap_family(pending.number)) {
        observe_successful_executable_mmap(pending, state, *runtime, deadline);
    }
    if (runtime != nullptr && result == 0 &&
        executable_protection_change(pending.number, pending.arguments)) {
        runtime->rescan_proc_map_files(deadline);
    }
    if (syscall_number(pending.number, SYS_close)) {
        process_close(pending, result, launch, state);
    }
    if (result >= 0 &&
        (syscall_number(pending.number, SYS_dup) || syscall_number(pending.number, SYS_dup2) ||
         syscall_number(pending.number, SYS_dup3))) {
        process_duplication(pending, result, state);
    }
    if (result >= 0 && syscall_number(pending.number, SYS_fcntl)) {
        process_fcntl(pending, result, state);
    }
}

void process_syscall_stop(
    PreparedLaunch& launch,
    LiveState& state,
    const PtraceOpenLimits& limits,
    std::size_t receipt_pipe_buf,
    RuntimeObserver* runtime,
    const MonotonicDeadline& deadline) {
    const __ptrace_syscall_info info = syscall_info(launch.child_pid());
    if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
        require_complete_fd_universe(launch.child_pid(), state.fds);
        state.initial_exec_exit_allowed = false;
        process_entry(info, launch, state, limits, runtime, deadline);
        return;
    }
    if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
        process_exit(info, launch, state, limits, receipt_pipe_buf, runtime, deadline);
        require_complete_fd_universe(launch.child_pid(), state.fds);
        return;
    }
    fail(SupervisorFailure::TraceFailure, "ptrace syscall stop has an unsupported classification");
}

std::uint32_t ptrace_event(int status) noexcept {
    return static_cast<std::uint32_t>(status) >> 16u;
}

std::string collector_namespace_path(
    const std::vector<NamespaceFileExpectation>& namespace_files) {
    std::optional<std::string> result;
    for (const NamespaceFileExpectation& row : namespace_files) {
        if (!std::binary_search(row.role_codes.begin(), row.role_codes.end(), kCollectorRole)) {
            continue;
        }
        if (result.has_value()) {
            fail(SupervisorFailure::InvalidRequest, "runtime namespace has multiple collector roles");
        }
        result = row.namespace_relative_path;
    }
    if (!result.has_value()) {
        fail(SupervisorFailure::InvalidRequest, "runtime namespace has no collector role");
    }
    return *result;
}

struct InternalTraceSlice final {
    CompletedOpenTraceSlice open_receipt;
    std::optional<CompletedRuntimeObservation> runtime_observation;
    CompletedNamespaceObservation namespace_observation;
    CompletedExecStopObservation exec_stop_observation;
    CompletedTerminationObservation termination_observation;
};

InternalTraceSlice run_trace(
    ExecStoppedLaunch& exec_stopped,
    ReceiptContextExpectation receipt_expectation,
    PtraceOpenLimits limits,
    bool enable_runtime_observation) {
    if (limits.total_timeout_milliseconds == 0u || limits.maximum_path_bytes == 0u ||
        limits.maximum_path_bytes > OpenPathResolver::kPathMaxBytes ||
        limits.maximum_opened_file_bytes == 0u || limits.maximum_actual_open_rows == 0u ||
        limits.maximum_syscall_events == 0u) {
        fail(SupervisorFailure::InvalidRequest, "ptrace open-supervisor request is invalid");
    }
    PreparedLaunch& launch = exec_stopped.launch();
    const StoppedProcessObservation& stopped = exec_stopped.observation();
    CompletedNamespaceObservation namespace_observation{
        launch.ready_record(),
        launch.namespace_identity_rows(),
    };
    CompletedExecStopObservation exec_stop_observation{
        stopped.pid(),
        stopped.argv(),
        stopped.executable_byte_length(),
        stopped.executable_sha256(),
        stopped.cwd_device(),
        stopped.cwd_inode(),
        stopped.cwd_proc_link(),
        stopped.zero_capability_sets(),
        stopped.no_new_privileges(),
        stopped.user_id(),
        stopped.group_id(),
        stopped.empty_supplementary_groups(),
    };
    const int receipt_reader =
        launch.pipe_pump().read_descriptor(PipePump::ChannelId::Receipt);
    const PipeObjectIdentity receipt_pipe_identity = inspect_pipe_identity(receipt_reader);
    const long pipe_buf = ::fpathconf(
        receipt_reader, _PC_PIPE_BUF);
    if (pipe_buf <= 0) {
        fail(SupervisorFailure::SystemFailure, "receipt PIPE_BUF lookup failed", errno);
    }
    const std::size_t receipt_pipe_buf = static_cast<std::size_t>(pipe_buf);
    LiveState state(
        launch.child_pid(),
        std::move(receipt_expectation),
        launch.expected_namespace_files(),
        limits.maximum_syscall_events);
    MonotonicDeadline deadline(limits.total_timeout_milliseconds);
    require_complete_fd_universe(launch.child_pid(), state.fds);
    std::unique_ptr<RuntimeObserver> runtime;
    if (enable_runtime_observation) {
        runtime = std::make_unique<RuntimeObserver>(
            launch.child_pid(),
            launch.pidfd(),
            collector_namespace_path(launch.expected_namespace_files()),
            launch.expected_namespace_files(),
            deadline,
            limits.runtime_observer);
        runtime->observe_exec_proc_exe(deadline);
        runtime->rescan_proc_map_files(deadline);
    }

    static_cast<void>(ptrace_resume(launch.child_pid()));
    int terminal_status = 0;
    for (;;) {
        const int status = wait_for_event(launch, state, deadline);
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            terminal_status = status;
            launch.termination_guard().mark_reaped(status);
            break;
        }
        if (!WIFSTOPPED(status) || ptrace_event(status) != 0u ||
            WSTOPSIG(status) != (SIGTRAP | 0x80)) {
            fail(SupervisorFailure::TraceFailure, "unexpected event during live syscall trace");
        }
        process_syscall_stop(
            launch, state, limits, receipt_pipe_buf, runtime.get(), deadline);
        static_cast<void>(ptrace_resume(launch.child_pid()));
    }

    drain_to_all_eof(launch, state, deadline);
    if (inspect_pipe_identity(receipt_reader) != receipt_pipe_identity) {
        fail(SupervisorFailure::ProtocolViolation, "receipt pipe identity changed during trace");
    }
    if (!WIFEXITED(terminal_status) || WEXITSTATUS(terminal_status) != 0) {
        fail(SupervisorFailure::ChildFailure, "collector did not exit successfully");
    }
    if (state.pending.has_value() || !state.terminal_entry_seen) {
        fail(SupervisorFailure::ProtocolViolation, "collector exit lacked an exact terminal syscall entry");
    }
    require_pair_transition(state.pairs.terminalize(), "syscall pairing did not terminalize");
    state.receipt.finish_fd3_eof();
    const ReceiptFinalValues& final_receipt = state.receipt.final_values();
    if (final_receipt.receipt_fd_device != receipt_pipe_identity.device ||
        final_receipt.receipt_fd_inode != receipt_pipe_identity.inode) {
        fail(SupervisorFailure::ProtocolViolation, "receipt self-report differs from parent pipe identity");
    }
    launch.pipe_pump().finish_success();
    const std::span<const std::uint8_t> stderr_bytes =
        launch.pipe_pump().channel_bytes(PipePump::ChannelId::Stderr);
    if (!stderr_bytes.empty()) {
        fail(SupervisorFailure::ProtocolViolation, "collector stderr is not empty");
    }
    if (state.actual_open_rows.empty()) {
        fail(SupervisorFailure::ProtocolViolation, "collector produced no actual input-open rows");
    }

    const std::span<const std::uint8_t> stdout_bytes =
        launch.pipe_pump().channel_bytes(PipePump::ChannelId::Stdout);
    if (stdout_bytes.empty() ||
        stdout_bytes.size() > kRawCollectorCaptureMaxBytesV1) {
        fail(
            SupervisorFailure::ProtocolViolation,
            "collector stdout is outside the frozen native success bounds");
    }
    std::optional<CompletedRuntimeObservation> completed_runtime;
    if (runtime != nullptr) {
        completed_runtime.emplace(runtime->finalize());
    }
    return InternalTraceSlice{
        CompletedOpenTraceSlice{
            std::move(state.actual_open_rows),
            state.pairs.snapshot(),
            final_receipt,
            state.receipt.exact_stream_bytes(),
            std::vector<std::uint8_t>(stdout_bytes.begin(), stdout_bytes.end()),
        },
        std::move(completed_runtime),
        std::move(namespace_observation),
        std::move(exec_stop_observation),
        CompletedTerminationObservation{
            terminal_status,
            static_cast<std::uint32_t>(WEXITSTATUS(terminal_status)),
            std::vector<std::uint8_t>(stderr_bytes.begin(), stderr_bytes.end()),
        },
    };
}

}  // namespace

CompletedNativeCaptureObservations PtraceOpenSupervisor::run(
    ExecStoppedLaunch& exec_stopped,
    ReceiptContextExpectation receipt_expectation,
    PtraceOpenLimits limits) {
    const Sha256Digest private_context_binding_digest =
        exec_stopped.launch().context().private_context_binding_digest();
    InternalTraceSlice result = run_trace(
        exec_stopped, std::move(receipt_expectation), limits, true);
    if (!result.runtime_observation.has_value()) {
        fail(SupervisorFailure::ProtocolViolation, "runtime-complete supervisor omitted runtime evidence");
    }
    return CompletedNativeCaptureObservations(
        std::move(result.namespace_observation),
        std::move(result.exec_stop_observation),
        std::move(result.open_receipt),
        std::move(*result.runtime_observation),
        std::move(result.termination_observation),
        private_context_binding_digest);
}

CompletedNativeCaptureObservations
PtraceOpenSupervisor::run_completed_observations_for_testing(
    std::unique_ptr<ExecStoppedLaunch> exec_stopped,
    ReceiptContextExpectation receipt_expectation,
    PtraceOpenLimits limits) {
    if (exec_stopped == nullptr) {
        fail(SupervisorFailure::InvalidRequest,
             "test completed-observation request has no exec-stopped launch");
    }
    return run(*exec_stopped, std::move(receipt_expectation), limits);
}

CompletedOpenTraceSlice PtraceOpenSupervisor::run_open_receipt_slice_for_testing(
    std::unique_ptr<ExecStoppedLaunch> exec_stopped,
    ReceiptContextExpectation receipt_expectation,
    PtraceOpenLimits limits) {
    if (exec_stopped == nullptr) {
        fail(SupervisorFailure::InvalidRequest,
             "test open-receipt request has no exec-stopped launch");
    }
    return run_trace(
               *exec_stopped, std::move(receipt_expectation), limits, false)
        .open_receipt;
}

}  // namespace evaluation_v6_3_1::capture_v2
