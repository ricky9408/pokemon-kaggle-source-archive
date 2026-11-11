#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "LaunchEngine.h"

#if !defined(__linux__)
#error "LaunchEngine is a Linux-only Capture V2 component"
#endif

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/sched.h>
#include <linux/securebits.h>
#include <limits>
#include <memory>
#include <optional>
#include <poll.h>
#include <signal.h>
#include <string>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {
namespace {

constexpr std::uint32_t kCollectorRole = 1u;
constexpr int kChildStdin = STDIN_FILENO;
constexpr int kChildStdout = STDOUT_FILENO;
constexpr int kChildStderr = STDERR_FILENO;
constexpr int kChildReceipt = 3;
constexpr int kChildReady = 4;
constexpr int kChildRelease = 5;
constexpr int kFirstStagingFd = 64;

[[noreturn]] void fail(SupervisorFailure failure, std::string message, int error = 0) {
    throw SupervisorError(failure, std::move(message), error);
}

bool digest_is_zero(const Sha256Digest& digest) noexcept {
    return std::all_of(digest.begin(), digest.end(), [](std::uint8_t byte) {
        return byte == 0u;
    });
}

struct LaunchProjection final {
    std::string collector_namespace_relative_path;
    std::uint64_t expected_collector_byte_length = 0u;
    Sha256Digest expected_collector_sha256{};
    std::vector<NamespaceFileExpectation> expected_namespace_files;
};

LaunchProjection validate_and_project(
    const RetainedInputSet& retained_inputs,
    const ValidatedPrelaunchPlan& plan,
    const LaunchRuntimeConfiguration& runtime) {
    if (runtime.staging_root_absolute_path.empty() || runtime.tmpfs_byte_limit == 0u ||
        runtime.stdout_byte_cap != kRawCollectorCaptureMaxBytesV1 ||
        runtime.stderr_byte_cap == 0u ||
        runtime.receipt_byte_cap == 0u || runtime.custody_timeout_milliseconds == 0u ||
        runtime.ready_timeout_milliseconds == 0u ||
        runtime.namespace_identity_timeout_milliseconds == 0u ||
        runtime.namespace_identity_total_byte_cap == 0u ||
        plan.public_file_rows().empty() ||
        plan.public_file_rows().size() != retained_inputs.inputs().size() ||
        plan.collector_launch_argv().empty()) {
        fail(SupervisorFailure::InvalidRequest, "launch plan or runtime configuration is incomplete");
    }

    LaunchProjection projection;
    projection.expected_namespace_files.reserve(plan.public_file_rows().size());
    std::size_t collector_count = 0u;
    std::uint64_t namespace_bytes = 0u;
    for (std::size_t index = 0u; index < retained_inputs.inputs().size(); ++index) {
        const RetainedInput& input = retained_inputs.inputs()[index];
        const DecodedPublicFileRow& decoded = plan.public_file_rows()[index];
        if (!is_normalized_relative_path(decoded.namespace_relative_path) ||
            decoded.normalized_mode > std::numeric_limits<std::uint32_t>::max() ||
            decoded.byte_length == 0u || digest_is_zero(decoded.sha256)) {
            fail(SupervisorFailure::InvalidRequest, "validated namespace row is not launchable");
        }
        std::vector<std::uint32_t> roles;
        roles.reserve(decoded.role_codes.size());
        for (const std::uint64_t role : decoded.role_codes) {
            if (role > std::numeric_limits<std::uint32_t>::max()) {
                fail(SupervisorFailure::InvalidRequest, "validated namespace role exceeds native range");
            }
            roles.push_back(static_cast<std::uint32_t>(role));
        }
        NamespaceFileExpectation expected{
            decoded.namespace_relative_path,
            std::move(roles),
            static_cast<std::uint32_t>(decoded.normalized_mode),
            decoded.byte_length,
            decoded.sha256,
        };
        if (expected.namespace_relative_path != input.spec().namespace_relative_path ||
            expected.role_codes != input.spec().role_codes ||
            expected.normalized_mode != input.spec().normalized_mode ||
            expected.byte_length != input.acquired_identity().byte_length) {
            fail(SupervisorFailure::InvalidRequest, "validated namespace row differs from retained input");
        }
        if (namespace_bytes > runtime.namespace_identity_total_byte_cap ||
            expected.byte_length > runtime.namespace_identity_total_byte_cap - namespace_bytes) {
            fail(SupervisorFailure::ResourceLimit,
                 "expected namespace files exceed identity observation cap");
        }
        namespace_bytes += expected.byte_length;
        if (std::binary_search(
                expected.role_codes.begin(),
                expected.role_codes.end(),
                kCollectorRole)) {
            ++collector_count;
            projection.collector_namespace_relative_path = expected.namespace_relative_path;
            projection.expected_collector_byte_length = expected.byte_length;
            projection.expected_collector_sha256 = expected.sha256;
        }
        projection.expected_namespace_files.push_back(std::move(expected));
    }
    if (collector_count != 1u || projection.collector_namespace_relative_path.empty() ||
        plan.collector_launch_argv().front() !=
            "/" + projection.collector_namespace_relative_path) {
        fail(SupervisorFailure::InvalidRequest, "derived collector launch argv is not bound to the role-1 executable");
    }
    return projection;
}

struct PipePair final {
    OwnedFd reader;
    OwnedFd writer;
};

PipePair create_pipe() {
    int descriptors[2]{-1, -1};
    if (::pipe2(descriptors, O_CLOEXEC) != 0) {
        fail(SupervisorFailure::ProcessLaunch, "pipe2 failed", errno);
    }
    return PipePair{OwnedFd(descriptors[0]), OwnedFd(descriptors[1])};
}

void make_nonblocking(int descriptor) {
    const int flags = ::fcntl(descriptor, F_GETFL);
    if (flags < 0 || ::fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0) {
        fail(SupervisorFailure::ProcessLaunch, "set nonblocking pipe failed", errno);
    }
}

OwnedFd create_release_event() {
    const int descriptor = ::eventfd(0u, EFD_CLOEXEC);
    if (descriptor < 0) {
        fail(SupervisorFailure::ProcessLaunch, "eventfd creation failed", errno);
    }
    return OwnedFd(descriptor);
}

void close_parent_only_child_ends(
    PipePair& standard_input,
    PipePair& standard_output,
    PipePair& standard_error,
    PipePair& receipt,
    PipePair& ready) noexcept {
    standard_input.writer.reset();
    standard_output.reader.reset();
    standard_error.reader.reset();
    receipt.reader.reset();
    ready.reader.reset();
}

void close_child_only_parent_ends(
    PipePair& standard_input,
    PipePair& standard_output,
    PipePair& standard_error,
    PipePair& receipt,
    PipePair& ready) noexcept {
    standard_input.reader.reset();
    standard_input.writer.reset();
    standard_output.writer.reset();
    standard_error.writer.reset();
    receipt.writer.reset();
    ready.writer.reset();
}

void duplicate_child_layout(const std::array<int, 6>& source_descriptors) {
    std::array<OwnedFd, 6> staged;
    for (std::size_t index = 0u; index < source_descriptors.size(); ++index) {
        const int duplicate = ::fcntl(source_descriptors[index], F_DUPFD_CLOEXEC, kFirstStagingFd);
        if (duplicate < 0) {
            fail(SupervisorFailure::ProcessLaunch, "stage child descriptor failed", errno);
        }
        staged[index].reset(duplicate);
    }

    constexpr std::array<int, 6> targets = {
        kChildStdin, kChildStdout, kChildStderr, kChildReceipt, kChildReady, kChildRelease};
    for (std::size_t index = 0u; index < targets.size(); ++index) {
        const int flags = targets[index] >= kChildReady ? O_CLOEXEC : 0;
        if (::dup3(staged[index].get(), targets[index], flags) != targets[index]) {
            fail(SupervisorFailure::ProcessLaunch, "install exact child descriptor failed", errno);
        }
    }
    if (::syscall(SYS_close_range, 6u, std::numeric_limits<unsigned int>::max(), 0u) != 0) {
        fail(SupervisorFailure::ProcessLaunch, "close_range child descriptor seal failed", errno);
    }
    for (int target : targets) {
        const int descriptor_flags = ::fcntl(target, F_GETFD);
        const bool expected_cloexec = target >= kChildReady;
        if (descriptor_flags < 0 ||
            (((descriptor_flags & FD_CLOEXEC) != 0) != expected_cloexec)) {
            fail(SupervisorFailure::ProcessLaunch, "exact child descriptor flags are invalid", errno);
        }
    }
}

void lock_and_drop_child_privileges() {
    constexpr unsigned long securebits =
        SECBIT_NOROOT | SECBIT_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP |
        SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_KEEP_CAPS_LOCKED |
        SECBIT_NO_CAP_AMBIENT_RAISE | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED;
    if (::prctl(PR_SET_SECUREBITS, securebits, 0u, 0u, 0u) != 0 ||
        ::prctl(PR_SET_NO_NEW_PRIVS, 1u, 0u, 0u, 0u) != 0 ||
        ::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0u, 0u, 0u) != 0) {
        fail(SupervisorFailure::ProcessLaunch, "lock child privilege state failed", errno);
    }

    constexpr unsigned int kMaximumCapabilityProbe = 1024u;
    bool found_capability_ceiling = false;
    for (unsigned int capability = 0u; capability < kMaximumCapabilityProbe; ++capability) {
        errno = 0;
        const int present = ::prctl(PR_CAPBSET_READ, capability, 0u, 0u, 0u);
        if (present < 0 && errno == EINVAL) {
            found_capability_ceiling = true;
            break;
        }
        if (present < 0 || present > 1 ||
            (present == 1 &&
             ::prctl(PR_CAPBSET_DROP, capability, 0u, 0u, 0u) != 0)) {
            fail(SupervisorFailure::ProcessLaunch, "drop child capability bounding set failed", errno);
        }
    }
    if (!found_capability_ceiling) {
        fail(SupervisorFailure::ProcessLaunch, "child capability ceiling was not bounded");
    }

    if (::setgroups(0u, nullptr) != 0) {
        fail(SupervisorFailure::ProcessLaunch, "drop child supplementary groups failed", errno);
    }

    __user_cap_header_struct header{};
    header.version = _LINUX_CAPABILITY_VERSION_3;
    header.pid = 0;
    std::array<__user_cap_data_struct, 2> capabilities{};
    if (::syscall(SYS_capset, &header, capabilities.data()) != 0) {
        fail(SupervisorFailure::ProcessLaunch, "drop child capabilities failed", errno);
    }
    std::array<__user_cap_data_struct, 2> observed{};
    if (::syscall(SYS_capget, &header, observed.data()) != 0) {
        fail(SupervisorFailure::ProcessLaunch, "verify child capabilities failed", errno);
    }
    for (const __user_cap_data_struct& row : observed) {
        if (row.effective != 0u || row.permitted != 0u || row.inheritable != 0u) {
            fail(SupervisorFailure::ProcessLaunch, "child capabilities remain after drop");
        }
    }
    uid_t real_uid = 0u;
    uid_t effective_uid = 0u;
    uid_t saved_uid = 0u;
    gid_t real_gid = 0u;
    gid_t effective_gid = 0u;
    gid_t saved_gid = 0u;
    if (::getresuid(&real_uid, &effective_uid, &saved_uid) != 0 ||
        ::getresgid(&real_gid, &effective_gid, &saved_gid) != 0 ||
        real_uid != 0u || effective_uid != 0u || saved_uid != 0u ||
        real_gid != 0u || effective_gid != 0u || saved_gid != 0u ||
        ::getgroups(0, nullptr) != 0) {
        fail(SupervisorFailure::ProcessLaunch, "child credential state differs from sealed requirement", errno);
    }
    for (unsigned int capability = 0u; capability < kMaximumCapabilityProbe; ++capability) {
        errno = 0;
        const int present = ::prctl(PR_CAPBSET_READ, capability, 0u, 0u, 0u);
        if (present < 0 && errno == EINVAL) {
            break;
        }
        if (present != 0) {
            fail(SupervisorFailure::ProcessLaunch, "child capability bounding set remains nonempty");
        }
    }
    if (::prctl(PR_GET_SECUREBITS, 0u, 0u, 0u, 0u) != static_cast<int>(securebits) ||
        ::prctl(PR_GET_NO_NEW_PRIVS, 0u, 0u, 0u, 0u) != 1 ||
        ::prctl(PR_SET_DUMPABLE, 1u, 0u, 0u, 0u) != 0 ||
        ::prctl(PR_GET_DUMPABLE, 0u, 0u, 0u, 0u) != 1) {
        fail(SupervisorFailure::ProcessLaunch, "child privilege-state verification failed", errno);
    }
}

const MaterializedInput& validate_materialized_rows_and_find_collector(
    const MountSandboxResult& sandbox,
    const LaunchProjection& projection) {
    if (sandbox.file_rows.size() != projection.expected_namespace_files.size()) {
        fail(SupervisorFailure::ProtocolViolation, "materialized namespace row count differs from context");
    }
    const MaterializedInput* collector = nullptr;
    for (std::size_t index = 0u; index < sandbox.file_rows.size(); ++index) {
        const MaterializedInput& row = sandbox.file_rows[index];
        const NamespaceFileExpectation& expected = projection.expected_namespace_files[index];
        if (row.namespace_relative_path != expected.namespace_relative_path ||
            row.role_codes != expected.role_codes || row.normalized_mode != expected.normalized_mode ||
            row.byte_length != expected.byte_length || row.sha256 != expected.sha256) {
            fail(SupervisorFailure::ProtocolViolation, "materialized namespace row differs from context");
        }
        if (!std::binary_search(row.role_codes.begin(), row.role_codes.end(), kCollectorRole)) {
            continue;
        }
        if (collector != nullptr) {
            fail(SupervisorFailure::ProtocolViolation, "materialized collector is ambiguous");
        }
        collector = &row;
    }
    if (collector == nullptr ||
        collector->namespace_relative_path != projection.collector_namespace_relative_path ||
        collector->byte_length != projection.expected_collector_byte_length ||
        collector->sha256 != projection.expected_collector_sha256) {
        fail(SupervisorFailure::ProtocolViolation, "materialized collector differs from context");
    }
    return *collector;
}

[[noreturn]] void child_failure(int ready_descriptor, std::uint32_t failure_code) noexcept {
    if (failure_code == 0u) {
        failure_code = std::numeric_limits<std::uint32_t>::max();
    }
    try {
        LaunchReadyRecord record{};
        record.status = LaunchReadyStatus::Failed;
        record.failure_code = failure_code;
        LaunchHandshake::write_one(ready_descriptor, record);
    } catch (...) {
    }
    ::_exit(125);
}

std::optional<SupervisorFailure> decode_child_supervisor_failure(
    std::uint32_t value) noexcept {
    switch (static_cast<SupervisorFailure>(value)) {
        case SupervisorFailure::InvalidRequest:
        case SupervisorFailure::UnsafePath:
        case SupervisorFailure::OriginalInputOpen:
        case SupervisorFailure::OriginalInputIdentity:
        case SupervisorFailure::OriginalInputChanged:
        case SupervisorFailure::DestinationInvalid:
        case SupervisorFailure::CopyFailure:
        case SupervisorFailure::ResourceLimit:
        case SupervisorFailure::ProtocolViolation:
        case SupervisorFailure::SystemFailure:
        case SupervisorFailure::NamespaceSetup:
        case SupervisorFailure::NamespaceSeal:
        case SupervisorFailure::NamespaceEnter:
        case SupervisorFailure::ProcessLaunch:
        case SupervisorFailure::HandshakeTimeout:
        case SupervisorFailure::ChildFailure:
        case SupervisorFailure::TraceFailure:
        case SupervisorFailure::TraceTimeout:
            return static_cast<SupervisorFailure>(value);
    }
    return std::nullopt;
}

[[noreturn]] void run_child(
    RetainedInputSet retained_inputs,
    const ValidatedPrelaunchPlan& plan,
    const LaunchRuntimeConfiguration& runtime,
    const LaunchProjection& projection,
    WorkDirectoryCustodySocketPair custody_pair,
    PipePair& standard_input,
    PipePair& standard_output,
    PipePair& standard_error,
    PipePair& receipt,
    PipePair& ready,
    int release_descriptor,
    pid_t expected_parent_pid) noexcept {
    int failure_ready_descriptor = ready.writer.get();
    try {
        if (::prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || ::getppid() != expected_parent_pid) {
            fail(SupervisorFailure::ProcessLaunch, "child parent-death custody setup failed", errno);
        }
        close_parent_only_child_ends(
            standard_input, standard_output, standard_error, receipt, ready);
        MountSandboxResult sandbox = MountSandbox::build_seal_and_enter(
            std::move(retained_inputs),
            MountSandboxConfig{
                runtime.staging_root_absolute_path,
                plan.working_directory_relative_path(),
                runtime.tmpfs_byte_limit,
            });
        const MaterializedInput& collector =
            validate_materialized_rows_and_find_collector(sandbox, projection);

        WorkDirectoryCustodyChildEndpoint child_endpoint =
            std::move(custody_pair).take_child_for_child();
        WorkDirectoryCustodyAckToken ack_token =
            std::move(child_endpoint).handoff_and_await_context_commit(
                sandbox.child_fchdir_fd.get());
        std::move(ack_token).enter_working_directory(
            std::move(sandbox.child_fchdir_fd));

        duplicate_child_layout({
            standard_input.reader.get(),
            standard_output.writer.get(),
            standard_error.writer.get(),
            receipt.writer.get(),
            ready.writer.get(),
            release_descriptor,
        });
        lock_and_drop_child_privileges();
        failure_ready_descriptor = kChildReady;

        LaunchReadyRecord record{};
        record.status = LaunchReadyStatus::Ready;
        record.root_device = sandbox.root_device;
        record.root_inode = sandbox.root_inode;
        record.working_directory_device = sandbox.working_directory_device;
        record.working_directory_inode = sandbox.working_directory_inode;
        record.collector_byte_length = collector.byte_length;
        record.collector_sha256 = collector.sha256;
        LaunchHandshake::write_one(kChildReady, record);
        if (::close(kChildReady) != 0) {
            child_failure(kChildReady, static_cast<std::uint32_t>(SupervisorFailure::ProcessLaunch));
        }
        failure_ready_descriptor = -1;

        std::uint64_t release_value = 0u;
        ssize_t count = -1;
        do {
            count = ::read(kChildRelease, &release_value, sizeof(release_value));
        } while (count < 0 && errno == EINTR);
        if (count != static_cast<ssize_t>(sizeof(release_value)) || release_value != 1u ||
            ::close(kChildRelease) != 0) {
            ::_exit(126);
        }

        std::vector<char*> argv;
        argv.reserve(plan.collector_launch_argv().size() + 1u);
        for (const std::string& argument : plan.collector_launch_argv()) {
            argv.push_back(const_cast<char*>(argument.c_str()));
        }
        argv.push_back(nullptr);
        char* const empty_environment[] = {nullptr};
        const std::string collector_path =
            "/" + projection.collector_namespace_relative_path;
        ::execve(collector_path.c_str(), argv.data(), empty_environment);
        ::_exit(127);
    } catch (const SupervisorError& error) {
        child_failure(failure_ready_descriptor, static_cast<std::uint32_t>(error.failure()));
    } catch (...) {
        child_failure(failure_ready_descriptor, std::numeric_limits<std::uint32_t>::max());
    }
}

struct ClonedChild final {
    pid_t pid = -1;
    OwnedFd pidfd;
};

ClonedChild clone_with_pidfd(
    RetainedInputSet& retained_inputs,
    const ValidatedPrelaunchPlan& plan,
    const LaunchRuntimeConfiguration& runtime,
    const LaunchProjection& projection,
    WorkDirectoryCustodySocketPair& custody_pair,
    PipePair& standard_input,
    PipePair& standard_output,
    PipePair& standard_error,
    PipePair& receipt,
    PipePair& ready,
    OwnedFd& release_event) {
    const pid_t expected_parent_pid = ::getpid();
    int pidfd = -1;
    clone_args arguments{};
    arguments.flags = CLONE_PIDFD;
    arguments.pidfd = reinterpret_cast<std::uint64_t>(&pidfd);
    arguments.exit_signal = SIGCHLD;
    const long result = ::syscall(SYS_clone3, &arguments, sizeof(arguments));
    if (result < 0) {
        fail(SupervisorFailure::ProcessLaunch, "clone3(CLONE_PIDFD) failed", errno);
    }
    if (result == 0) {
        run_child(
            std::move(retained_inputs),
            plan,
            runtime,
            projection,
            std::move(custody_pair),
            standard_input,
            standard_output,
            standard_error,
            receipt,
            ready,
            release_event.get(),
            expected_parent_pid);
    }
    if (result > static_cast<long>(std::numeric_limits<pid_t>::max()) || pidfd < 0) {
        fail(SupervisorFailure::ProcessLaunch, "clone3 returned an invalid child identity");
    }
    return ClonedChild{static_cast<pid_t>(result), OwnedFd(pidfd)};
}

void emergency_kill_reap(pid_t pid, int pidfd) noexcept {
    for (;;) {
        if (::syscall(SYS_pidfd_send_signal, pidfd, SIGKILL, nullptr, 0u) == 0 || errno == ESRCH) {
            break;
        }
        if (errno != EINTR) {
            break;
        }
    }
    int status = 0;
    while (::waitpid(pid, &status, __WALL) < 0 && errno == EINTR) {
    }
}

std::unique_ptr<ChildTerminationGuard> make_guard(ClonedChild& child) {
    const int descriptor = child.pidfd.release();
    try {
        return std::make_unique<ChildTerminationGuard>(child.pid, descriptor);
    } catch (...) {
        emergency_kill_reap(child.pid, descriptor);
        static_cast<void>(::close(descriptor));
        throw;
    }
}

LaunchReadyRecord read_ready_record(
    int ready_descriptor,
    int pidfd,
    const MonotonicDeadline& deadline) {
    std::array<std::uint8_t, LaunchHandshake::kWireBytes + 1u> bytes{};
    std::size_t length = 0u;
    bool eof = false;
    while (!eof) {
        pollfd descriptors[2] = {
            {ready_descriptor, POLLIN | POLLHUP | POLLERR, 0},
            {pidfd, POLLIN | POLLHUP | POLLERR, 0},
        };
        int poll_result = -1;
        do {
            poll_result = ::poll(descriptors, 2u, deadline.remaining_poll_timeout_ms());
        } while (poll_result < 0 && errno == EINTR);
        if (poll_result < 0) {
            fail(SupervisorFailure::ProcessLaunch, "ready poll failed", errno);
        }
        if (poll_result == 0) {
            fail(SupervisorFailure::HandshakeTimeout, "ready handshake timed out");
        }

        for (;;) {
            const ssize_t count = ::read(
                ready_descriptor, bytes.data() + length, bytes.size() - length);
            if (count > 0) {
                length += static_cast<std::size_t>(count);
                if (length > LaunchHandshake::kWireBytes) {
                    fail(SupervisorFailure::ProtocolViolation, "ready handshake is overlong");
                }
                continue;
            }
            if (count == 0) {
                eof = true;
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            fail(SupervisorFailure::ProcessLaunch, "ready pipe read failed", errno);
        }
        if (!eof && descriptors[1].revents != 0 && length < LaunchHandshake::kWireBytes) {
            fail(SupervisorFailure::ChildFailure, "child exited before ready handshake");
        }
    }
    if (length != LaunchHandshake::kWireBytes) {
        fail(SupervisorFailure::ProtocolViolation, "ready handshake has the wrong length");
    }
    return LaunchHandshake::decode(
        std::span<const std::uint8_t>(bytes.data(), LaunchHandshake::kWireBytes));
}

}  // namespace

void PreparedLaunch::release_child() {
    if (released_ || !release_writer_) {
        fail(SupervisorFailure::ProtocolViolation, "prepared child was already released");
    }
    const std::uint64_t value = 1u;
    ssize_t count = -1;
    do {
        count = ::write(release_writer_.get(), &value, sizeof(value));
    } while (count < 0 && errno == EINTR);
    if (count != static_cast<ssize_t>(sizeof(value))) {
        fail(SupervisorFailure::ProcessLaunch, "release event write failed", errno);
    }
    release_writer_.reset();
    released_ = true;
}

ValidatedPrelaunchContext PreparedLaunch::take_completed_context() {
    if (context_taken_ || !termination_->reaped() || !pipe_pump_->complete()) {
        fail(SupervisorFailure::ProtocolViolation,
             "prelaunch context cannot leave an incomplete capture");
    }
    context_taken_ = true;
    return std::move(context_);
}

std::unique_ptr<PreparedLaunch> LaunchEngine::prepare(
    RetainedInputSet retained_inputs,
    ValidatedPrelaunchPlan validated_plan,
    LaunchRuntimeConfiguration runtime) {
    const LaunchProjection projection =
        validate_and_project(retained_inputs, validated_plan, runtime);

    // Declared before child-facing RAII so any failure after commit destroys the
    // child and its pipes before releasing final context custody.
    std::optional<ValidatedPrelaunchContext> committed_context;

    PipePair standard_input = create_pipe();
    PipePair standard_output = create_pipe();
    PipePair standard_error = create_pipe();
    PipePair receipt = create_pipe();
    PipePair ready = create_pipe();
    OwnedFd release_event = create_release_event();
    make_nonblocking(standard_output.reader.get());
    make_nonblocking(standard_error.reader.get());
    make_nonblocking(receipt.reader.get());
    make_nonblocking(ready.reader.get());

    const MonotonicDeadline custody_deadline(
        runtime.custody_timeout_milliseconds);
    WorkDirectoryCustodySocketPair custody_pair =
        WorkDirectoryCustodySocketPair::create_production(custody_deadline);

    ClonedChild child = clone_with_pidfd(
        retained_inputs,
        validated_plan,
        runtime,
        projection,
        custody_pair,
        standard_input,
        standard_output,
        standard_error,
        receipt,
        ready,
        release_event);
    std::unique_ptr<ChildTerminationGuard> termination = make_guard(child);
    close_child_only_parent_ends(
        standard_input, standard_output, standard_error, receipt, ready);

    WorkDirectoryCustodyParentEndpoint parent_endpoint =
        std::move(custody_pair).take_parent_for_parent(child.pid);
    committed_context.emplace(
        std::move(validated_plan).bind_work_directory_custody(
            std::move(parent_endpoint)));

    auto pump = std::make_unique<PipePump>(std::vector<PipePump::ChannelSpec>{
        {PipePump::ChannelId::Stdout, standard_output.reader.get(), runtime.stdout_byte_cap},
        {PipePump::ChannelId::Stderr, standard_error.reader.get(), runtime.stderr_byte_cap},
        {PipePump::ChannelId::Receipt, receipt.reader.get(), runtime.receipt_byte_cap},
    });
    // PipePump now owns the validated descriptors.  Retain local ownership
    // until its constructor succeeds so an allocation/validation exception
    // cannot leak a released raw descriptor.
    static_cast<void>(standard_output.reader.release());
    static_cast<void>(standard_error.reader.release());
    static_cast<void>(receipt.reader.release());
    MonotonicDeadline deadline(runtime.ready_timeout_milliseconds);
    LaunchReadyRecord ready_record = read_ready_record(
        ready.reader.get(), termination->pidfd(), deadline);
    ready.reader.reset();
    if (ready_record.status != LaunchReadyStatus::Ready) {
        const std::optional<SupervisorFailure> child_failure =
            decode_child_supervisor_failure(ready_record.failure_code);
        if (!child_failure.has_value()) {
            fail(
                SupervisorFailure::ProtocolViolation,
                "child reported an unknown namespace failure code");
        }
        fail(
            *child_failure,
            "child namespace preparation failed");
    }
    if (ready_record.collector_byte_length != projection.expected_collector_byte_length ||
        ready_record.collector_sha256 != projection.expected_collector_sha256) {
        fail(SupervisorFailure::ProtocolViolation, "ready collector identity differs from context");
    }
    const WorkDirectoryIdentity& retained_working_directory =
        committed_context->retained_working_directory_identity();
    if (ready_record.working_directory_device != retained_working_directory.device ||
        ready_record.working_directory_inode != retained_working_directory.inode) {
        fail(SupervisorFailure::ProtocolViolation,
             "ready working-directory identity differs from context custody");
    }
    MonotonicDeadline namespace_identity_deadline(
        runtime.namespace_identity_timeout_milliseconds);
    std::vector<NamespaceIdentityObservation> namespace_identity_rows =
        NamespaceIdentityObserver::observe(
            child.pid,
            ready_record,
            projection.expected_namespace_files,
            runtime.namespace_identity_total_byte_cap,
            namespace_identity_deadline);

    return std::unique_ptr<PreparedLaunch>(new PreparedLaunch(
        std::move(*committed_context),
        std::move(termination),
        std::move(pump),
        std::move(release_event),
        ready_record,
        projection.expected_namespace_files,
        std::move(namespace_identity_rows)));
}

}  // namespace evaluation_v6_3_1::capture_v2
