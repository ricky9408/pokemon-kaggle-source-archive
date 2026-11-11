#ifndef EVALUATION_V6_3_1_CAPTURE_V2_WORK_DIRECTORY_CUSTODY_H
#define EVALUATION_V6_3_1_CAPTURE_V2_WORK_DIRECTORY_CUSTODY_H

// Zero-authority Linux capability handoff. The production API owns its nonce,
// deadline, endpoints, and state transitions. Only ValidatedPrelaunchPlan may
// consume the parent endpoint and ACK a committed final context.

#include "OwnedFd.h"
#include "SupervisorTypes.h"
#include "Timeout.h"

#include <array>
#include <cstdint>
#include <sys/types.h>
#include <utility>

namespace evaluation_v6_3_1::capture_v2 {

class ValidatedPrelaunchPlan;

using WorkDirectorySessionNonce = std::array<std::uint8_t, 32u>;

struct WorkDirectoryIdentity final {
    std::uint64_t device = 0u;
    std::uint64_t inode = 0u;

    friend bool operator==(const WorkDirectoryIdentity&, const WorkDirectoryIdentity&) = default;
};

class WorkDirectoryCustody final {
public:
    WorkDirectoryCustody(WorkDirectoryCustody&&) noexcept = default;
    WorkDirectoryCustody& operator=(WorkDirectoryCustody&&) = delete;
    WorkDirectoryCustody(const WorkDirectoryCustody&) = delete;
    WorkDirectoryCustody& operator=(const WorkDirectoryCustody&) = delete;
    ~WorkDirectoryCustody() noexcept = default;

    [[nodiscard]] int retained_directory_fd() const noexcept { return retained_directory_fd_.get(); }
    [[nodiscard]] const WorkDirectoryIdentity& identity() const noexcept { return identity_; }
    [[nodiscard]] OwnedFd take_retained_directory_fd() && noexcept {
        return std::move(retained_directory_fd_);
    }

private:
    friend class WorkDirectoryCustodyParentEndpoint;

    WorkDirectoryCustody(OwnedFd retained_directory_fd, WorkDirectoryIdentity identity) noexcept
        : retained_directory_fd_(std::move(retained_directory_fd)), identity_(identity) {}

    OwnedFd retained_directory_fd_;
    WorkDirectoryIdentity identity_;
};

class WorkDirectoryCustodyAckToken final {
public:
    WorkDirectoryCustodyAckToken(WorkDirectoryCustodyAckToken&& other) noexcept
        : valid_(std::exchange(other.valid_, false)) {}
    WorkDirectoryCustodyAckToken& operator=(WorkDirectoryCustodyAckToken&& other) noexcept {
        if (this != &other) {
            valid_ = std::exchange(other.valid_, false);
        }
        return *this;
    }
    WorkDirectoryCustodyAckToken(const WorkDirectoryCustodyAckToken&) = delete;
    WorkDirectoryCustodyAckToken& operator=(const WorkDirectoryCustodyAckToken&) = delete;

    // The only operation authorized by a valid ACK token.  The token is
    // unforgeable outside the custody endpoint and is consumed together with
    // the child's separately retained directory descriptor.
    void enter_working_directory(OwnedFd child_fchdir_fd) &&;

private:
    friend class WorkDirectoryCustodyChildEndpoint;

    explicit WorkDirectoryCustodyAckToken(bool valid) noexcept : valid_(valid) {}
    bool valid_ = false;
};

enum class WorkDirectoryParentState : std::uint8_t {
    WaitingForHandoff,
    HandoffAccepted,
    PeerWriteEofConfirmed,
    ContextCommitted,
    AckSent,
    Complete,
    Failed,
    MovedFrom,
};

enum class WorkDirectoryChildState : std::uint8_t {
    Ready,
    HandoffSent,
    WriteShutdown,
    WaitingForAck,
    AckAccepted,
    Complete,
    Failed,
    MovedFrom,
};

class WorkDirectoryCustodyParentEndpoint final {
public:
    WorkDirectoryCustodyParentEndpoint(WorkDirectoryCustodyParentEndpoint&& other) noexcept;
    WorkDirectoryCustodyParentEndpoint& operator=(WorkDirectoryCustodyParentEndpoint&& other) noexcept;
    WorkDirectoryCustodyParentEndpoint(const WorkDirectoryCustodyParentEndpoint&) = delete;
    WorkDirectoryCustodyParentEndpoint& operator=(const WorkDirectoryCustodyParentEndpoint&) = delete;
    ~WorkDirectoryCustodyParentEndpoint() noexcept = default;

    [[nodiscard]] WorkDirectoryParentState state() const noexcept { return state_; }

#if defined(V631302_CUSTODY_TEST_NONCE_INJECTION)
    static WorkDirectoryCustodyParentEndpoint adopt_for_testing(
        OwnedFd endpoint,
        WorkDirectorySessionNonce deterministic_nonce,
        MonotonicDeadline deadline,
        pid_t expected_child_pid);
    WorkDirectoryCustody receive_handoff_for_testing();
    void acknowledge_after_test_commit();
#endif

private:
    friend class WorkDirectoryCustodySocketPair;
    friend class ValidatedPrelaunchPlan;

    WorkDirectoryCustodyParentEndpoint(
        OwnedFd endpoint,
        WorkDirectorySessionNonce session_nonce,
        MonotonicDeadline deadline,
        pid_t expected_peer_pid,
        uid_t expected_peer_uid,
        gid_t expected_peer_gid) noexcept;

    WorkDirectoryCustody receive_handoff_and_confirm_peer_eof();
    void acknowledge_after_context_commit();
    void bind_expected_child(pid_t child_pid);
    void fail_terminal() noexcept;

    OwnedFd endpoint_;
    WorkDirectorySessionNonce session_nonce_{};
    MonotonicDeadline deadline_;
    pid_t expected_peer_pid_ = -1;
    uid_t expected_peer_uid_ = 0;
    gid_t expected_peer_gid_ = 0;
    WorkDirectoryParentState state_ = WorkDirectoryParentState::WaitingForHandoff;
};

class WorkDirectoryCustodyChildEndpoint final {
public:
    WorkDirectoryCustodyChildEndpoint(WorkDirectoryCustodyChildEndpoint&& other) noexcept;
    WorkDirectoryCustodyChildEndpoint& operator=(WorkDirectoryCustodyChildEndpoint&& other) noexcept;
    WorkDirectoryCustodyChildEndpoint(const WorkDirectoryCustodyChildEndpoint&) = delete;
    WorkDirectoryCustodyChildEndpoint& operator=(const WorkDirectoryCustodyChildEndpoint&) = delete;
    ~WorkDirectoryCustodyChildEndpoint() noexcept = default;

    [[nodiscard]] WorkDirectoryChildState state() const noexcept { return state_; }

    [[nodiscard]] WorkDirectoryCustodyAckToken handoff_and_await_context_commit(
        int child_fchdir_fd) &&;

#if defined(V631302_CUSTODY_TEST_NONCE_INJECTION)
    static WorkDirectoryCustodyChildEndpoint adopt_for_testing(
        OwnedFd endpoint,
        WorkDirectorySessionNonce deterministic_nonce,
        MonotonicDeadline deadline,
        pid_t expected_parent_pid);
#endif

private:
    friend class WorkDirectoryCustodySocketPair;

    WorkDirectoryCustodyChildEndpoint(
        OwnedFd endpoint,
        WorkDirectorySessionNonce session_nonce,
        MonotonicDeadline deadline,
        pid_t expected_peer_pid,
        uid_t expected_peer_uid,
        gid_t expected_peer_gid) noexcept;

    void fail_terminal() noexcept;

    OwnedFd endpoint_;
    WorkDirectorySessionNonce session_nonce_{};
    MonotonicDeadline deadline_;
    pid_t expected_peer_pid_ = -1;
    uid_t expected_peer_uid_ = 0;
    gid_t expected_peer_gid_ = 0;
    WorkDirectoryChildState state_ = WorkDirectoryChildState::Ready;
};

class WorkDirectoryCustodySocketPair final {
public:
    static WorkDirectoryCustodySocketPair create_production(MonotonicDeadline deadline);

#if defined(V631302_CUSTODY_TEST_NONCE_INJECTION)
    static WorkDirectoryCustodySocketPair create_for_testing(
        MonotonicDeadline deadline,
        WorkDirectorySessionNonce deterministic_nonce);
#endif

    WorkDirectoryCustodySocketPair(WorkDirectoryCustodySocketPair&&) noexcept = default;
    WorkDirectoryCustodySocketPair& operator=(WorkDirectoryCustodySocketPair&&) noexcept = default;
    WorkDirectoryCustodySocketPair(const WorkDirectoryCustodySocketPair&) = delete;
    WorkDirectoryCustodySocketPair& operator=(const WorkDirectoryCustodySocketPair&) = delete;
    ~WorkDirectoryCustodySocketPair() noexcept = default;

    // Invoke these only after clone/fork. Each operation closes the opposite
    // inherited endpoint before returning the process's sole endpoint.
    [[nodiscard]] WorkDirectoryCustodyParentEndpoint take_parent_for_parent(
        pid_t child_pid) &&;
    [[nodiscard]] WorkDirectoryCustodyChildEndpoint take_child_for_child() &&;

private:
    WorkDirectoryCustodySocketPair(
        WorkDirectoryCustodyParentEndpoint parent,
        WorkDirectoryCustodyChildEndpoint child) noexcept
        : parent_(std::move(parent)), child_(std::move(child)) {}

    static WorkDirectoryCustodySocketPair create_with_nonce(
        MonotonicDeadline deadline,
        WorkDirectorySessionNonce nonce);

    WorkDirectoryCustodyParentEndpoint parent_;
    WorkDirectoryCustodyChildEndpoint child_;
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_WORK_DIRECTORY_CUSTODY_H
