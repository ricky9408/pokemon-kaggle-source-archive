#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "WorkDirectoryCustody.h"

#if !defined(__linux__)
#error "WorkDirectoryCustody is a Linux-only Capture V2 component"
#endif

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <optional>
#include <poll.h>
#include <string>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {
namespace {

constexpr std::array<std::uint8_t, 8u> kPacketMagic = {
    'V', '6', '3', '1', 'W', 'D', 'C', '1',
};
constexpr std::uint8_t kPacketVersion = 1u;
constexpr std::uint8_t kHandoffMessageType = 1u;
constexpr std::uint8_t kAckMessageType = 2u;
constexpr std::size_t kPacketBytes = 48u;
constexpr std::size_t kMaximumReceivedFds = 8u;
constexpr std::size_t kControlBytes =
    CMSG_SPACE(sizeof(int) * kMaximumReceivedFds) + CMSG_SPACE(sizeof(struct ucred));

[[noreturn]] void protocol_fail(std::string message, int error = 0) {
    throw SupervisorError(SupervisorFailure::ProtocolViolation, std::move(message), error);
}

[[noreturn]] void system_fail(std::string message, int error) {
    throw SupervisorError(SupervisorFailure::SystemFailure, std::move(message), error);
}

[[noreturn]] void timeout_fail(std::string message) {
    throw SupervisorError(SupervisorFailure::HandshakeTimeout, std::move(message));
}

void require_deadline_live(const MonotonicDeadline& deadline, const char* stage) {
    if (deadline.expired()) {
        timeout_fail(std::string("work-directory custody deadline expired during ") + stage);
    }
}

short wait_for_socket(
    int endpoint,
    short requested_events,
    const MonotonicDeadline& deadline,
    const char* stage) {
    for (;;) {
        const int timeout = deadline.remaining_poll_timeout_ms();
        if (timeout == 0) {
            timeout_fail(std::string("work-directory custody timed out during ") + stage);
        }
        struct pollfd descriptor {};
        descriptor.fd = endpoint;
        descriptor.events = static_cast<short>(
            requested_events | POLLERR | POLLHUP | POLLRDHUP);
        const int count = ::poll(&descriptor, 1u, timeout);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            system_fail(std::string("work-directory custody poll failed during ") + stage, errno);
        }
        if (count == 0) {
            timeout_fail(std::string("work-directory custody timed out during ") + stage);
        }
        if ((descriptor.revents & POLLNVAL) != 0) {
            protocol_fail(std::string("work-directory custody endpoint invalid during ") + stage);
        }
        if ((descriptor.revents & POLLERR) != 0) {
            protocol_fail(std::string("work-directory custody endpoint error during ") + stage);
        }
        return descriptor.revents;
    }
}

void require_endpoint(int descriptor) {
    if (descriptor < 0) {
        protocol_fail("work-directory custody endpoint is absent");
    }
    int socket_type = 0;
    socklen_t socket_type_length = sizeof(socket_type);
    if (::getsockopt(
            descriptor,
            SOL_SOCKET,
            SO_TYPE,
            &socket_type,
            &socket_type_length) != 0) {
        system_fail("work-directory custody endpoint is not a socket", errno);
    }
    if (socket_type != SOCK_SEQPACKET || socket_type_length != sizeof(socket_type)) {
        protocol_fail("work-directory custody endpoint is not SOCK_SEQPACKET");
    }
    const int status_flags = ::fcntl(descriptor, F_GETFL);
    if (status_flags < 0) {
        system_fail("work-directory custody endpoint status flags are unavailable", errno);
    }
    if ((status_flags & O_NONBLOCK) == 0) {
        protocol_fail("work-directory custody endpoint is blocking");
    }
    const int descriptor_flags = ::fcntl(descriptor, F_GETFD);
    if (descriptor_flags < 0) {
        system_fail("work-directory custody endpoint descriptor flags are unavailable", errno);
    }
    if ((descriptor_flags & FD_CLOEXEC) == 0) {
        protocol_fail("work-directory custody endpoint is not close-on-exec");
    }
    int pass_credentials = 0;
    socklen_t pass_credentials_length = sizeof(pass_credentials);
    if (::getsockopt(
            descriptor,
            SOL_SOCKET,
            SO_PASSCRED,
            &pass_credentials,
            &pass_credentials_length) != 0) {
        system_fail("work-directory custody SO_PASSCRED state is unavailable", errno);
    }
    if (pass_credentials != 1 || pass_credentials_length != sizeof(pass_credentials)) {
        protocol_fail("work-directory custody endpoint does not require peer credentials");
    }
}

void enable_pass_credentials(int descriptor) {
    const int enabled = 1;
    if (::setsockopt(descriptor, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) != 0) {
        system_fail("work-directory custody SO_PASSCRED enable failed", errno);
    }
}

WorkDirectoryIdentity require_directory_descriptor(int descriptor, const char* role) {
    if (descriptor < 0) {
        protocol_fail(std::string(role) + " descriptor is absent");
    }
    const int status_flags = ::fcntl(descriptor, F_GETFL);
    if (status_flags < 0) {
        system_fail(std::string(role) + " descriptor status flags are unavailable", errno);
    }
    if ((status_flags & O_PATH) == 0) {
        protocol_fail(std::string(role) + " descriptor is not O_PATH");
    }
    const int descriptor_flags = ::fcntl(descriptor, F_GETFD);
    if (descriptor_flags < 0) {
        system_fail(std::string(role) + " descriptor flags are unavailable", errno);
    }
    if ((descriptor_flags & FD_CLOEXEC) == 0) {
        protocol_fail(std::string(role) + " descriptor is not close-on-exec");
    }
    struct stat status {};
    if (::fstat(descriptor, &status) != 0) {
        system_fail(std::string(role) + " descriptor fstat failed", errno);
    }
    if (!S_ISDIR(status.st_mode)) {
        protocol_fail(std::string(role) + " descriptor is not a directory");
    }
    return WorkDirectoryIdentity{
        static_cast<std::uint64_t>(status.st_dev),
        static_cast<std::uint64_t>(status.st_ino),
    };
}

std::array<std::uint8_t, kPacketBytes> encode_packet(
    std::uint8_t message_type,
    const WorkDirectorySessionNonce& nonce) noexcept {
    std::array<std::uint8_t, kPacketBytes> output{};
    std::copy(kPacketMagic.begin(), kPacketMagic.end(), output.begin());
    output[8u] = kPacketVersion;
    output[9u] = message_type;
    output[10u] = 0u;
    output[11u] = 32u;
    std::copy(nonce.begin(), nonce.end(), output.begin() + 16u);
    return output;
}

void validate_packet(
    const std::array<std::uint8_t, kPacketBytes>& bytes,
    std::size_t byte_count,
    int message_flags,
    std::uint8_t expected_message_type,
    const WorkDirectorySessionNonce& expected_nonce) {
    if (byte_count != bytes.size()) {
        protocol_fail("work-directory custody packet size is not exact");
    }
    if ((message_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0) {
        protocol_fail("work-directory custody packet was truncated");
    }
    if ((message_flags & ~(MSG_EOR | MSG_CMSG_CLOEXEC)) != 0) {
        protocol_fail(
            "work-directory custody packet has unexpected receive flags: " +
            std::to_string(message_flags));
    }
    if (!std::equal(kPacketMagic.begin(), kPacketMagic.end(), bytes.begin()) ||
        bytes[8u] != kPacketVersion || bytes[9u] != expected_message_type ||
        bytes[10u] != 0u || bytes[11u] != 32u || bytes[12u] != 0u ||
        bytes[13u] != 0u || bytes[14u] != 0u || bytes[15u] != 0u ||
        !std::equal(expected_nonce.begin(), expected_nonce.end(), bytes.begin() + 16u)) {
        protocol_fail("work-directory custody packet fields are not exact");
    }
}

struct ReceivedRecord final {
    std::array<std::uint8_t, kPacketBytes> bytes{};
    std::size_t byte_count = 0u;
    int message_flags = 0;
    short observed_revents = 0;
    std::size_t control_bytes = 0u;
    std::vector<OwnedFd> descriptors;
    std::optional<struct ucred> credentials;
    std::size_t rights_messages = 0u;
    std::size_t credential_messages = 0u;
    bool unexpected_ancillary = false;
};

ReceivedRecord receive_record(
    int endpoint,
    const MonotonicDeadline& deadline,
    const char* stage,
    bool poll_before_receive = false,
    std::size_t data_capacity = kPacketBytes) {
    if (data_capacity == 0u || data_capacity > kPacketBytes) {
        protocol_fail("work-directory custody receive buffer size is invalid");
    }
    short observed_revents = 0;
    bool must_poll = poll_before_receive;
    for (;;) {
        if (must_poll) {
            observed_revents = wait_for_socket(
                endpoint,
                static_cast<short>(POLLIN | POLLRDHUP),
                deadline,
                stage);
            must_poll = false;
        }

        ReceivedRecord record;
        record.observed_revents = observed_revents;
        std::array<std::byte, kControlBytes> control{};
        struct iovec iov {};
        iov.iov_base = record.bytes.data();
        iov.iov_len = data_capacity;
        struct msghdr message {};
        message.msg_iov = &iov;
        message.msg_iovlen = 1u;
        message.msg_control = control.data();
        message.msg_controllen = control.size();

        const ssize_t count = ::recvmsg(
            endpoint,
            &message,
            MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
        if (count < 0 && errno == EINTR) {
            require_deadline_live(deadline, stage);
            continue;
        }
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            must_poll = true;
            continue;
        }
        if (count < 0) {
            system_fail(std::string("work-directory custody recvmsg failed during ") + stage, errno);
        }

        record.byte_count = static_cast<std::size_t>(count);
        record.message_flags = message.msg_flags;
        record.control_bytes = message.msg_controllen;
        for (struct cmsghdr* header = CMSG_FIRSTHDR(&message); header != nullptr;
             header = CMSG_NXTHDR(&message, header)) {
            if (header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS) {
                ++record.rights_messages;
                if (header->cmsg_len < CMSG_LEN(0)) {
                    protocol_fail("work-directory custody SCM_RIGHTS length is malformed");
                }
                const std::size_t payload_bytes =
                    static_cast<std::size_t>(header->cmsg_len - CMSG_LEN(0));
                if (payload_bytes == 0u || payload_bytes % sizeof(int) != 0u) {
                    protocol_fail("work-directory custody SCM_RIGHTS payload is malformed");
                }
                const std::size_t descriptor_count = payload_bytes / sizeof(int);
                if (descriptor_count > kMaximumReceivedFds ||
                    descriptor_count > kMaximumReceivedFds - record.descriptors.size()) {
                    protocol_fail("work-directory custody received too many descriptors");
                }
                const auto* descriptor_bytes =
                    static_cast<const std::uint8_t*>(CMSG_DATA(header));
                for (std::size_t index = 0u; index < descriptor_count; ++index) {
                    int received = -1;
                    std::memcpy(
                        &received,
                        descriptor_bytes + index * sizeof(int),
                        sizeof(received));
                    if (received < 0) {
                        protocol_fail("work-directory custody received an invalid descriptor");
                    }
                    record.descriptors.emplace_back(received);
                    const int descriptor_flags = ::fcntl(received, F_GETFD);
                    if (descriptor_flags < 0) {
                        system_fail(
                            "work-directory custody received descriptor flags are unavailable",
                            errno);
                    }
                    if ((descriptor_flags & FD_CLOEXEC) == 0) {
                        protocol_fail(
                            "work-directory custody received descriptor is not close-on-exec");
                    }
                }
                continue;
            }
            if (header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_CREDENTIALS) {
                ++record.credential_messages;
                if (header->cmsg_len != CMSG_LEN(sizeof(struct ucred))) {
                    protocol_fail("work-directory custody SCM_CREDENTIALS length is malformed");
                }
                struct ucred credentials {};
                std::memcpy(&credentials, CMSG_DATA(header), sizeof(credentials));
                record.credentials = credentials;
                continue;
            }
            record.unexpected_ancillary = true;
        }
        return record;
    }
}

void validate_credentials(
    const ReceivedRecord& record,
    pid_t expected_pid,
    uid_t expected_uid,
    gid_t expected_gid) {
    if (record.credential_messages != 1u || !record.credentials.has_value() ||
        record.credentials->pid != expected_pid ||
        record.credentials->uid != expected_uid ||
        record.credentials->gid != expected_gid) {
        protocol_fail("work-directory custody peer credentials are not exact");
    }
}

void send_record(
    int endpoint,
    const std::array<std::uint8_t, kPacketBytes>& bytes,
    const MonotonicDeadline& deadline,
    const char* stage,
    int transferred_descriptor = -1) {
    for (;;) {
        require_deadline_live(deadline, stage);
        std::array<std::byte, CMSG_SPACE(sizeof(int))> control{};
        struct iovec iov {};
        iov.iov_base = const_cast<std::uint8_t*>(bytes.data());
        iov.iov_len = bytes.size();
        struct msghdr message {};
        message.msg_iov = &iov;
        message.msg_iovlen = 1u;
        if (transferred_descriptor >= 0) {
            message.msg_control = control.data();
            message.msg_controllen = control.size();
            struct cmsghdr* header = CMSG_FIRSTHDR(&message);
            if (header == nullptr) {
                protocol_fail("work-directory custody control-message construction failed");
            }
            header->cmsg_level = SOL_SOCKET;
            header->cmsg_type = SCM_RIGHTS;
            header->cmsg_len = CMSG_LEN(sizeof(int));
            std::memcpy(CMSG_DATA(header), &transferred_descriptor, sizeof(transferred_descriptor));
        }
        const ssize_t count = ::sendmsg(
            endpoint,
            &message,
            MSG_DONTWAIT | MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            static_cast<void>(wait_for_socket(endpoint, POLLOUT, deadline, stage));
            continue;
        }
        if (count < 0) {
            system_fail(std::string("work-directory custody sendmsg failed during ") + stage, errno);
        }
        if (static_cast<std::size_t>(count) != bytes.size()) {
            protocol_fail(std::string("work-directory custody short send during ") + stage);
        }
        require_deadline_live(deadline, stage);
        return;
    }
}

void confirm_peer_write_eof(
    int endpoint,
    const MonotonicDeadline& deadline) {
    ReceivedRecord record = receive_record(
        endpoint,
        deadline,
        "peer-write EOF barrier",
        true,
        1u);
    if (record.byte_count != 0u ||
        (record.message_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 ||
        !record.descriptors.empty() || record.control_bytes != 0u ||
        record.credential_messages != 0u || record.rights_messages != 0u ||
        record.unexpected_ancillary) {
        protocol_fail("work-directory custody duplicate handoff detected before context commit");
    }
    if ((record.observed_revents & POLLRDHUP) == 0) {
        protocol_fail("work-directory custody peer write EOF lacked POLLRDHUP");
    }
    if ((record.message_flags & ~(MSG_EOR | MSG_CMSG_CLOEXEC)) != 0) {
        protocol_fail("work-directory custody peer write EOF has unexpected flags");
    }
}

WorkDirectorySessionNonce generate_nonce(const MonotonicDeadline& deadline) {
    WorkDirectorySessionNonce nonce{};
    std::size_t offset = 0u;
    while (offset < nonce.size()) {
        require_deadline_live(deadline, "nonce generation");
        const ssize_t count = ::getrandom(
            nonce.data() + offset,
            nonce.size() - offset,
            0u);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            system_fail("work-directory custody getrandom failed", errno);
        }
        if (count == 0) {
            system_fail("work-directory custody getrandom returned zero bytes", EIO);
        }
        offset += static_cast<std::size_t>(count);
    }
    require_deadline_live(deadline, "nonce generation");
    return nonce;
}

}  // namespace

WorkDirectoryCustodyParentEndpoint::WorkDirectoryCustodyParentEndpoint(
    OwnedFd endpoint,
    WorkDirectorySessionNonce session_nonce,
    MonotonicDeadline deadline,
    pid_t expected_peer_pid,
    uid_t expected_peer_uid,
    gid_t expected_peer_gid) noexcept
    : endpoint_(std::move(endpoint)),
      session_nonce_(session_nonce),
      deadline_(deadline),
      expected_peer_pid_(expected_peer_pid),
      expected_peer_uid_(expected_peer_uid),
      expected_peer_gid_(expected_peer_gid) {}

WorkDirectoryCustodyParentEndpoint::WorkDirectoryCustodyParentEndpoint(
    WorkDirectoryCustodyParentEndpoint&& other) noexcept
    : endpoint_(std::move(other.endpoint_)),
      session_nonce_(other.session_nonce_),
      deadline_(other.deadline_),
      expected_peer_pid_(other.expected_peer_pid_),
      expected_peer_uid_(other.expected_peer_uid_),
      expected_peer_gid_(other.expected_peer_gid_),
      state_(other.state_) {
    other.expected_peer_pid_ = -1;
    other.state_ = WorkDirectoryParentState::MovedFrom;
}

WorkDirectoryCustodyParentEndpoint& WorkDirectoryCustodyParentEndpoint::operator=(
    WorkDirectoryCustodyParentEndpoint&& other) noexcept {
    if (this != &other) {
        endpoint_ = std::move(other.endpoint_);
        session_nonce_ = other.session_nonce_;
        deadline_ = other.deadline_;
        expected_peer_pid_ = other.expected_peer_pid_;
        expected_peer_uid_ = other.expected_peer_uid_;
        expected_peer_gid_ = other.expected_peer_gid_;
        state_ = other.state_;
        other.expected_peer_pid_ = -1;
        other.state_ = WorkDirectoryParentState::MovedFrom;
    }
    return *this;
}

void WorkDirectoryCustodyParentEndpoint::fail_terminal() noexcept {
    endpoint_.reset();
    expected_peer_pid_ = -1;
    state_ = WorkDirectoryParentState::Failed;
}

void WorkDirectoryCustodyParentEndpoint::bind_expected_child(pid_t child_pid) {
    if (state_ != WorkDirectoryParentState::WaitingForHandoff ||
        expected_peer_pid_ != -1 || child_pid <= 0) {
        protocol_fail("work-directory custody child PID binding is invalid");
    }
    expected_peer_pid_ = child_pid;
}

WorkDirectoryCustody
WorkDirectoryCustodyParentEndpoint::receive_handoff_and_confirm_peer_eof() {
    if (state_ != WorkDirectoryParentState::WaitingForHandoff ||
        expected_peer_pid_ <= 0 || !endpoint_) {
        protocol_fail("work-directory custody parent receive is not permitted in this state");
    }
    try {
        ReceivedRecord record = receive_record(
            endpoint_.get(),
            deadline_,
            "handoff receive");
        if (record.byte_count == 0u) {
            protocol_fail("work-directory custody peer closed before handoff");
        }
        validate_packet(
            record.bytes,
            record.byte_count,
            record.message_flags,
            kHandoffMessageType,
            session_nonce_);
        if ((record.message_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 ||
            record.unexpected_ancillary || record.rights_messages != 1u ||
            record.descriptors.size() != 1u) {
            protocol_fail("work-directory custody handoff ancillary data is not exact");
        }
        validate_credentials(
            record,
            expected_peer_pid_,
            expected_peer_uid_,
            expected_peer_gid_);
        state_ = WorkDirectoryParentState::HandoffAccepted;

        OwnedFd retained_directory = std::move(record.descriptors.front());
        const WorkDirectoryIdentity identity = require_directory_descriptor(
            retained_directory.get(),
            "received work-directory");
        confirm_peer_write_eof(endpoint_.get(), deadline_);
        state_ = WorkDirectoryParentState::PeerWriteEofConfirmed;
        return WorkDirectoryCustody(std::move(retained_directory), identity);
    } catch (...) {
        fail_terminal();
        throw;
    }
}

void WorkDirectoryCustodyParentEndpoint::acknowledge_after_context_commit() {
    if (state_ != WorkDirectoryParentState::PeerWriteEofConfirmed ||
        !endpoint_) {
        protocol_fail("work-directory custody ACK is not permitted before context commit");
    }
    try {
        state_ = WorkDirectoryParentState::ContextCommitted;
        require_deadline_live(deadline_, "context commit");
        send_record(
            endpoint_.get(),
            encode_packet(kAckMessageType, session_nonce_),
            deadline_,
            "ACK send");
        state_ = WorkDirectoryParentState::AckSent;
        endpoint_.reset();
        expected_peer_pid_ = -1;
        state_ = WorkDirectoryParentState::Complete;
    } catch (...) {
        fail_terminal();
        throw;
    }
}

#if defined(V631302_CUSTODY_TEST_NONCE_INJECTION)
WorkDirectoryCustodyParentEndpoint WorkDirectoryCustodyParentEndpoint::adopt_for_testing(
    OwnedFd endpoint,
    WorkDirectorySessionNonce deterministic_nonce,
    MonotonicDeadline deadline,
    pid_t expected_child_pid) {
    require_endpoint(endpoint.get());
    if (expected_child_pid <= 0) {
        protocol_fail("work-directory custody test child PID is invalid");
    }
    return WorkDirectoryCustodyParentEndpoint(
        std::move(endpoint),
        deterministic_nonce,
        deadline,
        expected_child_pid,
        ::getuid(),
        ::getgid());
}

WorkDirectoryCustody WorkDirectoryCustodyParentEndpoint::receive_handoff_for_testing() {
    return receive_handoff_and_confirm_peer_eof();
}

void WorkDirectoryCustodyParentEndpoint::acknowledge_after_test_commit() {
    acknowledge_after_context_commit();
}
#endif

WorkDirectoryCustodyChildEndpoint::WorkDirectoryCustodyChildEndpoint(
    OwnedFd endpoint,
    WorkDirectorySessionNonce session_nonce,
    MonotonicDeadline deadline,
    pid_t expected_peer_pid,
    uid_t expected_peer_uid,
    gid_t expected_peer_gid) noexcept
    : endpoint_(std::move(endpoint)),
      session_nonce_(session_nonce),
      deadline_(deadline),
      expected_peer_pid_(expected_peer_pid),
      expected_peer_uid_(expected_peer_uid),
      expected_peer_gid_(expected_peer_gid) {}

WorkDirectoryCustodyChildEndpoint::WorkDirectoryCustodyChildEndpoint(
    WorkDirectoryCustodyChildEndpoint&& other) noexcept
    : endpoint_(std::move(other.endpoint_)),
      session_nonce_(other.session_nonce_),
      deadline_(other.deadline_),
      expected_peer_pid_(other.expected_peer_pid_),
      expected_peer_uid_(other.expected_peer_uid_),
      expected_peer_gid_(other.expected_peer_gid_),
      state_(other.state_) {
    other.expected_peer_pid_ = -1;
    other.state_ = WorkDirectoryChildState::MovedFrom;
}

WorkDirectoryCustodyChildEndpoint& WorkDirectoryCustodyChildEndpoint::operator=(
    WorkDirectoryCustodyChildEndpoint&& other) noexcept {
    if (this != &other) {
        endpoint_ = std::move(other.endpoint_);
        session_nonce_ = other.session_nonce_;
        deadline_ = other.deadline_;
        expected_peer_pid_ = other.expected_peer_pid_;
        expected_peer_uid_ = other.expected_peer_uid_;
        expected_peer_gid_ = other.expected_peer_gid_;
        state_ = other.state_;
        other.expected_peer_pid_ = -1;
        other.state_ = WorkDirectoryChildState::MovedFrom;
    }
    return *this;
}

void WorkDirectoryCustodyChildEndpoint::fail_terminal() noexcept {
    endpoint_.reset();
    expected_peer_pid_ = -1;
    state_ = WorkDirectoryChildState::Failed;
}

WorkDirectoryCustodyAckToken
WorkDirectoryCustodyChildEndpoint::handoff_and_await_context_commit(
    int child_fchdir_fd) && {
    if (state_ != WorkDirectoryChildState::Ready ||
        expected_peer_pid_ <= 0 || !endpoint_) {
        protocol_fail("work-directory custody child handoff is not permitted in this state");
    }
    try {
        const WorkDirectoryIdentity child_identity = require_directory_descriptor(
            child_fchdir_fd,
            "child fchdir");
        const int raw_handoff_descriptor = ::openat(
            child_fchdir_fd,
            ".",
            O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (raw_handoff_descriptor < 0) {
            system_fail("work-directory custody child openat dot failed", errno);
        }
        OwnedFd handoff_descriptor(raw_handoff_descriptor);
        if (require_directory_descriptor(
                handoff_descriptor.get(),
                "child handoff") != child_identity) {
            protocol_fail("work-directory custody child handoff differs from fchdir directory");
        }

        send_record(
            endpoint_.get(),
            encode_packet(kHandoffMessageType, session_nonce_),
            deadline_,
            "handoff send",
            handoff_descriptor.get());
        state_ = WorkDirectoryChildState::HandoffSent;
        handoff_descriptor.reset();
        require_deadline_live(deadline_, "write-half shutdown");
        if (::shutdown(endpoint_.get(), SHUT_WR) != 0) {
            system_fail("work-directory custody child write-half shutdown failed", errno);
        }
        require_deadline_live(deadline_, "write-half shutdown");
        state_ = WorkDirectoryChildState::WriteShutdown;
        state_ = WorkDirectoryChildState::WaitingForAck;

        ReceivedRecord record = receive_record(
            endpoint_.get(),
            deadline_,
            "ACK receive");
        if (record.byte_count == 0u) {
            protocol_fail("work-directory custody parent closed before ACK");
        }
        validate_packet(
            record.bytes,
            record.byte_count,
            record.message_flags,
            kAckMessageType,
            session_nonce_);
        if ((record.message_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 ||
            record.unexpected_ancillary || record.rights_messages != 0u ||
            !record.descriptors.empty()) {
            protocol_fail("work-directory custody ACK ancillary data is not exact");
        }
        validate_credentials(
            record,
            expected_peer_pid_,
            expected_peer_uid_,
            expected_peer_gid_);
        require_deadline_live(deadline_, "ACK receive");
        state_ = WorkDirectoryChildState::AckAccepted;
        endpoint_.reset();
        expected_peer_pid_ = -1;
        state_ = WorkDirectoryChildState::Complete;
        return WorkDirectoryCustodyAckToken(true);
    } catch (...) {
        fail_terminal();
        throw;
    }
}

void WorkDirectoryCustodyAckToken::enter_working_directory(
    OwnedFd child_fchdir_fd) && {
    if (!valid_ || !child_fchdir_fd) {
        protocol_fail("work-directory custody ACK token cannot authorize fchdir");
    }
    valid_ = false;
    const WorkDirectoryIdentity retained_identity = require_directory_descriptor(
        child_fchdir_fd.get(),
        "child retained fchdir");
    if (::fchdir(child_fchdir_fd.get()) != 0) {
        system_fail("work-directory custody fchdir failed", errno);
    }
    child_fchdir_fd.reset();

    const int current_raw = ::open(
        ".",
        O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (current_raw < 0) {
        system_fail("work-directory custody current-directory verification open failed", errno);
    }
    OwnedFd current_directory(current_raw);
    if (require_directory_descriptor(
            current_directory.get(),
            "child current directory") != retained_identity) {
        protocol_fail("work-directory custody fchdir reached a different directory identity");
    }
}

#if defined(V631302_CUSTODY_TEST_NONCE_INJECTION)
WorkDirectoryCustodyChildEndpoint WorkDirectoryCustodyChildEndpoint::adopt_for_testing(
    OwnedFd endpoint,
    WorkDirectorySessionNonce deterministic_nonce,
    MonotonicDeadline deadline,
    pid_t expected_parent_pid) {
    require_endpoint(endpoint.get());
    if (expected_parent_pid <= 0) {
        protocol_fail("work-directory custody test parent PID is invalid");
    }
    return WorkDirectoryCustodyChildEndpoint(
        std::move(endpoint),
        deterministic_nonce,
        deadline,
        expected_parent_pid,
        ::getuid(),
        ::getgid());
}
#endif

WorkDirectoryCustodySocketPair WorkDirectoryCustodySocketPair::create_with_nonce(
    MonotonicDeadline deadline,
    WorkDirectorySessionNonce nonce) {
    require_deadline_live(deadline, "socket construction");
    std::array<int, 2u> descriptors = {-1, -1};
    if (::socketpair(
            AF_UNIX,
            SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC,
            0,
            descriptors.data()) != 0) {
        system_fail("work-directory custody socketpair failed", errno);
    }
    OwnedFd parent_descriptor(descriptors[0]);
    descriptors[0] = -1;
    OwnedFd child_descriptor(descriptors[1]);
    descriptors[1] = -1;
    enable_pass_credentials(parent_descriptor.get());
    enable_pass_credentials(child_descriptor.get());
    require_endpoint(parent_descriptor.get());
    require_endpoint(child_descriptor.get());
    require_deadline_live(deadline, "socket construction");

    const pid_t creator_pid = ::getpid();
    const uid_t creator_uid = ::getuid();
    const gid_t creator_gid = ::getgid();
    return WorkDirectoryCustodySocketPair(
        WorkDirectoryCustodyParentEndpoint(
            std::move(parent_descriptor),
            nonce,
            deadline,
            -1,
            creator_uid,
            creator_gid),
        WorkDirectoryCustodyChildEndpoint(
            std::move(child_descriptor),
            nonce,
            deadline,
            creator_pid,
            creator_uid,
            creator_gid));
}

WorkDirectoryCustodySocketPair WorkDirectoryCustodySocketPair::create_production(
    MonotonicDeadline deadline) {
    WorkDirectorySessionNonce nonce = generate_nonce(deadline);
    return create_with_nonce(deadline, nonce);
}

#if defined(V631302_CUSTODY_TEST_NONCE_INJECTION)
WorkDirectoryCustodySocketPair WorkDirectoryCustodySocketPair::create_for_testing(
    MonotonicDeadline deadline,
    WorkDirectorySessionNonce deterministic_nonce) {
    return create_with_nonce(deadline, deterministic_nonce);
}
#endif

WorkDirectoryCustodyParentEndpoint
WorkDirectoryCustodySocketPair::take_parent_for_parent(pid_t child_pid) && {
    if (::getpid() != child_.expected_peer_pid_) {
        protocol_fail("work-directory custody parent endpoint taken in the wrong process");
    }
    parent_.bind_expected_child(child_pid);
    child_.endpoint_.reset();
    child_.expected_peer_pid_ = -1;
    child_.state_ = WorkDirectoryChildState::MovedFrom;
    return std::move(parent_);
}

WorkDirectoryCustodyChildEndpoint
WorkDirectoryCustodySocketPair::take_child_for_child() && {
    if (::getpid() == child_.expected_peer_pid_) {
        protocol_fail("work-directory custody child endpoint taken before clone");
    }
    parent_.endpoint_.reset();
    parent_.expected_peer_pid_ = -1;
    parent_.state_ = WorkDirectoryParentState::MovedFrom;
    return std::move(child_);
}

}  // namespace evaluation_v6_3_1::capture_v2
