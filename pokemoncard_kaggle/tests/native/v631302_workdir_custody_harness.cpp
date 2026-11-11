#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "WorkDirectoryCustody.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <exception>
#include <iostream>
#include <span>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <type_traits>
#include <unistd.h>
#include <utility>

#include <fcntl.h>

namespace capture = evaluation_v6_3_1::capture_v2;

namespace {

constexpr std::array<std::uint8_t, 8u> kPacketMagic = {
    'V', '6', '3', '1', 'W', 'D', 'C', '1',
};
constexpr std::size_t kPacketBytes = 48u;

static_assert(!std::is_copy_constructible_v<capture::WorkDirectoryCustody>);
static_assert(std::is_move_constructible_v<capture::WorkDirectoryCustody>);
static_assert(!std::is_copy_constructible_v<capture::WorkDirectoryCustodyParentEndpoint>);
static_assert(std::is_move_constructible_v<capture::WorkDirectoryCustodyParentEndpoint>);
static_assert(!std::is_copy_constructible_v<capture::WorkDirectoryCustodyChildEndpoint>);
static_assert(std::is_move_constructible_v<capture::WorkDirectoryCustodyChildEndpoint>);
static_assert(!std::is_copy_constructible_v<capture::WorkDirectoryCustodyAckToken>);
static_assert(std::is_move_constructible_v<capture::WorkDirectoryCustodyAckToken>);

[[noreturn]] void die(std::string_view message) {
    std::cerr << "workdir_custody_failure: " << message << '\n';
    std::exit(1);
}

void require(bool condition, std::string_view message) {
    if (!condition) {
        die(message);
    }
}

struct RawPair final {
    capture::OwnedFd parent;
    capture::OwnedFd child;
};

void enable_pass_credentials(int descriptor) {
    const int enabled = 1;
    require(
        ::setsockopt(descriptor, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) == 0,
        "enable SO_PASSCRED");
}

RawPair raw_pair(bool nonblocking = true, bool pass_credentials = true) {
    std::array<int, 2u> descriptors = {-1, -1};
    int type = SOCK_SEQPACKET | SOCK_CLOEXEC;
    if (nonblocking) {
        type |= SOCK_NONBLOCK;
    }
    require(::socketpair(AF_UNIX, type, 0, descriptors.data()) == 0, "socketpair");
    capture::OwnedFd parent(descriptors[0]);
    capture::OwnedFd child(descriptors[1]);
    if (pass_credentials) {
        enable_pass_credentials(parent.get());
        enable_pass_credentials(child.get());
    }
    return {std::move(parent), std::move(child)};
}

capture::WorkDirectorySessionNonce nonce(std::uint8_t seed = 1u) {
    capture::WorkDirectorySessionNonce value{};
    for (std::size_t index = 0u; index < value.size(); ++index) {
        value[index] = static_cast<std::uint8_t>(seed + static_cast<std::uint8_t>(index));
    }
    return value;
}

capture::WorkDirectoryIdentity identity_for(int descriptor) {
    struct stat status {};
    require(::fstat(descriptor, &status) == 0, "fstat identity");
    return {
        static_cast<std::uint64_t>(status.st_dev),
        static_cast<std::uint64_t>(status.st_ino),
    };
}

capture::OwnedFd open_directory(const std::filesystem::path& path) {
    const int descriptor = ::open(
        path.c_str(),
        O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    require(descriptor >= 0, "open directory");
    return capture::OwnedFd(descriptor);
}

std::array<std::uint8_t, kPacketBytes> packet(
    const capture::WorkDirectorySessionNonce& value,
    std::uint8_t message_type) {
    std::array<std::uint8_t, kPacketBytes> output{};
    std::copy(kPacketMagic.begin(), kPacketMagic.end(), output.begin());
    output[8u] = 1u;
    output[9u] = message_type;
    output[10u] = 0u;
    output[11u] = 32u;
    std::copy(value.begin(), value.end(), output.begin() + 16u);
    return output;
}

void raw_send(
    int endpoint,
    std::span<const std::uint8_t> bytes,
    const int* descriptors = nullptr,
    std::size_t descriptor_count = 0u) {
    std::array<std::byte, CMSG_SPACE(sizeof(int) * 8u)> control{};
    struct iovec iov {};
    iov.iov_base = const_cast<std::uint8_t*>(bytes.data());
    iov.iov_len = bytes.size();
    struct msghdr message {};
    message.msg_iov = &iov;
    message.msg_iovlen = 1u;
    if (descriptor_count != 0u) {
        require(descriptor_count <= 8u, "raw descriptor count bound");
        message.msg_control = control.data();
        message.msg_controllen = CMSG_SPACE(sizeof(int) * descriptor_count);
        struct cmsghdr* header = CMSG_FIRSTHDR(&message);
        require(header != nullptr, "raw control header");
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int) * descriptor_count);
        std::memcpy(CMSG_DATA(header), descriptors, sizeof(int) * descriptor_count);
    }
    const ssize_t count = ::sendmsg(endpoint, &message, MSG_NOSIGNAL);
    require(count == static_cast<ssize_t>(bytes.size()), "raw send exact");
}

void drain_child_handoff(int endpoint) {
    std::array<std::uint8_t, kPacketBytes> bytes{};
    std::array<std::byte,
               CMSG_SPACE(sizeof(int) * 2u) + CMSG_SPACE(sizeof(struct ucred))>
        control{};
    struct iovec iov {};
    iov.iov_base = bytes.data();
    iov.iov_len = bytes.size();
    struct msghdr message {};
    message.msg_iov = &iov;
    message.msg_iovlen = 1u;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    ssize_t count = -1;
    for (unsigned attempt = 0u; attempt < 200u; ++attempt) {
        count = ::recvmsg(endpoint, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
        if (count >= 0) {
            break;
        }
        require(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR, "drain recvmsg");
        ::usleep(1000u);
    }
    require(count == static_cast<ssize_t>(bytes.size()), "drain handoff size");
    require((message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) == 0, "drain handoff truncation");
    std::size_t descriptor_count = 0u;
    for (struct cmsghdr* header = CMSG_FIRSTHDR(&message); header != nullptr;
         header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS) {
            const std::size_t payload =
                static_cast<std::size_t>(header->cmsg_len - CMSG_LEN(0));
            require(payload % sizeof(int) == 0u, "drain rights payload");
            const std::size_t count_fds = payload / sizeof(int);
            const auto* raw = static_cast<const std::uint8_t*>(CMSG_DATA(header));
            for (std::size_t index = 0u; index < count_fds; ++index) {
                int received = -1;
                std::memcpy(&received, raw + index * sizeof(int), sizeof(received));
                require(received >= 0, "drain received FD");
                static_cast<void>(::close(received));
                ++descriptor_count;
            }
        }
    }
    require(descriptor_count == 1u, "drain exact handoff FD");
}

void wait_success(pid_t child) {
    int status = 0;
    require(::waitpid(child, &status, 0) == child, "wait child");
    require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child did not exit successfully");
}

void run_successful_pair(
    capture::WorkDirectoryCustodySocketPair pair,
    const std::filesystem::path& directory) {
    capture::OwnedFd child_directory = open_directory(directory);
    const auto expected_identity = identity_for(child_directory.get());
    const pid_t child = ::fork();
    require(child >= 0, "fork successful pair");
    if (child == 0) {
        try {
            auto endpoint = std::move(pair).take_child_for_child();
            auto token = std::move(endpoint).handoff_and_await_context_commit(
                child_directory.get());
            static_cast<void>(token);
            require(::fchdir(child_directory.get()) == 0, "child fchdir after ACK");
            const int current = ::open(
                ".",
                O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            require(current >= 0, "open child cwd");
            const auto actual = identity_for(current);
            static_cast<void>(::close(current));
            require(actual == expected_identity, "child fchdir identity");
            _exit(0);
        } catch (...) {
            _exit(2);
        }
    }

    auto endpoint = std::move(pair).take_parent_for_parent(child);
    capture::WorkDirectoryCustody custody = endpoint.receive_handoff_for_testing();
    int status = 0;
    require(::waitpid(child, &status, WNOHANG) == 0, "child returned before ACK");
    endpoint.acknowledge_after_test_commit();
    wait_success(child);
    require(
        identity_for(custody.retained_directory_fd()) == expected_identity,
        "parent custody died with child");
}

void expect_parent_reject(
    capture::OwnedFd parent_fd,
    const capture::WorkDirectorySessionNonce& expected_nonce,
    pid_t expected_child_pid,
    std::uint64_t timeout_ms = 250u) {
    bool rejected = false;
    try {
        auto parent = capture::WorkDirectoryCustodyParentEndpoint::adopt_for_testing(
            std::move(parent_fd),
            expected_nonce,
            capture::MonotonicDeadline::from_milliseconds(timeout_ms),
            expected_child_pid);
        static_cast<void>(parent.receive_handoff_for_testing());
    } catch (const std::exception&) {
        rejected = true;
    }
    require(rejected, "malicious parent packet accepted");
}

void test_factory_and_success(const std::filesystem::path& directory) {
    run_successful_pair(
        capture::WorkDirectoryCustodySocketPair::create_production(
            capture::MonotonicDeadline::from_milliseconds(2000u)),
        directory);

    capture::WorkDirectorySessionNonce all_zero{};
    run_successful_pair(
        capture::WorkDirectoryCustodySocketPair::create_for_testing(
            capture::MonotonicDeadline::from_milliseconds(2000u),
            all_zero),
        directory);
}

void test_parent_attacks(const std::filesystem::path& directory) {
    capture::OwnedFd directory_fd = open_directory(directory);
    const int directory_descriptor = directory_fd.get();
    const auto expected_nonce = nonce();
    const auto message = packet(expected_nonce, 1u);

    {
        RawPair pair = raw_pair();
        raw_send(pair.child.get(), message);
        expect_parent_reject(std::move(pair.parent), expected_nonce, ::getpid());
    }
    {
        RawPair pair = raw_pair();
        const int fds[2] = {directory_descriptor, directory_descriptor};
        raw_send(pair.child.get(), message, fds, 2u);
        expect_parent_reject(std::move(pair.parent), expected_nonce, ::getpid());
    }
    {
        RawPair pair = raw_pair();
        std::array<std::uint8_t, kPacketBytes + 1u> oversized{};
        std::copy(message.begin(), message.end(), oversized.begin());
        raw_send(pair.child.get(), oversized, &directory_descriptor, 1u);
        expect_parent_reject(std::move(pair.parent), expected_nonce, ::getpid());
    }
    {
        RawPair pair = raw_pair();
        auto wrong_nonce = expected_nonce;
        ++wrong_nonce[0u];
        raw_send(pair.child.get(), packet(wrong_nonce, 1u), &directory_descriptor, 1u);
        expect_parent_reject(std::move(pair.parent), expected_nonce, ::getpid());
    }
    {
        RawPair pair = raw_pair();
        raw_send(pair.child.get(), packet(expected_nonce, 2u), &directory_descriptor, 1u);
        expect_parent_reject(std::move(pair.parent), expected_nonce, ::getpid());
    }
    {
        RawPair pair = raw_pair();
        pair.child.reset();
        expect_parent_reject(std::move(pair.parent), expected_nonce, ::getpid());
    }
    {
        RawPair pair = raw_pair();
        const int non_path = ::open(
            directory.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        require(non_path >= 0, "open non-O_PATH directory");
        raw_send(pair.child.get(), message, &non_path, 1u);
        static_cast<void>(::close(non_path));
        static_cast<void>(::shutdown(pair.child.get(), SHUT_WR));
        expect_parent_reject(std::move(pair.parent), expected_nonce, ::getpid());
    }
    {
        RawPair pair = raw_pair();
        raw_send(pair.child.get(), message, &directory_descriptor, 1u);
        raw_send(pair.child.get(), message, &directory_descriptor, 1u);
        static_cast<void>(::shutdown(pair.child.get(), SHUT_WR));
        expect_parent_reject(std::move(pair.parent), expected_nonce, ::getpid());
    }
    {
        RawPair pair = raw_pair();
        raw_send(pair.child.get(), message, &directory_descriptor, 1u);
        const std::span<const std::uint8_t> empty;
        raw_send(pair.child.get(), empty);
        static_cast<void>(::shutdown(pair.child.get(), SHUT_WR));
        expect_parent_reject(std::move(pair.parent), expected_nonce, ::getpid());
    }
    {
        RawPair pair = raw_pair();
        raw_send(pair.child.get(), message, &directory_descriptor, 1u);
        expect_parent_reject(
            std::move(pair.parent),
            expected_nonce,
            ::getpid(),
            30u);
    }
    {
        RawPair pair = raw_pair();
        raw_send(pair.child.get(), message, &directory_descriptor, 1u);
        static_cast<void>(::shutdown(pair.child.get(), SHUT_WR));
        expect_parent_reject(std::move(pair.parent), expected_nonce, ::getpid() + 1);
    }
}

void test_child_ack_attacks(const std::filesystem::path& directory) {
    const auto expected_nonce = nonce(11u);
    for (const unsigned attack : {0u, 1u, 2u}) {
        RawPair pair = raw_pair();
        capture::OwnedFd child_directory = open_directory(directory);
        const pid_t parent_pid = ::getpid();
        const pid_t child = ::fork();
        require(child >= 0, "fork ACK attack");
        if (child == 0) {
            pair.parent.reset();
            try {
                auto endpoint = capture::WorkDirectoryCustodyChildEndpoint::adopt_for_testing(
                    std::move(pair.child),
                    expected_nonce,
                    capture::MonotonicDeadline::from_milliseconds(250u),
                    parent_pid);
                static_cast<void>(
                    std::move(endpoint).handoff_and_await_context_commit(
                        child_directory.get()));
                _exit(4);
            } catch (const std::exception&) {
                _exit(0);
            }
        }

        pair.child.reset();
        drain_child_handoff(pair.parent.get());
        if (attack == 0u) {
            pair.parent.reset();
        } else if (attack == 1u) {
            auto wrong_nonce = expected_nonce;
            ++wrong_nonce[0u];
            raw_send(pair.parent.get(), packet(wrong_nonce, 2u));
            pair.parent.reset();
        } else {
            const int descriptor = child_directory.get();
            raw_send(pair.parent.get(), packet(expected_nonce, 2u), &descriptor, 1u);
            pair.parent.reset();
        }
        wait_success(child);
    }
}

void test_endpoint_validation_and_move_state() {
    const auto expected_nonce = nonce(31u);
    {
        RawPair pair = raw_pair(false, true);
        bool rejected = false;
        try {
            static_cast<void>(capture::WorkDirectoryCustodyParentEndpoint::adopt_for_testing(
                std::move(pair.parent),
                expected_nonce,
                capture::MonotonicDeadline::from_milliseconds(100u),
                ::getpid()));
        } catch (const std::exception&) {
            rejected = true;
        }
        require(rejected, "blocking endpoint was accepted");
    }
    {
        RawPair pair = raw_pair(true, false);
        bool rejected = false;
        try {
            static_cast<void>(capture::WorkDirectoryCustodyParentEndpoint::adopt_for_testing(
                std::move(pair.parent),
                expected_nonce,
                capture::MonotonicDeadline::from_milliseconds(100u),
                ::getpid()));
        } catch (const std::exception&) {
            rejected = true;
        }
        require(rejected, "endpoint without SO_PASSCRED was accepted");
    }
    {
        RawPair pair = raw_pair();
        auto endpoint = capture::WorkDirectoryCustodyParentEndpoint::adopt_for_testing(
            std::move(pair.parent),
            expected_nonce,
            capture::MonotonicDeadline::from_milliseconds(100u),
            ::getpid());
        auto moved = std::move(endpoint);
        static_cast<void>(moved);
        bool rejected = false;
        try {
            static_cast<void>(endpoint.receive_handoff_for_testing());
        } catch (const std::exception&) {
            rejected = true;
        }
        require(rejected, "moved-from endpoint performed a receive");
    }
}

}  // namespace

int main() {
    const std::filesystem::path root =
        std::filesystem::temp_directory_path() / "v631302-workdir-custody-harness";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root / "work");
    const std::filesystem::path directory = root / "work";
    test_factory_and_success(directory);
    test_parent_attacks(directory);
    test_child_ack_attacks(directory);
    test_endpoint_validation_and_move_state();
    std::filesystem::remove_all(root);
    std::cout << "workdir_custody_harness_ok zero_authority=1\n";
    return 0;
}
