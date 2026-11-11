#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "PidfdOpenedFile.h"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace capture = evaluation_v6_3_1::capture_v2;

namespace {

constexpr std::array<std::uint8_t, 23> kFixtureBytes{
    'p', 'i', 'd', 'f', 'd', '-', 'o', 'p', 'e', 'n', 'e', 'd', '-',
    'f', 'i', 'l', 'e', '-', 'v', '6', '3', '1', '\n'};
constexpr capture::Sha256Digest kFixtureSha256{
    0x5c, 0x9a, 0xbe, 0xeb, 0x29, 0x3c, 0xb0, 0x6d,
    0x69, 0x6f, 0xb3, 0xb4, 0x93, 0xa7, 0xc0, 0x5e,
    0x49, 0xf6, 0x1d, 0x4b, 0xe3, 0xa6, 0x42, 0xb6,
    0x35, 0x07, 0x50, 0xac, 0xc3, 0x27, 0xdc, 0x07};
constexpr off_t kChildInitialOffset = 5;
constexpr off_t kSharedOffset = 11;

struct Child final {
    pid_t pid = -1;
    int pidfd = -1;
    int child_fd = -1;
    int offset_reader = -1;
};

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void write_exact(int descriptor, const void* bytes, std::size_t length) {
    const auto* cursor = static_cast<const std::uint8_t*>(bytes);
    std::size_t written = 0;
    while (written < length) {
        const ssize_t count = ::write(descriptor, cursor + written, length - written);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        require(count > 0, "write failed");
        written += static_cast<std::size_t>(count);
    }
}

void read_exact(int descriptor, void* bytes, std::size_t length) {
    auto* cursor = static_cast<std::uint8_t*>(bytes);
    std::size_t read = 0;
    while (read < length) {
        const ssize_t count = ::read(descriptor, cursor + read, length - read);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        require(count > 0, "read failed");
        read += static_cast<std::size_t>(count);
    }
}

int open_pidfd(pid_t pid) {
    const long result = ::syscall(SYS_pidfd_open, pid, 0u);
    if (result < 0 && (errno == ENOSYS || errno == EPERM || errno == EACCES)) {
        throw std::system_error(errno, std::generic_category(), "pidfd unavailable");
    }
    require(result >= 0, "pidfd_open failed");
    return static_cast<int>(result);
}

bool pidfd_open_available() {
    const long result = ::syscall(SYS_pidfd_open, ::getpid(), 0u);
    if (result >= 0) {
        require(::close(static_cast<int>(result)) == 0, "pidfd probe close failed");
        return true;
    }
    if (errno == ENOSYS || errno == EPERM || errno == EACCES) {
        return false;
    }
    require(false, "pidfd probe failed");
    return false;
}

std::string create_fixture_file() {
    char path[] = "/tmp/v631302-pidfd-opened-file-XXXXXX";
    const int descriptor = ::mkstemp(path);
    require(descriptor >= 0, "mkstemp failed");
    try {
        write_exact(descriptor, kFixtureBytes.data(), kFixtureBytes.size());
        require(::fsync(descriptor) == 0, "fixture fsync failed");
        require(::close(descriptor) == 0, "fixture close failed");
    } catch (...) {
        static_cast<void>(::close(descriptor));
        static_cast<void>(::unlink(path));
        throw;
    }
    return path;
}

Child launch_stopped_child(const std::string& path) {
    int announcement[2]{};
    int offset_report[2]{};
    require(::pipe2(announcement, O_CLOEXEC) == 0, "announcement pipe failed");
    require(::pipe2(offset_report, O_CLOEXEC) == 0, "offset pipe failed");

    const pid_t pid = ::fork();
    require(pid >= 0, "fork failed");
    if (pid == 0) {
        static_cast<void>(::close(announcement[0]));
        static_cast<void>(::close(offset_report[0]));
        const int opened = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (opened < 0 || ::lseek(opened, kChildInitialOffset, SEEK_SET) != kChildInitialOffset) {
            _exit(126);
        }
        write_exact(announcement[1], &opened, sizeof(opened));
        ::raise(SIGSTOP);
        const off_t current = ::lseek(opened, 0, SEEK_CUR);
        write_exact(offset_report[1], &current, sizeof(current));
        _exit(current == kSharedOffset ? 0 : 125);
    }

    static_cast<void>(::close(announcement[1]));
    static_cast<void>(::close(offset_report[1]));
    int child_fd = -1;
    read_exact(announcement[0], &child_fd, sizeof(child_fd));
    require(::close(announcement[0]) == 0, "announcement close failed");
    int status = 0;
    require(::waitpid(pid, &status, WUNTRACED) == pid, "wait for stopped child failed");
    require(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP, "child did not stop for capture");
    return Child{pid, open_pidfd(pid), child_fd, offset_report[0]};
}

void destroy_child(Child& child) noexcept {
    if (child.pid > 0) {
        static_cast<void>(::kill(child.pid, SIGKILL));
        int status = 0;
        while (::waitpid(child.pid, &status, __WALL) < 0 && errno == EINTR) {
        }
    }
    if (child.pidfd >= 0) {
        static_cast<void>(::close(child.pidfd));
    }
    if (child.offset_reader >= 0) {
        static_cast<void>(::close(child.offset_reader));
    }
    child = Child{};
}

void test_exact_duplicate_and_shared_offset(const std::string& path) {
    Child child = launch_stopped_child(path);
    capture::MonotonicDeadline deadline(10'000u);
    try {
        const capture::PidfdOpenedFile captured =
            capture::PidfdOpenedFile::duplicate_stopped_child_file(
                child.pidfd, child.child_fd, 1024u, deadline);
        const auto& observation = captured.observation();
        require(observation.byte_length == kFixtureBytes.size(), "incorrect captured byte length");
        require(observation.sha256 == kFixtureSha256, "incorrect captured digest");
        require((observation.mode & S_IFMT) == S_IFREG, "captured mode is not regular");
        require(::lseek(captured.descriptor(), 0, SEEK_CUR) == kChildInitialOffset,
                "pidfd duplicate did not share the child OFD offset");
        require(::lseek(captured.descriptor(), kSharedOffset, SEEK_SET) == kSharedOffset,
                "parent could not move duplicate OFD offset");
        require(::kill(child.pid, SIGCONT) == 0, "SIGCONT failed");
        off_t reported_offset = -1;
        read_exact(child.offset_reader, &reported_offset, sizeof(reported_offset));
        require(reported_offset == kSharedOffset,
                "child did not observe the duplicate's shared OFD offset");
        int status = 0;
        require(::waitpid(child.pid, &status, __WALL) == child.pid, "child completion wait failed");
        require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child observed wrong shared offset");
        require(::close(child.pidfd) == 0, "pidfd close failed");
        require(::close(child.offset_reader) == 0, "offset reader close failed");
        child = Child{};
    } catch (...) {
        destroy_child(child);
        throw;
    }
}

void test_cap_and_pidfd_getfd_errors(const std::string& path) {
    Child child = launch_stopped_child(path);
    capture::MonotonicDeadline deadline(10'000u);
    try {
        bool cap_rejected = false;
        try {
            static_cast<void>(capture::PidfdOpenedFile::duplicate_stopped_child_file(
                child.pidfd, child.child_fd, kFixtureBytes.size() - 1u, deadline));
        } catch (const capture::SupervisorError& error) {
            cap_rejected = error.failure() == capture::SupervisorFailure::ResourceLimit;
        }
        require(cap_rejected, "file above cap was accepted");

        bool syscall_error_rejected = false;
        try {
            static_cast<void>(capture::PidfdOpenedFile::duplicate_stopped_child_file(
                child.pidfd, 1'000'000, 1024u, deadline));
        } catch (const capture::SupervisorError& error) {
            syscall_error_rejected = error.failure() == capture::SupervisorFailure::SystemFailure &&
                                     error.system_errno() == EBADF;
        }
        require(syscall_error_rejected, "pidfd_getfd child-fd error was accepted");

        bool invalid_rejected = false;
        try {
            static_cast<void>(capture::PidfdOpenedFile::duplicate_stopped_child_file(
                child.pidfd, child.child_fd, 0u, deadline));
        } catch (const capture::SupervisorError& error) {
            invalid_rejected = error.failure() == capture::SupervisorFailure::InvalidRequest;
        }
        require(invalid_rejected, "zero cap was accepted");
        destroy_child(child);
    } catch (...) {
        destroy_child(child);
        throw;
    }
}

bool pidfd_getfd_is_unavailable_or_forbidden(const capture::SupervisorError& error) {
    return error.failure() == capture::SupervisorFailure::SystemFailure &&
           (error.system_errno() == ENOSYS || error.system_errno() == EPERM ||
            error.system_errno() == EACCES);
}

}  // namespace

int main() {
    if (!pidfd_open_available()) {
        std::cout << "pidfd_opened_file_harness_skipped pidfd_unavailable=1\n";
        return 77;
    }

    std::string path;
    try {
        path = create_fixture_file();
        test_exact_duplicate_and_shared_offset(path);
        test_cap_and_pidfd_getfd_errors(path);
    } catch (const capture::SupervisorError& error) {
        static_cast<void>(::unlink(path.c_str()));
        if (pidfd_getfd_is_unavailable_or_forbidden(error)) {
            std::cout << "pidfd_opened_file_harness_skipped pidfd_getfd_unavailable=1\n";
            return 77;
        }
        std::cerr << "pidfd opened file harness failure: " << error.what() << '\n';
        return EXIT_FAILURE;
    } catch (const std::system_error& error) {
        static_cast<void>(::unlink(path.c_str()));
        if (std::string(error.what()).find("pidfd unavailable") != std::string::npos) {
            std::cout << "pidfd_opened_file_harness_skipped pidfd_unavailable=1\n";
            return 77;
        }
        std::cerr << "pidfd opened file harness failure: " << error.what() << '\n';
        return EXIT_FAILURE;
    } catch (const std::exception& error) {
        static_cast<void>(::unlink(path.c_str()));
        std::cerr << "pidfd opened file harness failure: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    static_cast<void>(::unlink(path.c_str()));
    std::cout << "pidfd_opened_file_harness_ok zero_authority=1\n";
    return EXIT_SUCCESS;
}
