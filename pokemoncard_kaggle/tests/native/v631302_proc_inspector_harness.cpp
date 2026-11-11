#include "ProcInspector.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/SHA256.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <grp.h>
#include <iostream>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace capture = evaluation_v6_3_1::capture_v2;

namespace {

constexpr std::string_view kChildArgv0 = "v631302-proc-inspector-child";
constexpr std::string_view kChildArgv1 = "--exact";
constexpr std::string_view kChildArgv2 = "capture-v2";
constexpr std::size_t kReadBufferBytes = 64u * 1024u;

class TempDirectory final {
public:
    TempDirectory() {
        std::array<char, 64> pattern{};
        constexpr std::string_view value = "/tmp/v631302-proc-inspector-XXXXXX";
        std::memcpy(pattern.data(), value.data(), value.size());
        if (::mkdtemp(pattern.data()) == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        path_ = pattern.data();
    }

    ~TempDirectory() { std::filesystem::remove_all(path_); }

    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

class StoppedChild final {
public:
    explicit StoppedChild(pid_t pid) noexcept : pid_(pid) {}
    ~StoppedChild() noexcept {
        if (pid_ <= 0) {
            return;
        }
        static_cast<void>(::kill(pid_, SIGKILL));
        int status = 0;
        while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {
        }
    }

    StoppedChild(const StoppedChild&) = delete;
    StoppedChild& operator=(const StoppedChild&) = delete;

    [[nodiscard]] pid_t pid() const noexcept { return pid_; }

private:
    pid_t pid_ = -1;
};

std::string self_executable_path() {
    std::array<char, 4096> path{};
    const ssize_t length = ::readlink("/proc/self/exe", path.data(), path.size());
    if (length <= 0 || static_cast<std::size_t>(length) >= path.size()) {
        throw std::runtime_error("readlink /proc/self/exe failed");
    }
    return std::string(path.data(), static_cast<std::size_t>(length));
}

std::vector<std::string> observed_child_argv(pid_t pid) {
    const std::string directory = "/proc/" + std::to_string(static_cast<std::intmax_t>(pid));
    const int proc_directory = ::open(
        directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW);
    if (proc_directory < 0) {
        throw std::runtime_error("open stopped child proc directory failed");
    }
    const int descriptor = ::openat(proc_directory, "cmdline", O_RDONLY | O_CLOEXEC | O_NOCTTY);
    const int open_error = errno;
    if (::close(proc_directory) != 0 || descriptor < 0) {
        throw std::runtime_error("open stopped child cmdline failed: " + std::to_string(open_error));
    }
    std::array<char, 4096> bytes{};
    const ssize_t count = ::read(descriptor, bytes.data(), bytes.size());
    if (::close(descriptor) != 0 || count <= 0 ||
        static_cast<std::size_t>(count) == bytes.size() ||
        bytes[static_cast<std::size_t>(count) - 1u] != '\0') {
        throw std::runtime_error("read stopped child cmdline failed");
    }
    std::vector<std::string> argv;
    std::size_t start = 0u;
    for (std::size_t index = 0u; index < static_cast<std::size_t>(count); ++index) {
        if (bytes[index] == '\0') {
            argv.emplace_back(bytes.data() + start, index - start);
            start = index + 1u;
        }
    }
    return argv;
}

struct ExpectedExecutable final {
    std::uint64_t byte_length = 0;
    capture::Sha256Digest sha256{};
};

ExpectedExecutable expected_child_executable(pid_t pid) {
    const std::string directory = "/proc/" + std::to_string(static_cast<std::intmax_t>(pid));
    const int proc_directory = ::open(
        directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW);
    if (proc_directory < 0) {
        throw std::runtime_error("open stopped child proc directory for executable failed");
    }
    const int descriptor = ::openat(proc_directory, "exe", O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (::close(proc_directory) != 0 || descriptor < 0) {
        throw std::runtime_error("open stopped child executable failed");
    }
    struct stat status {};
    if (::fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) || status.st_size < 0) {
        static_cast<void>(::close(descriptor));
        throw std::runtime_error("fstat stopped child executable failed");
    }
    const std::uint64_t byte_length = static_cast<std::uint64_t>(status.st_size);
    llvm::SHA256 hasher;
    std::array<std::uint8_t, kReadBufferBytes> buffer{};
    std::uint64_t offset = 0;
    while (offset < byte_length) {
        const std::uint64_t remaining = byte_length - offset;
        const std::size_t requested = static_cast<std::size_t>(
            std::min<std::uint64_t>(remaining, static_cast<std::uint64_t>(buffer.size())));
        const ssize_t count = ::pread(descriptor, buffer.data(), requested, static_cast<off_t>(offset));
        if (count > 0) {
            hasher.update(llvm::ArrayRef<std::uint8_t>(
                buffer.data(), static_cast<std::size_t>(count)));
            offset += static_cast<std::uint64_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        static_cast<void>(::close(descriptor));
        throw std::runtime_error("read stopped child executable failed");
    }
    if (::close(descriptor) != 0) {
        throw std::runtime_error("close stopped child executable failed");
    }
    return {byte_length, hasher.final()};
}

StoppedChild spawn_stopped_child(
    const std::filesystem::path& cwd,
    const std::string& executable,
    bool nonempty_environment,
    bool retain_privileges) {
    const pid_t pid = ::fork();
    if (pid < 0) {
        throw std::runtime_error("fork failed");
    }
    if (pid == 0) {
        if (::chdir(cwd.c_str()) != 0) {
            _exit(120);
        }
        char argv0[] = "v631302-proc-inspector-child";
        char argv1[] = "--exact";
        char argv2[] = "capture-v2";
        char argv3[] = "--retain-privileges";
        char* const normal_argv[] = {argv0, argv1, argv2, nullptr};
        char* const retained_argv[] = {argv0, argv1, argv2, argv3, nullptr};
        char environment_entry[] = "PROC_INSPECTOR_MUTATION=1";
        char* const empty_environment[] = {nullptr};
        char* const mutated_environment[] = {environment_entry, nullptr};
        ::execve(
            executable.c_str(),
            retain_privileges ? retained_argv : normal_argv,
            nonempty_environment ? mutated_environment : empty_environment);
        _exit(121);
    }
    int status = 0;
    for (;;) {
        const pid_t waited = ::waitpid(pid, &status, WUNTRACED);
        if (waited == pid) {
            break;
        }
        if (waited < 0 && errno == EINTR) {
            continue;
        }
        throw std::runtime_error("waitpid for stopped child failed");
    }
    if (!WIFSTOPPED(status)) {
        throw std::runtime_error("child did not enter stopped state");
    }
    return StoppedChild(pid);
}

std::string hex(const capture::Sha256Digest& digest) {
    constexpr char digits[] = "0123456789abcdef";
    std::string output;
    output.reserve(digest.size() * 2u);
    for (const std::uint8_t byte : digest) {
        output.push_back(digits[byte >> 4u]);
        output.push_back(digits[byte & 0x0fu]);
    }
    return output;
}

capture::StoppedProcessRequirement requirement_for(
    pid_t pid,
    const std::filesystem::path& cwd,
    ExpectedExecutable executable,
    std::vector<std::string> expected_argv) {
    struct stat cwd_status {};
    if (::stat(cwd.c_str(), &cwd_status) != 0) {
        throw std::runtime_error("stat expected child identity failed");
    }
    return capture::StoppedProcessRequirement{
        pid,
        std::move(expected_argv),
        true,
        executable.byte_length,
        executable.sha256,
        static_cast<std::uint64_t>(cwd_status.st_dev),
        static_cast<std::uint64_t>(cwd_status.st_ino),
        {},
        true,
        true,
        0u,
        0u,
        true,
    };
}

bool drop_child_privileges() {
    constexpr unsigned long securebits =
        SECBIT_NOROOT | SECBIT_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP |
        SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_KEEP_CAPS_LOCKED |
        SECBIT_NO_CAP_AMBIENT_RAISE | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED;
    if (::prctl(PR_SET_SECUREBITS, securebits, 0u, 0u, 0u) != 0 ||
        ::prctl(PR_SET_NO_NEW_PRIVS, 1u, 0u, 0u, 0u) != 0 ||
        ::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0u, 0u, 0u) != 0) {
        return false;
    }
    for (unsigned int capability = 0u; capability < 1024u; ++capability) {
        errno = 0;
        const int present = ::prctl(PR_CAPBSET_READ, capability, 0u, 0u, 0u);
        if (present < 0 && errno == EINVAL) {
            break;
        }
        if (present < 0 ||
            (present == 1 && ::prctl(PR_CAPBSET_DROP, capability, 0u, 0u, 0u) != 0)) {
            return false;
        }
    }
    if (::setgroups(0u, nullptr) != 0) {
        return false;
    }
    __user_cap_header_struct header{};
    header.version = _LINUX_CAPABILITY_VERSION_3;
    header.pid = 0;
    std::array<__user_cap_data_struct, 2> capabilities{};
    return ::syscall(SYS_capset, &header, capabilities.data()) == 0 &&
        ::prctl(PR_SET_DUMPABLE, 1u, 0u, 0u, 0u) == 0;
}

int run_child(bool retain_privileges) {
    if (!retain_privileges && !drop_child_privileges()) {
        return 123;
    }
    if (::raise(SIGSTOP) != 0) {
        return 122;
    }
    for (;;) {
        static_cast<void>(::pause());
    }
}

int run(const std::string& mode) {
    TempDirectory cwd;
    const std::string executable = self_executable_path();
    const bool nonempty_environment = mode == "environment";
    const bool retain_privileges = mode == "privileges";
    StoppedChild child = spawn_stopped_child(
        cwd.path(), executable, nonempty_environment, retain_privileges);
    auto requirement = requirement_for(
        child.pid(),
        cwd.path(),
        expected_child_executable(child.pid()),
        observed_child_argv(child.pid()));
    if (mode == "argv") {
        requirement.expected_argv.back() = "mutated";
    } else if (mode == "digest") {
        requirement.expected_executable_sha256[0] ^= 0xffu;
    } else if (mode == "length") {
        ++requirement.expected_executable_byte_length;
    } else if (mode == "cwd") {
        ++requirement.expected_cwd_inode;
    } else if (mode == "running") {
        if (::kill(child.pid(), SIGCONT) != 0) {
            throw std::runtime_error("SIGCONT failed");
        }
        int continued_status = 0;
        for (;;) {
            const pid_t waited = ::waitpid(child.pid(), &continued_status, WCONTINUED);
            if (waited == child.pid()) {
                break;
            }
            if (waited < 0 && errno == EINTR) {
                continue;
            }
            throw std::runtime_error("waitpid for continued child failed");
        }
        if (!WIFCONTINUED(continued_status)) {
            throw std::runtime_error("child did not continue");
        }
    }

    capture::ProcInspector inspector(std::move(requirement));
    if (mode == "valid" || mode == "cwd-path") {
        const auto& observation = inspector.authenticate();
        if (inspector.state() != capture::ProcInspector::State::Authenticated ||
            &observation != &inspector.observation()) {
            return 30;
        }
        std::cout << "proc_inspector_ok pid=" << observation.pid() << " argv="
                  << observation.argv().size() << " size=" << observation.executable_byte_length()
                  << " digest=" << hex(observation.executable_sha256()) << " cwd="
                  << observation.cwd_device() << ':' << observation.cwd_inode()
                  << " cwd_link=" << observation.cwd_proc_link()
                  << " uid=" << observation.user_id() << " gid=" << observation.group_id()
                  << " caps0=" << observation.zero_capability_sets()
                  << " nnp=" << observation.no_new_privileges()
                  << " zero_authority=1\n";
        return 0;
    }
    try {
        static_cast<void>(inspector.authenticate());
        return 31;
    } catch (const capture::SupervisorError& error) {
        if (inspector.state() != capture::ProcInspector::State::Failed) {
            return 32;
        }
        std::cout << "proc_inspector_rejected " << mode << " failure="
                  << static_cast<std::uint32_t>(error.failure()) << " terminal_failed=1\n";
        return 0;
    }
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 3 && std::string_view(argv[0]) == kChildArgv0 &&
        std::string_view(argv[1]) == kChildArgv1 && std::string_view(argv[2]) == kChildArgv2) {
        return run_child(false);
    }
    if (argc == 4 && std::string_view(argv[0]) == kChildArgv0 &&
        std::string_view(argv[1]) == kChildArgv1 && std::string_view(argv[2]) == kChildArgv2 &&
        std::string_view(argv[3]) == "--retain-privileges") {
        return run_child(true);
    }
    if (argc != 2) {
        return 10;
    }
    try {
        return run(argv[1]);
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 11;
    }
}
