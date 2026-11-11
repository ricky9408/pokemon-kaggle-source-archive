#include "MountSandbox.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace capture = evaluation_v6_3_1::capture_v2;

namespace {

class TempTree final {
public:
    TempTree() {
        std::array<char, 64> pattern{};
        const std::string value = "/tmp/v631302-mount-XXXXXX";
        std::copy(value.begin(), value.end(), pattern.begin());
        if (::mkdtemp(pattern.data()) == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        path_ = pattern.data();
        std::filesystem::create_directory(path_ / "original");
        std::filesystem::create_directory(path_ / "stage");
        if (::chmod((path_ / "stage").c_str(), 0700) != 0) {
            throw std::runtime_error("stage chmod failed");
        }
    }

    ~TempTree() { std::filesystem::remove_all(path_); }

    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

void write_file(const std::filesystem::path& path, const std::string& bytes, mode_t mode) {
    const int descriptor = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (descriptor < 0) {
        throw std::runtime_error("file creation failed");
    }
    std::size_t offset = 0u;
    while (offset < bytes.size()) {
        const ssize_t written = ::write(descriptor, bytes.data() + offset, bytes.size() - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            static_cast<void>(::close(descriptor));
            throw std::runtime_error("file write failed");
        }
        offset += static_cast<std::size_t>(written);
    }
    if (::fchmod(descriptor, mode) != 0 || ::fsync(descriptor) != 0 || ::close(descriptor) != 0) {
        throw std::runtime_error("file finalize failed");
    }
}

std::string read_file(const char* path) {
    const int descriptor = ::open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        throw std::runtime_error("sealed file open failed");
    }
    std::string bytes;
    std::array<char, 128> buffer{};
    for (;;) {
        const ssize_t count = ::read(descriptor, buffer.data(), buffer.size());
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            static_cast<void>(::close(descriptor));
            throw std::runtime_error("sealed file read failed");
        }
        if (count == 0) {
            break;
        }
        bytes.append(buffer.data(), static_cast<std::size_t>(count));
    }
    if (::close(descriptor) != 0) {
        throw std::runtime_error("sealed file close failed");
    }
    return bytes;
}

std::vector<capture::RetainedInputSpec> specs(int root) {
    return {
        {root, "collector", "bin/collector", {1}, 0555},
        {root, "fixture.cc", "src/fixture.cc", {2, 3}, 0444},
    };
}

int child_case(const std::string& mode, const std::filesystem::path& root) {
    const auto original = root / "original";
    const auto stage = root / "stage";
    const int original_root = ::open(original.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (original_root < 0) {
        return 20;
    }
    auto retained = capture::RetainedInputSet::acquire(specs(original_root));
    if (::close(original_root) != 0) {
        return 21;
    }
    capture::MountSandboxConfig config{
        stage.string(),
        mode == "invalid-workdir" ? "../work" : "work",
        mode == "tiny-tmpfs" ? 1u : 16u * 1024u * 1024u,
    };
    if (mode == "nonempty-stage") {
        write_file(stage / "unexpected", "x", 0400);
    } else if (mode == "bad-stage-mode") {
        if (::chmod(stage.c_str(), 0755) != 0) {
            return 22;
        }
    } else if (mode == "stage-symlink") {
        const auto replacement = root / "replacement-stage";
        std::filesystem::create_directory(replacement);
        std::filesystem::remove(stage);
        std::filesystem::create_directory_symlink(replacement, stage);
    }

    try {
        capture::MountSandboxResult result =
            capture::MountSandbox::build_seal_and_enter(std::move(retained), config);
        if (mode != "valid") {
            return 23;
        }
        if (result.file_rows.size() != 2u || result.root_device == 0u || result.root_inode == 0u ||
            result.working_directory_device == 0u || result.working_directory_inode == 0u ||
            !result.child_fchdir_fd) {
            return 24;
        }
        std::array<char, 256> cwd{};
        if (::getcwd(cwd.data(), cwd.size()) == nullptr ||
            std::string(cwd.data()) != "/") {
            return 25;
        }
        if (::fchdir(result.child_fchdir_fd.get()) != 0 ||
            ::getcwd(cwd.data(), cwd.size()) == nullptr ||
            std::string(cwd.data()) != "/work") {
            return 25;
        }
        if (read_file("/bin/collector") != "collector-bytes" ||
            read_file("/src/fixture.cc") != "int value = 7;\n") {
            return 26;
        }
        struct stat source_status {};
        struct stat directory_status {};
        struct statvfs filesystem {};
        if (::stat("/src/fixture.cc", &source_status) != 0 ||
            ::stat("/work", &directory_status) != 0 || ::statvfs("/", &filesystem) != 0 ||
            (source_status.st_mode & 07777) != 0444 ||
            (directory_status.st_mode & 07777) != 0555 ||
            (filesystem.f_flag & ST_RDONLY) == 0u) {
            return 27;
        }
        const int probe = ::open("/probe", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (probe >= 0 || errno != EROFS) {
            if (probe >= 0) static_cast<void>(::close(probe));
            return 28;
        }
        std::cout << "mount_sandbox_ok zero_authority=1\n" << std::flush;
        return 0;
    } catch (const capture::SupervisorError& error) {
        if (mode == "invalid-workdir" && error.failure() == capture::SupervisorFailure::InvalidRequest) {
            return 0;
        }
        if (mode == "tiny-tmpfs" && error.failure() == capture::SupervisorFailure::ResourceLimit) {
            return 0;
        }
        if ((mode == "nonempty-stage" || mode == "bad-stage-mode" || mode == "stage-symlink") &&
            error.failure() == capture::SupervisorFailure::NamespaceSetup) {
            return 0;
        }
        std::cerr << static_cast<std::uint32_t>(error.failure()) << ':' << error.what() << '\n';
        return 29;
    }
}

int run_case(const std::string& mode) {
    TempTree tree;
    write_file(tree.path() / "original/collector", "collector-bytes", 0555);
    write_file(tree.path() / "original/fixture.cc", "int value = 7;\n", 0444);
    const pid_t child = ::fork();
    if (child < 0) {
        return 30;
    }
    if (child == 0) {
        int result = 31;
        try {
            result = child_case(mode, tree.path());
        } catch (const std::exception& error) {
            std::cerr << error.what() << '\n';
            result = 32;
        }
        ::_exit(result);
    }
    int status = 0;
    if (::waitpid(child, &status, 0) != child || !WIFEXITED(status)) {
        return 33;
    }
    return WEXITSTATUS(status);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        return 10;
    }
    return run_case(argv[1]);
}
