#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "MountSandbox.h"

#if !defined(__linux__)
#error "MountSandbox is a Linux-only Capture V2 component"
#endif

#include "OwnedFd.h"
#include "SupervisorTypes.h"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <dirent.h>
#include <fcntl.h>
#include <limits>
#include <sched.h>
#include <set>
#include <string>
#include <string_view>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {
namespace {

constexpr std::uint64_t kMaximumTmpfsBytes = 8ULL * 1024ULL * 1024ULL * 1024ULL;
constexpr std::size_t kMaximumFiles = 100'000u;

[[noreturn]] void fail(SupervisorFailure failure, std::string message, int error = 0) {
    throw SupervisorError(failure, std::move(message), error);
}

struct Utf8ByteLess final {
    bool operator()(std::string_view left, std::string_view right) const noexcept {
        return std::lexicographical_compare(
            left.begin(), left.end(), right.begin(), right.end(), [](char a, char b) {
                return static_cast<std::uint8_t>(a) < static_cast<std::uint8_t>(b);
            });
    }
};

bool normalized_absolute_path(const std::string& path) noexcept {
    return path.size() > 1u && path.front() == '/' && path.back() != '/' &&
           is_normalized_relative_path(path.substr(1u));
}

void require_empty_directory(int descriptor) {
    const int duplicate = ::fcntl(descriptor, F_DUPFD_CLOEXEC, 3);
    if (duplicate < 0) {
        fail(SupervisorFailure::NamespaceSetup, "duplicate staging-root descriptor failed", errno);
    }
    DIR* directory = ::fdopendir(duplicate);
    if (directory == nullptr) {
        const int error = errno;
        static_cast<void>(::close(duplicate));
        fail(SupervisorFailure::NamespaceSetup, "open staging-root directory stream failed", error);
    }
    errno = 0;
    for (;;) {
        dirent* entry = ::readdir(directory);
        if (entry == nullptr) {
            const int error = errno;
            static_cast<void>(::closedir(directory));
            if (error != 0) {
                fail(SupervisorFailure::NamespaceSetup, "read staging-root directory failed", error);
            }
            return;
        }
        const std::string_view name(entry->d_name);
        if (name != "." && name != "..") {
            static_cast<void>(::closedir(directory));
            fail(SupervisorFailure::NamespaceSetup, "staging root is not empty");
        }
    }
}

OwnedFd validate_staging_root(const std::string& path) {
    if (!normalized_absolute_path(path)) {
        fail(SupervisorFailure::InvalidRequest, "staging root is not a normalized absolute path");
    }
    struct stat link_status {};
    if (::lstat(path.c_str(), &link_status) != 0 || !S_ISDIR(link_status.st_mode) ||
        link_status.st_uid != ::geteuid() || (link_status.st_mode & 07777u) != 0700u) {
        fail(SupervisorFailure::NamespaceSetup, "staging root identity or mode is invalid", errno);
    }
    const int opened = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (opened < 0) {
        fail(SupervisorFailure::NamespaceSetup, "open staging root failed", errno);
    }
    OwnedFd descriptor(opened);
    struct stat opened_status {};
    if (::fstat(descriptor.get(), &opened_status) != 0 ||
        opened_status.st_dev != link_status.st_dev || opened_status.st_ino != link_status.st_ino) {
        fail(SupervisorFailure::NamespaceSetup, "staging root changed during validation", errno);
    }
    require_empty_directory(descriptor.get());
    return descriptor;
}

std::size_t path_depth(std::string_view path) noexcept {
    return static_cast<std::size_t>(std::count(path.begin(), path.end(), '/')) + 1u;
}

void insert_directory_and_parents(
    std::set<std::string, Utf8ByteLess>& directories,
    const std::string& directory) {
    std::size_t end = 0u;
    for (;;) {
        end = directory.find('/', end);
        if (end == std::string::npos) {
            directories.insert(directory);
            return;
        }
        directories.insert(directory.substr(0u, end));
        ++end;
    }
}

void insert_file_parents(
    std::set<std::string, Utf8ByteLess>& directories,
    const std::string& file) {
    std::size_t separator = file.find('/');
    while (separator != std::string::npos) {
        directories.insert(file.substr(0u, separator));
        separator = file.find('/', separator + 1u);
    }
}

std::vector<std::string> required_directories(
    const RetainedInputSet& inputs,
    const std::string& working_directory) {
    std::set<std::string, Utf8ByteLess> directories;
    insert_directory_and_parents(directories, working_directory);
    std::set<std::string, Utf8ByteLess> file_paths;
    for (const RetainedInput& input : inputs.inputs()) {
        file_paths.insert(input.spec().namespace_relative_path);
        insert_file_parents(directories, input.spec().namespace_relative_path);
    }
    for (const std::string& directory : directories) {
        if (file_paths.contains(directory)) {
            fail(SupervisorFailure::InvalidRequest, "namespace path is both a file and directory");
        }
    }
    std::vector<std::string> result(directories.begin(), directories.end());
    std::sort(result.begin(), result.end(), [](const std::string& left, const std::string& right) {
        const std::size_t left_depth = path_depth(left);
        const std::size_t right_depth = path_depth(right);
        return left_depth != right_depth ? left_depth < right_depth : Utf8ByteLess{}(left, right);
    });
    return result;
}

void create_directories(int root_fd, const std::vector<std::string>& directories) {
    for (const std::string& directory : directories) {
        if (::mkdirat(root_fd, directory.c_str(), 0700) != 0) {
            fail(SupervisorFailure::NamespaceSetup, "create namespace directory failed", errno);
        }
    }
}

void set_directory_mode(int root_fd, const std::string& directory, mode_t mode) {
    const int opened = ::openat(
        root_fd, directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (opened < 0) {
        fail(SupervisorFailure::NamespaceSeal, "open namespace directory for sealing failed", errno);
    }
    OwnedFd descriptor(opened);
    if (::fchmod(descriptor.get(), mode) != 0) {
        fail(SupervisorFailure::NamespaceSeal, "seal namespace directory mode failed", errno);
    }
}

void verify_file_rows(int root_fd, const std::vector<MaterializedInput>& rows) {
    for (const MaterializedInput& row : rows) {
        const int opened = ::openat(
            root_fd, row.namespace_relative_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (opened < 0) {
            fail(SupervisorFailure::NamespaceSeal, "open sealed namespace file failed", errno);
        }
        OwnedFd descriptor(opened);
        struct stat status {};
        if (::fstat(descriptor.get(), &status) != 0 || !S_ISREG(status.st_mode) ||
            status.st_size < 0 || static_cast<std::uint64_t>(status.st_size) != row.byte_length ||
            (status.st_mode & 07777u) != row.normalized_mode || status.st_nlink != 1) {
            fail(SupervisorFailure::NamespaceSeal, "sealed namespace file identity is invalid", errno);
        }
    }
}

void require_read_only_mount(int root_fd) {
    struct statvfs filesystem {};
    if (::fstatvfs(root_fd, &filesystem) != 0 || (filesystem.f_flag & ST_RDONLY) == 0u) {
        fail(SupervisorFailure::NamespaceSeal, "namespace filesystem is not read-only", errno);
    }
    const int probe = ::openat(
        root_fd,
        ".v631302-write-probe",
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
        0600);
    if (probe >= 0) {
        static_cast<void>(::close(probe));
        fail(SupervisorFailure::NamespaceSeal, "write probe succeeded after namespace seal");
    }
    if (errno != EROFS) {
        fail(SupervisorFailure::NamespaceSeal, "write probe did not fail with EROFS", errno);
    }
}

std::pair<std::uint64_t, std::uint64_t> identity_of(int descriptor, SupervisorFailure failure) {
    struct stat status {};
    if (::fstat(descriptor, &status) != 0 || !S_ISDIR(status.st_mode)) {
        fail(failure, "namespace directory identity lookup failed", errno);
    }
    return {static_cast<std::uint64_t>(status.st_dev), static_cast<std::uint64_t>(status.st_ino)};
}

}  // namespace

MountSandboxResult MountSandbox::build_seal_and_enter(
    RetainedInputSet retained_inputs,
    const MountSandboxConfig& config) {
    if (!is_normalized_relative_path(config.working_directory_relative_path) ||
        config.tmpfs_byte_limit == 0u || config.tmpfs_byte_limit > kMaximumTmpfsBytes ||
        retained_inputs.inputs().empty() || retained_inputs.inputs().size() > kMaximumFiles) {
        fail(SupervisorFailure::InvalidRequest, "mount sandbox configuration is invalid");
    }
    std::uint64_t total_file_bytes = 0u;
    for (const RetainedInput& input : retained_inputs.inputs()) {
        if (input.acquired_identity().byte_length >
            std::numeric_limits<std::uint64_t>::max() - total_file_bytes) {
            fail(SupervisorFailure::ResourceLimit, "namespace file-size sum overflow");
        }
        total_file_bytes += input.acquired_identity().byte_length;
    }
    if (total_file_bytes > config.tmpfs_byte_limit) {
        fail(SupervisorFailure::ResourceLimit, "namespace files exceed the tmpfs byte limit");
    }
    const std::vector<std::string> directories =
        required_directories(retained_inputs, config.working_directory_relative_path);
    OwnedFd original_staging_root = validate_staging_root(config.staging_root_absolute_path);

    if (::unshare(CLONE_NEWNS) != 0 ||
        ::mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0) {
        fail(SupervisorFailure::NamespaceSetup, "create private mount namespace failed", errno);
    }
    const std::string mount_options =
        "mode=0700,size=" + std::to_string(config.tmpfs_byte_limit);
    if (::mount(
            "v631302-capture-v2",
            config.staging_root_absolute_path.c_str(),
            "tmpfs",
            MS_NOSUID | MS_NODEV,
            mount_options.c_str()) != 0) {
        fail(SupervisorFailure::NamespaceSetup, "mount private tmpfs root failed", errno);
    }
    original_staging_root.reset();

    const int root_opened = ::open(
        config.staging_root_absolute_path.c_str(),
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root_opened < 0) {
        fail(SupervisorFailure::NamespaceSetup, "open private tmpfs root failed", errno);
    }
    OwnedFd root_fd(root_opened);
    create_directories(root_fd.get(), directories);
    std::vector<MaterializedInput> rows;
    rows.reserve(retained_inputs.inputs().size());
    for (RetainedInput& input : retained_inputs.inputs()) {
        const int destination = ::openat(
            root_fd.get(),
            input.spec().namespace_relative_path.c_str(),
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0600);
        if (destination < 0) {
            fail(SupervisorFailure::NamespaceSetup, "create namespace file failed", errno);
        }
        OwnedFd destination_fd(destination);
        rows.push_back(input.materialize_to(destination_fd.get()));
    }

    for (auto iterator = directories.rbegin(); iterator != directories.rend(); ++iterator) {
        set_directory_mode(root_fd.get(), *iterator, 0555);
    }
    if (::fchmod(root_fd.get(), 0555) != 0 || ::syncfs(root_fd.get()) != 0) {
        fail(SupervisorFailure::NamespaceSeal, "synchronize namespace root failed", errno);
    }
    if (::mount(
            nullptr,
            config.staging_root_absolute_path.c_str(),
            nullptr,
            MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV,
            nullptr) != 0) {
        fail(SupervisorFailure::NamespaceSeal, "remount namespace root read-only failed", errno);
    }
    verify_file_rows(root_fd.get(), rows);
    require_read_only_mount(root_fd.get());
    const auto [root_device, root_inode] = identity_of(root_fd.get(), SupervisorFailure::NamespaceSeal);

    if (::chdir(config.staging_root_absolute_path.c_str()) != 0 || ::chroot(".") != 0 ||
        ::chdir("/") != 0) {
        fail(SupervisorFailure::NamespaceEnter, "enter sealed namespace root failed", errno);
    }
    const int entered_root = ::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (entered_root < 0) {
        fail(SupervisorFailure::NamespaceEnter, "open entered namespace root failed", errno);
    }
    OwnedFd entered_root_fd(entered_root);
    const auto [entered_device, entered_inode] =
        identity_of(entered_root_fd.get(), SupervisorFailure::NamespaceEnter);
    if (entered_device != root_device || entered_inode != root_inode) {
        fail(SupervisorFailure::NamespaceEnter, "entered root does not match sealed tmpfs root");
    }
    const int working = ::openat(
        entered_root_fd.get(),
        config.working_directory_relative_path.c_str(),
        O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (working < 0) {
        fail(SupervisorFailure::NamespaceEnter,
             "open post-seal child working-directory capability failed", errno);
    }
    OwnedFd working_fd(working);
    const auto [working_device, working_inode] =
        identity_of(working_fd.get(), SupervisorFailure::NamespaceEnter);

    return MountSandboxResult{
        std::move(rows),
        root_device,
        root_inode,
        working_device,
        working_inode,
        std::move(working_fd),
    };
}

}  // namespace evaluation_v6_3_1::capture_v2
