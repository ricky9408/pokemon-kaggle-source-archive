#include "RetainedInputs.h"

#if !defined(__linux__)
#error "RetainedInputs is a Linux-only Capture V2 component"
#endif

#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/SHA256.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <set>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {
namespace {

constexpr std::uint32_t kCollectorExecutable = 1;
constexpr std::uint32_t kPrimarySource = 2;
constexpr std::uint32_t kMaximumRole = 8;
constexpr std::size_t kCopyBufferBytes = 64u * 1024u;

[[noreturn]] void fail(SupervisorFailure failure, std::string message, int error = 0) {
    throw SupervisorError(failure, std::move(message), error);
}

bool valid_utf8(std::string_view value) noexcept {
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(value.data());
    std::size_t index = 0;
    while (index < value.size()) {
        const std::uint8_t first = bytes[index++];
        if (first <= 0x7fu) {
            continue;
        }
        const auto continuation = [](std::uint8_t byte) { return (byte & 0xc0u) == 0x80u; };
        if (first >= 0xc2u && first <= 0xdfu) {
            if (index >= value.size() || !continuation(bytes[index++])) {
                return false;
            }
            continue;
        }
        if (first >= 0xe0u && first <= 0xefu) {
            if (index + 1u >= value.size()) {
                return false;
            }
            const std::uint8_t second = bytes[index++];
            const std::uint8_t third = bytes[index++];
            const bool second_valid =
                first == 0xe0u   ? second >= 0xa0u && second <= 0xbfu
                : first == 0xedu ? second >= 0x80u && second <= 0x9fu
                                 : continuation(second);
            if (!second_valid || !continuation(third)) {
                return false;
            }
            continue;
        }
        if (first >= 0xf0u && first <= 0xf4u) {
            if (index + 2u >= value.size()) {
                return false;
            }
            const std::uint8_t second = bytes[index++];
            const std::uint8_t third = bytes[index++];
            const std::uint8_t fourth = bytes[index++];
            const bool second_valid =
                first == 0xf0u   ? second >= 0x90u && second <= 0xbfu
                : first == 0xf4u ? second >= 0x80u && second <= 0x8fu
                                 : continuation(second);
            if (!second_valid || !continuation(third) || !continuation(fourth)) {
                return false;
            }
            continue;
        }
        return false;
    }
    return true;
}

bool utf8_byte_less(std::string_view left, std::string_view right) noexcept {
    return std::lexicographical_compare(
        left.begin(), left.end(), right.begin(), right.end(), [](char a, char b) {
            return static_cast<std::uint8_t>(a) < static_cast<std::uint8_t>(b);
        });
}

FileIdentity identity_from_stat(const struct stat& status) {
    if (status.st_size < 0) {
        fail(SupervisorFailure::OriginalInputIdentity, "negative input length");
    }
    return FileIdentity{
        static_cast<std::uint64_t>(status.st_dev),
        static_cast<std::uint64_t>(status.st_ino),
        static_cast<std::uint64_t>(status.st_size),
        static_cast<std::uint64_t>(status.st_nlink),
        static_cast<std::uint32_t>(status.st_mode),
        static_cast<std::uint32_t>(status.st_uid),
        static_cast<std::uint32_t>(status.st_gid),
        static_cast<std::int64_t>(status.st_mtim.tv_sec),
        static_cast<std::int64_t>(status.st_mtim.tv_nsec),
        static_cast<std::int64_t>(status.st_ctim.tv_sec),
        static_cast<std::int64_t>(status.st_ctim.tv_nsec),
    };
}

FileIdentity stat_identity(int descriptor, SupervisorFailure failure, const char* message) {
    struct stat status {};
    if (::fstat(descriptor, &status) != 0) {
        fail(failure, message, errno);
    }
    return identity_from_stat(status);
}

void validate_roles_and_mode(const RetainedInputSpec& spec) {
    if (spec.role_codes.empty()) {
        fail(SupervisorFailure::InvalidRequest, "input roles must be nonempty");
    }
    std::uint32_t previous = 0;
    for (const std::uint32_t role : spec.role_codes) {
        if (role == 0 || role > kMaximumRole || role <= previous) {
            fail(SupervisorFailure::InvalidRequest, "input roles must be strictly increasing in range");
        }
        previous = role;
    }
    const bool collector = std::binary_search(
        spec.role_codes.begin(), spec.role_codes.end(), kCollectorExecutable);
    const std::uint32_t expected_mode = collector ? 0555u : 0444u;
    if (spec.normalized_mode != expected_mode) {
        fail(SupervisorFailure::InvalidRequest, "input has the wrong normalized mode");
    }
}

OwnedFd open_original_once(const RetainedInputSpec& spec) {
    if (spec.original_root_fd < 0) {
        fail(SupervisorFailure::InvalidRequest, "original root descriptor is invalid");
    }
    struct stat root_status {};
    if (::fstat(spec.original_root_fd, &root_status) != 0 || !S_ISDIR(root_status.st_mode)) {
        fail(SupervisorFailure::InvalidRequest, "original root descriptor is not a directory", errno);
    }
    OwnedFd current_directory;
    int current_directory_fd = spec.original_root_fd;
    std::size_t start = 0;
    for (;;) {
        const std::size_t separator = spec.original_relative_path.find('/', start);
        const std::size_t end =
            separator == std::string::npos ? spec.original_relative_path.size() : separator;
        const std::string component = spec.original_relative_path.substr(start, end - start);
        if (separator == std::string::npos) {
            const int opened = ::openat(
                current_directory_fd,
                component.c_str(),
                O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW);
            if (opened < 0) {
                fail(SupervisorFailure::OriginalInputOpen, "openat original input failed", errno);
            }
            return OwnedFd(opened);
        }
        const int next_directory = ::openat(
            current_directory_fd,
            component.c_str(),
            O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next_directory < 0) {
            fail(SupervisorFailure::OriginalInputOpen, "openat original directory failed", errno);
        }
        current_directory.reset(next_directory);
        current_directory_fd = current_directory.get();
        start = separator + 1u;
    }
}

void require_original_identity(const FileIdentity& identity) {
    if (!S_ISREG(identity.mode)) {
        fail(SupervisorFailure::OriginalInputIdentity, "original input is not regular");
    }
    if (identity.link_count != 1u) {
        fail(SupervisorFailure::OriginalInputIdentity, "original input has hard-link ambiguity");
    }
    if ((identity.mode & 0222u) != 0u) {
        fail(SupervisorFailure::OriginalInputIdentity, "original input is writable");
    }
}

void write_all(int descriptor, const std::uint8_t* data, std::size_t length) {
    std::size_t offset = 0;
    while (offset < length) {
        const ssize_t written = ::write(descriptor, data + offset, length - offset);
        if (written > 0) {
            offset += static_cast<std::size_t>(written);
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        fail(SupervisorFailure::CopyFailure, "destination write failed", errno);
    }
}

}  // namespace

bool is_normalized_relative_path(const std::string& path) noexcept {
    if (path.empty() || path.front() == '/' || path.find('\\') != std::string::npos ||
        path.find('\0') != std::string::npos || !valid_utf8(path)) {
        return false;
    }
    std::size_t start = 0;
    for (;;) {
        const std::size_t separator = path.find('/', start);
        const std::size_t end = separator == std::string::npos ? path.size() : separator;
        const std::string_view component(path.data() + start, end - start);
        if (component.empty() || component == "." || component == "..") {
            return false;
        }
        if (separator == std::string::npos) {
            return true;
        }
        start = separator + 1u;
    }
}

RetainedInputSet RetainedInputSet::acquire(std::vector<RetainedInputSpec> specs) {
    if (specs.empty()) {
        fail(SupervisorFailure::InvalidRequest, "input set must be nonempty");
    }
    std::set<std::string> namespace_paths;
    std::set<std::pair<int, std::string>> original_paths;
    std::size_t collector_count = 0;
    std::size_t primary_count = 0;
    std::string_view previous_namespace_path;
    for (const RetainedInputSpec& spec : specs) {
        if (!is_normalized_relative_path(spec.original_relative_path) ||
            !is_normalized_relative_path(spec.namespace_relative_path)) {
            fail(SupervisorFailure::UnsafePath, "input path is not normalized relative UTF-8");
        }
        validate_roles_and_mode(spec);
        if (!namespace_paths.insert(spec.namespace_relative_path).second) {
            fail(SupervisorFailure::InvalidRequest, "duplicate namespace path");
        }
        if (!previous_namespace_path.empty() &&
            !utf8_byte_less(previous_namespace_path, spec.namespace_relative_path)) {
            fail(SupervisorFailure::InvalidRequest, "namespace rows are not strictly UTF-8 byte sorted");
        }
        previous_namespace_path = spec.namespace_relative_path;
        if (!original_paths.emplace(spec.original_root_fd, spec.original_relative_path).second) {
            fail(SupervisorFailure::InvalidRequest, "original path requested more than once");
        }
        collector_count += static_cast<std::size_t>(std::binary_search(
            spec.role_codes.begin(), spec.role_codes.end(), kCollectorExecutable));
        primary_count += static_cast<std::size_t>(std::binary_search(
            spec.role_codes.begin(), spec.role_codes.end(), kPrimarySource));
    }
    if (collector_count != 1u || primary_count != 1u) {
        fail(SupervisorFailure::InvalidRequest, "input set requires exactly one collector and primary source");
    }

    std::vector<RetainedInput> inputs;
    inputs.reserve(specs.size());
    for (RetainedInputSpec& spec : specs) {
        OwnedFd descriptor = open_original_once(spec);
        const FileIdentity identity = stat_identity(
            descriptor.get(), SupervisorFailure::OriginalInputIdentity, "fstat original input failed");
        require_original_identity(identity);
        inputs.push_back(RetainedInput(std::move(spec), std::move(descriptor), identity));
    }
    return RetainedInputSet(std::move(inputs));
}

MaterializedInput RetainedInput::materialize_to(int destination_fd) {
    if (materialized_) {
        fail(SupervisorFailure::ProtocolViolation, "retained input was materialized more than once");
    }
    if (destination_fd < 0) {
        fail(SupervisorFailure::DestinationInvalid, "destination descriptor is invalid");
    }
    const FileIdentity before = stat_identity(
        descriptor_.get(), SupervisorFailure::OriginalInputChanged, "fstat before copy failed");
    if (before != acquired_identity_) {
        fail(SupervisorFailure::OriginalInputChanged, "original input changed before copy");
    }
    const FileIdentity destination_before = stat_identity(
        destination_fd, SupervisorFailure::DestinationInvalid, "fstat destination failed");
    if (!S_ISREG(destination_before.mode) || destination_before.byte_length != 0u ||
        destination_before.link_count != 1u) {
        fail(SupervisorFailure::DestinationInvalid, "destination must be an empty single-link regular file");
    }
    if (destination_before.device == acquired_identity_.device &&
        destination_before.inode == acquired_identity_.inode) {
        fail(SupervisorFailure::DestinationInvalid, "destination aliases the retained original input");
    }
    if (::lseek(destination_fd, 0, SEEK_SET) != 0) {
        fail(SupervisorFailure::DestinationInvalid, "destination seek failed", errno);
    }

    llvm::SHA256 hasher;
    std::array<std::uint8_t, kCopyBufferBytes> buffer{};
    std::uint64_t offset = 0;
    while (offset < before.byte_length) {
        const std::uint64_t remaining = before.byte_length - offset;
        const std::size_t requested = static_cast<std::size_t>(
            std::min<std::uint64_t>(remaining, buffer.size()));
        const ssize_t count = ::pread(
            descriptor_.get(), buffer.data(), requested, static_cast<off_t>(offset));
        if (count > 0) {
            const std::size_t length = static_cast<std::size_t>(count);
            hasher.update(llvm::ArrayRef<std::uint8_t>(buffer.data(), length));
            write_all(destination_fd, buffer.data(), length);
            offset += length;
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        fail(SupervisorFailure::OriginalInputChanged, "original input ended before committed length", errno);
    }
    std::uint8_t extra = 0;
    ssize_t extra_count = -1;
    do {
        extra_count = ::pread(
            descriptor_.get(), &extra, 1u, static_cast<off_t>(before.byte_length));
    } while (extra_count < 0 && errno == EINTR);
    if (extra_count != 0) {
        fail(SupervisorFailure::OriginalInputChanged, "original input exceeds committed length", errno);
    }
    if (::fchmod(destination_fd, static_cast<mode_t>(spec_.normalized_mode)) != 0 ||
        ::fsync(destination_fd) != 0) {
        fail(SupervisorFailure::CopyFailure, "destination finalize failed", errno);
    }
    const FileIdentity after = stat_identity(
        descriptor_.get(), SupervisorFailure::OriginalInputChanged, "fstat after copy failed");
    if (after != acquired_identity_) {
        fail(SupervisorFailure::OriginalInputChanged, "original input changed during copy");
    }
    const FileIdentity destination_after = stat_identity(
        destination_fd, SupervisorFailure::DestinationInvalid, "fstat copied destination failed");
    if (!S_ISREG(destination_after.mode) || destination_after.device != destination_before.device ||
        destination_after.inode != destination_before.inode || destination_after.link_count != 1u ||
        destination_after.byte_length != before.byte_length ||
        (destination_after.mode & 07777u) != spec_.normalized_mode) {
        fail(SupervisorFailure::CopyFailure, "destination identity, bytes, links, or mode changed");
    }
    materialized_ = true;
    return MaterializedInput{
        spec_.namespace_relative_path,
        spec_.role_codes,
        spec_.normalized_mode,
        before.byte_length,
        hasher.final(),
        acquired_identity_,
    };
}

}  // namespace evaluation_v6_3_1::capture_v2
