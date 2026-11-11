#include "NamespaceIdentityObserver.h"

#if !defined(__linux__)
#error "NamespaceIdentityObserver is a Linux-only Capture V2 component"
#endif

#include "LaunchEngine.h"
#include "OwnedFd.h"
#include "RetainedInputs.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/SHA256.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <limits>
#include <set>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {
namespace {

constexpr std::uint64_t kRegularFileTypeCode = 1u;
constexpr std::size_t kHashBufferBytes = 64u * 1024u;

[[noreturn]] void fail(SupervisorFailure failure, std::string message, int error = 0) {
    throw SupervisorError(failure, std::move(message), error);
}

void require_live_deadline(const MonotonicDeadline& deadline) {
    if (deadline.expired()) {
        fail(SupervisorFailure::TraceTimeout, "namespace identity observation exceeded its deadline");
    }
}

bool utf8_byte_less(std::string_view left, std::string_view right) noexcept {
    return std::lexicographical_compare(
        left.begin(), left.end(), right.begin(), right.end(), [](char a, char b) {
            return static_cast<std::uint8_t>(a) < static_cast<std::uint8_t>(b);
        });
}

struct StableIdentity final {
    std::uint64_t device = 0u;
    std::uint64_t inode = 0u;
    std::uint64_t byte_length = 0u;
    std::uint64_t link_count = 0u;
    std::uint32_t mode = 0u;
    std::int64_t modification_seconds = 0;
    std::int64_t modification_nanoseconds = 0;
    std::int64_t change_seconds = 0;
    std::int64_t change_nanoseconds = 0;

    friend bool operator==(const StableIdentity&, const StableIdentity&) = default;
};

StableIdentity inspect_regular_file(int descriptor, const char* stage) {
    struct stat status {};
    if (::fstat(descriptor, &status) != 0) {
        fail(SupervisorFailure::SystemFailure, std::string("fstat ") + stage + " failed", errno);
    }
    if (!S_ISREG(status.st_mode) || status.st_size < 0 || status.st_nlink != 1) {
        fail(SupervisorFailure::ProtocolViolation,
             std::string(stage) + " is not a single-link regular namespace file");
    }
    if (static_cast<std::uintmax_t>(status.st_size) >
        static_cast<std::uintmax_t>(std::numeric_limits<off_t>::max())) {
        fail(SupervisorFailure::ProtocolViolation,
             "namespace file length cannot be represented by pread offset");
    }
    return StableIdentity{
        static_cast<std::uint64_t>(status.st_dev),
        static_cast<std::uint64_t>(status.st_ino),
        static_cast<std::uint64_t>(status.st_size),
        static_cast<std::uint64_t>(status.st_nlink),
        static_cast<std::uint32_t>(status.st_mode),
        static_cast<std::int64_t>(status.st_mtim.tv_sec),
        static_cast<std::int64_t>(status.st_mtim.tv_nsec),
        static_cast<std::int64_t>(status.st_ctim.tv_sec),
        static_cast<std::int64_t>(status.st_ctim.tv_nsec),
    };
}

std::pair<std::uint64_t, std::uint64_t> inspect_directory(int descriptor, const char* stage) {
    struct stat status {};
    if (::fstat(descriptor, &status) != 0 || !S_ISDIR(status.st_mode)) {
        fail(SupervisorFailure::SystemFailure, std::string("inspect ") + stage + " failed", errno);
    }
    return {
        static_cast<std::uint64_t>(status.st_dev),
        static_cast<std::uint64_t>(status.st_ino),
    };
}

OwnedFd open_proc_root(pid_t pid) {
    if (pid <= 0) {
        fail(SupervisorFailure::InvalidRequest, "namespace observer child PID is invalid");
    }
    const std::string proc_path = "/proc/" + std::to_string(pid);
    OwnedFd proc(::open(
        proc_path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW));
    if (!proc) {
        fail(SupervisorFailure::SystemFailure, "open child proc directory failed", errno);
    }
    // /proc/<live-direct-child>/root is the one intentional procfs symlink.
    // All traversal below that descriptor is component-wise O_NOFOLLOW.
    OwnedFd root(::openat(
        proc.get(), "root", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOCTTY));
    if (!root) {
        fail(SupervisorFailure::SystemFailure, "open sealed child namespace root failed", errno);
    }
    return root;
}

OwnedFd open_beneath_without_links(int root_fd, const std::string& relative_path) {
    if (!is_normalized_relative_path(relative_path)) {
        fail(SupervisorFailure::InvalidRequest, "namespace identity path is not canonical");
    }
    OwnedFd current;
    int directory_fd = root_fd;
    std::size_t start = 0u;
    for (;;) {
        const std::size_t separator = relative_path.find('/', start);
        const std::size_t end =
            separator == std::string::npos ? relative_path.size() : separator;
        const std::string component = relative_path.substr(start, end - start);
        const bool final = separator == std::string::npos;
        const int flags = final
                              ? O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW
                              : O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW;
        const int opened = ::openat(directory_fd, component.c_str(), flags);
        if (opened < 0) {
            fail(SupervisorFailure::ProtocolViolation,
                 "no-follow namespace identity traversal failed", errno);
        }
        OwnedFd next(opened);
        if (final) {
            return next;
        }
        current = std::move(next);
        directory_fd = current.get();
        start = separator + 1u;
    }
}

Sha256Digest hash_exact_file(
    int descriptor,
    std::uint64_t byte_length,
    const MonotonicDeadline& deadline) {
    llvm::SHA256 hasher;
    std::array<std::uint8_t, kHashBufferBytes> buffer{};
    std::uint64_t offset = 0u;
    while (offset < byte_length) {
        require_live_deadline(deadline);
        const std::uint64_t remaining = byte_length - offset;
        const std::size_t requested = static_cast<std::size_t>(
            std::min<std::uint64_t>(remaining, buffer.size()));
        const ssize_t count = ::pread(
            descriptor, buffer.data(), requested, static_cast<off_t>(offset));
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            fail(SupervisorFailure::SystemFailure,
                 "pread sealed namespace file failed", errno);
        }
        if (static_cast<std::size_t>(count) != requested) {
            fail(SupervisorFailure::ProtocolViolation,
                 "sealed namespace file produced a short read");
        }
        hasher.update(llvm::ArrayRef<std::uint8_t>(buffer.data(), requested));
        offset += static_cast<std::uint64_t>(requested);
    }
    std::uint8_t extra = 0u;
    require_live_deadline(deadline);
    for (;;) {
        const ssize_t count = ::pread(
            descriptor, &extra, 1u, static_cast<off_t>(byte_length));
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            fail(SupervisorFailure::SystemFailure,
                 "pread sealed namespace EOF probe failed", errno);
        }
        if (count != 0) {
            fail(SupervisorFailure::ProtocolViolation,
                 "sealed namespace file exceeds its observed length");
        }
        return hasher.final();
    }
}

}  // namespace

std::vector<NamespaceIdentityObservation> NamespaceIdentityObserver::observe(
    pid_t blocked_child_pid,
    const LaunchReadyRecord& ready_record,
    const std::vector<NamespaceFileExpectation>& expected_files,
    std::uint64_t positive_total_byte_cap,
    const MonotonicDeadline& deadline) {
    if (ready_record.status != LaunchReadyStatus::Ready ||
        ready_record.root_device == 0u || ready_record.root_inode == 0u ||
        expected_files.empty() || positive_total_byte_cap == 0u) {
        fail(SupervisorFailure::InvalidRequest,
             "namespace identity observation request is incomplete");
    }
    require_live_deadline(deadline);
    OwnedFd root = open_proc_root(blocked_child_pid);
    const auto expected_root =
        std::pair{ready_record.root_device, ready_record.root_inode};
    if (inspect_directory(root.get(), "sealed namespace root before observation") != expected_root) {
        fail(SupervisorFailure::ProtocolViolation,
             "observed namespace root differs from launch-ready custody");
    }

    std::vector<NamespaceIdentityObservation> rows;
    rows.reserve(expected_files.size());
    std::set<std::pair<std::uint64_t, std::uint64_t>> object_identities;
    std::uint64_t consumed_bytes = 0u;
    std::string previous_path;
    for (const NamespaceFileExpectation& expected : expected_files) {
        if (!is_normalized_relative_path(expected.namespace_relative_path) ||
            (!previous_path.empty() &&
             !utf8_byte_less(previous_path, expected.namespace_relative_path))) {
            fail(SupervisorFailure::InvalidRequest,
                 "namespace expectations are not strictly path sorted");
        }
        previous_path = expected.namespace_relative_path;
        if (expected.byte_length > positive_total_byte_cap - consumed_bytes) {
            fail(SupervisorFailure::ResourceLimit,
                 "namespace identity observations exceed their total byte cap");
        }
        consumed_bytes += expected.byte_length;
        OwnedFd file = open_beneath_without_links(
            root.get(), expected.namespace_relative_path);
        const StableIdentity before = inspect_regular_file(
            file.get(), "sealed namespace file before hash");
        if (before.byte_length != expected.byte_length ||
            (before.mode & 07777u) != expected.normalized_mode) {
            fail(SupervisorFailure::ProtocolViolation,
                 "sealed namespace identity differs from public expectation");
        }
        const Sha256Digest digest = hash_exact_file(
            file.get(), before.byte_length, deadline);
        const StableIdentity after = inspect_regular_file(
            file.get(), "sealed namespace file after hash");
        if (after != before || digest != expected.sha256) {
            fail(SupervisorFailure::ProtocolViolation,
                 "sealed namespace file changed or differs from its expected hash");
        }
        if (!object_identities.emplace(before.device, before.inode).second) {
            fail(SupervisorFailure::ProtocolViolation,
                 "sealed namespace contains a device/inode alias");
        }
        rows.push_back(NamespaceIdentityObservation{
            expected.namespace_relative_path,
            static_cast<std::uint64_t>(major(static_cast<dev_t>(before.device))),
            static_cast<std::uint64_t>(minor(static_cast<dev_t>(before.device))),
            before.inode,
            kRegularFileTypeCode,
            expected.normalized_mode,
            before.byte_length,
            digest,
        });
    }
    require_live_deadline(deadline);
    if (inspect_directory(root.get(), "sealed namespace root after observation") != expected_root) {
        fail(SupervisorFailure::ProtocolViolation,
             "sealed namespace root changed during identity observation");
    }
    return rows;
}

}  // namespace evaluation_v6_3_1::capture_v2
