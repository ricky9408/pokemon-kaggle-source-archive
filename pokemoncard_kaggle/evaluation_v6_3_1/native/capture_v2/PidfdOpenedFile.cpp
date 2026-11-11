#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "PidfdOpenedFile.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/SHA256.h"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <utility>

namespace evaluation_v6_3_1::capture_v2 {
namespace {

constexpr std::size_t kHashBufferBytes = 64u * 1024u;

struct StableFileIdentity final {
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    std::uint64_t byte_length = 0;
    std::uint64_t link_count = 0;
    std::uint32_t mode = 0;
    std::int64_t modification_seconds = 0;
    std::int64_t modification_nanoseconds = 0;
    std::int64_t change_seconds = 0;
    std::int64_t change_nanoseconds = 0;

    friend bool operator==(const StableFileIdentity&, const StableFileIdentity&) = default;
};

[[noreturn]] void fail(SupervisorFailure failure, std::string message, int error = 0) {
    throw SupervisorError(failure, std::move(message), error);
}

StableFileIdentity inspect_regular_file(int descriptor, const char* stage) {
    struct stat status {};
    if (::fstat(descriptor, &status) != 0) {
        fail(SupervisorFailure::SystemFailure, std::string("fstat ") + stage + " failed", errno);
    }
    if (!S_ISREG(status.st_mode) || status.st_size < 0) {
        fail(SupervisorFailure::ProtocolViolation,
             std::string("pidfd duplicated object is not a nonnegative-sized regular file at ") + stage);
    }
    if (static_cast<std::uintmax_t>(status.st_size) >
        static_cast<std::uintmax_t>(std::numeric_limits<off_t>::max())) {
        fail(SupervisorFailure::ProtocolViolation,
             "pidfd duplicated file length cannot be represented by pread offset");
    }
    return StableFileIdentity{
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

void require_live_deadline(const MonotonicDeadline& deadline) {
    if (deadline.expired()) {
        fail(SupervisorFailure::TraceTimeout, "pidfd opened-file capture exceeded its deadline");
    }
}

Sha256Digest hash_exact_bytes_without_offset_mutation(
    int descriptor,
    std::uint64_t byte_length,
    const MonotonicDeadline& deadline) {
    llvm::SHA256 hasher;
    std::array<std::uint8_t, kHashBufferBytes> buffer{};
    std::uint64_t offset = 0;
    while (offset < byte_length) {
        require_live_deadline(deadline);
        const std::uint64_t remaining = byte_length - offset;
        const std::size_t requested = static_cast<std::size_t>(
            remaining < static_cast<std::uint64_t>(buffer.size())
                ? remaining
                : static_cast<std::uint64_t>(buffer.size()));
        const ssize_t count = ::pread(
            descriptor, buffer.data(), requested, static_cast<off_t>(offset));
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            fail(SupervisorFailure::SystemFailure, "pread while hashing pidfd duplicate failed", errno);
        }
        if (static_cast<std::size_t>(count) != requested) {
            fail(SupervisorFailure::ProtocolViolation,
                 "pidfd duplicated file produced a short or long pread during hash");
        }
        hasher.update(llvm::ArrayRef<std::uint8_t>(buffer.data(), requested));
        offset += static_cast<std::uint64_t>(requested);
    }

    std::uint8_t eof_probe = 0;
    require_live_deadline(deadline);
    for (;;) {
        const ssize_t count = ::pread(
            descriptor, &eof_probe, 1u, static_cast<off_t>(byte_length));
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            fail(SupervisorFailure::SystemFailure, "pread EOF probe for pidfd duplicate failed", errno);
        }
        if (count != 0) {
            fail(SupervisorFailure::ProtocolViolation,
                 "pidfd duplicated file produced bytes beyond committed length");
        }
        break;
    }
    return hasher.final();
}

}  // namespace

PidfdOpenedFile PidfdOpenedFile::duplicate_stopped_child_file(
    int validated_pidfd,
    int child_fd,
    std::uint64_t positive_maximum_bytes,
    const MonotonicDeadline& deadline) {
    if (validated_pidfd < 0 || child_fd < 0 || positive_maximum_bytes == 0u) {
        fail(SupervisorFailure::InvalidRequest,
             "pidfd duplicate requires a validated pidfd, nonnegative child fd, and positive cap");
    }

    require_live_deadline(deadline);
    const long raw_duplicate = ::syscall(SYS_pidfd_getfd, validated_pidfd, child_fd, 0u);
    if (raw_duplicate < 0) {
        fail(SupervisorFailure::SystemFailure, "pidfd_getfd for stopped child file failed", errno);
    }
    if (raw_duplicate > static_cast<long>(std::numeric_limits<int>::max())) {
        static_cast<void>(::close(static_cast<int>(raw_duplicate)));
        fail(SupervisorFailure::SystemFailure, "pidfd_getfd returned an out-of-range descriptor");
    }

    OwnedFd duplicate(static_cast<int>(raw_duplicate));
    const StableFileIdentity before = inspect_regular_file(duplicate.get(), "before hash");
    if (before.byte_length > positive_maximum_bytes) {
        fail(SupervisorFailure::ResourceLimit, "pidfd duplicated file exceeds configured byte cap");
    }
    const Sha256Digest digest =
        hash_exact_bytes_without_offset_mutation(duplicate.get(), before.byte_length, deadline);
    require_live_deadline(deadline);
    const StableFileIdentity after = inspect_regular_file(duplicate.get(), "after hash");
    if (after != before) {
        fail(SupervisorFailure::ProtocolViolation,
             "pidfd duplicated file changed while its exact bytes were captured");
    }

    return PidfdOpenedFile(
        std::move(duplicate),
        PidfdOpenedFileObservation{
            before.device, before.inode, before.byte_length, before.mode, digest});
}

}  // namespace evaluation_v6_3_1::capture_v2
