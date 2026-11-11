#ifndef EVALUATION_V6_3_1_CAPTURE_V2_PIDFD_OPENED_FILE_H
#define EVALUATION_V6_3_1_CAPTURE_V2_PIDFD_OPENED_FILE_H

#if !defined(__linux__)
#error "PidfdOpenedFile is a Linux-only Capture V2 component"
#endif

#include "OwnedFd.h"
#include "SupervisorTypes.h"
#include "Timeout.h"

#include <cstdint>
#include <utility>

namespace evaluation_v6_3_1::capture_v2 {

// Immutable identity observed from one duplicate of a stopped tracee's open
// file description. This is a zero-authority capture primitive only.
struct PidfdOpenedFileObservation final {
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    std::uint64_t byte_length = 0;
    std::uint32_t mode = 0;
    Sha256Digest sha256{};

    friend bool operator==(const PidfdOpenedFileObservation&,
                           const PidfdOpenedFileObservation&) = default;
};

// Owns exactly the descriptor duplicated through pidfd_getfd(2). The
// duplicator deliberately has no pathname, procfs, or namespace fallback.
class PidfdOpenedFile final {
public:
    PidfdOpenedFile(PidfdOpenedFile&&) noexcept = default;
    PidfdOpenedFile& operator=(PidfdOpenedFile&&) noexcept = default;
    PidfdOpenedFile(const PidfdOpenedFile&) = delete;
    PidfdOpenedFile& operator=(const PidfdOpenedFile&) = delete;

    [[nodiscard]] static PidfdOpenedFile duplicate_stopped_child_file(
        int validated_pidfd,
        int child_fd,
        std::uint64_t positive_maximum_bytes,
        const MonotonicDeadline& deadline);

    [[nodiscard]] int descriptor() const noexcept { return duplicate_.get(); }
    [[nodiscard]] const PidfdOpenedFileObservation& observation() const noexcept {
        return observation_;
    }

private:
    PidfdOpenedFile(OwnedFd duplicate, PidfdOpenedFileObservation observation) noexcept
        : duplicate_(std::move(duplicate)), observation_(std::move(observation)) {}

    OwnedFd duplicate_;
    PidfdOpenedFileObservation observation_;
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_PIDFD_OPENED_FILE_H
