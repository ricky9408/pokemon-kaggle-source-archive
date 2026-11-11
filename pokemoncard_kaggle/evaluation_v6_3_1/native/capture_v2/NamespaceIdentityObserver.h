#ifndef EVALUATION_V6_3_1_CAPTURE_V2_NAMESPACE_IDENTITY_OBSERVER_H
#define EVALUATION_V6_3_1_CAPTURE_V2_NAMESPACE_IDENTITY_OBSERVER_H

#if !defined(__linux__)
#error "NamespaceIdentityObserver is a Linux-only Capture V2 component"
#endif

#include "LaunchHandshake.h"
#include "SupervisorTypes.h"
#include "Timeout.h"

#include <cstdint>
#include <string>
#include <vector>

#include <sys/types.h>

namespace evaluation_v6_3_1::capture_v2 {

struct NamespaceFileExpectation;

struct NamespaceIdentityObservation final {
    std::string namespace_relative_path;
    std::uint64_t device_major = 0u;
    std::uint64_t device_minor = 0u;
    std::uint64_t inode = 0u;
    std::uint64_t file_type_code = 0u;
    std::uint32_t normalized_mode = 0u;
    std::uint64_t byte_length = 0u;
    Sha256Digest sha256{};

    friend bool operator==(const NamespaceIdentityObservation&,
                           const NamespaceIdentityObservation&) = default;
};

// Observes the already-sealed child namespace from the parent supervisor while
// the direct child remains blocked before exec. It performs no protocol
// construction, root derivation, permit operation, or campaign operation.
class NamespaceIdentityObserver final {
public:
    [[nodiscard]] static std::vector<NamespaceIdentityObservation> observe(
        pid_t blocked_child_pid,
        const LaunchReadyRecord& ready_record,
        const std::vector<NamespaceFileExpectation>& expected_files,
        std::uint64_t positive_total_byte_cap,
        const MonotonicDeadline& deadline);
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_NAMESPACE_IDENTITY_OBSERVER_H
