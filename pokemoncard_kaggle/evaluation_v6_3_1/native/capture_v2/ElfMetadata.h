#ifndef EVALUATION_V6_3_1_CAPTURE_V2_ELF_METADATA_H
#define EVALUATION_V6_3_1_CAPTURE_V2_ELF_METADATA_H

#if !defined(__linux__)
#error "ElfMetadata is a Linux-only Capture V2 component"
#endif

#include "SupervisorTypes.h"
#include "Timeout.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {

struct ElfMetadataLimits final {
    std::size_t maximum_program_headers = 4096u;
    std::size_t maximum_section_headers = 65'536u;
    std::uint64_t maximum_metadata_bytes = 16u * 1024u * 1024u;
    std::size_t maximum_interpreter_bytes = 65'535u;
    std::size_t maximum_soname_bytes = 65'535u;
    std::size_t maximum_build_id_bytes = 65'535u;
};

struct ElfMetadataObservation final {
    // Exact bytes excluding the PT_INTERP terminating NUL. Empty means absent.
    std::vector<std::uint8_t> interpreter;
    // Exact DT_SONAME bytes excluding its terminating NUL. Empty means absent.
    std::vector<std::uint8_t> soname;
    // Exact GNU build-ID descriptor bytes. Empty means absent.
    std::vector<std::uint8_t> build_id;

    friend bool operator==(const ElfMetadataObservation&,
                           const ElfMetadataObservation&) = default;
};

// Reads only from an already authenticated regular-file descriptor. It never
// opens a pathname and grants no capture, campaign, or upload authority.
class ElfMetadata final {
public:
    [[nodiscard]] static ElfMetadataObservation inspect_linux_amd64(
        int authenticated_descriptor,
        std::uint64_t positive_maximum_file_bytes,
        const MonotonicDeadline& deadline,
        ElfMetadataLimits limits = {});
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_ELF_METADATA_H
