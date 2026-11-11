#ifndef EVALUATION_V6_3_1_CAPTURE_V2_PROC_MAPS_PARSER_H
#define EVALUATION_V6_3_1_CAPTURE_V2_PROC_MAPS_PARSER_H

#if !defined(__linux__)
#error "ProcMapsParser is a Linux-only Capture V2 component"
#endif

#include "SupervisorTypes.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {

struct ExecutableFileMapping final {
    std::uint64_t start_address = 0u;
    std::uint64_t end_address = 0u;
    std::uint64_t file_offset = 0u;
    std::uint64_t device_major = 0u;
    std::uint64_t device_minor = 0u;
    std::uint64_t inode = 0u;
    std::uint64_t protection_flags = 0u;
    std::string diagnostic_absolute_path;

    [[nodiscard]] std::uint64_t mapping_length() const noexcept {
        return end_address - start_address;
    }

    friend bool operator==(const ExecutableFileMapping&,
                           const ExecutableFileMapping&) = default;
};

// Parses one bounded /proc/<pid>/maps snapshot already read while the tracee
// was stopped. Anonymous executable mappings are ignored; malformed or
// noncanonical file-backed rows fail closed. No pathname is opened here.
class ProcMapsParser final {
public:
    [[nodiscard]] static std::vector<ExecutableFileMapping>
    parse_executable_file_mappings(
        std::span<const std::uint8_t> maps_bytes,
        std::size_t positive_maximum_rows,
        std::size_t positive_maximum_line_bytes);
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_PROC_MAPS_PARSER_H
