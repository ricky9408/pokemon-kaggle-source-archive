#ifndef POKEMON_EVALUATION_V631302_STAGE1_SECCOMP_FILTER_V1_H
#define POKEMON_EVALUATION_V631302_STAGE1_SECCOMP_FILTER_V1_H

// Zero-authority offline/runtime-byte conformance primitive.  This file does
// not install seccomp, launch a child, or create campaign/upload authority.

#include <cstddef>
#include <cstdint>
#include <linux/filter.h>
#include <string_view>

namespace pokemon::evaluation_v631302 {

struct SeccompPolicyV1 final {
    static constexpr std::size_t instruction_count = 43u;
    static constexpr std::size_t raw_byte_count = 344u;
    static constexpr std::uint32_t audit_arch_x86_64 = 0xC000003Eu;
    static constexpr std::uint32_t x32_syscall_bit = 0x40000000u;
    static constexpr std::uint32_t kill_process = 0x80000000u;
    static constexpr std::uint32_t allow = 0x7FFF0000u;
    static constexpr std::uint8_t raw_bpf_sha256[32] = {
        0x12u, 0x30u, 0x51u, 0xe7u, 0x32u, 0x3fu, 0x8du, 0xaeu,
        0xf9u, 0x35u, 0xd7u, 0xeeu, 0x73u, 0xefu, 0x62u, 0xffu,
        0xf8u, 0x11u, 0x7cu, 0x6au, 0x03u, 0x5cu, 0x75u, 0xe9u,
        0x9cu, 0x91u, 0x9cu, 0xf8u, 0xa9u, 0x00u, 0xd7u, 0xa6u,
    };
};

static_assert(sizeof(sock_filter) == 8u);
static_assert(offsetof(sock_filter, code) == 0u);
static_assert(offsetof(sock_filter, jt) == 2u);
static_assert(offsetof(sock_filter, jf) == 3u);
static_assert(offsetof(sock_filter, k) == 4u);

static_assert(sizeof(sock_fprog) == 16u);
static_assert(offsetof(sock_fprog, len) == 0u);
static_assert(offsetof(sock_fprog, filter) == 8u);

inline constexpr bool kStage1SeccompV1ZeroAuthority = true;
inline constexpr bool kStage1SeccompV1UploadAuthority = false;

// The array is the sole policy object.  It is const so the custodian places
// it in a read-only load; callers cannot supply or generate a replacement.
extern const sock_filter kStage1SeccompFilterV1[SeccompPolicyV1::instruction_count];

// This is the canonical little-endian serialization of the array, exposed for
// independent byte-level conformance checks.  It is not a runtime builder.
extern const std::uint8_t kStage1SeccompRawBpfV1[SeccompPolicyV1::raw_byte_count];

// Initializes the only permitted program descriptor in caller-owned storage.
// The complete object is zeroed in place before len and filter are assigned,
// avoiding any ABI copy that could leave padding indeterminate.
bool initialize_stage1_seccomp_program_v1(sock_fprog* output) noexcept;

// Validates an already-existing filter object.  The caller owns the memory;
// this function only proves byte conformance and never installs the filter.
bool validate_stage1_seccomp_filter_v1(
    const sock_filter* actual_filter,
    std::size_t instruction_count) noexcept;

// Validates the exact descriptor passed to the child gate.  In addition to
// bytes, this requires the canonical read-only object pointer and zero
// sock_fprog padding, so an equivalent caller-created policy is rejected.
bool validate_stage1_seccomp_program_v1(const sock_fprog* actual_program) noexcept;

// Cross-binds the exact filter bytes to one readable, non-writable mapping in
// a complete /proc/self/maps snapshot supplied by the PID-1 custodian.
bool validate_stage1_seccomp_program_mapping_v1(
    const sock_fprog* actual_program,
    std::string_view proc_self_maps) noexcept;

}  // namespace pokemon::evaluation_v631302

#endif
