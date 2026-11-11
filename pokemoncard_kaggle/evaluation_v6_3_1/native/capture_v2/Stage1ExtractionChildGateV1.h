#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

#include <linux/filter.h>

namespace pokemon::evaluation_v631302 {

inline constexpr bool kStage1ExtractionChildGateCandidateOnly = true;
inline constexpr bool kStage1ExtractionChildGateAuthority = false;

// Provisional private ABI for the ready-barrier candidate. It is not a public
// wire schema and has no profile authority until separately frozen.
struct Stage1ExtractionChildGateInputV1 final {
    const void* clone_args = nullptr;
    std::uint64_t clone_args_size = 0;
    std::int32_t control_read_fd = -1;
    std::int32_t control_write_fd = -1;
    std::int32_t ready_read_fd = -1;
    std::int32_t ready_write_fd = -1;
    std::int32_t stdout_read_fd = -1;
    std::int32_t stderr_read_fd = -1;
    std::int32_t parent_receipt_saved_fd = -1;
    std::int32_t parent_diagnostic_saved_fd = -1;
    std::int32_t extraction_directory_fd = -1;
    std::int32_t environment_executable_fd = -1;
    std::uint8_t* one_byte_buffer = nullptr;
    void* statx_buffer = nullptr;
    const char* empty_path = nullptr;
    const sock_fprog* seccomp_program = nullptr;
    const char* const* extraction_argv = nullptr;
    const char* const* extraction_envp = nullptr;
    std::uint64_t expected_mount_id = 0;
    std::uint64_t expected_inode = 0;
    std::uint32_t expected_device_major = 0;
    std::uint32_t expected_device_minor = 0;
};

struct Stage1ExtractionChildGateResultV1 final {
    std::int64_t clone_return = -1;
    std::int32_t child_pid = -1;
    std::int32_t pidfd = -1;
    std::uint32_t parent_outcome = 0;
    std::uint32_t reserved = 0;
};

static_assert(std::is_standard_layout_v<Stage1ExtractionChildGateInputV1>);
static_assert(std::is_trivially_copyable_v<Stage1ExtractionChildGateInputV1>);
static_assert(sizeof(Stage1ExtractionChildGateInputV1) == 128u);
static_assert(alignof(Stage1ExtractionChildGateInputV1) == 8u);
static_assert(offsetof(Stage1ExtractionChildGateInputV1, clone_args) == 0u);
static_assert(offsetof(Stage1ExtractionChildGateInputV1, clone_args_size) == 8u);
static_assert(offsetof(Stage1ExtractionChildGateInputV1, control_read_fd) == 16u);
static_assert(offsetof(Stage1ExtractionChildGateInputV1, control_write_fd) == 20u);
static_assert(offsetof(Stage1ExtractionChildGateInputV1, ready_read_fd) == 24u);
static_assert(offsetof(Stage1ExtractionChildGateInputV1, ready_write_fd) == 28u);
static_assert(offsetof(Stage1ExtractionChildGateInputV1, stdout_read_fd) == 32u);
static_assert(offsetof(Stage1ExtractionChildGateInputV1, stderr_read_fd) == 36u);
static_assert(offsetof(Stage1ExtractionChildGateInputV1, parent_receipt_saved_fd) == 40u);
static_assert(offsetof(Stage1ExtractionChildGateInputV1, parent_diagnostic_saved_fd) == 44u);
static_assert(offsetof(Stage1ExtractionChildGateInputV1, extraction_directory_fd) == 48u);
static_assert(offsetof(Stage1ExtractionChildGateInputV1, environment_executable_fd) == 52u);
static_assert(offsetof(Stage1ExtractionChildGateInputV1, one_byte_buffer) == 56u);
static_assert(offsetof(Stage1ExtractionChildGateInputV1, statx_buffer) == 64u);
static_assert(offsetof(Stage1ExtractionChildGateInputV1, empty_path) == 72u);
static_assert(offsetof(Stage1ExtractionChildGateInputV1, seccomp_program) == 80u);
static_assert(offsetof(Stage1ExtractionChildGateInputV1, extraction_argv) == 88u);
static_assert(offsetof(Stage1ExtractionChildGateInputV1, extraction_envp) == 96u);
static_assert(offsetof(Stage1ExtractionChildGateInputV1, expected_mount_id) == 104u);
static_assert(offsetof(Stage1ExtractionChildGateInputV1, expected_inode) == 112u);
static_assert(offsetof(Stage1ExtractionChildGateInputV1, expected_device_major) == 120u);
static_assert(offsetof(Stage1ExtractionChildGateInputV1, expected_device_minor) == 124u);

static_assert(std::is_standard_layout_v<Stage1ExtractionChildGateResultV1>);
static_assert(std::is_trivially_copyable_v<Stage1ExtractionChildGateResultV1>);
static_assert(sizeof(Stage1ExtractionChildGateResultV1) == 24u);
static_assert(alignof(Stage1ExtractionChildGateResultV1) == 8u);
static_assert(offsetof(Stage1ExtractionChildGateResultV1, clone_return) == 0u);
static_assert(offsetof(Stage1ExtractionChildGateResultV1, child_pid) == 8u);
static_assert(offsetof(Stage1ExtractionChildGateResultV1, pidfd) == 12u);
static_assert(offsetof(Stage1ExtractionChildGateResultV1, parent_outcome) == 16u);

}  // namespace pokemon::evaluation_v631302

extern "C" long stage1_extraction_child_gate_v1(
    const pokemon::evaluation_v631302::Stage1ExtractionChildGateInputV1* input,
    pokemon::evaluation_v631302::Stage1ExtractionChildGateResultV1* result) noexcept;
