#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

namespace pokemon::evaluation_v631302 {

inline constexpr bool kStage1CustodianZeroAuthority = true;
inline constexpr bool kStage1CustodianUploadAuthority = false;
inline constexpr bool kStage1CustodianReceiptAvailable = false;
inline constexpr bool kStage1CustodianChildLaunchAvailable = true;
inline constexpr bool kStage1CustodianReadyBarrierCandidateAvailable = true;
inline constexpr bool kStage1CustodianStopAfterReady = true;
inline constexpr bool kStage1CustodianAuthoritativeExtractionAvailable = false;
inline constexpr bool kStage1CustodyReceiptV1Accepted = false;
inline constexpr std::uint32_t kStage1CustodyReceiptRequiredWireVersion = 2u;

struct Stage1MountExpectationV1 final {
    std::uint64_t root_mount_id = 0;
    std::uint64_t root_parent_mount_id = 0;
    std::uint64_t root_device_major = 0;
    std::uint64_t root_device_minor = 0;
    std::uint64_t proc_mount_id = 0;
    std::uint64_t proc_device_major = 0;
    std::uint64_t proc_device_minor = 0;
};

struct Stage1MountInfoV1 final {
    std::uint64_t root_mount_id = 0;
    std::uint64_t root_parent_mount_id = 0;
    std::uint64_t proc_mount_id = 0;
};

struct Stage1CwdIdentityV1 final {
    std::uint64_t mount_id = 0;
    std::uint64_t device_major = 0;
    std::uint64_t device_minor = 0;
    std::uint64_t inode = 0;

    [[nodiscard]] bool operator==(const Stage1CwdIdentityV1&) const noexcept = default;
};

struct Stage1TaskCensusRowV1 final {
    std::uint64_t tid = 0;
    Stage1CwdIdentityV1 cwd;

    [[nodiscard]] bool operator==(const Stage1TaskCensusRowV1&) const noexcept = default;
};

struct Stage1ProcessCensusRowV1 final {
    std::uint64_t pid = 0;
    std::uint64_t starttime = 0;
    std::vector<Stage1TaskCensusRowV1> tasks;

    [[nodiscard]] bool operator==(const Stage1ProcessCensusRowV1&) const noexcept = default;
};

using Stage1ProcessCensusV1 = std::vector<Stage1ProcessCensusRowV1>;

// Strict, allocation-bounded parser for the two mountinfo records required by
// the Stage-1 PID-1 custody ruling. This is a local semantic primitive only.
[[nodiscard]] bool validate_stage1_mountinfo_v1(
    std::string_view bytes,
    const Stage1MountExpectationV1& expected,
    Stage1MountInfoV1* observed,
    const char** error_code) noexcept;

// Strict parser for field 22 (starttime) of one /proc/<pid>/stat record.  The
// parser is exposed only so the native wire primitive can be mutation-tested
// without manufacturing procfs state.
[[nodiscard]] bool parse_stage1_proc_stat_starttime_v1(
    std::string_view bytes,
    std::uint64_t expected_pid,
    std::uint64_t* starttime,
    const char** error_code) noexcept;

// Pure paired-census predicate used by both the native controller and focused
// mutation harnesses. It validates the exact pre-launch {PID 1/TID 1} shape,
// full cwd keys, positive starttime, and pair equality.
[[nodiscard]] bool validate_stage1_prelaunch_census_pair_v1(
    const Stage1ProcessCensusV1& first,
    const Stage1ProcessCensusV1& second,
    const Stage1CwdIdentityV1& root_cwd,
    const Stage1CwdIdentityV1& extraction_cwd,
    const char** error_code) noexcept;

// Strict security-state parser for PID 2 after it emits the ready byte.  This
// is a pure mutation-test seam and does not observe procfs by itself.
[[nodiscard]] bool validate_stage1_ready_status_v1(
    std::string_view bytes,
    std::uint64_t expected_final_nspid,
    const char** error_code) noexcept;

// Pure predicates for the exact ready-barrier and post-exit census pairs.
// Both require byte-semantic equality across two independently captured
// procfs censuses and bind the already observed PID starttimes.
[[nodiscard]] bool validate_stage1_barrier_census_pair_v1(
    const Stage1ProcessCensusV1& first,
    const Stage1ProcessCensusV1& second,
    const Stage1CwdIdentityV1& root_cwd,
    const Stage1CwdIdentityV1& extraction_cwd,
    std::uint64_t expected_pid1_starttime,
    std::uint64_t expected_pid2_starttime,
    const char** error_code) noexcept;

[[nodiscard]] bool validate_stage1_postexit_census_pair_v1(
    const Stage1ProcessCensusV1& first,
    const Stage1ProcessCensusV1& second,
    const Stage1CwdIdentityV1& root_cwd,
    const Stage1CwdIdentityV1& extraction_cwd,
    std::uint64_t expected_pid1_starttime,
    const char** error_code) noexcept;

// The candidate entry point closes only the native preflight and the frozen
// stop-after-ready boundary. It deliberately withholds byte 0x43, kills and
// reaps PID 2 by pidfd, emits no stdout, and cannot create a custody receipt.
[[nodiscard]] int run_stage1_extraction_custodian_v1(
    int argc,
    char** argv,
    char** envp) noexcept;

}  // namespace pokemon::evaluation_v631302
