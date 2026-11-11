#ifndef EVALUATION_V6_3_1_CAPTURE_V2_PROC_INSPECTOR_H
#define EVALUATION_V6_3_1_CAPTURE_V2_PROC_INSPECTOR_H

#include "SupervisorTypes.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <sys/types.h>

namespace evaluation_v6_3_1::capture_v2 {

struct ProcInspectorLimits final {
    std::size_t maximum_cmdline_bytes = 64u * 1024u;
    std::size_t maximum_environ_bytes = 64u * 1024u;
    std::size_t maximum_status_bytes = 64u * 1024u;
    std::size_t maximum_cwd_link_bytes = 64u * 1024u;
    std::uint64_t maximum_executable_bytes = 1024u * 1024u * 1024u;
};

struct StoppedProcessRequirement final {
    pid_t pid = -1;
    std::vector<std::string> expected_argv;
    bool require_empty_environment = false;
    std::uint64_t expected_executable_byte_length = 0;
    Sha256Digest expected_executable_sha256{};
    std::uint64_t expected_cwd_device = 0;
    std::uint64_t expected_cwd_inode = 0;
    ProcInspectorLimits limits{};
    bool require_zero_capability_sets = false;
    bool require_no_new_privileges = false;
    std::optional<std::uint32_t> expected_user_id{};
    std::optional<std::uint32_t> expected_group_id{};
    bool require_empty_supplementary_groups = false;
};

class StoppedProcessObservation final {
public:
    StoppedProcessObservation(StoppedProcessObservation&&) noexcept = default;
    StoppedProcessObservation& operator=(StoppedProcessObservation&&) noexcept = default;
    StoppedProcessObservation(const StoppedProcessObservation&) = delete;
    StoppedProcessObservation& operator=(const StoppedProcessObservation&) = delete;

    [[nodiscard]] pid_t pid() const noexcept { return pid_; }
    [[nodiscard]] const std::vector<std::string>& argv() const noexcept { return argv_; }
    [[nodiscard]] std::uint64_t executable_byte_length() const noexcept {
        return executable_byte_length_;
    }
    [[nodiscard]] const Sha256Digest& executable_sha256() const noexcept {
        return executable_sha256_;
    }
    [[nodiscard]] std::uint64_t cwd_device() const noexcept { return cwd_device_; }
    [[nodiscard]] std::uint64_t cwd_inode() const noexcept { return cwd_inode_; }
    [[nodiscard]] const std::string& cwd_proc_link() const noexcept { return cwd_proc_link_; }
    [[nodiscard]] bool zero_capability_sets() const noexcept {
        return zero_capability_sets_;
    }
    [[nodiscard]] bool no_new_privileges() const noexcept { return no_new_privileges_; }
    [[nodiscard]] std::uint32_t user_id() const noexcept { return user_id_; }
    [[nodiscard]] std::uint32_t group_id() const noexcept { return group_id_; }
    [[nodiscard]] bool empty_supplementary_groups() const noexcept {
        return empty_supplementary_groups_;
    }

private:
    friend class ProcInspector;

    StoppedProcessObservation(
        pid_t pid,
        std::vector<std::string> argv,
        std::uint64_t executable_byte_length,
        Sha256Digest executable_sha256,
        std::uint64_t cwd_device,
        std::uint64_t cwd_inode,
        std::string cwd_proc_link,
        bool zero_capability_sets,
        bool no_new_privileges,
        std::uint32_t user_id,
        std::uint32_t group_id,
        bool empty_supplementary_groups)
        : pid_(pid),
          argv_(std::move(argv)),
          executable_byte_length_(executable_byte_length),
          executable_sha256_(executable_sha256),
          cwd_device_(cwd_device),
          cwd_inode_(cwd_inode),
          cwd_proc_link_(std::move(cwd_proc_link)),
          zero_capability_sets_(zero_capability_sets),
          no_new_privileges_(no_new_privileges),
          user_id_(user_id),
          group_id_(group_id),
          empty_supplementary_groups_(empty_supplementary_groups) {}

    pid_t pid_ = -1;
    std::vector<std::string> argv_;
    std::uint64_t executable_byte_length_ = 0;
    Sha256Digest executable_sha256_{};
    std::uint64_t cwd_device_ = 0;
    std::uint64_t cwd_inode_ = 0;
    std::string cwd_proc_link_;
    bool zero_capability_sets_ = false;
    bool no_new_privileges_ = false;
    std::uint32_t user_id_ = 0;
    std::uint32_t group_id_ = 0;
    bool empty_supplementary_groups_ = false;
};

class ProcInspector final {
public:
    enum class State : std::uint8_t {
        Ready = 1,
        Authenticated = 2,
        Failed = 3,
    };

    explicit ProcInspector(StoppedProcessRequirement requirement);

    ProcInspector(const ProcInspector&) = delete;
    ProcInspector& operator=(const ProcInspector&) = delete;
    ProcInspector(ProcInspector&&) = delete;
    ProcInspector& operator=(ProcInspector&&) = delete;

    const StoppedProcessObservation& authenticate();
    [[nodiscard]] const StoppedProcessObservation& observation() const;
    [[nodiscard]] State state() const noexcept { return state_; }

private:
    StoppedProcessRequirement requirement_;
    State state_ = State::Ready;
    std::optional<StoppedProcessObservation> observation_;
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_PROC_INSPECTOR_H
