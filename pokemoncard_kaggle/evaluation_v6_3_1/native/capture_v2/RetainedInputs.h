#ifndef EVALUATION_V6_3_1_CAPTURE_V2_RETAINED_INPUTS_H
#define EVALUATION_V6_3_1_CAPTURE_V2_RETAINED_INPUTS_H

#include "OwnedFd.h"
#include "SupervisorTypes.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {

struct RetainedInputSpec final {
    int original_root_fd = -1;
    std::string original_relative_path;
    std::string namespace_relative_path;
    std::vector<std::uint32_t> role_codes;
    std::uint32_t normalized_mode = 0;
};

struct FileIdentity final {
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    std::uint64_t byte_length = 0;
    std::uint64_t link_count = 0;
    std::uint32_t mode = 0;
    std::uint32_t uid = 0;
    std::uint32_t gid = 0;
    std::int64_t modification_seconds = 0;
    std::int64_t modification_nanoseconds = 0;
    std::int64_t change_seconds = 0;
    std::int64_t change_nanoseconds = 0;

    friend bool operator==(const FileIdentity&, const FileIdentity&) = default;
};

struct MaterializedInput final {
    std::string namespace_relative_path;
    std::vector<std::uint32_t> role_codes;
    std::uint32_t normalized_mode = 0;
    std::uint64_t byte_length = 0;
    Sha256Digest sha256{};
    FileIdentity original_identity;
};

class RetainedInput final {
public:
    RetainedInput(RetainedInput&&) noexcept = default;
    RetainedInput& operator=(RetainedInput&&) noexcept = default;
    RetainedInput(const RetainedInput&) = delete;
    RetainedInput& operator=(const RetainedInput&) = delete;

    [[nodiscard]] const RetainedInputSpec& spec() const noexcept { return spec_; }
    [[nodiscard]] const FileIdentity& acquired_identity() const noexcept { return acquired_identity_; }
    [[nodiscard]] int descriptor() const noexcept { return descriptor_.get(); }

    MaterializedInput materialize_to(int destination_fd);

private:
    friend class RetainedInputSet;

    RetainedInput(RetainedInputSpec spec, OwnedFd descriptor, FileIdentity identity)
        : spec_(std::move(spec)), descriptor_(std::move(descriptor)), acquired_identity_(identity) {}

    RetainedInputSpec spec_;
    OwnedFd descriptor_;
    FileIdentity acquired_identity_;
    bool materialized_ = false;
};

class RetainedInputSet final {
public:
    static RetainedInputSet acquire(std::vector<RetainedInputSpec> specs);

    RetainedInputSet(RetainedInputSet&&) noexcept = default;
    RetainedInputSet& operator=(RetainedInputSet&&) noexcept = default;
    RetainedInputSet(const RetainedInputSet&) = delete;
    RetainedInputSet& operator=(const RetainedInputSet&) = delete;

    [[nodiscard]] std::vector<RetainedInput>& inputs() noexcept { return inputs_; }
    [[nodiscard]] const std::vector<RetainedInput>& inputs() const noexcept { return inputs_; }

private:
    explicit RetainedInputSet(std::vector<RetainedInput> inputs) : inputs_(std::move(inputs)) {}

    std::vector<RetainedInput> inputs_;
};

bool is_normalized_relative_path(const std::string& path) noexcept;

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_RETAINED_INPUTS_H
