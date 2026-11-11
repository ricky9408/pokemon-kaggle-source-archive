#ifndef EVALUATION_V6_3_1_CAPTURE_V2_MOUNT_SANDBOX_H
#define EVALUATION_V6_3_1_CAPTURE_V2_MOUNT_SANDBOX_H

#include "OwnedFd.h"
#include "RetainedInputs.h"

#include <cstdint>
#include <string>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {

struct MountSandboxConfig final {
    std::string staging_root_absolute_path;
    std::string working_directory_relative_path;
    std::uint64_t tmpfs_byte_limit = 0;
};

struct MountSandboxResult final {
    std::vector<MaterializedInput> file_rows;
    std::uint64_t root_device = 0;
    std::uint64_t root_inode = 0;
    std::uint64_t working_directory_device = 0;
    std::uint64_t working_directory_inode = 0;
    OwnedFd child_fchdir_fd;
};

// Linux-only, zero-authority namespace materialization.  A successful call
// leaves the calling process chrooted at "/" inside a private, read-only tmpfs
// and returns a separately owned FD for the bound working directory.  It
// performs no process launch, ptrace, capture assembly, campaign, permit,
// holdout, or upload operation.
class MountSandbox final {
public:
    static MountSandboxResult build_seal_and_enter(
        RetainedInputSet retained_inputs,
        const MountSandboxConfig& config);
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_MOUNT_SANDBOX_H
