#ifndef EVALUATION_V6_3_1_CAPTURE_V2_OPEN_PATH_RESOLVER_H
#define EVALUATION_V6_3_1_CAPTURE_V2_OPEN_PATH_RESOLVER_H

#include <cstddef>
#include <cstdint>
#include <string>

#include <limits.h>

namespace evaluation_v6_3_1::capture_v2 {

// Host-pure path interpretation only. This class does not inspect the
// filesystem, process state, namespace state, or syscall arguments beyond
// the explicitly supplied family and dirfd.
class OpenPathResolver final {
public:
    enum class SyscallFamily : std::uint8_t {
        Open,
        OpenAt,
        OpenAt2,
    };

#ifdef PATH_MAX
    static constexpr std::size_t kPathMaxBytes = static_cast<std::size_t>(PATH_MAX);
#else
    static constexpr std::size_t kPathMaxBytes = 4096u;
#endif
    static constexpr std::int64_t kAtFdcwd = -100;

    [[nodiscard]] static std::string resolve(
        const std::string& raw_syscall_path,
        SyscallFamily family,
        std::int64_t dirfd,
        const std::string& frozen_cwd_relative_path);
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_OPEN_PATH_RESOLVER_H
