#ifndef EVALUATION_V6_3_1_CAPTURE_V2_TRACEE_MEMORY_H
#define EVALUATION_V6_3_1_CAPTURE_V2_TRACEE_MEMORY_H

#if !defined(__linux__)
#error "TraceeMemory is a Linux-only Capture V2 component"
#endif

#include "SupervisorTypes.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <sys/types.h>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {

// Reads memory from one already-stopped direct child.  This is a bounded,
// zero-authority primitive: it neither stops nor authenticates the process.
class TraceeMemory final {
public:
    enum class State : std::uint8_t {
        Ready = 1,
        Failed = 2,
    };

    explicit TraceeMemory(pid_t stopped_pid);

    TraceeMemory(const TraceeMemory&) = delete;
    TraceeMemory& operator=(const TraceeMemory&) = delete;
    TraceeMemory(TraceeMemory&&) = delete;
    TraceeMemory& operator=(TraceeMemory&&) = delete;

    // exact_length and positive_maximum are both explicit positive byte
    // counts.  A successful read is exactly exact_length bytes; no retry or
    // partial result is returned.
    [[nodiscard]] std::vector<std::uint8_t> exact_bytes(
        std::uintptr_t remote_address,
        std::size_t exact_length,
        std::size_t positive_maximum);

    // The bound includes the terminating NUL.  Reading one byte per syscall
    // makes the first NUL the only possible terminator and avoids ambiguous
    // over-read beyond the string.
    [[nodiscard]] std::string nul_terminated_string(
        std::uintptr_t remote_address,
        std::size_t positive_maximum);

    [[nodiscard]] pid_t stopped_pid() const noexcept { return stopped_pid_; }
    [[nodiscard]] State state() const noexcept { return state_; }

private:
    void require_ready() const;
    void fail_terminal() noexcept { state_ = State::Failed; }

    pid_t stopped_pid_ = -1;
    State state_ = State::Ready;
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_TRACEE_MEMORY_H
