#ifndef EVALUATION_V6_3_1_CAPTURE_V2_PIPE_PUMP_H
#define EVALUATION_V6_3_1_CAPTURE_V2_PIPE_PUMP_H

#include "OwnedFd.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {

// This component owns only caller-supplied nonblocking pipe read ends.  It
// does not wait, launch, inspect, or authorize anything.
enum class PipePumpFailure : std::uint32_t {
    EmptyChannelSet = 1,
    InvalidChannelId = 2,
    DuplicateChannelId = 3,
    DuplicateDescriptor = 4,
    InvalidDescriptor = 5,
    NonBlockingRequired = 6,
    CapOverflow = 7,
    ReadFailure = 8,
    ResourceFailure = 9,
    TerminalFailure = 10,
    PrematureSuccess = 11,
    AlreadyComplete = 12,
    UnknownChannel = 13,
    IncompleteChannelSet = 14,
};

class PipePumpError final : public std::runtime_error {
public:
    PipePumpError(PipePumpFailure failure, std::string message, int system_errno = 0)
        : std::runtime_error(std::move(message)), failure_(failure), system_errno_(system_errno) {}

    [[nodiscard]] PipePumpFailure failure() const noexcept { return failure_; }
    [[nodiscard]] int system_errno() const noexcept { return system_errno_; }

private:
    PipePumpFailure failure_;
    int system_errno_;
};

class PipePump final {
public:
    using Byte = std::uint8_t;

    enum class ChannelId : std::uint8_t {
        Stdout = 0,
        Stderr = 1,
        Receipt = 2,
    };

    struct ChannelSpec final {
        ChannelId id;
        int read_fd;
        std::size_t byte_cap;
    };

    struct ChannelSnapshot final {
        ChannelId id;
        std::size_t byte_cap;
        std::uint64_t total_bytes_seen;
        std::vector<Byte> bytes;
        std::vector<Byte> overflow_probe;
        bool eof;

        friend bool operator==(const ChannelSnapshot&, const ChannelSnapshot&) = default;
    };

    struct Snapshot final {
        std::vector<ChannelSnapshot> channels;
        bool terminal_failure;
        bool complete;

        friend bool operator==(const Snapshot&, const Snapshot&) = default;
    };

    // Construction validates all descriptors before taking ownership.  On a
    // successful construction, each read_fd is owned and closed exactly once.
    explicit PipePump(std::vector<ChannelSpec> channels);
    ~PipePump() noexcept = default;

    PipePump(const PipePump&) = delete;
    PipePump& operator=(const PipePump&) = delete;
    PipePump(PipePump&&) = delete;
    PipePump& operator=(PipePump&&) = delete;

    // The caller supplies readiness.  This method performs no polling and
    // drains one channel until EAGAIN, EOF, or a terminal failure.
    void drain_ready(ChannelId id);
    void drain_until_eagain(ChannelId id) { drain_ready(id); }

    // Success is accepted only after every registered channel returned EOF.
    // A premature call is terminal and cannot later be repaired.
    void finish_success();

    [[nodiscard]] bool failed() const noexcept { return terminal_failure_; }
    [[nodiscard]] bool complete() const noexcept { return complete_; }
    [[nodiscard]] bool all_eof() const noexcept;

    [[nodiscard]] Snapshot snapshot() const;
    [[nodiscard]] ChannelSnapshot channel_snapshot(ChannelId id) const;
    [[nodiscard]] std::span<const Byte> channel_bytes(ChannelId id) const;
    [[nodiscard]] int read_descriptor(ChannelId id) const;

private:
    struct ChannelState final {
        ChannelId id;
        OwnedFd reader;
        std::size_t byte_cap;
        std::uint64_t total_bytes_seen = 0u;
        std::vector<Byte> bytes;
        std::vector<Byte> overflow_probe;
        bool eof = false;
    };

    using ChannelTable = std::map<ChannelId, ChannelState>;

    static bool valid_channel_id(ChannelId id) noexcept;
    static void validate_descriptor(int descriptor);
    static void throw_unknown_channel(ChannelId id);

    ChannelState& require_channel(ChannelId id);
    const ChannelState& require_channel(ChannelId id) const;
    void require_operable() const;
    [[noreturn]] void fail(PipePumpFailure failure, const char* message, int system_errno = 0);

    ChannelTable channels_;
    bool terminal_failure_ = false;
    bool complete_ = false;
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_PIPE_PUMP_H
