#ifndef EVALUATION_V6_3_1_CAPTURE_V2_RECEIPT_STREAM_PARSER_H
#define EVALUATION_V6_3_1_CAPTURE_V2_RECEIPT_STREAM_PARSER_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {

// This parser is a zero-authority component.  It validates only FD3 bytes and
// externally supplied write observations; it performs no process, namespace,
// descriptor, permit, or campaign operation.
class ReceiptStreamError final : public std::runtime_error {
public:
    explicit ReceiptStreamError(const char* message) : std::runtime_error(message) {}
};

struct ReceiptContextExpectation final {
    std::string primary_source_relative_path;
    std::vector<std::uint8_t> path_profile_cbor;
};

struct PhaseTransition final {
    std::uint64_t ordinal;
    std::uint64_t code;
    std::uint64_t event_sequence;
};

struct ReceiptFinalValues final {
    std::uint64_t receipt_fd_device;
    std::uint64_t receipt_fd_inode;
    std::string primary_source_relative_path;
    std::vector<std::uint8_t> path_profile_cbor;
    std::vector<std::string> driver_argv;
    std::vector<std::string> cc1_argv;
    std::array<PhaseTransition, 7> phase_transitions;
};

enum class Amendment8OpenPhase : std::uint64_t {
    PreDriver = 0u,
    Driver = 1u,
    Cc1 = 2u,
    PostCc1 = 3u,
};

// The transition whose write return made this phase effective.  A caller may
// associate later actual-open observations with this value only after it is
// returned by current_open_phase_mapping().
struct OpenPhaseMapping final {
    Amendment8OpenPhase phase;
    std::uint64_t receipt_phase_ordinal;
    std::uint64_t effective_event_sequence;
};

class ReceiptStreamParser final {
public:
    using Byte = std::uint8_t;

    static constexpr std::size_t kReceiptStreamMaxBytes = 16'777'216u;
    static constexpr int kReceiptDescriptor = 3;

    explicit ReceiptStreamParser(ReceiptContextExpectation expectation);

    ReceiptStreamParser(const ReceiptStreamParser&) = delete;
    ReceiptStreamParser& operator=(const ReceiptStreamParser&) = delete;
    ReceiptStreamParser(ReceiptStreamParser&&) = delete;
    ReceiptStreamParser& operator=(ReceiptStreamParser&&) = delete;

    // Feed exactly the bytes drained from FD3.  Calls may split frames at any
    // byte boundary, but the complete stream must later reach EOF.
    void append_drained_fd3_bytes(std::span<const Byte> bytes);

    // Record one observed write-like syscall to FD3.  Only the first
    // returned_count bytes entered the pipe.  phase frames must later match a
    // single successful non-writev observation no larger than supplied_pipe_buf.
    void observe_fd3_write(std::span<const Byte> requested_bytes,
                           std::int64_t returned_count,
                           std::size_t supplied_pipe_buf,
                           bool writev_labelled = false);

    // EOF is an explicit terminal observation.  It is valid only immediately
    // after the eleventh and final frame, with complete matching write evidence.
    void finish_fd3_eof();

    [[nodiscard]] bool failed() const noexcept { return failed_; }
    [[nodiscard]] bool complete() const noexcept { return complete_ && !failed_; }
    [[nodiscard]] bool final_frame_parsed() const noexcept {
        return final_event_parsed_ && events_parsed_ == 11u && !failed_;
    }
    [[nodiscard]] std::optional<OpenPhaseMapping> current_open_phase_mapping() const;

    // These accessors fail closed until all receipt, write, and EOF checks are
    // complete.  The returned stream bytes are the immutable drained FD3 stream.
    [[nodiscard]] const std::vector<Byte>& exact_stream_bytes() const;
    [[nodiscard]] const ReceiptFinalValues& final_values() const;

private:
    struct WriteSegment final {
        std::size_t start;
        std::size_t end;
        std::size_t requested_count;
        std::size_t returned_count;
        std::size_t pipe_buf;
        bool writev_labelled;
    };

    struct PhaseFrame final {
        std::size_t start;
        std::size_t end;
        std::uint64_t ordinal;
        std::uint64_t sequence;
        bool effective;
    };

    [[noreturn]] void fail(const char* message);
    void parse_available_frames();
    void parse_one_frame(std::span<const Byte> payload, std::size_t frame_start,
                         std::size_t frame_end);
    void verify_observed_prefix();
    void advance_phase_commitments();
    void require_unfailed_and_open();

    ReceiptContextExpectation expectation_;
    std::vector<Byte> drained_stream_;
    std::vector<Byte> observed_write_bytes_;
    std::vector<WriteSegment> write_segments_;
    std::vector<PhaseFrame> phase_frames_;
    std::optional<ReceiptFinalValues> final_values_;
    std::optional<OpenPhaseMapping> open_phase_mapping_;
    std::size_t parse_offset_ = 0u;
    std::size_t events_parsed_ = 0u;
    bool final_event_parsed_ = false;
    bool eof_seen_ = false;
    bool complete_ = false;
    bool failed_ = false;
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_RECEIPT_STREAM_PARSER_H
