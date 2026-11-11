#ifndef EVALUATION_V6_3_1_CAPTURE_V2_COLLECTOR_RECEIPT_H
#define EVALUATION_V6_3_1_CAPTURE_V2_COLLECTOR_RECEIPT_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {

struct CaptureContextV1 final {
    std::string primary_source_relative_path;
    std::vector<std::uint8_t> path_profile_cbor;
};

CaptureContextV1 decode_capture_context_v1_hex(std::string_view lowercase_hex);

class CollectorReceipt final {
public:
    explicit CollectorReceipt(std::string_view lowercase_context_hex);
    ~CollectorReceipt() noexcept;

    CollectorReceipt(const CollectorReceipt&) = delete;
    CollectorReceipt& operator=(const CollectorReceipt&) = delete;
    CollectorReceipt(CollectorReceipt&&) = delete;
    CollectorReceipt& operator=(CollectorReceipt&&) = delete;

    void start();
    void driver_argv_frozen(const std::vector<std::string>& driver_argv);
    void driver_execution_begin();
    void cc1_argv_frozen(const std::vector<std::string>& cc1_argv);
    void cc1_execution_begin();
    void cc1_execution_end();
    void finalize();
    void abort() noexcept;

private:
    using Byte = std::uint8_t;

    void require_sequence(std::uint64_t expected);
    void emit_binding();
    void emit_phase(std::uint64_t phase);
    void emit_argv(std::uint64_t event_code, const std::vector<std::string>& argv);
    void emit_final_receipt();
    void emit_frame(std::vector<Byte> payload, bool phase_frame);
    [[noreturn]] void fail();
    void close_receipt_fd();

    CaptureContextV1 context_;
    std::vector<std::string> driver_argv_;
    std::vector<std::string> cc1_argv_;
    std::uint64_t pipe_st_dev_ = 0;
    std::uint64_t pipe_st_ino_ = 0;
    std::uint64_t next_sequence_ = 0;
    std::size_t stream_bytes_ = 0;
    long pipe_buf_ = 0;
    bool fd_open_ = false;
    bool started_ = false;
    bool failed_ = false;
    bool finalized_ = false;
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_COLLECTOR_RECEIPT_H
