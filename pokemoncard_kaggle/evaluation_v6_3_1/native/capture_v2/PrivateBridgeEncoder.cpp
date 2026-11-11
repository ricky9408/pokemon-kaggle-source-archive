#include "PrivateBridgeEncoder.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::capture_v2::private_bridge_v3 {
namespace {

#if defined(EVALUATION_V631302_PRIVATE_BRIDGE_V3_TEST_ONLY)
thread_local EncodeTestFault g_encode_test_fault = EncodeTestFault::kNone;

EncodeTestFault take_encode_test_fault() noexcept {
    return std::exchange(g_encode_test_fault, EncodeTestFault::kNone);
}
#endif

EncodeResult failure(EncodeFailureCode code) noexcept {
    return EncodeResult::failure(EncodeFailure{code});
}

bool valid_profile_label(std::string_view label) noexcept {
    if (label.empty() ||
        label.size() > kValidatedCollectorProfileBuildLabelMaximumBytes) {
        return false;
    }
    return std::all_of(label.begin(), label.end(), [](unsigned char byte) {
        return byte >= 0x20u && byte <= 0x7eu;
    });
}

class CountingSink final {
public:
    void put(std::uint8_t) noexcept { add(1u); }

    void put(std::span<const std::uint8_t> bytes) noexcept {
        add(bytes.size());
    }

    void fail_internal() noexcept { internal_failure_ = true; }

    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] bool overflowed() const noexcept { return overflowed_; }
    [[nodiscard]] bool internal_failure() const noexcept {
        return internal_failure_;
    }

private:
    void add(std::size_t amount) noexcept {
        if (overflowed_ || amount > std::numeric_limits<std::size_t>::max() - size_) {
            overflowed_ = true;
            return;
        }
        size_ += amount;
    }

    std::size_t size_ = 0u;
    bool overflowed_ = false;
    bool internal_failure_ = false;
};

class FixedSink final {
public:
    explicit FixedSink(std::span<std::uint8_t> output) noexcept
        : output_(output) {}

    void put(std::uint8_t value) noexcept {
        if (failed_ || cursor_ >= output_.size()) {
            failed_ = true;
            return;
        }
        output_[cursor_++] = value;
    }

    void put(std::span<const std::uint8_t> bytes) noexcept {
        if (failed_ || cursor_ > output_.size() ||
            bytes.size() > output_.size() - cursor_) {
            failed_ = true;
            return;
        }
        std::copy(bytes.begin(), bytes.end(), output_.begin() +
            static_cast<std::ptrdiff_t>(cursor_));
        cursor_ += bytes.size();
    }

    void fail_internal() noexcept { failed_ = true; }

    [[nodiscard]] std::size_t size() const noexcept { return cursor_; }
    [[nodiscard]] bool failed() const noexcept { return failed_; }

private:
    std::span<std::uint8_t> output_;
    std::size_t cursor_ = 0u;
    bool failed_ = false;
};

template <typename Sink>
void encode_head(Sink& sink, std::uint8_t major, std::uint64_t value) noexcept {
    const std::uint8_t prefix = static_cast<std::uint8_t>(major << 5u);
    if (value <= 23u) {
        sink.put(static_cast<std::uint8_t>(prefix | static_cast<std::uint8_t>(value)));
        return;
    }
    if (value <= 0xffu) {
        sink.put(static_cast<std::uint8_t>(prefix | 24u));
        sink.put(static_cast<std::uint8_t>(value));
        return;
    }
    if (value <= 0xffffu) {
        sink.put(static_cast<std::uint8_t>(prefix | 25u));
        sink.put(static_cast<std::uint8_t>((value >> 8u) & 0xffu));
        sink.put(static_cast<std::uint8_t>(value & 0xffu));
        return;
    }
    if (value <= 0xffffffffu) {
        sink.put(static_cast<std::uint8_t>(prefix | 26u));
        sink.put(static_cast<std::uint8_t>((value >> 24u) & 0xffu));
        sink.put(static_cast<std::uint8_t>((value >> 16u) & 0xffu));
        sink.put(static_cast<std::uint8_t>((value >> 8u) & 0xffu));
        sink.put(static_cast<std::uint8_t>(value & 0xffu));
        return;
    }
    sink.put(static_cast<std::uint8_t>(prefix | 27u));
    sink.put(static_cast<std::uint8_t>((value >> 56u) & 0xffu));
    sink.put(static_cast<std::uint8_t>((value >> 48u) & 0xffu));
    sink.put(static_cast<std::uint8_t>((value >> 40u) & 0xffu));
    sink.put(static_cast<std::uint8_t>((value >> 32u) & 0xffu));
    sink.put(static_cast<std::uint8_t>((value >> 24u) & 0xffu));
    sink.put(static_cast<std::uint8_t>((value >> 16u) & 0xffu));
    sink.put(static_cast<std::uint8_t>((value >> 8u) & 0xffu));
    sink.put(static_cast<std::uint8_t>(value & 0xffu));
}

template <typename Sink>
void encode_uint(Sink& sink, std::uint64_t value) noexcept {
    encode_head(sink, 0u, value);
}

template <typename Sink>
void encode_array(Sink& sink, std::size_t size) noexcept {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (size > static_cast<std::size_t>(
                       std::numeric_limits<std::uint64_t>::max())) {
            sink.fail_internal();
            return;
        }
    }
    encode_head(sink, 4u, static_cast<std::uint64_t>(size));
}

template <typename Sink>
void encode_bytes(
    Sink& sink,
    std::span<const std::uint8_t> bytes) noexcept {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (bytes.size() > static_cast<std::size_t>(
                               std::numeric_limits<std::uint64_t>::max())) {
            sink.fail_internal();
            return;
        }
    }
    encode_head(sink, 2u, static_cast<std::uint64_t>(bytes.size()));
    sink.put(bytes);
}

template <typename Sink>
void encode_text(Sink& sink, std::string_view value) noexcept {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value.size() > static_cast<std::size_t>(
                               std::numeric_limits<std::uint64_t>::max())) {
            sink.fail_internal();
            return;
        }
    }
    encode_head(sink, 3u, static_cast<std::uint64_t>(value.size()));
    sink.put(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(value.data()), value.size()));
}

template <typename Sink>
void encode_raw_item(
    Sink& sink,
    std::span<const std::uint8_t> item) noexcept {
    if (item.empty()) {
        sink.fail_internal();
        return;
    }
    sink.put(item);
}

template <typename Sink>
void encode_digest(Sink& sink, const Sha256Digest& digest) noexcept {
    encode_bytes(
        sink,
        std::span<const std::uint8_t>(digest.data(), digest.size()));
}

template <typename Sink>
void encode_string_array(
    Sink& sink,
    const std::vector<std::string>& values) noexcept {
    encode_array(sink, values.size());
    for (const std::string& value : values) {
        encode_text(sink, value);
    }
}

template <typename Sink>
void encode_runtime_object(
    Sink& sink,
    const RuntimeObjectEvidence& row) noexcept {
    encode_array(sink, 5u);
    encode_text(sink, row.namespace_relative_path);
    encode_bytes(sink, row.elf_soname);
    encode_uint(sink, row.byte_length);
    encode_digest(sink, row.sha256);
    encode_bytes(sink, row.elf_build_id);
}

template <typename Sink>
void encode_component(Sink& sink, const ComponentFacts& component) noexcept {
    encode_array(sink, 3u);
    encode_uint(sink, component.byte_length());
    encode_digest(sink, component.sha256());
    encode_bytes(sink, component.build_id());
}

template <typename Sink>
void encode_bridge(
    Sink& sink,
    const ValidatedPrelaunchContext& context,
    const CompletedNativeCaptureObservations& observations,
    const HarnessObservation& harness,
    const RuntimeObjectEvidence& observed_collector,
    const Sha256Digest32& validated_prelaunch_expectations_root) noexcept {
    const CompletedNamespaceObservation& namespace_observation =
        observations.namespace_observation();
    const CompletedExecStopObservation& exec =
        observations.exec_stop_observation();
    const CompletedOpenTraceSlice& invocation = observations.open_receipt();
    const CompletedRuntimeObservation& runtime =
        observations.runtime_observation();
    const CompletedTerminationObservation& termination =
        observations.termination_observation();

    encode_array(sink, 10u);
    encode_uint(sink, kProtocol);
    encode_uint(sink, kPrivateBridgeVersion);

    encode_array(sink, 5u);
    encode_text(sink, context.collector_profile_build_label_text().value());
    encode_bytes(sink, observed_collector.elf_build_id);
    encode_bytes(sink, context.collector_profile_cbor_bytes());
    encode_uint(sink, context.argv_grammar_version());
    encode_digest(sink, context.argv_grammar_sha256());

    encode_array(sink, 5u);
    encode_text(sink, context.namespace_relative_cwd());
    encode_text(sink, context.primary_source());
    encode_bytes(sink, context.path_profile_cbor_bytes());
    encode_raw_item(sink, context.public_file_rows_cbor_bytes());
    encode_array(sink, namespace_observation.namespace_identity_rows.size());
    for (const NamespaceIdentityObservation& row :
         namespace_observation.namespace_identity_rows) {
        encode_array(sink, 7u);
        encode_text(sink, row.namespace_relative_path);
        encode_array(sink, 2u);
        encode_uint(sink, row.device_major);
        encode_uint(sink, row.device_minor);
        encode_uint(sink, row.inode);
        encode_uint(sink, row.file_type_code);
        encode_uint(sink, row.normalized_mode);
        encode_uint(sink, row.byte_length);
        encode_digest(sink, row.sha256);
    }

    encode_array(sink, 2u);
    encode_array(sink, 4u);
    encode_string_array(sink, exec.argv);
    encode_text(sink, context.namespace_relative_cwd());
    encode_uint(sink, exec.proc_exe_byte_length);
    encode_digest(sink, exec.proc_exe_sha256);
    encode_digest(sink, validated_prelaunch_expectations_root);

    encode_array(sink, 2u);
    encode_bytes(sink, invocation.exact_receipt_stream);
    encode_array(sink, invocation.actual_open_rows.size());
    for (const ActualOpenObservation& row : invocation.actual_open_rows) {
        encode_array(sink, 9u);
        encode_uint(sink, row.observation_sequence);
        encode_uint(sink, static_cast<std::uint64_t>(row.phase));
        encode_text(sink, row.namespace_relative_path);
        encode_uint(sink, row.open_flags);
        encode_uint(sink, row.device);
        encode_uint(sink, row.inode);
        encode_uint(sink, row.normalized_mode);
        encode_uint(sink, row.byte_length);
        encode_digest(sink, row.sha256);
    }

    encode_array(sink, 4u);
    encode_runtime_object(sink, runtime.primary_clang_cpp_record);
    encode_runtime_object(sink, runtime.elf_interpreter_record);
    encode_array(sink, runtime.runtime_object_rows.size());
    for (const RuntimeObjectEvidence& row : runtime.runtime_object_rows) {
        encode_runtime_object(sink, row);
    }
    encode_array(sink, runtime.runtime_observation_rows.size());
    for (const RuntimeObservationEvidence& row :
         runtime.runtime_observation_rows) {
        encode_array(sink, 8u);
        encode_uint(sink, row.observation_sequence);
        encode_uint(
            sink,
            static_cast<std::uint64_t>(row.observation_kind));
        encode_uint(sink, row.runtime_object_index);
        encode_uint(sink, row.device);
        encode_uint(sink, row.inode);
        encode_uint(sink, row.file_offset);
        encode_uint(sink, row.mapping_length);
        encode_uint(sink, row.protection_flags);
    }

    encode_array(sink, 1u);
    encode_bytes(sink, invocation.stdout_bytes);

    encode_array(sink, 3u);
    encode_component(sink, harness.capture_entry_component());
    encode_component(sink, harness.capture_interpreter_component());
    encode_component(sink, harness.native_supervisor_component());

    encode_array(sink, 2u);
    encode_uint(sink, termination.exit_status);
    encode_bytes(sink, termination.stderr_bytes);
}

}  // namespace

#if defined(EVALUATION_V631302_PRIVATE_BRIDGE_V3_TEST_ONLY)
void set_encode_test_fault(EncodeTestFault fault) noexcept {
    g_encode_test_fault = fault;
}
#endif

EncodeResult encode_private_capture_bridge_v3(
    CompletedNativeCaptureSuccess success) noexcept {
    try {
#if defined(EVALUATION_V631302_PRIVATE_BRIDGE_V3_TEST_ONLY)
        const EncodeTestFault test_fault = take_encode_test_fault();
#endif
        const ValidatedPrelaunchContext& context =
            success.validated_prelaunch_context();
        const std::string& label =
            context.collector_profile_build_label_text().value();
        if (!valid_profile_label(label)) {
            return failure(EncodeFailureCode::kProfileLabelInvalid);
        }

        const std::size_t stdout_size =
            success.observations_.open_receipt().stdout_bytes.size();
        if (stdout_size == 0u ||
            stdout_size >
                CompletedNativeCaptureSuccess::kMaximumCollectorStdoutBytes) {
            return failure(EncodeFailureCode::kStdoutLengthInvalid);
        }

        const RuntimeObjectEvidence* observed_collector = nullptr;
        try {
            CompletedNativeCaptureSuccess::validate_preconstruction(
                context,
                success.observations_,
                success.harness_observation_);
            observed_collector =
                &success.observed_collector_runtime_object();
        } catch (const std::bad_alloc&) {
            return failure(EncodeFailureCode::kAllocationFailure);
        } catch (...) {
            return failure(EncodeFailureCode::kInvalidSuccessInvariant);
        }

        CountingSink counter;
        encode_bridge(
            counter,
            context,
            success.observations_,
            success.harness_observation_,
            *observed_collector,
            success.validated_prelaunch_expectations_root());
#if defined(EVALUATION_V631302_PRIVATE_BRIDGE_V3_TEST_ONLY)
        if (test_fault == EncodeTestFault::kEncodedSizeOverflow) {
            return failure(EncodeFailureCode::kEncodedSizeOverflow);
        }
#endif
        if (counter.overflowed()) {
            return failure(EncodeFailureCode::kEncodedSizeOverflow);
        }
        if (counter.internal_failure()) {
            return failure(EncodeFailureCode::kInternalEncodingFailure);
        }

        Bytes output;
        try {
            output.resize(counter.size());
        } catch (const std::bad_alloc&) {
            return failure(EncodeFailureCode::kAllocationFailure);
        } catch (const std::length_error&) {
            return failure(EncodeFailureCode::kEncodedSizeOverflow);
        } catch (...) {
            return failure(EncodeFailureCode::kInternalEncodingFailure);
        }

#if defined(EVALUATION_V631302_PRIVATE_BRIDGE_V3_TEST_ONLY)
        if (test_fault == EncodeTestFault::kInternalEncodingFailure) {
            return failure(EncodeFailureCode::kInternalEncodingFailure);
        }
#endif
        FixedSink writer(std::span<std::uint8_t>(
            output.data(), output.size()));
        encode_bridge(
            writer,
            context,
            success.observations_,
            success.harness_observation_,
            *observed_collector,
            success.validated_prelaunch_expectations_root());
        if (writer.failed() || writer.size() != output.size()) {
            return failure(EncodeFailureCode::kInternalEncodingFailure);
        }
        return EncodeResult::success(std::move(output));
    } catch (const std::bad_alloc&) {
        return failure(EncodeFailureCode::kAllocationFailure);
    } catch (const std::length_error&) {
        return failure(EncodeFailureCode::kEncodedSizeOverflow);
    } catch (...) {
        return failure(EncodeFailureCode::kInternalEncodingFailure);
    }
}

static_assert(noexcept(encode_private_capture_bridge_v3(
    std::declval<CompletedNativeCaptureSuccess>())));

}  // namespace evaluation_v6_3_1::capture_v2::private_bridge_v3
