#include "CaptureOutcome.h"

#include <algorithm>
#include <array>
#include <limits>
#include <span>
#include <stdexcept>
#include <string_view>
#include <sys/wait.h>

namespace evaluation_v6_3_1::capture_v2 {
namespace {

constexpr std::uint64_t kCollectorExecutableRole = 1u;
constexpr std::string_view kLibclangRelativePath =
    "lib/libclang-cpp.so.16";

std::size_t encode_cbor_head(
    std::array<std::uint8_t, 9u>& output,
    std::uint8_t major,
    std::uint64_t value) noexcept {
    std::size_t size = 0u;
    const auto append = [&](std::uint8_t byte) noexcept {
        output[size] = byte;
        ++size;
    };
    const std::uint8_t prefix = static_cast<std::uint8_t>(
        static_cast<std::uint32_t>(major) << 5u);
    if (value < 24u) {
        append(static_cast<std::uint8_t>(
            static_cast<std::uint32_t>(prefix) |
            static_cast<std::uint32_t>(value)));
    } else if (value <= 0xffu) {
        append(static_cast<std::uint8_t>(
            static_cast<std::uint32_t>(prefix) | 24u));
        append(static_cast<std::uint8_t>(value));
    } else if (value <= 0xffffu) {
        append(static_cast<std::uint8_t>(
            static_cast<std::uint32_t>(prefix) | 25u));
        append(static_cast<std::uint8_t>(value >> 8u));
        append(static_cast<std::uint8_t>(value));
    } else if (value <= 0xffffffffULL) {
        append(static_cast<std::uint8_t>(
            static_cast<std::uint32_t>(prefix) | 26u));
        for (int shift = 24; shift >= 0; shift -= 8) {
            append(static_cast<std::uint8_t>(
                value >> static_cast<unsigned>(shift)));
        }
    } else {
        append(static_cast<std::uint8_t>(
            static_cast<std::uint32_t>(prefix) | 27u));
        for (int shift = 56; shift >= 0; shift -= 8) {
            append(static_cast<std::uint8_t>(
                value >> static_cast<unsigned>(shift)));
        }
    }
    return size;
}

bool consume_bytes(
    std::span<const std::uint8_t> expected,
    std::size_t& offset,
    std::span<const std::uint8_t> value) noexcept {
    if (offset > expected.size() || value.size() > expected.size() - offset ||
        !std::equal(
            value.begin(), value.end(), expected.subspan(offset).begin())) {
        return false;
    }
    offset += value.size();
    return true;
}

bool consume_cbor_head(
    std::span<const std::uint8_t> expected,
    std::size_t& offset,
    std::uint8_t major,
    std::uint64_t value) noexcept {
    std::array<std::uint8_t, 9u> encoded{};
    const std::size_t size = encode_cbor_head(encoded, major, value);
    return consume_bytes(
        expected, offset, std::span<const std::uint8_t>(encoded).first(size));
}

bool receipt_context_matches_exact_bytes(
    const ReceiptFinalValues& receipt,
    std::span<const std::uint8_t> expected) noexcept {
    std::size_t offset = 0u;
    if (!consume_cbor_head(expected, offset, 4u, 3u) ||
        !consume_cbor_head(expected, offset, 0u, 1u) ||
        !consume_cbor_head(
            expected,
            offset,
            3u,
            receipt.primary_source_relative_path.size())) {
        return false;
    }
    for (const char byte : receipt.primary_source_relative_path) {
        const std::uint8_t encoded = static_cast<std::uint8_t>(
            static_cast<unsigned char>(byte));
        if (offset >= expected.size() || expected[offset] != encoded) {
            return false;
        }
        ++offset;
    }
    return consume_bytes(expected, offset, receipt.path_profile_cbor) &&
           offset == expected.size();
}

const DecodedPublicFileRow& libclang_public_row(
    const ValidatedPrelaunchContext& context) {
    const DecodedPublicFileRow* result = nullptr;
    for (const DecodedPublicFileRow& row : context.public_file_rows()) {
        if (row.namespace_relative_path != kLibclangRelativePath) continue;
        if (result != nullptr) {
            throw SupervisorError(
                SupervisorFailure::ProtocolViolation,
                "validated context duplicates the retained libclang object");
        }
        result = &row;
    }
    if (result == nullptr) {
        throw SupervisorError(
            SupervisorFailure::ProtocolViolation,
            "validated context omits the retained libclang object");
    }
    return *result;
}

const std::string& collector_namespace_relative_path(
    const ValidatedPrelaunchContext& context) {
    const std::string* collector_path = nullptr;
    for (const DecodedPublicFileRow& row : context.public_file_rows()) {
        if (!std::binary_search(
                row.role_codes.begin(),
                row.role_codes.end(),
                kCollectorExecutableRole)) {
            continue;
        }
        if (collector_path != nullptr) {
            throw SupervisorError(
                SupervisorFailure::ProtocolViolation,
                "validated context has multiple collector role rows");
        }
        collector_path = &row.namespace_relative_path;
    }
    if (collector_path == nullptr) {
        throw SupervisorError(
            SupervisorFailure::ProtocolViolation,
            "validated context has no collector role row");
    }
    return *collector_path;
}

bool valid_collector_profile_build_label(
    const std::string& label) noexcept {
    if (label.empty() ||
        label.size() > kValidatedCollectorProfileBuildLabelMaximumBytes) {
        return false;
    }
    return std::all_of(label.begin(), label.end(), [](unsigned char byte) {
        return byte >= 0x01u && byte <= 0x7fu;
    });
}

const RuntimeObjectEvidence& find_observed_collector_runtime_object(
    const ValidatedPrelaunchContext& context,
    const CompletedNativeCaptureObservations& observations) {
    const std::string& expected_path = collector_namespace_relative_path(context);
    const CompletedRuntimeObservation& runtime = observations.runtime_observation();
    const RuntimeObjectEvidence* collector = nullptr;
    std::size_t collector_index = 0u;
    for (std::size_t index = 0u; index < runtime.runtime_object_rows.size(); ++index) {
        const RuntimeObjectEvidence& row = runtime.runtime_object_rows[index];
        if (row.namespace_relative_path != expected_path) {
            continue;
        }
        if (collector != nullptr) {
            throw SupervisorError(
                SupervisorFailure::ProtocolViolation,
                "completed runtime evidence duplicates the collector object");
        }
        collector = &row;
        collector_index = index;
    }
    if (collector == nullptr) {
        throw SupervisorError(
            SupervisorFailure::ProtocolViolation,
            "completed runtime evidence omits the collector object");
    }

    std::size_t exec_observation_count = 0u;
    for (const RuntimeObservationEvidence& row : runtime.runtime_observation_rows) {
        if (row.observation_kind != RuntimeObservationKind::PtraceExecProcExe) {
            continue;
        }
        if (row.runtime_object_index != static_cast<std::uint64_t>(collector_index)) {
            throw SupervisorError(
                SupervisorFailure::ProtocolViolation,
                "exec observation does not reference the collector object");
        }
        ++exec_observation_count;
    }
    if (exec_observation_count != 1u) {
        throw SupervisorError(
            SupervisorFailure::ProtocolViolation,
            "completed runtime evidence does not contain exactly one collector exec observation");
    }
    return *collector;
}

}  // namespace

void CompletedNativeCaptureSuccess::validate_preconstruction(
    const ValidatedPrelaunchContext& context,
    const CompletedNativeCaptureObservations& observations,
    const HarnessObservation& harness_observation) {
    if (!valid_collector_profile_build_label(
            context.collector_profile_build_label_text().value())) {
        throw SupervisorError(
            SupervisorFailure::ProtocolViolation,
            "native success contains an invalid collector profile build label");
    }
    if (context.private_context_binding_digest() !=
        observations.private_context_binding_digest()) {
        throw SupervisorError(
            SupervisorFailure::ProtocolViolation,
            "native success context and observations have different private bindings");
    }
    HarnessObserver::cross_check_expectations(
        harness_observation, context.harness_expectations());
    const CompletedTerminationObservation& termination =
        observations.termination_observation();
    if (termination.exit_status != 0u || !termination.stderr_bytes.empty()) {
        throw SupervisorError(
            SupervisorFailure::ProtocolViolation,
            "native success contains failure termination evidence");
    }
    const std::size_t stdout_size = observations.open_receipt().stdout_bytes.size();
    if (stdout_size == 0u || stdout_size > kMaximumCollectorStdoutBytes) {
        throw SupervisorError(
            SupervisorFailure::ProtocolViolation,
            "native success contains stdout outside its frozen bounds");
    }
    const RuntimeObjectEvidence& collector =
        find_observed_collector_runtime_object(context, observations);
    const ReceiptFinalValues& final_receipt =
        observations.open_receipt().final_receipt;
    if (!receipt_context_matches_exact_bytes(
            final_receipt, context.capture_context_cbor_bytes())) {
        throw SupervisorError(
            SupervisorFailure::ProtocolViolation,
            "receipt context differs from the exact derived capture context");
    }
    const DecodedPublicFileRow& expected_libclang = libclang_public_row(context);
    const RuntimeObjectEvidence& observed_libclang =
        observations.runtime_observation().primary_clang_cpp_record;
    if (observed_libclang.namespace_relative_path !=
            expected_libclang.namespace_relative_path ||
        observed_libclang.byte_length != expected_libclang.byte_length ||
        observed_libclang.sha256 != expected_libclang.sha256) {
        throw SupervisorError(
            SupervisorFailure::ProtocolViolation,
            "runtime libclang object differs from its retained public row");
    }
    const CompletedExecStopObservation& exec =
        observations.exec_stop_observation();
    const WorkDirectoryIdentity& retained_working_directory =
        context.retained_working_directory_identity();
    if (exec.argv != context.collector_launch_argv()) {
        throw SupervisorError(
            SupervisorFailure::ProtocolViolation,
            "observed exec argv differs from the validated prelaunch context");
    }
    if (exec.cwd_device != retained_working_directory.device ||
        exec.cwd_inode != retained_working_directory.inode) {
        throw SupervisorError(
            SupervisorFailure::ProtocolViolation,
            "observed cwd object differs from retained work-directory custody");
    }
    if (exec.proc_exe_byte_length != collector.byte_length ||
        exec.proc_exe_sha256 != collector.sha256) {
        throw SupervisorError(
            SupervisorFailure::ProtocolViolation,
            "observed proc executable differs from the collector runtime object");
    }
    if (collector.elf_build_id !=
        context.expected_collector_gnu_build_id_descriptor_bytes().value()) {
        throw SupervisorError(
            SupervisorFailure::ProtocolViolation,
            "observed collector GNU build-ID descriptor differs from expectation");
    }
}

CompletedNativeCaptureSuccess::CompletedNativeCaptureSuccess(
    CaptureSessionSuccessAuthority,
    ValidatedPrelaunchContext context,
    CompletedNativeCaptureObservations observations,
    HarnessObservation harness_observation)
    : context_(std::move(context)),
      observations_(std::move(observations)),
      harness_observation_(std::move(harness_observation)) {
    validate_preconstruction(context_, observations_, harness_observation_);
}

const RuntimeObjectEvidence&
CompletedNativeCaptureSuccess::observed_collector_runtime_object() const {
    return find_observed_collector_runtime_object(context_, observations_);
}

StderrAccumulator::StderrAccumulator(
    std::size_t prefix_capacity,
    std::size_t suffix_capacity)
    : prefix_capacity_(prefix_capacity), suffix_capacity_(suffix_capacity) {
    if (suffix_capacity_ > std::numeric_limits<std::size_t>::max() - prefix_capacity_) {
        throw std::length_error("stderr prefix/suffix capacity overflows size_t");
    }
    if (prefix_capacity_ + suffix_capacity_ > kMaximumRetainedBytes) {
        throw std::length_error("stderr retained diagnostic capacity exceeds frozen bound");
    }
    prefix_.reserve(prefix_capacity_);
    suffix_.reserve(suffix_capacity_);
}

bool StderrAccumulator::append(std::span<const std::uint8_t> bytes) noexcept {
    constexpr std::uint64_t kMaximum = std::numeric_limits<std::uint64_t>::max();
    if (bytes.size() > static_cast<std::size_t>(kMaximum)) {
        return false;
    }
    const std::uint64_t byte_count = static_cast<std::uint64_t>(bytes.size());
    if (byte_count > kMaximum - total_bytes_) {
        return false;
    }

    const std::size_t prefix_remaining = prefix_capacity_ - prefix_.size();
    const std::size_t prefix_count = std::min(prefix_remaining, bytes.size());
    const std::span<const std::uint8_t> prefix_bytes = bytes.first(prefix_count);
    prefix_.insert(prefix_.end(), prefix_bytes.begin(), prefix_bytes.end());

    if (suffix_capacity_ != 0u && !bytes.empty()) {
        if (bytes.size() >= suffix_capacity_) {
            suffix_.resize(suffix_capacity_);
            const std::span<const std::uint8_t> suffix_bytes =
                bytes.subspan(bytes.size() - suffix_capacity_);
            std::copy(suffix_bytes.begin(), suffix_bytes.end(), suffix_.begin());
        } else if (bytes.size() <= suffix_capacity_ - suffix_.size()) {
            suffix_.insert(suffix_.end(), bytes.begin(), bytes.end());
        } else {
            const std::size_t available = suffix_capacity_ - suffix_.size();
            const std::size_t remove_count = bytes.size() - available;
            std::move(
                suffix_.data() + remove_count,
                suffix_.data() + suffix_.size(),
                suffix_.data());
            suffix_.resize(suffix_.size() - remove_count);
            suffix_.insert(suffix_.end(), bytes.begin(), bytes.end());
        }
    }

    total_bytes_ += byte_count;
    truncated_ = total_bytes_ > static_cast<std::uint64_t>(
        prefix_capacity_ + suffix_capacity_);
    return true;
}

NativeCaptureFailure::NativeCaptureFailure(
    FailureStage stage,
    FailureCode code,
    int primary_errno,
    int cleanup_errno,
    bool raw_wait_status_present,
    int raw_wait_status,
    StderrAccumulator&& stderr) noexcept
    : stage_(stage),
      code_(code),
      primary_errno_(primary_errno),
      cleanup_errno_(cleanup_errno),
      raw_wait_status_present_(raw_wait_status_present),
      raw_wait_status_(raw_wait_status),
      stderr_total_bytes_(stderr.total_bytes()),
      stderr_prefix_(std::move(stderr).take_prefix()),
      stderr_suffix_(std::move(stderr).take_suffix()),
      stderr_truncated_(stderr.truncated()) {}

NativeCaptureFailureBuilder::NativeCaptureFailureBuilder(
    std::size_t stderr_prefix_capacity,
    std::size_t stderr_suffix_capacity)
    : stage_(FailureStage::SuccessInvalid),
      code_(FailureCode::SuccessInvalid),
      primary_errno_(0),
      stderr_(stderr_prefix_capacity, stderr_suffix_capacity) {}

NativeCaptureFailureBuilder::NativeCaptureFailureBuilder(
    FailureStage stage,
    FailureCode code,
    int primary_errno,
    std::size_t stderr_prefix_capacity,
    std::size_t stderr_suffix_capacity)
    : stage_(stage),
      code_(code),
      primary_errno_(primary_errno),
      primary_latched_(true),
      stderr_(stderr_prefix_capacity, stderr_suffix_capacity) {}

void NativeCaptureFailureBuilder::latch_primary(
    FailureStage stage,
    FailureCode code,
    int primary_errno) noexcept {
    if (primary_latched_) {
        return;
    }
    stage_ = stage;
    code_ = code;
    primary_errno_ = primary_errno;
    primary_latched_ = true;
}

void NativeCaptureFailureBuilder::record_cleanup_errno(int cleanup_errno) noexcept {
    if (cleanup_errno_ == 0 && cleanup_errno != 0) {
        cleanup_errno_ = cleanup_errno;
    }
}

bool NativeCaptureFailureBuilder::set_raw_wait_status(int raw_wait_status) noexcept {
    if (raw_wait_status_present_ ||
        (!WIFEXITED(raw_wait_status) && !WIFSIGNALED(raw_wait_status))) {
        return false;
    }
    raw_wait_status_present_ = true;
    raw_wait_status_ = raw_wait_status;
    return true;
}

NativeCaptureFailure NativeCaptureFailureBuilder::finish() && noexcept {
    return NativeCaptureFailure(
        stage_,
        code_,
        primary_errno_,
        cleanup_errno_,
        raw_wait_status_present_,
        raw_wait_status_,
        std::move(stderr_));
}

}  // namespace evaluation_v6_3_1::capture_v2
