#include "CaptureOutcome.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <span>
#include <string_view>
#include <sys/wait.h>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace capture = evaluation_v6_3_1::capture_v2;

static_assert(!std::is_copy_constructible_v<capture::StderrAccumulator>);
static_assert(std::is_move_constructible_v<capture::StderrAccumulator>);
static_assert(!std::is_move_assignable_v<capture::StderrAccumulator>);
static_assert(!std::is_copy_constructible_v<capture::NativeCaptureFailure>);
static_assert(std::is_move_constructible_v<capture::NativeCaptureFailure>);
static_assert(!std::is_move_assignable_v<capture::NativeCaptureFailure>);
static_assert(!std::is_copy_constructible_v<capture::CompletedNativeCaptureSuccess>);
static_assert(std::is_move_constructible_v<capture::CompletedNativeCaptureSuccess>);
static_assert(!std::is_move_assignable_v<capture::CompletedNativeCaptureSuccess>);
static_assert(!std::is_default_constructible_v<capture::CaptureSessionSuccessAuthority>);
static_assert(!std::is_copy_constructible_v<capture::CaptureSessionOutcome>);
static_assert(std::is_move_constructible_v<capture::CaptureSessionOutcome>);
static_assert(capture::kRawCollectorCaptureMaxBytesV1 == 67'108'864u);
static_assert(
    capture::CompletedNativeCaptureSuccess::kMaximumCollectorStdoutBytes ==
    capture::kRawCollectorCaptureMaxBytesV1);

namespace {

[[maybe_unused]] void encode_for_test(const capture::CompletedNativeCaptureSuccess&);

template <typename T>
concept AcceptedByTestEncoder = requires(const T& value) {
    encode_for_test(value);
};

static_assert(AcceptedByTestEncoder<capture::CompletedNativeCaptureSuccess>);
static_assert(!AcceptedByTestEncoder<capture::NativeCaptureFailure>);

void require(bool condition, std::string_view message) {
    if (!condition) {
        std::cerr << "capture_outcome_failure: " << message << '\n';
        std::exit(1);
    }
}

std::span<const std::uint8_t> bytes(const char* data, std::size_t size) {
    return {reinterpret_cast<const std::uint8_t*>(data), size};
}

void test_accumulator() {
    capture::StderrAccumulator accumulator(3u, 4u);
    const std::array<std::uint8_t, 3u> first{'a', 'b', 'c'};
    const std::array<std::uint8_t, 5u> second{'d', 'e', 'f', 'g', 'h'};
    const std::array<std::uint8_t, 2u> third{'i', 'j'};
    require(accumulator.append(first), "first append rejected");
    require(accumulator.append(second), "second append rejected");
    require(accumulator.append(third), "third append rejected");
    require(accumulator.total_bytes() == 10u, "total byte count changed");
    require(
        accumulator.prefix() == std::vector<std::uint8_t>({'a', 'b', 'c'}),
        "prefix is not deterministic");
    require(
        accumulator.suffix() == std::vector<std::uint8_t>({'g', 'h', 'i', 'j'}),
        "suffix is not deterministic");
    require(accumulator.truncated(), "overflow beyond retained view not reported");

    std::vector<std::uint8_t> source{'x', 'y', 'z'};
    capture::StderrAccumulator lifetime(8u, 8u);
    require(lifetime.append(source), "lifetime append rejected");
    std::fill(source.begin(), source.end(), static_cast<std::uint8_t>('!'));
    require(
        lifetime.prefix() == std::vector<std::uint8_t>({'x', 'y', 'z'}),
        "accumulator retained caller memory");

    capture::StderrAccumulator empty(0u, 0u);
    require(empty.append(bytes("discarded", 9u)), "zero-capacity append rejected");
    require(empty.total_bytes() == 9u, "zero-capacity total is wrong");
    require(empty.prefix().empty() && empty.suffix().empty(), "zero-capacity storage grew");
    require(empty.truncated(), "zero-capacity truncation is missing");

    bool overflow_rejected = false;
    try {
        capture::StderrAccumulator impossible(
            std::numeric_limits<std::size_t>::max(), 1u);
    } catch (const std::length_error&) {
        overflow_rejected = true;
    }
    require(overflow_rejected, "capacity overflow was not rejected");
}

void test_failure_and_precedence() {
    capture::NativeCaptureFailureBuilder preallocated(2u, 3u);
    preallocated.latch_primary(
        capture::FailureStage::Namespace,
        capture::FailureCode::Namespace,
        EINVAL);
    preallocated.latch_primary(
        capture::FailureStage::Launch,
        capture::FailureCode::Launch,
        EPERM);
    capture::NativeCaptureFailure latched = std::move(preallocated).finish();
    require(latched.stage() == capture::FailureStage::Namespace,
            "preallocated primary stage was overwritten");
    require(latched.primary_errno() == EINVAL,
            "preallocated primary errno was overwritten");

    capture::NativeCaptureFailureBuilder builder(
        capture::FailureStage::Launch,
        capture::FailureCode::Launch,
        EACCES,
        2u,
        3u);
    const std::array<std::uint8_t, 7u> diagnostic{'a', 'b', 'c', 'd', 'e', 'f', 'g'};
    require(builder.append_stderr(diagnostic), "diagnostic append rejected");
    builder.record_cleanup_errno(EBUSY);
    builder.record_cleanup_errno(EPERM);
    require(builder.set_raw_wait_status(0), "terminal wait status was rejected");
    require(
        !builder.set_raw_wait_status(W_EXITCODE(7, 0)),
        "second terminal wait status was accepted");
    capture::NativeCaptureFailure failure = std::move(builder).finish();

    require(failure.stage() == capture::FailureStage::Launch, "stage changed");
    require(failure.code() == capture::FailureCode::Launch, "code changed");
    require(failure.primary_errno() == EACCES, "primary errno changed");
    require(failure.cleanup_errno() == EBUSY, "cleanup precedence changed");
    require(failure.has_raw_wait_status(), "present zero wait status was lost");
    require(failure.raw_wait_status_value() == 0, "raw wait status changed");
    require(failure.raw_wait_status().value() == 0, "optional wait status changed");
    require(failure.stderr_total_bytes() == 7u, "failure total changed");
    require(
        failure.stderr_prefix() == std::vector<std::uint8_t>({'a', 'b'}),
        "failure prefix changed");
    require(
        failure.stderr_suffix() == std::vector<std::uint8_t>({'e', 'f', 'g'}),
        "failure suffix changed");
    require(failure.stderr_truncated(), "failure truncation changed");

    capture::NativeCaptureFailureBuilder absent(
        capture::FailureStage::Termination,
        capture::FailureCode::Termination,
        0,
        1u,
        1u);
    capture::NativeCaptureFailure no_wait = std::move(absent).finish();
    require(!no_wait.raw_wait_status_present(), "wait status is falsely present");
    require(!no_wait.raw_wait_status().has_value(), "optional wait status is falsely present");

    capture::NativeCaptureFailureBuilder stopped(
        capture::FailureStage::ExecAuthentication,
        capture::FailureCode::ExecAuthentication,
        0,
        1u,
        1u);
    require(!stopped.set_raw_wait_status(0x7f), "nonterminal wait status was accepted");

    bool diagnostic_bound_rejected = false;
    try {
        capture::StderrAccumulator too_large(
            capture::StderrAccumulator::kMaximumRetainedBytes,
            1u);
    } catch (const std::length_error&) {
        diagnostic_bound_rejected = true;
    }
    require(diagnostic_bound_rejected, "frozen stderr storage bound was not enforced");
}

void test_variant() {
    capture::NativeCaptureFailureBuilder builder(
        capture::FailureStage::SuccessInvalid,
        capture::FailureCode::SuccessInvalid,
        EPROTO,
        1u,
        1u);
    capture::CaptureSessionOutcome outcome(std::in_place_type<capture::NativeCaptureFailure>,
                                          std::move(builder).finish());
    require(std::holds_alternative<capture::NativeCaptureFailure>(outcome), "variant alternative changed");
    require(
        std::get<capture::NativeCaptureFailure>(outcome).stage() ==
            capture::FailureStage::SuccessInvalid,
        "variant failure stage changed");
}

}  // namespace

int main() {
    test_accumulator();
    test_failure_and_precedence();
    test_variant();
    std::cout << "capture_outcome_harness_ok zero_authority=1\n";
    return 0;
}
