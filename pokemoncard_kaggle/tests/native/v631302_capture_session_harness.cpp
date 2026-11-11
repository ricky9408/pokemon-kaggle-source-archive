#include "CaptureSession.h"
#include "NativePrelaunchHandoff.h"
#include "PrivateBridgeEncoder.h"

#include <cstdint>
#include <cstdlib>
#include <fcntl.h>
#include <iostream>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace capture = evaluation_v6_3_1::capture_v2;

static_assert(!std::is_copy_constructible_v<capture::CaptureSession>);
static_assert(!std::is_copy_assignable_v<capture::CaptureSession>);
static_assert(!std::is_move_constructible_v<capture::CaptureSession>);
static_assert(!std::is_move_assignable_v<capture::CaptureSession>);
static_assert(std::is_nothrow_destructible_v<capture::CaptureSession>);
static_assert(noexcept(std::declval<capture::CaptureSession&&>().run()));

using RvalueNoexceptRun = capture::CaptureSessionOutcome (
    capture::CaptureSession::*)() && noexcept;

static_assert(
    std::is_same_v<
        decltype(static_cast<RvalueNoexceptRun>(&capture::CaptureSession::run)),
        RvalueNoexceptRun>);
static_assert(!std::is_constructible_v<
              capture::CompletedNativeCaptureSuccess,
              capture::CaptureSessionSuccessAuthority,
              capture::ValidatedPrelaunchContext,
              capture::CompletedNativeCaptureObservations,
              capture::HarnessObservation>);
static_assert(!std::is_default_constructible_v<capture::CaptureSessionSuccessAuthority>);

using PrivateEncodeFunction = capture::private_bridge_v3::EncodeResult (*)(
    capture::CompletedNativeCaptureSuccess) noexcept;

static_assert(std::is_same_v<
              decltype(&capture::private_bridge_v3::encode_private_capture_bridge_v3),
              PrivateEncodeFunction>);
static_assert(std::is_invocable_v<
              PrivateEncodeFunction,
              capture::CompletedNativeCaptureSuccess&&>);
static_assert(!std::is_invocable_v<
              PrivateEncodeFunction,
              capture::CompletedNativeCaptureSuccess&>);
static_assert(!std::is_invocable_v<
              PrivateEncodeFunction,
              capture::NativeCaptureFailure&&>);

namespace {

void require(bool condition, std::string_view message) {
    if (!condition) {
        std::cerr << "capture_session_failure: " << message << '\n';
        std::exit(1);
    }
}

void write_fixture(const char* path, const char* contents, mode_t mode) {
    const int descriptor = ::open(
        path,
        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
        0600);
    require(descriptor >= 0, "fixture file could not be opened");
    const std::size_t length = std::char_traits<char>::length(contents);
    require(::write(descriptor, contents, length) == static_cast<ssize_t>(length), "fixture write failed");
    require(::fchmod(descriptor, mode) == 0, "fixture mode could not be set");
    require(::close(descriptor) == 0, "fixture file could not be closed");
}

void test_malformed_raw_request_fails_closed() {
    constexpr char collector_path[] = "/tmp/v631302-capture-session-collector";
    constexpr char source_path[] = "/tmp/v631302-capture-session-source";
    static_cast<void>(::unlink(collector_path));
    static_cast<void>(::unlink(source_path));
    write_fixture(collector_path, "collector\n", 0555);
    write_fixture(source_path, "int main;\n", 0444);

    const int root = ::open("/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(root >= 0, "temporary root directory could not be opened");
    std::vector<capture::RetainedInputSpec> specs{
        {root, "v631302-capture-session-collector", "bin/collector", {1u}, 0555u},
        {root, "v631302-capture-session-source", "src/main.cc", {2u}, 0444u},
    };
    capture::RetainedInputSet retained = capture::RetainedInputSet::acquire(std::move(specs));
    require(::close(root) == 0, "temporary root directory could not be closed");

    capture::CaptureSession session(
        std::vector<std::uint8_t>{0xffu},
        std::move(retained),
        capture::CaptureSessionLimits{});

    // Calling this rvalue-only operation must not throw, including when raw
    // validation raises internally.
    capture::CaptureSessionOutcome outcome = std::move(session).run();
    require(
        std::holds_alternative<capture::NativeCaptureFailure>(outcome),
        "malformed raw input produced a success alternative");

    capture::NativeCaptureFailure failure =
        std::get<capture::NativeCaptureFailure>(std::move(outcome));
    require(
        failure.stage() == capture::FailureStage::Validate,
        "malformed raw input changed the failure stage");
    require(
        failure.code() == capture::FailureCode::Validate,
        "malformed raw input changed the failure code");
    require(failure.primary_errno() == 0, "validation failure reported an errno");
    require(!failure.has_raw_wait_status(), "validation failure reported a wait status");
    static_cast<void>(::unlink(collector_path));
    static_cast<void>(::unlink(source_path));
}

}  // namespace

int main() {
    test_malformed_raw_request_fails_closed();
    std::cout << "capture_session_harness_ok zero_authority=1\n";
    return 0;
}
