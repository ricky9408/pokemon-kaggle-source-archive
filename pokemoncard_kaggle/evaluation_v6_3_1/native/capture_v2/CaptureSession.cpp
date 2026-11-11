#include "CaptureSession.h"
#include "NativePrelaunchHandoff.h"

#if !defined(__linux__)
#error "CaptureSession is a Linux-only Capture V2 component"
#endif

#include "PipePump.h"
#include "PtraceExecAuthenticator.h"
#include "SupervisorTypes.h"
#include "Timeout.h"

#include <cerrno>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <utility>

namespace evaluation_v6_3_1::capture_v2 {
namespace {

FailureCode code_for_stage(FailureStage stage) noexcept {
    switch (stage) {
        case FailureStage::Validate:
            return FailureCode::Validate;
        case FailureStage::Namespace:
            return FailureCode::Namespace;
        case FailureStage::Harness:
            return FailureCode::Harness;
        case FailureStage::Launch:
            return FailureCode::Launch;
        case FailureStage::ExecAuthentication:
            return FailureCode::ExecAuthentication;
        case FailureStage::ReceiptOpenRuntime:
            return FailureCode::ReceiptOpenRuntime;
        case FailureStage::Termination:
            return FailureCode::Termination;
        case FailureStage::SuccessInvalid:
            return FailureCode::SuccessInvalid;
    }
    return FailureCode::SuccessInvalid;
}

FailureStage refine_stage(
    FailureStage fallback,
    SupervisorFailure failure) noexcept {
    switch (failure) {
        case SupervisorFailure::NamespaceSetup:
        case SupervisorFailure::NamespaceSeal:
        case SupervisorFailure::NamespaceEnter:
        case SupervisorFailure::DestinationInvalid:
        case SupervisorFailure::CopyFailure:
        case SupervisorFailure::OriginalInputChanged:
            return FailureStage::Namespace;
        case SupervisorFailure::ProcessLaunch:
        case SupervisorFailure::HandshakeTimeout:
        case SupervisorFailure::ChildFailure:
            return fallback == FailureStage::ReceiptOpenRuntime ||
                           fallback == FailureStage::Termination
                       ? fallback
                       : FailureStage::Launch;
        case SupervisorFailure::TraceFailure:
        case SupervisorFailure::TraceTimeout:
            return fallback == FailureStage::Harness ||
                           fallback == FailureStage::ReceiptOpenRuntime ||
                           fallback == FailureStage::Termination
                       ? fallback
                       : FailureStage::ExecAuthentication;
        default:
            return fallback;
    }
}

int exception_errno(const std::exception& error) noexcept {
    if (const auto* supervisor = dynamic_cast<const SupervisorError*>(&error)) {
        return supervisor->system_errno();
    }
    if (const auto* timeout = dynamic_cast<const TimeoutError*>(&error)) {
        return timeout->system_errno();
    }
    if (const auto* pump = dynamic_cast<const PipePumpError*>(&error)) {
        return pump->system_errno();
    }
    return 0;
}

void append_stderr_if_available(
    PreparedLaunch* launch,
    NativeCaptureFailureBuilder& failure) noexcept {
    if (launch == nullptr) {
        return;
    }
    try {
        const std::span<const std::uint8_t> bytes =
            launch->pipe_pump().channel_bytes(PipePump::ChannelId::Stderr);
        static_cast<void>(failure.append_stderr(bytes));
    } catch (...) {
    }
}

void cleanup_launch(
    PreparedLaunch* launch,
    NativeCaptureFailureBuilder& failure) noexcept {
    if (launch == nullptr) {
        return;
    }
    ChildTerminationGuard& guard = launch->termination_guard();
    if (!guard.reaped()) {
        try {
            guard.abort();
        } catch (const std::exception& error) {
            failure.record_cleanup_errno(exception_errno(error));
        } catch (...) {
        }
    }
    for (const PipePump::ChannelId channel : {
             PipePump::ChannelId::Stdout,
             PipePump::ChannelId::Stderr,
             PipePump::ChannelId::Receipt}) {
        try {
            launch->pipe_pump().drain_ready(channel);
        } catch (const std::exception& error) {
            failure.record_cleanup_errno(exception_errno(error));
        } catch (...) {
        }
    }
    append_stderr_if_available(launch, failure);
    if (guard.terminal_wait_status().has_value()) {
        static_cast<void>(failure.set_raw_wait_status(
            *guard.terminal_wait_status()));
    }
}

}  // namespace

CaptureSessionOutcome CaptureSession::run() && noexcept {
#if defined(EVALUATION_V631302_PRIVATE_BRIDGE_V3_TEST_ONLY)
    if (fixture_outcome_.has_value()) {
        if (fixture_run_count_ != nullptr) ++*fixture_run_count_;
        CaptureSessionOutcome outcome(std::move(*fixture_outcome_));
        fixture_outcome_.reset();
        return outcome;
    }
#endif
    FailureStage stage = FailureStage::Validate;
    int primary_errno = 0;
    std::unique_ptr<PreparedLaunch> prepared;
    std::unique_ptr<ExecStoppedLaunch> exec_stopped;
    try {
        RawPrelaunchRequest raw_request = NativePrelaunchHandoff::decode(
            native_prelaunch_handoff_cbor_);
        ValidatedPrelaunchPlan plan =
            ValidatedPrelaunchPlan::validate(std::move(raw_request));
        if (plan.capture_context_cbor_bytes().empty()) {
            throw SupervisorError(
                SupervisorFailure::InvalidRequest,
                "capture session has no derived canonical capture context");
        }
        ReceiptContextExpectation receipt_expectation{
            plan.primary_source(),
            plan.path_profile_cbor_bytes(),
        };

        stage = FailureStage::Namespace;
        prepared = LaunchEngine::prepare(
            std::move(retained_inputs_),
            std::move(plan),
            std::move(limits_.launch));

        stage = FailureStage::Harness;
        if (limits_.harness_timeout_milliseconds == 0u) {
            throw SupervisorError(
                SupervisorFailure::InvalidRequest,
                "capture session harness timeout is zero");
        }
        HarnessObservation harness =
            HarnessObserver::observe_direct_dynamic_elf_supervisor(
                MonotonicDeadline(limits_.harness_timeout_milliseconds),
                limits_.harness_observer);
        HarnessObserver::cross_check_expectations(
            harness,
            prepared->context().harness_expectations());

        stage = FailureStage::Launch;
        stage = FailureStage::ExecAuthentication;
        exec_stopped = PtraceExecAuthenticator::reach_authenticated_exec(
            std::move(prepared),
            limits_.exec_authentication_timeout_milliseconds);

        stage = FailureStage::ReceiptOpenRuntime;
        CompletedNativeCaptureObservations observations =
            PtraceOpenSupervisor::run(
                *exec_stopped,
                std::move(receipt_expectation),
                limits_.ptrace_open);

        stage = FailureStage::SuccessInvalid;
        ValidatedPrelaunchContext context =
            exec_stopped->launch().take_completed_context();
        CompletedNativeCaptureSuccess::validate_preconstruction(
            context, observations, harness);
        return CaptureSessionOutcome(
            std::in_place_type<CompletedNativeCaptureSuccess>,
            CompletedNativeCaptureSuccess(
                CaptureSessionSuccessAuthority{},
                std::move(context),
                std::move(observations),
                std::move(harness)));
    } catch (const SupervisorError& error) {
        stage = refine_stage(stage, error.failure());
        primary_errno = error.system_errno();
    } catch (const std::exception& error) {
        primary_errno = exception_errno(error);
    } catch (...) {
    }

    failure_builder_.latch_primary(
        stage, code_for_stage(stage), primary_errno);
    PreparedLaunch* launch = exec_stopped != nullptr
                                 ? &exec_stopped->launch()
                                 : prepared.get();
    cleanup_launch(launch, failure_builder_);
    return CaptureSessionOutcome(
        std::in_place_type<NativeCaptureFailure>,
        std::move(failure_builder_).finish());
}

}  // namespace evaluation_v6_3_1::capture_v2
