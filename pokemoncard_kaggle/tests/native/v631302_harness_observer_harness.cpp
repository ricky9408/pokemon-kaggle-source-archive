#include "HarnessObserver.h"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <type_traits>

namespace capture = evaluation_v6_3_1::capture_v2;

namespace {

static_assert(!std::is_copy_constructible_v<capture::ComponentFacts>);
static_assert(std::is_nothrow_move_constructible_v<capture::ComponentFacts>);
static_assert(!std::is_copy_assignable_v<capture::ComponentFacts>);
static_assert(!std::is_copy_constructible_v<capture::HarnessObservation>);
static_assert(std::is_nothrow_move_constructible_v<capture::HarnessObservation>);
static_assert(!std::is_move_assignable_v<capture::HarnessObservation>);

int run(std::string_view mode) {
    try {
        capture::HarnessObserverLimits limits{};
        capture::MonotonicDeadline deadline(10'000u);
        if (mode == "expired") {
            capture::MonotonicDeadline expired(1u);
            std::this_thread::sleep_for(std::chrono::milliseconds(3));
            static_cast<void>(capture::HarnessObserver::observe_direct_dynamic_elf_supervisor(
                expired, limits));
            return 20;
        }
        if (mode == "invalid-limits") {
            limits.maximum_component_bytes = 0u;
            static_cast<void>(capture::HarnessObserver::observe_direct_dynamic_elf_supervisor(
                deadline, limits));
            return 20;
        }
        const capture::HarnessObservation observed =
            capture::HarnessObserver::observe_direct_dynamic_elf_supervisor(deadline, limits);
        if (mode == "observe") {
            const capture::HarnessExpectations exact =
                capture::HarnessExpectations::exact_from(observed);
            capture::HarnessObserver::cross_check_expectations(observed, exact);
            if (observed.capture_entry_component().build_id().empty() ||
                observed.capture_interpreter_component().build_id().empty() ||
                observed.capture_entry_component() != observed.native_supervisor_component() ||
                observed.capture_entry_component() == observed.capture_interpreter_component()) {
                return 21;
            }
            std::cout << "harness_observer_ok entry_bytes="
                      << observed.capture_entry_component().byte_length()
                      << " loader_bytes="
                      << observed.capture_interpreter_component().byte_length()
                      << " duplicate_supervisor=1 zero_authority=1\n";
            return 0;
        }
        if (mode == "expectation-mismatch") {
            capture::HarnessExpectations wrong = capture::HarnessExpectations::exact_from(observed);
            ++wrong.capture_interpreter_component.byte_length;
            capture::HarnessObserver::cross_check_expectations(observed, wrong);
            return 20;
        }
        return 10;
    } catch (const capture::SupervisorError& error) {
        if (mode == "observe") {
            std::cerr << error.what() << '\n';
            return 22;
        }
        std::cout << "harness_observer_rejected " << mode << " failure="
                  << static_cast<std::uint32_t>(error.failure())
                  << " zero_authority=1\n";
        return 0;
    }
}

}  // namespace

int main(int argc, char** argv) {
    return argc == 2 ? run(argv[1]) : 11;
}
