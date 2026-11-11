#ifndef EVALUATION_V6_3_1_CAPTURE_V2_HARNESS_OBSERVER_H
#define EVALUATION_V6_3_1_CAPTURE_V2_HARNESS_OBSERVER_H

#if !defined(__linux__)
#error "HarnessObserver is a Linux-only Capture V2 component"
#endif

#include "SupervisorTypes.h"
#include "Timeout.h"

#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {

#if defined(EVALUATION_V631302_PRIVATE_BRIDGE_V3_TEST_ONLY)
class PrivateBridgeV3FixtureAccess;
#endif

// Immutable, native-observed component identity. Expectations are deliberately
// represented by a different type so caller bytes cannot become observations.
class ComponentFacts final {
public:
    ComponentFacts(const ComponentFacts&) = delete;
    ComponentFacts(ComponentFacts&&) noexcept = default;
    ComponentFacts& operator=(const ComponentFacts&) = delete;
    ComponentFacts& operator=(ComponentFacts&&) = delete;

    [[nodiscard]] std::uint64_t byte_length() const noexcept { return byte_length_; }
    [[nodiscard]] const Sha256Digest& sha256() const noexcept { return sha256_; }
    [[nodiscard]] const std::vector<std::uint8_t>& build_id() const noexcept {
        return build_id_;
    }

    friend bool operator==(const ComponentFacts&, const ComponentFacts&) = default;

private:
    friend class HarnessObserver;
#if defined(EVALUATION_V631302_PRIVATE_BRIDGE_V3_TEST_ONLY)
    friend class PrivateBridgeV3FixtureAccess;
#endif

    ComponentFacts(
        std::uint64_t byte_length,
        Sha256Digest sha256,
        std::vector<std::uint8_t> build_id)
        : byte_length_(byte_length), sha256_(sha256), build_id_(std::move(build_id)) {}

    std::uint64_t byte_length_;
    Sha256Digest sha256_;
    std::vector<std::uint8_t> build_id_;
};

static_assert(!std::is_copy_constructible_v<ComponentFacts>);
static_assert(std::is_nothrow_move_constructible_v<ComponentFacts>);
static_assert(!std::is_copy_assignable_v<ComponentFacts>);
static_assert(!std::is_move_assignable_v<ComponentFacts>);

struct ComponentExpectation final {
    std::uint64_t byte_length = 0u;
    Sha256Digest sha256{};
    std::vector<std::uint8_t> build_id;

    [[nodiscard]] static ComponentExpectation exact(const ComponentFacts& observed);
};

struct HarnessExpectations final {
    ComponentExpectation capture_entry_component;
    ComponentExpectation capture_interpreter_component;
    ComponentExpectation native_supervisor_component;

    [[nodiscard]] static HarnessExpectations exact_from(
        const class HarnessObservation& observed);
};

class HarnessObservation final {
public:
    HarnessObservation(const HarnessObservation&) = delete;
    HarnessObservation(HarnessObservation&&) noexcept = default;
    HarnessObservation& operator=(const HarnessObservation&) = delete;
    HarnessObservation& operator=(HarnessObservation&&) = delete;

    [[nodiscard]] const ComponentFacts& capture_entry_component() const noexcept {
        return capture_entry_component_;
    }
    [[nodiscard]] const ComponentFacts& capture_interpreter_component() const noexcept {
        return capture_interpreter_component_;
    }
    [[nodiscard]] const ComponentFacts& native_supervisor_component() const noexcept {
        return native_supervisor_component_;
    }

private:
    friend class HarnessObserver;
#if defined(EVALUATION_V631302_PRIVATE_BRIDGE_V3_TEST_ONLY)
    friend class PrivateBridgeV3FixtureAccess;
#endif

    HarnessObservation(
        ComponentFacts capture_entry_component,
        ComponentFacts capture_interpreter_component,
        ComponentFacts native_supervisor_component)
        : capture_entry_component_(std::move(capture_entry_component)),
          capture_interpreter_component_(std::move(capture_interpreter_component)),
          native_supervisor_component_(std::move(native_supervisor_component)) {}

    ComponentFacts capture_entry_component_;
    ComponentFacts capture_interpreter_component_;
    ComponentFacts native_supervisor_component_;
};

static_assert(std::is_nothrow_move_constructible_v<HarnessObservation>);
static_assert(!std::is_copy_constructible_v<HarnessObservation>);
static_assert(!std::is_copy_assignable_v<HarnessObservation>);
static_assert(!std::is_move_assignable_v<HarnessObservation>);

struct HarnessObserverLimits final {
    std::uint64_t maximum_component_bytes = 1024u * 1024u * 1024u;
    std::size_t maximum_proc_maps_bytes = 16u * 1024u * 1024u;
    std::size_t maximum_proc_maps_lines = 65'536u;
    std::size_t maximum_proc_maps_line_bytes = 64u * 1024u;
    std::size_t maximum_build_id_bytes = 65'535u;
};

// Observes only the frozen DIRECT_DYNAMIC_ELF_SUPERVISOR_V1 topology. It has
// zero campaign, permit, upload, and protocol-encoding authority.
class HarnessObserver final {
public:
    [[nodiscard]] static HarnessObservation observe_direct_dynamic_elf_supervisor(
        const MonotonicDeadline& deadline,
        HarnessObserverLimits limits = {});

    // Expectations are cross-checks only; they are not used to build any
    // ComponentFacts returned by observe_direct_dynamic_elf_supervisor.
    static void cross_check_expectations(
        const HarnessObservation& observed,
        const HarnessExpectations& expectations);
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_HARNESS_OBSERVER_H
