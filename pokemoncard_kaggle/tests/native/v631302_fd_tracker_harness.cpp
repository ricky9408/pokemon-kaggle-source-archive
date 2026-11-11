#include "FdTracker.h"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>

namespace {

using evaluation_v6_3_1::capture_v2::FdTracker;
using Result = FdTracker::TransitionResult;
using SyscallResult = FdTracker::SyscallResult;
using CloseDisposition = FdTracker::CloseDisposition;

constexpr FdTracker::OpenDescriptionIdentity kIdentityA{11u, 22u, 33u};
constexpr FdTracker::OpenDescriptionIdentity kIdentityB{44u, 55u, 66u};

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "fd tracker harness failure: " << message << '\n';
        std::exit(1);
    }
}

void require_state(
    const FdTracker& tracker,
    int descriptor,
    std::uint64_t generation,
    const FdTracker::OpenDescriptionIdentity* identity,
    bool close_on_exec) {
    const auto state = tracker.lookup(descriptor);
    require(state.has_value(), "expected descriptor snapshot");
    require(state->generation == generation, "unexpected generation");
    require(state->close_on_exec == close_on_exec, "unexpected CLOEXEC flag");
    require(state->identity.has_value() == (identity != nullptr), "unexpected open state");
    if (identity != nullptr) {
        require(state->identity.value() == *identity, "unexpected open-description identity");
    }
}

void test_transitions_and_tombstones() {
    FdTracker tracker;
    require(
        tracker.install_open(3, kIdentityA, true) == Result::Applied,
        "open should install");
    require_state(tracker, 3, 1u, &kIdentityA, true);

    const auto before_failed = tracker.snapshot();
    require(
        tracker.install_open(3, kIdentityB, false, SyscallResult::Failed) == Result::NoOp,
        "failed open should be a no-op");
    require(tracker.snapshot() == before_failed, "failed open changed state");

    require(tracker.dup(3, 4) == Result::Applied, "dup should install target");
    require_state(tracker, 4, 1u, &kIdentityA, false);
    require(
        tracker.install_open(5, kIdentityB, false) == Result::Applied,
        "second open should install");
    require(tracker.dup2(3, 5) == Result::Applied, "dup2 should replace target");
    require_state(tracker, 5, 2u, &kIdentityA, false);

    const auto before_same_fd = tracker.snapshot();
    require(tracker.dup2(3, 3) == Result::NoOp, "same-fd dup2 should be a no-op");
    require(tracker.snapshot() == before_same_fd, "same-fd dup2 changed state");

    const auto before_failed_dup = tracker.snapshot();
    require(
        tracker.dup2(99, 6, SyscallResult::Failed) == Result::NoOp,
        "failed dup2 should be a no-op");
    require(tracker.snapshot() == before_failed_dup, "failed dup2 changed state");

    require(tracker.close(3) == Result::Applied, "close should apply");
    require_state(tracker, 3, 2u, nullptr, false);
    require(!tracker.lookup_open(3).has_value(), "closed tombstone is not open");
    require(
        tracker.install_open(3, kIdentityB, false) == Result::Applied,
        "reuse should install");
    require_state(tracker, 3, 3u, &kIdentityB, false);
    require(
        tracker.lookup(3)->identity.value() != kIdentityA,
        "descriptor reuse retained stale identity");

    require(tracker.dup3(4, 6, true) == Result::Applied, "dup3 should install target");
    require_state(tracker, 6, 1u, &kIdentityA, true);
    require(tracker.exec_close_on_exec() == Result::Applied, "exec should close CLOEXEC");
    require_state(tracker, 6, 2u, nullptr, false);
    require_state(tracker, 4, 1u, &kIdentityA, false);
    require(
        tracker.install_open(6, kIdentityB, true) == Result::Applied,
        "reopen target before dup3 replacement");
    require(tracker.dup3(4, 6, false) == Result::Applied, "dup3 should replace target");
    require_state(tracker, 6, 4u, &kIdentityA, false);
    require(
        tracker.exec_close_on_exec() == Result::NoOp,
        "exec with no CLOEXEC descriptors should be a no-op");
    require(
        tracker.close(4, CloseDisposition::DidNotClose) == Result::NoOp,
        "definite no-close should be a no-op");
    const auto before_indeterminate_close = tracker.snapshot();
    require(
        tracker.close(4, CloseDisposition::Indeterminate) == Result::Rejected,
        "indeterminate close must reject");
    require(
        tracker.snapshot() == before_indeterminate_close,
        "indeterminate close partially mutated state");
    require(tracker.close(4) == Result::Applied, "close should remove source");
    require(tracker.close(4) == Result::Rejected, "closing a closed fd must reject");
}

void test_invalid_and_conflicting_transitions() {
    FdTracker tracker;
    const auto before = tracker.snapshot();
    require(
        tracker.install_open(-1, kIdentityA, false) == Result::Rejected,
        "negative descriptor must reject");
    require(
        tracker.install_open(1, FdTracker::OpenDescriptionIdentity{}, false) == Result::Rejected,
        "empty identity must reject");
    require(tracker.snapshot() == before, "invalid open changed state");

    require(tracker.install_open(1, kIdentityA, false) == Result::Applied, "source open");
    require(tracker.install_open(2, kIdentityB, false) == Result::Applied, "target open");
    const auto before_conflict = tracker.snapshot();
    require(tracker.dup(1, 2) == Result::Rejected, "dup target conflict must reject");
    require(tracker.dup3(1, 1, false) == Result::Rejected, "dup3 same fd must reject");
    require(tracker.dup2(-1, 2) == Result::Rejected, "invalid source must reject");
    require(tracker.snapshot() == before_conflict, "rejected transition changed state");
}

void test_overflow_and_atomic_exec_guard() {
    constexpr auto kMax = std::numeric_limits<FdTracker::Generation>::max();
    FdTracker tracker(kMax - 1u);
    require(tracker.install_open(7, kIdentityA, false) == Result::Applied, "seed open");
    require_state(tracker, 7, kMax - 1u, &kIdentityA, false);
    require(tracker.close(7) == Result::Applied, "maximum generation should be reachable");
    require_state(tracker, 7, kMax, nullptr, false);
    require(
        tracker.install_open(7, kIdentityB, false) == Result::Rejected,
        "reuse past generation maximum must reject");
    require_state(tracker, 7, kMax, nullptr, false);

    FdTracker exec_tracker(kMax - 1u);
    require(exec_tracker.install_open(8, kIdentityA, false) == Result::Applied, "source open");
    require(exec_tracker.install_open(9, kIdentityB, true) == Result::Applied, "target open");
    require(exec_tracker.dup3(8, 9, true) == Result::Applied, "target reaches maximum");
    require(exec_tracker.install_open(10, kIdentityB, true) == Result::Applied, "second target");
    const auto before = exec_tracker.snapshot();
    require(
        exec_tracker.exec_close_on_exec() == Result::Rejected,
        "overflowing exec must reject");
    require(exec_tracker.snapshot() == before, "overflowing exec partially mutated state");
}

void test_deterministic_snapshots() {
    FdTracker left;
    FdTracker right;
    require(left.install_open(12, kIdentityA, true) == Result::Applied, "left open");
    require(right.install_open(12, kIdentityA, true) == Result::Applied, "right open");
    require(left.dup2(12, 14) == Result::Applied, "left dup2");
    require(right.dup2(12, 14) == Result::Applied, "right dup2");
    require(left.close(12) == Result::Applied, "left close");
    require(right.close(12) == Result::Applied, "right close");
    require(left.snapshot() == right.snapshot(), "snapshots are not deterministic");
}

}  // namespace

int main() {
    test_transitions_and_tombstones();
    test_invalid_and_conflicting_transitions();
    test_overflow_and_atomic_exec_guard();
    test_deterministic_snapshots();
    std::cout << "fd_tracker_harness_ok zero_authority=1\n";
    return 0;
}
