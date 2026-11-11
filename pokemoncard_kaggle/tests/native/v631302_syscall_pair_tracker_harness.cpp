#include "SyscallPairTracker.h"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>

namespace {

using evaluation_v6_3_1::capture_v2::SyscallPairTracker;
using Result = SyscallPairTracker::TransitionResult;
using State = SyscallPairTracker::State;

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "syscall pair tracker harness failure: " << message << '\n';
        std::exit(1);
    }
}

SyscallPairTracker::EntryRecord entry(
    std::int64_t number,
    std::uint64_t sequence,
    std::uint64_t ordinal = 1u,
    std::uint64_t generation = 1u) {
    return SyscallPairTracker::EntryRecord{
        number,
        std::array<SyscallPairTracker::RawArgument, 6>{1u, 2u, 3u, 4u, 5u, 6u},
        sequence,
        SyscallPairTracker::ReceiptPhase{ordinal, generation},
    };
}

SyscallPairTracker::ExitRecord exit_record(
    std::uint64_t sequence,
    std::int64_t raw_return,
    bool restart_observed = false) {
    return SyscallPairTracker::ExitRecord{sequence, raw_return, restart_observed};
}

void test_interleaved_tids_preserve_entries() {
    SyscallPairTracker tracker;
    const auto first = entry(10, 1u, 1u, 7u);
    const auto second = entry(20, 2u, 2u, 7u);
    require(tracker.record_entry(200, second) == Result::Applied, "second TID entry");
    require(tracker.record_entry(100, first) == Result::Rejected, "out-of-order event must reject");
    require(tracker.state() == State::Failed, "ordering failure is terminal");

    SyscallPairTracker interleaved;
    require(interleaved.record_entry(100, first) == Result::Applied, "first TID entry");
    require(interleaved.record_entry(200, second) == Result::Applied, "second TID entry");
    require(interleaved.record_exit(100, exit_record(3u, 41)) == Result::Applied, "first TID exit");
    require(interleaved.record_exit(200, exit_record(4u, -12)) == Result::Applied, "second TID exit");

    const auto snapshot = interleaved.snapshot();
    require(snapshot.state == State::Active, "paired tracker remains active before terminalization");
    require(snapshot.active_entries.empty(), "interleaved entries remain unresolved");
    require(snapshot.completed_pairs.size() == 2u, "two completed pairs");
    require(snapshot.completed_pairs[0].tid == 100, "pairs sorted by entry sequence");
    require(snapshot.completed_pairs[0].entry == first, "entry record changed before pairing");
    require(snapshot.completed_pairs[0].exit.raw_return == 41, "first raw return");
    require(snapshot.completed_pairs[1].tid == 200, "second pair TID");
    require(snapshot.completed_pairs[1].entry == second, "second immutable entry");
    require(interleaved.terminalize() == Result::Applied, "terminalization with resolved TIDs");
    require(interleaved.state() == State::Finalized, "terminalized state");
}

void test_unexpected_events_and_failed_terminal_state() {
    SyscallPairTracker exit_without_entry;
    require(
        exit_without_entry.record_exit(11, exit_record(1u, 0)) == Result::Rejected,
        "exit without entry must reject");
    require(exit_without_entry.failed(), "exit without entry enters failed state");
    require(
        exit_without_entry.record_entry(11, entry(1, 2u)) == Result::Rejected,
        "failed tracker cannot recover");

    SyscallPairTracker duplicate_entry;
    require(duplicate_entry.record_entry(11, entry(1, 1u)) == Result::Applied, "first entry");
    require(
        duplicate_entry.record_entry(11, entry(2, 2u)) == Result::Rejected,
        "entry while active must reject");
    require(duplicate_entry.failed(), "duplicate entry enters failed state");

    SyscallPairTracker invalid_tid;
    require(invalid_tid.record_entry(0, entry(1, 1u)) == Result::Rejected, "zero TID must reject");
    require(invalid_tid.failed(), "zero TID is terminal");

    SyscallPairTracker invalid_phase;
    require(
        invalid_phase.record_entry(7, entry(1, 1u, 1u, 0u)) == Result::Rejected,
        "zero phase generation must reject");
    require(invalid_phase.failed(), "invalid phase is terminal");

    SyscallPairTracker invalid_ordinal;
    require(
        invalid_ordinal.record_entry(7, entry(1, 1u, 7u, 1u)) == Result::Rejected,
        "out-of-range phase ordinal must reject");
    require(invalid_ordinal.failed(), "invalid ordinal is terminal");
}

void test_restart_and_sequence_fail_closed() {
    SyscallPairTracker restart;
    require(restart.record_entry(9, entry(60, 9u)) == Result::Applied, "restart entry");
    require(restart.record_restart(9, 10u) == Result::Rejected, "explicit restart must reject");
    require(restart.failed(), "restart cannot recover by guessing registers");

    SyscallPairTracker raw_restart_value;
    require(raw_restart_value.record_entry(9, entry(60, 9u)) == Result::Applied, "raw restart entry");
    require(
        raw_restart_value.record_exit(9, exit_record(10u, -512, true)) == Result::Rejected,
        "observer-marked restart exit must reject");
    require(raw_restart_value.failed(), "marked restart is terminal");

    SyscallPairTracker ordering;
    require(ordering.record_entry(1, entry(1, 1u)) == Result::Applied, "ordering entry");
    require(
        ordering.record_exit(1, exit_record(1u, 0)) == Result::Rejected,
        "duplicate sequence must reject");
    require(ordering.failed(), "duplicate sequence is terminal");

    SyscallPairTracker zero_sequence;
    require(
        zero_sequence.record_entry(1, entry(1, 0u, 0u, 1u)) == Result::Applied,
        "zero-based first global sequence and phase ordinal must be accepted");
    require(
        zero_sequence.record_exit(1, exit_record(1u, 0)) == Result::Applied,
        "zero-based sequence must pair normally");
    require(zero_sequence.terminalize() == Result::Applied, "zero-based sequence terminalization");
}

void test_terminalization_and_determinism() {
    SyscallPairTracker unresolved;
    require(unresolved.record_entry(5, entry(5, 1u)) == Result::Applied, "unresolved entry");
    require(unresolved.terminalize() == Result::Rejected, "unresolved terminalization must reject");
    require(unresolved.failed(), "unresolved terminalization is terminal failure");

    SyscallPairTracker left;
    SyscallPairTracker right;
    const auto left_entry = entry(2, 1u, 3u, 2u);
    const auto right_entry = entry(3, 2u, 3u, 2u);
    for (SyscallPairTracker* tracker : {&left, &right}) {
        require(tracker->record_entry(17, left_entry) == Result::Applied, "deterministic entry one");
        require(tracker->record_entry(3, right_entry) == Result::Applied, "deterministic entry two");
        require(tracker->record_exit(3, exit_record(3u, 8)) == Result::Applied, "deterministic exit two");
        require(tracker->record_exit(17, exit_record(4u, 9)) == Result::Applied, "deterministic exit one");
    }
    require(left.snapshot() == right.snapshot(), "repeat transitions must have identical snapshots");
    const auto snapshot = left.snapshot();
    require(snapshot.completed_pairs[0].tid == 17, "completed snapshot has canonical pair order");
    require(snapshot.completed_pairs[1].tid == 3, "completed snapshot retains pair order by entry");
}

}  // namespace

int main() {
    test_interleaved_tids_preserve_entries();
    test_unexpected_events_and_failed_terminal_state();
    test_restart_and_sequence_fail_closed();
    test_terminalization_and_determinism();
    std::cout << "syscall_pair_tracker_harness_ok zero_authority=1\n";
    return 0;
}
