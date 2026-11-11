#include "SyscallPairTracker.h"

#include <algorithm>
#include <new>

namespace evaluation_v6_3_1::capture_v2 {

bool SyscallPairTracker::valid_tid(Tid tid) noexcept {
    return tid > 0;
}

bool SyscallPairTracker::valid_sequence(GlobalEventSequence sequence) noexcept {
    (void)sequence;
    return true;
}

bool SyscallPairTracker::accepts_sequence(GlobalEventSequence sequence) const noexcept {
    return valid_sequence(sequence) &&
           (!last_global_event_sequence_.has_value() || sequence > *last_global_event_sequence_);
}

SyscallPairTracker::TransitionResult SyscallPairTracker::reject() noexcept {
    state_ = State::Failed;
    return TransitionResult::Rejected;
}

SyscallPairTracker::TransitionResult SyscallPairTracker::record_entry(
    Tid tid,
    const EntryRecord& entry) {
    if (state_ != State::Active || !valid_tid(tid) || !entry.receipt_phase.valid() ||
        !accepts_sequence(entry.global_event_sequence) ||
        active_entries_.find(tid) != active_entries_.end()) {
        return reject();
    }

    try {
        active_entries_.emplace(tid, entry);
    } catch (const std::bad_alloc&) {
        return reject();
    }
    last_global_event_sequence_ = entry.global_event_sequence;
    return TransitionResult::Applied;
}

SyscallPairTracker::TransitionResult SyscallPairTracker::record_exit(
    Tid tid,
    const ExitRecord& exit) {
    if (state_ != State::Active || !valid_tid(tid) || exit.restart_observed ||
        !accepts_sequence(exit.global_event_sequence)) {
        return reject();
    }
    const auto active = active_entries_.find(tid);
    if (active == active_entries_.end()) {
        return reject();
    }

    const CompletedPair completed{tid, active->second, exit};
    try {
        completed_pairs_.push_back(completed);
    } catch (const std::bad_alloc&) {
        return reject();
    }
    active_entries_.erase(active);
    last_global_event_sequence_ = exit.global_event_sequence;
    return TransitionResult::Applied;
}

SyscallPairTracker::TransitionResult SyscallPairTracker::record_restart(
    Tid tid,
    GlobalEventSequence sequence) {
    // The record is explicit, but no restart transition is modeled. In
    // particular, a later entry is never synthesized from register contents.
    (void)tid;
    (void)sequence;
    return reject();
}

SyscallPairTracker::TransitionResult SyscallPairTracker::terminalize() {
    if (state_ != State::Active || !active_entries_.empty()) {
        return reject();
    }
    state_ = State::Finalized;
    return TransitionResult::Applied;
}

SyscallPairTracker::Snapshot SyscallPairTracker::snapshot() const {
    Snapshot result;
    result.state = state_;
    result.active_entries.reserve(active_entries_.size());
    result.completed_pairs = completed_pairs_;

    for (const auto& [tid, entry] : active_entries_) {
        result.active_entries.push_back(ActiveEntry{tid, entry});
    }
    std::sort(
        result.completed_pairs.begin(),
        result.completed_pairs.end(),
        [](const CompletedPair& left, const CompletedPair& right) {
            return left.entry.global_event_sequence < right.entry.global_event_sequence;
        });
    return result;
}

}  // namespace evaluation_v6_3_1::capture_v2
