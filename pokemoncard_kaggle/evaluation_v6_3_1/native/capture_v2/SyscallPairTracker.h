#ifndef EVALUATION_V6_3_1_CAPTURE_V2_SYSCALL_PAIR_TRACKER_H
#define EVALUATION_V6_3_1_CAPTURE_V2_SYSCALL_PAIR_TRACKER_H

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {

// This is an offline state component only. It performs no ptrace, syscalls,
// CBOR, process, agent, campaign, permit, holdout, or upload operations.
class SyscallPairTracker final {
public:
    using Tid = std::int64_t;
    using SyscallNumber = std::int64_t;
    using RawArgument = std::uint64_t;
    using RawReturn = std::int64_t;
    using GlobalEventSequence = std::uint64_t;
    using ReceiptPhaseOrdinal = std::uint64_t;
    using ReceiptPhaseGeneration = std::uint64_t;

    enum class TransitionResult : std::uint8_t {
        Applied,
        Rejected,
    };

    enum class State : std::uint8_t {
        Active,
        Finalized,
        Failed,
    };

    struct ReceiptPhase final {
        ReceiptPhaseOrdinal ordinal = 0u;
        ReceiptPhaseGeneration generation = 0u;

        [[nodiscard]] constexpr bool valid() const noexcept {
            return ordinal <= 6u && generation != 0u;
        }

        friend constexpr bool operator==(const ReceiptPhase& left, const ReceiptPhase& right) {
            return left.ordinal == right.ordinal && left.generation == right.generation;
        }
    };

    struct EntryRecord final {
        SyscallNumber number = 0;
        std::array<RawArgument, 6> arguments{};
        GlobalEventSequence global_event_sequence = 0u;
        ReceiptPhase receipt_phase{};

        friend constexpr bool operator==(const EntryRecord& left, const EntryRecord& right) {
            return left.number == right.number && left.arguments == right.arguments &&
                   left.global_event_sequence == right.global_event_sequence &&
                   left.receipt_phase == right.receipt_phase;
        }
    };

    // A restart must be reported explicitly by the future observer. The raw
    // return value is retained without interpreting architecture registers.
    struct ExitRecord final {
        GlobalEventSequence global_event_sequence = 0u;
        RawReturn raw_return = 0;
        bool restart_observed = false;

        friend constexpr bool operator==(const ExitRecord& left, const ExitRecord& right) {
            return left.global_event_sequence == right.global_event_sequence &&
                   left.raw_return == right.raw_return &&
                   left.restart_observed == right.restart_observed;
        }
    };

    struct CompletedPair final {
        Tid tid = 0;
        EntryRecord entry{};
        ExitRecord exit{};

        friend constexpr bool operator==(const CompletedPair& left, const CompletedPair& right) {
            return left.tid == right.tid && left.entry == right.entry && left.exit == right.exit;
        }
    };

    struct ActiveEntry final {
        Tid tid = 0;
        EntryRecord entry{};

        friend constexpr bool operator==(const ActiveEntry& left, const ActiveEntry& right) {
            return left.tid == right.tid && left.entry == right.entry;
        }
    };

    struct Snapshot final {
        State state = State::Active;
        std::vector<ActiveEntry> active_entries;
        std::vector<CompletedPair> completed_pairs;

        friend bool operator==(const Snapshot& left, const Snapshot& right) {
            return left.state == right.state && left.active_entries == right.active_entries &&
                   left.completed_pairs == right.completed_pairs;
        }
    };

    [[nodiscard]] TransitionResult record_entry(Tid tid, const EntryRecord& entry);
    [[nodiscard]] TransitionResult record_exit(Tid tid, const ExitRecord& exit);

    // This is intentionally distinct from an ordinary exit: an observer that
    // saw restart handling cannot infer a replacement entry from registers.
    [[nodiscard]] TransitionResult record_restart(Tid tid, GlobalEventSequence sequence);

    // Successful terminalization requires every per-TID entry to be paired.
    [[nodiscard]] TransitionResult terminalize();

    [[nodiscard]] State state() const noexcept { return state_; }
    [[nodiscard]] bool failed() const noexcept { return state_ == State::Failed; }

    // Entries are sorted by TID; completed pairs are sorted by entry sequence.
    // The returned values are copies and cannot mutate tracker state.
    [[nodiscard]] Snapshot snapshot() const;

private:
    using ActiveTable = std::map<Tid, EntryRecord>;

    [[nodiscard]] static bool valid_tid(Tid tid) noexcept;
    [[nodiscard]] static bool valid_sequence(GlobalEventSequence sequence) noexcept;
    [[nodiscard]] bool accepts_sequence(GlobalEventSequence sequence) const noexcept;
    [[nodiscard]] TransitionResult reject() noexcept;

    State state_ = State::Active;
    std::optional<GlobalEventSequence> last_global_event_sequence_;
    ActiveTable active_entries_;
    std::vector<CompletedPair> completed_pairs_;
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_SYSCALL_PAIR_TRACKER_H
