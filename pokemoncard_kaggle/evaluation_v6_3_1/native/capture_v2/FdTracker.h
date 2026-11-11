#ifndef EVALUATION_V6_3_1_CAPTURE_V2_FD_TRACKER_H
#define EVALUATION_V6_3_1_CAPTURE_V2_FD_TRACKER_H

#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {

// This is an offline state component only.  It performs no syscalls and
// grants no capture, protocol, campaign, or upload authority.
class FdTracker final {
public:
    using Descriptor = int;
    using Generation = std::uint64_t;

    static constexpr Generation kFirstGeneration = 1u;

    enum class SyscallResult : std::uint8_t {
        Failed,
        Succeeded,
    };

    enum class TransitionResult : std::uint8_t {
        Applied,
        NoOp,
        Rejected,
    };

    enum class CloseDisposition : std::uint8_t {
        DidNotClose,
        Closed,
        Indeterminate,
    };

    struct OpenDescriptionIdentity final {
        // object_id is an opaque, non-zero identity supplied by a future
        // observer.  device and inode retain immutable file metadata without
        // pretending that metadata alone identifies an open description.
        std::uint64_t object_id = 0u;
        std::uint64_t device = 0u;
        std::uint64_t inode = 0u;

        constexpr bool valid() const noexcept { return object_id != 0u; }

        friend constexpr bool operator==(
            const OpenDescriptionIdentity& left,
            const OpenDescriptionIdentity& right) noexcept {
            return left.object_id == right.object_id && left.device == right.device &&
                   left.inode == right.inode;
        }
    };

    struct DescriptorState final {
        Descriptor descriptor = -1;
        Generation generation = 0u;
        std::optional<OpenDescriptionIdentity> identity;
        bool close_on_exec = false;

        bool is_open() const noexcept { return identity.has_value(); }

        friend bool operator==(const DescriptorState& left, const DescriptorState& right) {
            return left.descriptor == right.descriptor && left.generation == right.generation &&
                   left.identity == right.identity && left.close_on_exec == right.close_on_exec;
        }
    };

    struct Snapshot final {
        std::vector<DescriptorState> descriptors;

        friend bool operator==(const Snapshot& left, const Snapshot& right) {
            return left.descriptors == right.descriptors;
        }
    };

    // first_generation exists to make overflow-adjacent behavior testable.
    // Production callers should use the default.
    explicit FdTracker(Generation first_generation = kFirstGeneration);

    TransitionResult install_open(
        Descriptor descriptor,
        const OpenDescriptionIdentity& identity,
        bool close_on_exec,
        SyscallResult result = SyscallResult::Succeeded);

    TransitionResult close(
        Descriptor descriptor,
        CloseDisposition disposition = CloseDisposition::Closed);

    // dup() installs into a descriptor which must not currently be open.
    TransitionResult dup(
        Descriptor source,
        Descriptor target,
        SyscallResult result = SyscallResult::Succeeded);

    TransitionResult dup2(
        Descriptor source,
        Descriptor target,
        SyscallResult result = SyscallResult::Succeeded);

    TransitionResult dup3(
        Descriptor source,
        Descriptor target,
        bool close_on_exec,
        SyscallResult result = SyscallResult::Succeeded);

    // Model a successful exec event.  Every open descriptor marked CLOEXEC is
    // closed atomically; unmarked descriptors and failed events are untouched.
    TransitionResult exec_close_on_exec();

    // A closed record is retained as a generation tombstone.  The returned
    // value is a copy, so callers cannot mutate tracker state through lookup.
    std::optional<DescriptorState> lookup(Descriptor descriptor) const noexcept;

    // Returns only an open descriptor; closed tombstones are deliberately not
    // usable as open-description identities.
    std::optional<DescriptorState> lookup_open(Descriptor descriptor) const noexcept;

    // Entries are sorted by numeric descriptor and include closed tombstones.
    Snapshot snapshot() const;

private:
    using Table = std::map<Descriptor, DescriptorState>;

    static bool valid_descriptor(Descriptor descriptor) noexcept;
    static bool needs_increment(const DescriptorState& state) noexcept;

    Generation next_generation(const DescriptorState* previous) const noexcept;
    TransitionResult install(
        Descriptor descriptor,
        const OpenDescriptionIdentity& identity,
        bool close_on_exec,
        bool allow_replacement);

    Generation first_generation_;
    Table descriptors_;
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_FD_TRACKER_H
