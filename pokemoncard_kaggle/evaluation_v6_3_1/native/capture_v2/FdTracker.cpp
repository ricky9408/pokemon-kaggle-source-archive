#include "FdTracker.h"

#include <limits>
#include <new>
#include <stdexcept>

namespace evaluation_v6_3_1::capture_v2 {

FdTracker::FdTracker(Generation first_generation) : first_generation_(first_generation) {
    if (first_generation_ == 0u) {
        throw std::invalid_argument("FD generation must start above zero");
    }
}

bool FdTracker::valid_descriptor(Descriptor descriptor) noexcept {
    return descriptor >= 0;
}

bool FdTracker::needs_increment(const DescriptorState& state) noexcept {
    return state.generation == std::numeric_limits<Generation>::max();
}

FdTracker::Generation FdTracker::next_generation(const DescriptorState* previous) const noexcept {
    if (previous == nullptr) {
        return first_generation_;
    }
    return previous->generation + 1u;
}

FdTracker::TransitionResult FdTracker::install(
    Descriptor descriptor,
    const OpenDescriptionIdentity& identity,
    bool close_on_exec,
    bool allow_replacement) {
    if (!valid_descriptor(descriptor) || !identity.valid()) {
        return TransitionResult::Rejected;
    }

    const auto found = descriptors_.find(descriptor);
    if (found != descriptors_.end()) {
        if (!allow_replacement && found->second.is_open()) {
            return TransitionResult::Rejected;
        }
        if (needs_increment(found->second)) {
            return TransitionResult::Rejected;
        }
    }

    const DescriptorState replacement{
        descriptor,
        next_generation(found == descriptors_.end() ? nullptr : &found->second),
        identity,
        close_on_exec,
    };

    if (found != descriptors_.end()) {
        found->second = replacement;
        return TransitionResult::Applied;
    }

    try {
        descriptors_.emplace(descriptor, replacement);
    } catch (const std::bad_alloc&) {
        return TransitionResult::Rejected;
    }
    return TransitionResult::Applied;
}

FdTracker::TransitionResult FdTracker::install_open(
    Descriptor descriptor,
    const OpenDescriptionIdentity& identity,
    bool close_on_exec,
    SyscallResult result) {
    if (result == SyscallResult::Failed) {
        return TransitionResult::NoOp;
    }
    return install(descriptor, identity, close_on_exec, false);
}

FdTracker::TransitionResult FdTracker::close(
    Descriptor descriptor,
    CloseDisposition disposition) {
    if (disposition == CloseDisposition::DidNotClose) {
        return TransitionResult::NoOp;
    }
    if (disposition == CloseDisposition::Indeterminate) {
        return TransitionResult::Rejected;
    }
    if (!valid_descriptor(descriptor)) {
        return TransitionResult::Rejected;
    }
    const auto found = descriptors_.find(descriptor);
    if (found == descriptors_.end() || !found->second.is_open() ||
        needs_increment(found->second)) {
        return TransitionResult::Rejected;
    }
    ++found->second.generation;
    found->second.identity.reset();
    found->second.close_on_exec = false;
    return TransitionResult::Applied;
}

FdTracker::TransitionResult FdTracker::dup(
    Descriptor source,
    Descriptor target,
    SyscallResult result) {
    if (result == SyscallResult::Failed) {
        return TransitionResult::NoOp;
    }
    if (!valid_descriptor(source) || !valid_descriptor(target) || source == target) {
        return TransitionResult::Rejected;
    }
    const auto source_found = descriptors_.find(source);
    if (source_found == descriptors_.end() || !source_found->second.is_open()) {
        return TransitionResult::Rejected;
    }
    const auto target_found = descriptors_.find(target);
    if (target_found != descriptors_.end() && target_found->second.is_open()) {
        return TransitionResult::Rejected;
    }
    return install(target, *source_found->second.identity, false, false);
}

FdTracker::TransitionResult FdTracker::dup2(
    Descriptor source,
    Descriptor target,
    SyscallResult result) {
    if (result == SyscallResult::Failed) {
        return TransitionResult::NoOp;
    }
    if (!valid_descriptor(source) || !valid_descriptor(target)) {
        return TransitionResult::Rejected;
    }
    const auto source_found = descriptors_.find(source);
    if (source_found == descriptors_.end() || !source_found->second.is_open()) {
        return TransitionResult::Rejected;
    }
    if (source == target) {
        return TransitionResult::NoOp;
    }
    return install(target, *source_found->second.identity, false, true);
}

FdTracker::TransitionResult FdTracker::dup3(
    Descriptor source,
    Descriptor target,
    bool close_on_exec,
    SyscallResult result) {
    if (result == SyscallResult::Failed) {
        return TransitionResult::NoOp;
    }
    if (!valid_descriptor(source) || !valid_descriptor(target) || source == target) {
        return TransitionResult::Rejected;
    }
    const auto source_found = descriptors_.find(source);
    if (source_found == descriptors_.end() || !source_found->second.is_open()) {
        return TransitionResult::Rejected;
    }
    return install(target, *source_found->second.identity, close_on_exec, true);
}

FdTracker::TransitionResult FdTracker::exec_close_on_exec() {
    bool any = false;
    for (const auto& [descriptor, state] : descriptors_) {
        (void)descriptor;
        if (!state.is_open() || !state.close_on_exec) {
            continue;
        }
        any = true;
        if (needs_increment(state)) {
            return TransitionResult::Rejected;
        }
    }
    if (!any) {
        return TransitionResult::NoOp;
    }

    for (auto& [descriptor, state] : descriptors_) {
        (void)descriptor;
        if (!state.is_open() || !state.close_on_exec) {
            continue;
        }
        ++state.generation;
        state.identity.reset();
        state.close_on_exec = false;
    }
    return TransitionResult::Applied;
}

std::optional<FdTracker::DescriptorState> FdTracker::lookup(Descriptor descriptor) const noexcept {
    if (!valid_descriptor(descriptor)) {
        return std::nullopt;
    }
    const auto found = descriptors_.find(descriptor);
    if (found == descriptors_.end()) {
        return std::nullopt;
    }
    return found->second;
}

std::optional<FdTracker::DescriptorState> FdTracker::lookup_open(
    Descriptor descriptor) const noexcept {
    const auto found = lookup(descriptor);
    if (!found.has_value() || !found->is_open()) {
        return std::nullopt;
    }
    return found;
}

FdTracker::Snapshot FdTracker::snapshot() const {
    Snapshot result;
    result.descriptors.reserve(descriptors_.size());
    for (const auto& [descriptor, state] : descriptors_) {
        (void)descriptor;
        result.descriptors.push_back(state);
    }
    return result;
}

}  // namespace evaluation_v6_3_1::capture_v2
