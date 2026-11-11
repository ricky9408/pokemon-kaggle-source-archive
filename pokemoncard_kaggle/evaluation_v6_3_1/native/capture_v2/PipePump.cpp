#include "PipePump.h"

#if !defined(__linux__)
#error "PipePump is a Linux-only Capture V2 component"
#endif

#include <algorithm>
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <limits>
#include <new>
#include <set>
#include <sys/stat.h>
#include <unistd.h>

namespace evaluation_v6_3_1::capture_v2 {

namespace {

constexpr std::size_t kReadChunkBytes = 64u * 1024u;

[[noreturn]] void throw_failure(
    PipePumpFailure failure,
    const char* message,
    int system_errno = 0) {
    throw PipePumpError(failure, message, system_errno);
}

}  // namespace

bool PipePump::valid_channel_id(ChannelId id) noexcept {
    switch (id) {
    case ChannelId::Stdout:
    case ChannelId::Stderr:
    case ChannelId::Receipt:
        return true;
    }
    return false;
}

void PipePump::validate_descriptor(int descriptor) {
    if (descriptor < 0) {
        throw_failure(PipePumpFailure::InvalidDescriptor, "pipe reader descriptor is invalid");
    }

    const int flags = ::fcntl(descriptor, F_GETFL);
    if (flags < 0) {
        throw_failure(
            PipePumpFailure::InvalidDescriptor,
            "pipe reader descriptor cannot be inspected",
            errno);
    }
    if ((flags & O_NONBLOCK) == 0) {
        throw_failure(
            PipePumpFailure::NonBlockingRequired,
            "pipe reader descriptor is not nonblocking");
    }
    if ((flags & O_ACCMODE) != O_RDONLY) {
        throw_failure(
            PipePumpFailure::InvalidDescriptor,
            "pipe reader descriptor is not read-only");
    }

    struct stat metadata {};
    if (::fstat(descriptor, &metadata) != 0) {
        throw_failure(
            PipePumpFailure::InvalidDescriptor,
            "pipe reader descriptor cannot be stat'ed",
            errno);
    }
    if (!S_ISFIFO(metadata.st_mode)) {
        throw_failure(PipePumpFailure::InvalidDescriptor, "descriptor is not a pipe");
    }
}

PipePump::PipePump(std::vector<ChannelSpec> channels) {
    if (channels.empty()) {
        throw PipePumpError(PipePumpFailure::EmptyChannelSet, "pipe pump needs a channel");
    }

    std::set<ChannelId> channel_ids;
    std::set<int> descriptors;
    for (const ChannelSpec& channel : channels) {
        if (!valid_channel_id(channel.id)) {
            throw PipePumpError(
                PipePumpFailure::InvalidChannelId,
                "pipe pump channel ID is invalid");
        }
        if (!channel_ids.insert(channel.id).second) {
            throw PipePumpError(
                PipePumpFailure::DuplicateChannelId,
                "pipe pump channel ID is duplicated");
        }
        if (!descriptors.insert(channel.read_fd).second) {
            throw PipePumpError(
                PipePumpFailure::DuplicateDescriptor,
                "pipe pump descriptor is duplicated");
        }
        validate_descriptor(channel.read_fd);
    }
    if (channels.size() != 3u) {
        throw PipePumpError(
            PipePumpFailure::IncompleteChannelSet,
            "pipe pump requires exactly stdout, stderr, and receipt channels");
    }

    // Keep every descriptor owned while the table is being built.  This also
    // makes constructor exceptions close all successfully validated inputs.
    std::vector<OwnedFd> owned;
    owned.reserve(channels.size());
    for (const ChannelSpec& channel : channels) {
        owned.emplace_back(channel.read_fd);
    }

    channels_.clear();
    for (std::size_t index = 0; index < channels.size(); ++index) {
        ChannelState state{
            channels[index].id,
            std::move(owned[index]),
            channels[index].byte_cap,
            0u,
            {},
            {},
            false,
        };
        channels_.emplace(state.id, std::move(state));
    }
}

void PipePump::throw_unknown_channel(ChannelId) {
    throw PipePumpError(PipePumpFailure::UnknownChannel, "pipe pump channel is not registered");
}

PipePump::ChannelState& PipePump::require_channel(ChannelId id) {
    const auto found = channels_.find(id);
    if (found == channels_.end()) {
        throw_unknown_channel(id);
    }
    return found->second;
}

const PipePump::ChannelState& PipePump::require_channel(ChannelId id) const {
    const auto found = channels_.find(id);
    if (found == channels_.end()) {
        throw_unknown_channel(id);
    }
    return found->second;
}

void PipePump::require_operable() const {
    if (terminal_failure_) {
        throw PipePumpError(PipePumpFailure::TerminalFailure, "pipe pump is in terminal failure");
    }
    if (complete_) {
        throw PipePumpError(PipePumpFailure::AlreadyComplete, "pipe pump is already complete");
    }
}

[[noreturn]] void PipePump::fail(
    PipePumpFailure failure,
    const char* message,
    int system_errno) {
    terminal_failure_ = true;
    throw PipePumpError(failure, message, system_errno);
}

void PipePump::drain_ready(ChannelId id) {
    require_operable();
    ChannelState& channel = require_channel(id);
    if (channel.eof) {
        return;
    }

    std::array<Byte, kReadChunkBytes> buffer{};
    for (;;) {
        const std::size_t remaining = channel.byte_cap - channel.bytes.size();
        const std::size_t request = remaining == 0u ? 1u : std::min(remaining, buffer.size());
        const ssize_t count = ::read(channel.reader.get(), buffer.data(), request);
        if (count > 0) {
            const std::size_t received = static_cast<std::size_t>(count);
            if (received > std::numeric_limits<std::uint64_t>::max() -
                               channel.total_bytes_seen) {
                fail(PipePumpFailure::ResourceFailure, "pipe channel byte count overflow");
            }
            channel.total_bytes_seen += static_cast<std::uint64_t>(received);
            if (received > remaining) {
                try {
                    channel.overflow_probe.assign(
                        buffer.begin(), buffer.begin() + count);
                } catch (const std::bad_alloc&) {
                    fail(PipePumpFailure::ResourceFailure,
                         "pipe overflow probe allocation failed");
                }
                fail(PipePumpFailure::CapOverflow, "pipe channel byte cap overflow");
            }
            try {
                channel.bytes.insert(channel.bytes.end(), buffer.begin(), buffer.begin() + count);
            } catch (const std::bad_alloc&) {
                fail(PipePumpFailure::ResourceFailure, "pipe channel buffer allocation failed");
            }
            continue;
        }
        if (count == 0) {
            channel.eof = true;
            return;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return;
        }
        fail(PipePumpFailure::ReadFailure, "pipe channel read failed", errno);
    }
}

bool PipePump::all_eof() const noexcept {
    for (const auto& [id, channel] : channels_) {
        (void)id;
        if (!channel.eof) {
            return false;
        }
    }
    return true;
}

void PipePump::finish_success() {
    require_operable();
    if (!all_eof()) {
        fail(PipePumpFailure::PrematureSuccess, "pipe pump success arrived before all EOFs");
    }
    complete_ = true;
}

PipePump::ChannelSnapshot PipePump::channel_snapshot(ChannelId id) const {
    const ChannelState& channel = require_channel(id);
    return ChannelSnapshot{
        channel.id,
        channel.byte_cap,
        channel.total_bytes_seen,
        channel.bytes,
        channel.overflow_probe,
        channel.eof,
    };
}

std::span<const PipePump::Byte> PipePump::channel_bytes(ChannelId id) const {
    const ChannelState& channel = require_channel(id);
    return std::span<const Byte>(channel.bytes.data(), channel.bytes.size());
}

int PipePump::read_descriptor(ChannelId id) const {
    return require_channel(id).reader.get();
}

PipePump::Snapshot PipePump::snapshot() const {
    Snapshot result;
    result.channels.reserve(channels_.size());
    for (const auto& [id, channel] : channels_) {
        (void)id;
        result.channels.push_back(
            ChannelSnapshot{
                channel.id,
                channel.byte_cap,
                channel.total_bytes_seen,
                channel.bytes,
                channel.overflow_probe,
                channel.eof,
            });
    }
    result.terminal_failure = terminal_failure_;
    result.complete = complete_;
    return result;
}

}  // namespace evaluation_v6_3_1::capture_v2
