#include "ReceiptStreamParser.h"

#include <algorithm>
#include <array>
#include <string>
#include <utility>

namespace evaluation_v6_3_1::capture_v2 {
namespace {

using Byte = ReceiptStreamParser::Byte;

constexpr std::array<Byte, 8> kFrameMagic = {'V', '6', '3', '1', 'C', 'R', '0', '1'};
constexpr std::uint64_t kProtocol = 631302u;
constexpr std::array<std::uint64_t, 11> kEventCodes = {
    1u, 2u, 3u, 2u, 2u, 4u, 2u, 2u, 2u, 2u, 5u,
};
constexpr std::array<std::uint64_t, 7> kPhaseSequences = {1u, 3u, 4u, 6u, 7u, 8u, 9u};
constexpr std::size_t kMaxCborDepth = 512u;
constexpr std::size_t kMaxCborNodes = 1'000'000u;

struct CborNode final {
    enum class Kind : std::uint8_t { Uint, Bytes, Text, Array };

    Kind kind;
    std::uint64_t uint_value = 0u;
    std::vector<Byte> bytes_value;
    std::string text_value;
    std::vector<CborNode> array_value;
    std::size_t start = 0u;
    std::size_t end = 0u;
};

struct CborHead final {
    Byte major;
    std::uint64_t argument;
};

[[noreturn]] void cbor_fail() {
    throw ReceiptStreamError("receipt payload is not canonical arrays-only CBOR");
}

bool is_continuation(Byte value) {
    return (value & 0xC0u) == 0x80u;
}

bool valid_utf8(std::span<const Byte> value) {
    std::size_t index = 0u;
    while (index < value.size()) {
        const Byte first = value[index++];
        if (first <= 0x7Fu) {
            continue;
        }
        if (first >= 0xC2u && first <= 0xDFu) {
            if (index >= value.size() || !is_continuation(value[index])) {
                return false;
            }
            ++index;
            continue;
        }
        if (first >= 0xE0u && first <= 0xEFu) {
            if (index + 1u >= value.size()) {
                return false;
            }
            const Byte second = value[index];
            const bool valid_second =
                first == 0xE0u ? second >= 0xA0u && second <= 0xBFu
                : first == 0xEDu ? second >= 0x80u && second <= 0x9Fu
                                : is_continuation(second);
            if (!valid_second || !is_continuation(value[index + 1u])) {
                return false;
            }
            index += 2u;
            continue;
        }
        if (first >= 0xF0u && first <= 0xF4u) {
            if (index + 2u >= value.size()) {
                return false;
            }
            const Byte second = value[index];
            const bool valid_second =
                first == 0xF0u ? second >= 0x90u && second <= 0xBFu
                : first == 0xF4u ? second >= 0x80u && second <= 0x8Fu
                                : is_continuation(second);
            if (!valid_second || !is_continuation(value[index + 1u]) ||
                !is_continuation(value[index + 2u])) {
                return false;
            }
            index += 3u;
            continue;
        }
        return false;
    }
    return true;
}

CborHead parse_head(std::span<const Byte> bytes, std::size_t& cursor) {
    if (cursor >= bytes.size()) {
        cbor_fail();
    }
    const Byte initial = bytes[cursor++];
    const Byte major = static_cast<Byte>(initial >> 5u);
    const Byte additional = static_cast<Byte>(initial & 0x1Fu);
    if (major != 0u && major != 2u && major != 3u && major != 4u) {
        cbor_fail();
    }
    std::size_t width = 0u;
    std::uint64_t argument = 0u;
    if (additional < 24u) {
        argument = additional;
    } else if (additional == 24u) {
        width = 1u;
    } else if (additional == 25u) {
        width = 2u;
    } else if (additional == 26u) {
        width = 4u;
    } else if (additional == 27u) {
        width = 8u;
    } else {
        cbor_fail();
    }
    if (width == 0u) {
        return CborHead{major, argument};
    }
    if (width > bytes.size() - cursor) {
        cbor_fail();
    }
    for (std::size_t offset = 0u; offset < width; ++offset) {
        argument = (argument << 8u) | bytes[cursor++];
    }
    const std::uint64_t minimum =
        width == 1u   ? 24u
        : width == 2u ? 0x100u
        : width == 4u ? 0x10000u
                      : 0x100000000ULL;
    if (argument < minimum) {
        cbor_fail();
    }
    return CborHead{major, argument};
}

CborNode parse_item(std::span<const Byte> bytes, std::size_t& cursor, std::size_t depth,
                    std::size_t& node_count) {
    if (depth > kMaxCborDepth || ++node_count > kMaxCborNodes) {
        cbor_fail();
    }
    const std::size_t start = cursor;
    const CborHead head = parse_head(bytes, cursor);
    if (head.major == 0u) {
        return CborNode{CborNode::Kind::Uint, head.argument, {}, {}, {}, start, cursor};
    }
    if (head.argument > bytes.size() - cursor) {
        cbor_fail();
    }
    const std::size_t length = static_cast<std::size_t>(head.argument);
    if (head.major == 2u) {
        std::vector<Byte> value(bytes.begin() + static_cast<std::ptrdiff_t>(cursor),
                                bytes.begin() + static_cast<std::ptrdiff_t>(cursor + length));
        cursor += length;
        return CborNode{CborNode::Kind::Bytes, 0u, std::move(value), {}, {}, start, cursor};
    }
    if (head.major == 3u) {
        const std::span<const Byte> raw = bytes.subspan(cursor, length);
        if (!valid_utf8(raw)) {
            cbor_fail();
        }
        std::string value(reinterpret_cast<const char*>(raw.data()), raw.size());
        cursor += length;
        return CborNode{CborNode::Kind::Text, 0u, {}, std::move(value), {}, start, cursor};
    }
    std::vector<CborNode> values;
    if (head.argument > kMaxCborNodes - node_count) {
        cbor_fail();
    }
    values.reserve(static_cast<std::size_t>(head.argument));
    for (std::uint64_t index = 0u; index < head.argument; ++index) {
        values.push_back(parse_item(bytes, cursor, depth + 1u, node_count));
    }
    return CborNode{CborNode::Kind::Array, 0u, {}, {}, std::move(values), start, cursor};
}

const CborNode& array_at(const CborNode& value, std::size_t index) {
    if (value.kind != CborNode::Kind::Array || index >= value.array_value.size()) {
        cbor_fail();
    }
    return value.array_value[index];
}

void exact_array_width(const CborNode& value, std::size_t width) {
    if (value.kind != CborNode::Kind::Array || value.array_value.size() != width) {
        cbor_fail();
    }
}

std::uint64_t uint_value(const CborNode& value) {
    if (value.kind != CborNode::Kind::Uint) {
        cbor_fail();
    }
    return value.uint_value;
}

std::string text_value(const CborNode& value) {
    if (value.kind != CborNode::Kind::Text || value.text_value.find('\0') != std::string::npos) {
        cbor_fail();
    }
    return value.text_value;
}

void validate_relative_path(std::string_view path) {
    if (path.empty() || path.front() == '/' || path.find('\\') != std::string_view::npos ||
        path.find('\0') != std::string_view::npos) {
        cbor_fail();
    }
    std::size_t start = 0u;
    while (start < path.size()) {
        const std::size_t separator = path.find('/', start);
        const std::size_t end = separator == std::string_view::npos ? path.size() : separator;
        const std::string_view component = path.substr(start, end - start);
        if (component.empty() || component == "." || component == "..") {
            cbor_fail();
        }
        if (separator == std::string_view::npos) {
            return;
        }
        start = separator + 1u;
    }
    cbor_fail();
}

std::vector<std::string> argv_value(const CborNode& value) {
    if (value.kind != CborNode::Kind::Array || value.array_value.empty()) {
        cbor_fail();
    }
    std::vector<std::string> result;
    result.reserve(value.array_value.size());
    for (const CborNode& item : value.array_value) {
        result.push_back(text_value(item));
    }
    return result;
}

std::vector<Byte> raw_slice(std::span<const Byte> payload, const CborNode& value) {
    if (value.start > value.end || value.end > payload.size()) {
        cbor_fail();
    }
    return std::vector<Byte>(payload.begin() + static_cast<std::ptrdiff_t>(value.start),
                             payload.begin() + static_cast<std::ptrdiff_t>(value.end));
}

std::uint64_t read_be_u64(std::span<const Byte> bytes) {
    if (bytes.size() != 8u) {
        cbor_fail();
    }
    std::uint64_t value = 0u;
    for (const Byte item : bytes) {
        value = (value << 8u) | item;
    }
    return value;
}

std::array<PhaseTransition, 7> exact_phase_transitions(const CborNode& value) {
    exact_array_width(value, 7u);
    std::array<PhaseTransition, 7> result{};
    for (std::size_t index = 0u; index < result.size(); ++index) {
        const CborNode& row = array_at(value, index);
        exact_array_width(row, 3u);
        const std::uint64_t ordinal = uint_value(array_at(row, 0u));
        const std::uint64_t code = uint_value(array_at(row, 1u));
        const std::uint64_t sequence = uint_value(array_at(row, 2u));
        if (ordinal != index || code != index || sequence != kPhaseSequences[index]) {
            cbor_fail();
        }
        result[index] = PhaseTransition{ordinal, code, sequence};
    }
    return result;
}

}  // namespace

ReceiptStreamParser::ReceiptStreamParser(ReceiptContextExpectation expectation)
    : expectation_(std::move(expectation)) {
    try {
        validate_relative_path(expectation_.primary_source_relative_path);
        std::size_t cursor = 0u;
        std::size_t node_count = 0u;
        const CborNode profile = parse_item(expectation_.path_profile_cbor, cursor, 0u, node_count);
        if (cursor != expectation_.path_profile_cbor.size() || profile.kind != CborNode::Kind::Array) {
            cbor_fail();
        }
    } catch (const ReceiptStreamError&) {
        failed_ = true;
        throw;
    }
}

[[noreturn]] void ReceiptStreamParser::fail(const char* message) {
    failed_ = true;
    throw ReceiptStreamError(message);
}

void ReceiptStreamParser::require_unfailed_and_open() {
    if (failed_) {
        throw ReceiptStreamError("receipt parser is already failed");
    }
    if (eof_seen_) {
        fail("receipt parser received input after EOF");
    }
}

void ReceiptStreamParser::verify_observed_prefix() {
    const std::size_t common = std::min(drained_stream_.size(), observed_write_bytes_.size());
    if (!std::equal(drained_stream_.begin(), drained_stream_.begin() + static_cast<std::ptrdiff_t>(common),
                    observed_write_bytes_.begin())) {
        fail("receipt drain bytes disagree with observed FD3 writes");
    }
}

void ReceiptStreamParser::advance_phase_commitments() {
    for (PhaseFrame& frame : phase_frames_) {
        if (frame.effective || observed_write_bytes_.size() < frame.end) {
            continue;
        }
        const auto iterator = std::find_if(
            write_segments_.begin(), write_segments_.end(),
            [&frame](const WriteSegment& segment) {
                return segment.start == frame.start && segment.end == frame.end;
            });
        if (iterator == write_segments_.end() || iterator->writev_labelled ||
            iterator->returned_count != iterator->requested_count ||
            iterator->returned_count != frame.end - frame.start || iterator->pipe_buf == 0u ||
            iterator->returned_count > iterator->pipe_buf) {
            fail("receipt phase frame was not one complete successful FD3 write");
        }
        frame.effective = true;
        Amendment8OpenPhase phase = Amendment8OpenPhase::PreDriver;
        if (frame.ordinal >= 5u) {
            phase = Amendment8OpenPhase::PostCc1;
        } else if (frame.ordinal >= 4u) {
            phase = Amendment8OpenPhase::Cc1;
        } else if (frame.ordinal >= 2u) {
            phase = Amendment8OpenPhase::Driver;
        }
        open_phase_mapping_ = OpenPhaseMapping{phase, frame.ordinal, frame.sequence};
    }
}

void ReceiptStreamParser::parse_one_frame(std::span<const Byte> payload, std::size_t frame_start,
                                          std::size_t frame_end) {
    std::size_t cursor = 0u;
    std::size_t node_count = 0u;
    CborNode event = parse_item(payload, cursor, 0u, node_count);
    if (cursor != payload.size()) {
        cbor_fail();
    }
    exact_array_width(event, 5u);
    if (uint_value(array_at(event, 0u)) != kProtocol || uint_value(array_at(event, 1u)) != 1u ||
        uint_value(array_at(event, 2u)) != events_parsed_ ||
        uint_value(array_at(event, 3u)) != kEventCodes[events_parsed_]) {
        cbor_fail();
    }
    const CborNode& event_payload = array_at(event, 4u);
    if (events_parsed_ == 0u) {
        exact_array_width(event_payload, 3u);
        if (uint_value(array_at(event_payload, 0u)) != kReceiptDescriptor) {
            cbor_fail();
        }
    } else if (events_parsed_ == 1u || events_parsed_ == 3u || events_parsed_ == 4u ||
               events_parsed_ == 6u || events_parsed_ == 7u || events_parsed_ == 8u ||
               events_parsed_ == 9u) {
        const auto phase_position = static_cast<std::size_t>(
            std::find(kPhaseSequences.begin(), kPhaseSequences.end(), events_parsed_) -
            kPhaseSequences.begin());
        if (phase_position >= kPhaseSequences.size()) {
            cbor_fail();
        }
        exact_array_width(event_payload, 2u);
        if (uint_value(array_at(event_payload, 0u)) != phase_position ||
            uint_value(array_at(event_payload, 1u)) != phase_position) {
            cbor_fail();
        }
        phase_frames_.push_back(
            PhaseFrame{frame_start, frame_end, phase_position, events_parsed_, false});
    } else if (events_parsed_ == 2u || events_parsed_ == 5u) {
        static_cast<void>(argv_value(event_payload));
    } else if (events_parsed_ == 10u) {
        exact_array_width(event_payload, 8u);
        if (uint_value(array_at(event_payload, 0u)) != kProtocol ||
            uint_value(array_at(event_payload, 1u)) != 1u) {
            cbor_fail();
        }
        const CborNode& final_binding = array_at(event_payload, 2u);
        exact_array_width(final_binding, 3u);
        if (uint_value(array_at(final_binding, 0u)) != kReceiptDescriptor) {
            cbor_fail();
        }
        const std::string primary = text_value(array_at(event_payload, 3u));
        validate_relative_path(primary);
        const std::vector<Byte> profile = raw_slice(payload, array_at(event_payload, 4u));
        {
            std::size_t profile_cursor = 0u;
            std::size_t profile_nodes = 0u;
            const CborNode profile_value = parse_item(profile, profile_cursor, 0u, profile_nodes);
            if (profile_cursor != profile.size() || profile_value.kind != CborNode::Kind::Array) {
                cbor_fail();
            }
        }
        const std::vector<std::string> final_driver = argv_value(array_at(event_payload, 5u));
        const std::vector<std::string> final_cc1 = argv_value(array_at(event_payload, 6u));
        const std::array<PhaseTransition, 7> transitions =
            exact_phase_transitions(array_at(event_payload, 7u));
        if (primary != expectation_.primary_source_relative_path ||
            profile != expectation_.path_profile_cbor) {
            cbor_fail();
        }
        if (events_parsed_ != 10u) {
            cbor_fail();
        }
        if (phase_frames_.size() != 7u) {
            cbor_fail();
        }
        // The first, driver, and cc1 event payloads are retained as exact
        // canonical slices below through their fixed event frame offsets.
        final_values_ = ReceiptFinalValues{
            uint_value(array_at(final_binding, 1u)), uint_value(array_at(final_binding, 2u)), primary,
            profile, final_driver, final_cc1, transitions};
        final_event_parsed_ = true;
    }

    ++events_parsed_;
    if (events_parsed_ > kEventCodes.size()) {
        cbor_fail();
    }

    // Canonical CBOR makes semantic equality byte equality.  Validate the
    // duplicated fields only when the final event is available.
    if (events_parsed_ == 11u) {
        // Reparse all event payloads from the immutable stream after this frame
        // is committed.  This keeps the equality comparison tied to exact bytes.
        const std::span<const Byte> complete = std::span<const Byte>(drained_stream_).first(frame_end);
        std::array<std::vector<Byte>, 11> payloads{};
        std::size_t offset = 0u;
        for (std::size_t index = 0u; index < payloads.size(); ++index) {
            if (offset + 16u > complete.size() ||
                !std::equal(kFrameMagic.begin(), kFrameMagic.end(), complete.begin() + static_cast<std::ptrdiff_t>(offset))) {
                cbor_fail();
            }
            const std::uint64_t length = read_be_u64(complete.subspan(offset + 8u, 8u));
            offset += 16u;
            if (length > complete.size() - offset) {
                cbor_fail();
            }
            payloads[index] = std::vector<Byte>(
                complete.begin() + static_cast<std::ptrdiff_t>(offset),
                complete.begin() + static_cast<std::ptrdiff_t>(offset + static_cast<std::size_t>(length)));
            offset += static_cast<std::size_t>(length);
        }
        if (offset != frame_end) {
            cbor_fail();
        }
        std::size_t final_cursor = 0u;
        std::size_t final_nodes = 0u;
        const CborNode final_event = parse_item(payloads[10], final_cursor, 0u, final_nodes);
        if (final_cursor != payloads[10].size()) {
            cbor_fail();
        }
        const CborNode& final = array_at(final_event, 4u);
        const std::vector<Byte> final_binding = raw_slice(payloads[10], array_at(final, 2u));
        const std::vector<Byte> final_driver = raw_slice(payloads[10], array_at(final, 5u));
        const std::vector<Byte> final_cc1 = raw_slice(payloads[10], array_at(final, 6u));
        const auto event_payload_slice = [&payloads](std::size_t index) {
            std::size_t event_cursor = 0u;
            std::size_t event_nodes = 0u;
            const CborNode parsed = parse_item(payloads[index], event_cursor, 0u, event_nodes);
            if (event_cursor != payloads[index].size()) {
                cbor_fail();
            }
            return raw_slice(payloads[index], array_at(parsed, 4u));
        };
        if (event_payload_slice(0u) != final_binding || event_payload_slice(2u) != final_driver ||
            event_payload_slice(5u) != final_cc1) {
            cbor_fail();
        }
    }
}

void ReceiptStreamParser::parse_available_frames() {
    while (parse_offset_ < drained_stream_.size()) {
        if (final_event_parsed_) {
            fail("receipt stream has bytes after the final frame");
        }
        if (drained_stream_.size() - parse_offset_ < 16u) {
            return;
        }
        const std::span<const Byte> header(drained_stream_.data() + parse_offset_, 16u);
        if (!std::equal(kFrameMagic.begin(), kFrameMagic.end(), header.begin())) {
            fail("receipt stream has malformed frame magic");
        }
        const std::uint64_t payload_length = read_be_u64(header.subspan(8u, 8u));
        if (payload_length > kReceiptStreamMaxBytes - 16u ||
            payload_length > drained_stream_.size() - parse_offset_ - 16u) {
            if (payload_length > kReceiptStreamMaxBytes - 16u) {
                fail("receipt frame length exceeds the stream cap");
            }
            return;
        }
        const std::size_t frame_start = parse_offset_;
        const std::size_t frame_end = frame_start + 16u + static_cast<std::size_t>(payload_length);
        try {
            parse_one_frame(
                std::span<const Byte>(drained_stream_.data() + frame_start + 16u,
                                      static_cast<std::size_t>(payload_length)),
                frame_start, frame_end);
        } catch (const ReceiptStreamError& error) {
            fail(error.what());
        }
        parse_offset_ = frame_end;
        advance_phase_commitments();
    }
}

void ReceiptStreamParser::append_drained_fd3_bytes(std::span<const Byte> bytes) {
    require_unfailed_and_open();
    if (bytes.size() > kReceiptStreamMaxBytes - drained_stream_.size()) {
        fail("receipt stream exceeds the 16 MiB cap");
    }
    drained_stream_.insert(drained_stream_.end(), bytes.begin(), bytes.end());
    verify_observed_prefix();
    try {
        parse_available_frames();
    } catch (const ReceiptStreamError& error) {
        fail(error.what());
    }
}

void ReceiptStreamParser::observe_fd3_write(std::span<const Byte> requested_bytes,
                                            std::int64_t returned_count,
                                            std::size_t supplied_pipe_buf,
                                            bool writev_labelled) {
    require_unfailed_and_open();
    if (returned_count <= 0 || static_cast<std::uint64_t>(returned_count) > requested_bytes.size()) {
        fail("receipt FD3 write return is zero, negative, or overlong");
    }
    const std::size_t returned = static_cast<std::size_t>(returned_count);
    if (returned > kReceiptStreamMaxBytes - observed_write_bytes_.size()) {
        fail("observed FD3 bytes exceed the receipt cap");
    }
    const std::size_t start = observed_write_bytes_.size();
    observed_write_bytes_.insert(observed_write_bytes_.end(), requested_bytes.begin(),
                                 requested_bytes.begin() + static_cast<std::ptrdiff_t>(returned));
    write_segments_.push_back(
        WriteSegment{start, start + returned, requested_bytes.size(), returned, supplied_pipe_buf,
                     writev_labelled});
    verify_observed_prefix();
    try {
        advance_phase_commitments();
    } catch (const ReceiptStreamError& error) {
        fail(error.what());
    }
}

void ReceiptStreamParser::finish_fd3_eof() {
    require_unfailed_and_open();
    eof_seen_ = true;
    try {
        parse_available_frames();
        if (parse_offset_ != drained_stream_.size() || events_parsed_ != 11u || !final_event_parsed_ ||
            observed_write_bytes_ != drained_stream_ || !final_values_.has_value() ||
            phase_frames_.size() != 7u ||
            std::any_of(phase_frames_.begin(), phase_frames_.end(),
                        [](const PhaseFrame& frame) { return !frame.effective; })) {
            fail("receipt EOF arrived before a complete valid eleven-event stream");
        }
        complete_ = true;
    } catch (const ReceiptStreamError& error) {
        fail(error.what());
    }
}

std::optional<OpenPhaseMapping> ReceiptStreamParser::current_open_phase_mapping() const {
    if (failed_) {
        return std::nullopt;
    }
    return open_phase_mapping_;
}

const std::vector<ReceiptStreamParser::Byte>& ReceiptStreamParser::exact_stream_bytes() const {
    if (!complete_ || failed_) {
        throw ReceiptStreamError("receipt stream is not complete");
    }
    return drained_stream_;
}

const ReceiptFinalValues& ReceiptStreamParser::final_values() const {
    if (!complete_ || failed_ || !final_values_.has_value()) {
        throw ReceiptStreamError("receipt final values are not complete");
    }
    return *final_values_;
}

}  // namespace evaluation_v6_3_1::capture_v2
