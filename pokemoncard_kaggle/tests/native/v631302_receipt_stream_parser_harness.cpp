#include "ReceiptStreamParser.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using Parser = evaluation_v6_3_1::capture_v2::ReceiptStreamParser;
using Byte = Parser::Byte;

std::vector<Byte> read_file(const char* path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("unable to read fixture");
    }
    return std::vector<Byte>(std::istreambuf_iterator<char>(input), {});
}

std::uint64_t be_u64(std::span<const Byte> value) {
    if (value.size() != 8u) {
        throw std::runtime_error("bad test frame");
    }
    std::uint64_t result = 0u;
    for (const Byte item : value) {
        result = (result << 8u) | item;
    }
    return result;
}

std::vector<std::vector<Byte>> frames(const std::vector<Byte>& receipt) {
    std::vector<std::vector<Byte>> result;
    std::size_t offset = 0u;
    while (offset < receipt.size()) {
        if (receipt.size() - offset < 16u ||
            std::string_view(reinterpret_cast<const char*>(receipt.data() + offset), 8u) != "V631CR01") {
            throw std::runtime_error("bad receipt fixture");
        }
        const std::uint64_t length = be_u64(std::span<const Byte>(receipt).subspan(offset + 8u, 8u));
        if (length > receipt.size() - offset - 16u) {
            throw std::runtime_error("truncated receipt fixture");
        }
        const std::size_t end = offset + 16u + static_cast<std::size_t>(length);
        result.emplace_back(receipt.begin() + static_cast<std::ptrdiff_t>(offset),
                            receipt.begin() + static_cast<std::ptrdiff_t>(end));
        offset = end;
    }
    return result;
}

std::vector<std::uint64_t> trace_results(const std::vector<Byte>& trace) {
    if (trace.empty() || trace.size() % 24u != 0u) {
        throw std::runtime_error("bad write trace fixture");
    }
    std::vector<std::uint64_t> result;
    for (std::size_t offset = 0u; offset < trace.size(); offset += 24u) {
        if (std::string_view(reinterpret_cast<const char*>(trace.data() + offset), 8u) != "V631WT01") {
            throw std::runtime_error("bad write trace magic");
        }
        const std::uint64_t requested = be_u64(std::span<const Byte>(trace).subspan(offset + 8u, 8u));
        const std::uint64_t returned = be_u64(std::span<const Byte>(trace).subspan(offset + 16u, 8u));
        if (requested != returned || returned == 0u) {
            throw std::runtime_error("fixture write is not complete");
        }
        result.push_back(returned);
    }
    return result;
}

Parser parser() {
    return Parser(evaluation_v6_3_1::capture_v2::ReceiptContextExpectation{"fixture.cc", {0x80u}});
}

void feed_valid(Parser& value, const std::vector<Byte>& receipt, const std::vector<Byte>& trace,
                bool chunked) {
    const std::vector<std::vector<Byte>> receipt_frames = frames(receipt);
    const std::vector<std::uint64_t> trace_sizes = trace_results(trace);
    if (receipt_frames.size() != trace_sizes.size()) {
        throw std::runtime_error("fixture frame/write cardinality mismatch");
    }
    for (std::size_t index = 0u; index < receipt_frames.size(); ++index) {
        if (trace_sizes[index] != receipt_frames[index].size()) {
            throw std::runtime_error("fixture write/frame mismatch");
        }
        value.observe_fd3_write(receipt_frames[index], static_cast<std::int64_t>(trace_sizes[index]),
                                4096u, false);
    }
    if (chunked) {
        for (const Byte item : receipt) {
            value.append_drained_fd3_bytes(std::span<const Byte>(&item, 1u));
        }
    } else {
        value.append_drained_fd3_bytes(receipt);
    }
}

bool rejects(std::string_view mutation, const std::vector<Byte>& receipt, const std::vector<Byte>& trace) {
    try {
        Parser value = parser();
        std::vector<std::vector<Byte>> receipt_frames = frames(receipt);
        if (mutation == "bad_magic") {
            std::vector<Byte> changed = receipt;
            changed[0] ^= 1u;
            value.append_drained_fd3_bytes(changed);
        } else if (mutation == "noncanonical") {
            std::vector<Byte> changed = receipt;
            changed[15] = 18u;
            changed[16] = 0x98u;
            changed.insert(changed.begin() + 17, 0x05u);
            value.append_drained_fd3_bytes(changed);
        } else if (mutation == "truncated") {
            for (const std::vector<Byte>& frame : receipt_frames) {
                value.observe_fd3_write(frame, static_cast<std::int64_t>(frame.size()), 4096u, false);
            }
            value.append_drained_fd3_bytes(
                std::span<const Byte>(receipt).first(receipt.size() - 1u));
            value.finish_fd3_eof();
        } else if (mutation == "extra") {
            feed_valid(value, receipt, trace, false);
            value.append_drained_fd3_bytes(std::array<Byte, 1>{0u});
        } else if (mutation == "short_phase") {
            for (std::size_t index = 0u; index < receipt_frames.size(); ++index) {
                if (index == 1u) {
                    const std::size_t first = receipt_frames[index].size() - 1u;
                    value.observe_fd3_write(receipt_frames[index], static_cast<std::int64_t>(first),
                                            4096u, false);
                    value.observe_fd3_write(
                        std::span<const Byte>(receipt_frames[index]).subspan(first), 1, 4096u, false);
                } else {
                    value.observe_fd3_write(receipt_frames[index],
                                            static_cast<std::int64_t>(receipt_frames[index].size()),
                                            4096u, false);
                }
            }
            value.append_drained_fd3_bytes(receipt);
        } else if (mutation == "writev_phase") {
            for (std::size_t index = 0u; index < receipt_frames.size(); ++index) {
                value.observe_fd3_write(receipt_frames[index],
                                        static_cast<std::int64_t>(receipt_frames[index].size()), 4096u,
                                        index == 1u);
            }
            value.append_drained_fd3_bytes(receipt);
        } else if (mutation == "pipebuf_phase") {
            for (std::size_t index = 0u; index < receipt_frames.size(); ++index) {
                value.observe_fd3_write(receipt_frames[index],
                                        static_cast<std::int64_t>(receipt_frames[index].size()),
                                        index == 1u ? 1u : 4096u, false);
            }
            value.append_drained_fd3_bytes(receipt);
        } else if (mutation == "stream_write_disagreement") {
            std::vector<Byte> changed = receipt_frames[0];
            changed.back() ^= 1u;
            value.observe_fd3_write(changed, static_cast<std::int64_t>(changed.size()), 4096u, false);
            value.append_drained_fd3_bytes(receipt_frames[0]);
        } else if (mutation == "sequence") {
            std::vector<Byte> changed = receipt;
            changed[23] = 1u;
            value.append_drained_fd3_bytes(changed);
        } else if (mutation == "reordered_phase") {
            std::swap(receipt_frames[1], receipt_frames[3]);
            std::vector<Byte> changed;
            for (const std::vector<Byte>& frame : receipt_frames) {
                changed.insert(changed.end(), frame.begin(), frame.end());
            }
            value.append_drained_fd3_bytes(changed);
        } else if (mutation == "duplicate_phase") {
            std::vector<Byte> changed;
            for (std::size_t index = 0u; index < receipt_frames.size(); ++index) {
                changed.insert(changed.end(), receipt_frames[index].begin(), receipt_frames[index].end());
                if (index == 1u) {
                    changed.insert(changed.end(), receipt_frames[index].begin(), receipt_frames[index].end());
                }
            }
            value.append_drained_fd3_bytes(changed);
        } else if (mutation == "final_path") {
            std::vector<Byte> changed = receipt;
            const std::string needle = "fixture.cc";
            const auto found = std::find_end(changed.begin(), changed.end(), needle.begin(), needle.end());
            if (found == changed.end()) {
                throw std::runtime_error("missing fixture path");
            }
            *found = static_cast<Byte>('X');
            for (const std::vector<Byte>& frame : frames(changed)) {
                value.observe_fd3_write(frame, static_cast<std::int64_t>(frame.size()), 4096u, false);
            }
            value.append_drained_fd3_bytes(changed);
        } else if (mutation == "bad_path") {
            std::vector<Byte> changed = receipt;
            const std::string needle = "fixture.cc";
            const std::string replacement = "../ture.cc";
            const auto found = std::find_end(changed.begin(), changed.end(), needle.begin(), needle.end());
            if (found == changed.end() || replacement.size() != needle.size()) {
                throw std::runtime_error("missing fixture path");
            }
            std::copy(replacement.begin(), replacement.end(), found);
            for (const std::vector<Byte>& frame : frames(changed)) {
                value.observe_fd3_write(frame, static_cast<std::int64_t>(frame.size()), 4096u, false);
            }
            value.append_drained_fd3_bytes(changed);
        } else if (mutation == "nul_argv") {
            std::vector<Byte> changed = receipt;
            const std::string needle = "fixture.cc";
            const auto found = std::search(changed.begin(), changed.end(), needle.begin(), needle.end());
            if (found == changed.end()) {
                throw std::runtime_error("missing argv path");
            }
            *found = 0u;
            for (const std::vector<Byte>& frame : frames(changed)) {
                value.observe_fd3_write(frame, static_cast<std::int64_t>(frame.size()), 4096u, false);
            }
            value.append_drained_fd3_bytes(changed);
        } else if (mutation == "zero_write") {
            value.observe_fd3_write(receipt_frames[0], 0, 4096u, false);
        } else if (mutation == "overlong_write") {
            value.observe_fd3_write(receipt_frames[0],
                                    static_cast<std::int64_t>(receipt_frames[0].size() + 1u), 4096u,
                                    false);
        } else {
            throw std::runtime_error("unknown mutation");
        }
    } catch (const evaluation_v6_3_1::capture_v2::ReceiptStreamError&) {
        return true;
    }
    return false;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc != 4) {
            throw std::runtime_error("usage: HARNESS RECEIPT TRACE MODE");
        }
        const std::vector<Byte> receipt = read_file(argv[1]);
        const std::vector<Byte> trace = read_file(argv[2]);
        const std::string_view mode(argv[3]);
        if (mode == "valid" || mode == "chunked" || mode == "phase_mapping" ||
            mode == "after_eof") {
            Parser value = parser();
            if (mode == "phase_mapping") {
                const std::vector<std::vector<Byte>> receipt_frames = frames(receipt);
                const std::vector<std::uint64_t> trace_sizes = trace_results(trace);
                const std::array<evaluation_v6_3_1::capture_v2::Amendment8OpenPhase, 7>
                    expected_phases = {
                        evaluation_v6_3_1::capture_v2::Amendment8OpenPhase::PreDriver,
                        evaluation_v6_3_1::capture_v2::Amendment8OpenPhase::PreDriver,
                        evaluation_v6_3_1::capture_v2::Amendment8OpenPhase::Driver,
                        evaluation_v6_3_1::capture_v2::Amendment8OpenPhase::Driver,
                        evaluation_v6_3_1::capture_v2::Amendment8OpenPhase::Cc1,
                        evaluation_v6_3_1::capture_v2::Amendment8OpenPhase::PostCc1,
                        evaluation_v6_3_1::capture_v2::Amendment8OpenPhase::PostCc1,
                    };
                std::size_t phase_index = 0u;
                for (std::size_t index = 0u; index < receipt_frames.size(); ++index) {
                    value.observe_fd3_write(receipt_frames[index],
                                            static_cast<std::int64_t>(trace_sizes[index]), 4096u, false);
                    value.append_drained_fd3_bytes(receipt_frames[index]);
                    if (index == 1u || index == 3u || index == 4u || index == 6u ||
                        index == 7u || index == 8u || index == 9u) {
                        const auto phase = value.current_open_phase_mapping();
                        if (!phase.has_value() || phase->receipt_phase_ordinal != phase_index ||
                            phase->phase != expected_phases[phase_index]) {
                            throw std::runtime_error("incorrect effective Amendment-8 phase mapping");
                        }
                        ++phase_index;
                    }
                }
            } else {
                feed_valid(value, receipt, trace, mode == "chunked");
            }
            value.finish_fd3_eof();
            if (mode == "after_eof") {
                bool rejected = false;
                try {
                    value.append_drained_fd3_bytes(std::span<const Byte>{});
                } catch (const evaluation_v6_3_1::capture_v2::ReceiptStreamError&) {
                    rejected = true;
                }
                if (!rejected || !value.failed() || value.complete() ||
                    value.current_open_phase_mapping().has_value()) {
                    throw std::runtime_error("post-EOF misuse retained a successful parser state");
                }
                try {
                    static_cast<void>(value.exact_stream_bytes());
                    throw std::runtime_error("failed parser exposed exact receipt bytes");
                } catch (const evaluation_v6_3_1::capture_v2::ReceiptStreamError&) {
                }
                return 0;
            }
            const auto phase = value.current_open_phase_mapping();
            if (!value.complete() || !phase.has_value() ||
                phase->phase != evaluation_v6_3_1::capture_v2::Amendment8OpenPhase::PostCc1 ||
                value.exact_stream_bytes() != receipt || value.final_values().primary_source_relative_path != "fixture.cc" ||
                value.final_values().phase_transitions[6].event_sequence != 9u) {
                throw std::runtime_error("valid receipt did not produce complete exact state");
            }
            return 0;
        }
        return rejects(mode, receipt, trace) ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 2;
    }
}
