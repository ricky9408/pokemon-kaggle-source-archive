#include "NativePrelaunchHandoff.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace capture = evaluation_v6_3_1::capture_v2;

namespace {

using Byte = std::uint8_t;

[[noreturn]] void fail(std::string_view message) {
    std::cerr << "native_amendment5_failure=" << message << '\n';
    std::exit(1);
}

Byte nibble(char value) {
    if (value >= '0' && value <= '9') {
        return static_cast<Byte>(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return static_cast<Byte>(value - 'a' + 10);
    }
    fail("input is not lowercase hexadecimal");
}

std::vector<Byte> decode_hex(std::string_view value) {
    if (value.empty() || value.size() % 2u != 0u) fail("input hex width is invalid");
    std::vector<Byte> result;
    result.reserve(value.size() / 2u);
    for (std::size_t index = 0u; index < value.size(); index += 2u) {
        result.push_back(static_cast<Byte>(
            (nibble(value[index]) << 4u) | nibble(value[index + 1u])));
    }
    return result;
}

std::vector<Byte> read_bytes(std::string_view path) {
    std::ifstream input(std::string(path), std::ios::binary);
    if (!input) fail("handoff file cannot be opened");
    const std::vector<char> raw(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>());
    std::vector<Byte> result;
    result.reserve(raw.size());
    for (const char value : raw) {
        result.push_back(static_cast<Byte>(static_cast<unsigned char>(value)));
    }
    return result;
}

std::string encode_hex(std::span<const Byte> value) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string result;
    result.reserve(value.size() * 2u);
    for (const Byte byte : value) {
        result.push_back(kDigits[byte >> 4u]);
        result.push_back(kDigits[byte & 0x0fu]);
    }
    return result;
}

void require(bool condition, std::string_view message) {
    if (!condition) fail(message);
}

void accept(std::span<const Byte> handoff) {
    capture::RawPrelaunchRequest raw =
        capture::NativePrelaunchHandoff::decode(handoff);
    capture::ValidatedPrelaunchPlan plan =
        capture::ValidatedPrelaunchPlan::validate(std::move(raw));
    require(plan.public_file_rows().size() == 5u, "topology does not have five rows");
    for (const capture::DecodedPublicFileRow& row : plan.public_file_rows()) {
        require(row.namespace_relative_path != "bin/clang-tool",
                "retired fake clang executable row survived");
    }
    require(plan.requested_argv().front() == "/bin/clang-tool",
            "logical driver argv0 changed");
    require(plan.absolute_primary_source() == "/src/Export.cpp",
            "absolute primary derivation differs");
    const std::vector<std::string>& launch = plan.collector_launch_argv();
    require(launch.size() == plan.requested_argv().size() + 6u,
            "collector wrapper width differs");
    require(launch[0] == "/bin/collector" &&
                launch[1] == "--protocol=631302" &&
                launch[2] == "--level=2" &&
                launch[3] == "--primary-source=/src/Export.cpp" &&
                launch[5] == "--",
            "collector wrapper prefix differs");
    require(launch[4] == "--capture-context-v1-cbor-hex=" +
                             encode_hex(plan.capture_context_cbor_bytes()),
            "collector context option differs");
    require(std::equal(
                plan.requested_argv().begin(),
                plan.requested_argv().end(),
                launch.begin() + 6),
            "inner driver argv was not preserved after the separator");

    std::cout << "status=accepted\n";
    std::cout << "absolute_primary=" << plan.absolute_primary_source() << '\n';
    std::cout << "context_hex="
              << encode_hex(plan.capture_context_cbor_bytes()) << '\n';
    std::cout << "launch_argc=" << launch.size() << '\n';
    for (std::size_t index = 0u; index < launch.size(); ++index) {
        std::cout << "launch_" << index << '='
                  << encode_hex(std::span<const Byte>(
                         reinterpret_cast<const Byte*>(launch[index].data()),
                         launch[index].size()))
                  << '\n';
    }
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) fail("usage: harness MODE HANDOFF_HEX");
    const std::string_view mode(argv[1]);
    const std::string_view handoff_argument(argv[2]);
    const std::vector<Byte> handoff =
        handoff_argument.starts_with('@')
            ? read_bytes(handoff_argument.substr(1u))
            : decode_hex(handoff_argument);
    try {
        accept(handoff);
        if (mode == "reject") fail("invalid handoff was accepted");
    } catch (const capture::SupervisorError& error) {
        if (mode != "reject") {
            std::cerr << "native_supervisor_error=" << error.what() << '\n';
            fail("valid handoff was rejected");
        }
        std::cout << "status=rejected\n";
    } catch (...) {
        fail("handoff escaped through a non-supervisor exception");
    }
    std::cout << "native_amendment5_harness_ok zero_authority=1\n";
    return 0;
}
