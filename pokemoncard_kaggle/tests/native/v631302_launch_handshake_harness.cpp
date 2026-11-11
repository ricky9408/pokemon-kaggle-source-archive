#include "LaunchHandshake.h"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <sys/wait.h>
#include <unistd.h>

namespace capture = evaluation_v6_3_1::capture_v2;

namespace {

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

capture::LaunchReadyRecord ready() {
    capture::Sha256Digest digest{};
    for (std::size_t index = 0u; index < digest.size(); ++index) {
        digest[index] = static_cast<std::uint8_t>(index + 1u);
    }
    return capture::LaunchReadyRecord{
        capture::LaunchReadyStatus::Ready, 0u, 11u, 12u, 13u, 14u, 15u, digest};
}

void test_round_trip_and_pipe() {
    const auto expected = ready();
    const auto wire = capture::LaunchHandshake::encode(expected);
    require(capture::LaunchHandshake::decode(wire) == expected, "ready record round trip failed");
    int descriptors[2]{};
    require(::pipe(descriptors) == 0, "pipe failed");
    const pid_t child = ::fork();
    require(child >= 0, "fork failed");
    if (child == 0) {
        static_cast<void>(::close(descriptors[0]));
        try {
            capture::LaunchHandshake::write_one(descriptors[1], expected);
            ::_exit(0);
        } catch (...) {
            ::_exit(1);
        }
    }
    static_cast<void>(::close(descriptors[1]));
    require(capture::LaunchHandshake::read_one(descriptors[0]) == expected, "pipe record changed");
    static_cast<void>(::close(descriptors[0]));
    int status = 0;
    require(::waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "writer child failed");
}

void test_failure_and_mutations() {
    const capture::LaunchReadyRecord failure{
        capture::LaunchReadyStatus::Failed, 11u, 0u, 0u, 0u, 0u, 0u, {}};
    require(capture::LaunchHandshake::decode(capture::LaunchHandshake::encode(failure)) == failure,
            "failure record round trip failed");
    auto bad_magic = capture::LaunchHandshake::encode(ready());
    bad_magic[0] ^= 1u;
    bool rejected = false;
    try {
        static_cast<void>(capture::LaunchHandshake::decode(bad_magic));
    } catch (const capture::SupervisorError&) {
        rejected = true;
    }
    require(rejected, "bad magic was accepted");
    auto noncanonical = ready();
    noncanonical.failure_code = 1u;
    rejected = false;
    try {
        static_cast<void>(capture::LaunchHandshake::encode(noncanonical));
    } catch (const capture::SupervisorError&) {
        rejected = true;
    }
    require(rejected, "noncanonical success was accepted");
}

}  // namespace

int main() {
    try {
        test_round_trip_and_pipe();
        test_failure_and_mutations();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    std::cout << "launch_handshake_harness_ok zero_authority=1\n";
    return 0;
}
