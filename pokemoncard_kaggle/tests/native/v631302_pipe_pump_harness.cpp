#include "PipePump.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace capture = evaluation_v6_3_1::capture_v2;

namespace {

using Id = capture::PipePump::ChannelId;
using Spec = capture::PipePump::ChannelSpec;

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

struct Pipe final {
    int read = -1;
    int write = -1;

    Pipe() {
        int descriptors[2]{};
        require(::pipe(descriptors) == 0, "pipe failed");
        for (const int descriptor : descriptors) {
            const int flags = ::fcntl(descriptor, F_GETFL);
            require(flags >= 0, "pipe flags failed");
            require(
                ::fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0,
                "pipe nonblocking setup failed");
            const int descriptor_flags = ::fcntl(descriptor, F_GETFD);
            require(descriptor_flags >= 0, "pipe descriptor flags failed");
            require(
                ::fcntl(descriptor, F_SETFD, descriptor_flags | FD_CLOEXEC) == 0,
                "pipe close-on-exec setup failed");
        }
        read = descriptors[0];
        write = descriptors[1];
    }

    ~Pipe() {
        if (read >= 0) static_cast<void>(::close(read));
        if (write >= 0) static_cast<void>(::close(write));
    }

    Pipe(const Pipe&) = delete;
    Pipe& operator=(const Pipe&) = delete;

    int release_read() {
        require(read >= 0, "read descriptor already released");
        const int descriptor = read;
        read = -1;
        return descriptor;
    }
};

void write_all(int descriptor, const std::vector<std::uint8_t>& bytes) {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const ssize_t count = ::write(
            descriptor,
            bytes.data() + offset,
            bytes.size() - offset);
        if (count > 0) {
            offset += static_cast<std::size_t>(count);
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            throw std::runtime_error("write failed");
        }
    }
}

void close_write(int& descriptor) {
    require(descriptor >= 0, "write descriptor already closed");
    require(::close(descriptor) == 0, "write close failed");
    descriptor = -1;
}

std::vector<Spec> specs(Pipe& stdout_pipe, Pipe& stderr_pipe, Pipe& receipt_pipe) {
    return {
        {Id::Receipt, receipt_pipe.release_read(), 16u * 1024u * 1024u},
        {Id::Stdout, stdout_pipe.release_read(), 64u * 1024u * 1024u},
        {Id::Stderr, stderr_pipe.release_read(), 32u},
    };
}

void test_fragmented_eagain_eof_and_snapshot() {
    Pipe stdout_pipe;
    Pipe stderr_pipe;
    Pipe receipt_pipe;
    const std::vector<std::uint8_t> stdout_bytes{0u, 1u, 2u, 0xffu, 0u};
    const std::vector<std::uint8_t> stderr_bytes{'d', 0u, 'i', 'a', 'g'};
    const std::vector<std::uint8_t> receipt_bytes{0xa5u, 0u, 0xb6u};

    capture::PipePump pump(specs(stdout_pipe, stderr_pipe, receipt_pipe));
    require(pump.read_descriptor(Id::Stdout) >= 0, "owned stdout descriptor unavailable for polling");
    pump.drain_ready(Id::Stdout);
    require(pump.snapshot().channels[1].bytes.empty(), "unexpected cross-channel bytes");

    write_all(
        stdout_pipe.write,
        std::vector<std::uint8_t>(stdout_bytes.begin(), stdout_bytes.begin() + 2));
    pump.drain_ready(Id::Stdout);
    write_all(
        stdout_pipe.write,
        std::vector<std::uint8_t>(stdout_bytes.begin() + 2, stdout_bytes.end()));
    write_all(stderr_pipe.write, stderr_bytes);
    write_all(receipt_pipe.write, receipt_bytes);
    pump.drain_until_eagain(Id::Stdout);
    pump.drain_ready(Id::Stderr);
    pump.drain_ready(Id::Receipt);
    require(!pump.all_eof(), "EAGAIN was mistaken for EOF");

    close_write(stdout_pipe.write);
    close_write(stderr_pipe.write);
    close_write(receipt_pipe.write);
    pump.drain_ready(Id::Stdout);
    pump.drain_ready(Id::Stderr);
    pump.drain_ready(Id::Receipt);
    require(pump.all_eof(), "not all EOFs were tracked");

    const auto snapshot = pump.snapshot();
    require(snapshot.channels.size() == 3u, "unexpected channel count");
    require(snapshot.channels[0].id == Id::Stdout, "snapshot is not ID ordered");
    require(snapshot.channels[1].id == Id::Stderr, "snapshot is not ID ordered");
    require(snapshot.channels[2].id == Id::Receipt, "snapshot is not ID ordered");
    require(snapshot.channels[0].bytes == stdout_bytes, "stdout bytes changed");
    require(snapshot.channels[1].bytes == stderr_bytes, "stderr bytes changed");
    require(snapshot.channels[2].bytes == receipt_bytes, "receipt bytes changed");
    require(
        snapshot.channels[0].total_bytes_seen == stdout_bytes.size() &&
            snapshot.channels[1].total_bytes_seen == stderr_bytes.size() &&
            snapshot.channels[2].total_bytes_seen == receipt_bytes.size(),
        "exact channel byte totals changed");
    require(
        snapshot.channels[0].overflow_probe.empty() &&
            snapshot.channels[1].overflow_probe.empty() &&
            snapshot.channels[2].overflow_probe.empty(),
        "successful channel retained an overflow probe");
    pump.finish_success();
    require(pump.complete(), "success was not recorded");
}

void test_cap_boundary_and_failure_is_terminal() {
    Pipe pipe;
    Pipe stderr_pipe;
    Pipe receipt_pipe;
    capture::PipePump pump({
        {Id::Stdout, pipe.release_read(), 4u},
        {Id::Stderr, stderr_pipe.release_read(), 0u},
        {Id::Receipt, receipt_pipe.release_read(), 8u},
    });
    write_all(pipe.write, {1u, 2u, 3u, 4u});
    pump.drain_ready(Id::Stdout);
    require(pump.channel_snapshot(Id::Stdout).bytes == std::vector<std::uint8_t>({1u, 2u, 3u, 4u}),
            "cap boundary rejected valid bytes");
    write_all(pipe.write, {5u});
    bool overflow = false;
    try {
        pump.drain_ready(Id::Stdout);
    } catch (const capture::PipePumpError& error) {
        overflow = error.failure() == capture::PipePumpFailure::CapOverflow;
    }
    require(overflow, "cap overflow was not rejected");
    const auto overflow_snapshot = pump.channel_snapshot(Id::Stdout);
    require(overflow_snapshot.total_bytes_seen == 5u, "overflow byte total was lost");
    require(
        overflow_snapshot.bytes == std::vector<std::uint8_t>({1u, 2u, 3u, 4u}) &&
            overflow_snapshot.overflow_probe == std::vector<std::uint8_t>({5u}),
        "overflow probe did not preserve the consumed diagnostic byte");
    bool terminal = false;
    try {
        pump.drain_ready(Id::Stdout);
    } catch (const capture::PipePumpError& error) {
        terminal = error.failure() == capture::PipePumpFailure::TerminalFailure;
    }
    require(terminal, "read after terminal failure was accepted");
}

void test_validation_and_premature_success() {
    Pipe first;
    Pipe second;
    auto expect = [](std::vector<Spec> channel_specs, capture::PipePumpFailure failure) {
        bool rejected = false;
        try {
            capture::PipePump pump(std::move(channel_specs));
        } catch (const capture::PipePumpError& error) {
            rejected = error.failure() == failure;
        }
        require(rejected, "invalid PipePump construction was accepted");
    };

    expect({{Id::Stdout, first.read, 4u}, {Id::Stdout, second.read, 4u}},
           capture::PipePumpFailure::DuplicateChannelId);
    expect({{Id::Stdout, first.read, 4u}, {Id::Stderr, first.read, 4u}},
           capture::PipePumpFailure::DuplicateDescriptor);
    expect({{Id::Stdout, -1, 4u}}, capture::PipePumpFailure::InvalidDescriptor);

    Pipe incomplete_pipe;
    expect(
        {{Id::Stdout, incomplete_pipe.read, 4u}},
        capture::PipePumpFailure::IncompleteChannelSet);

    Pipe blocking_pipe;
    const int flags = ::fcntl(blocking_pipe.read, F_GETFL);
    require(flags >= 0 && ::fcntl(blocking_pipe.read, F_SETFL, flags & ~O_NONBLOCK) == 0,
            "failed to make descriptor blocking");
    expect(
        {{Id::Stdout, blocking_pipe.release_read(), 4u}},
        capture::PipePumpFailure::NonBlockingRequired);

    Pipe premature_stderr;
    Pipe premature_receipt;
    capture::PipePump pump({
        {Id::Stdout, first.release_read(), 4u},
        {Id::Stderr, premature_stderr.release_read(), 4u},
        {Id::Receipt, premature_receipt.release_read(), 4u},
    });
    bool premature = false;
    try {
        pump.finish_success();
    } catch (const capture::PipePumpError& error) {
        premature = error.failure() == capture::PipePumpFailure::PrematureSuccess;
    }
    require(premature, "premature success was accepted");
    require(pump.failed(), "premature success was not terminal");
}

void test_deterministic_snapshots() {
    Pipe left_pipe;
    Pipe right_pipe;
    Pipe left_receipt_pipe;
    capture::PipePump left({
        {Id::Stderr, left_pipe.release_read(), 8u},
        {Id::Stdout, right_pipe.release_read(), 8u},
        {Id::Receipt, left_receipt_pipe.release_read(), 8u},
    });
    Pipe second_left_pipe;
    Pipe second_right_pipe;
    Pipe right_receipt_pipe;
    capture::PipePump right({
        {Id::Stdout, second_right_pipe.release_read(), 8u},
        {Id::Stderr, second_left_pipe.release_read(), 8u},
        {Id::Receipt, right_receipt_pipe.release_read(), 8u},
    });
    write_all(left_pipe.write, {7u, 0u});
    write_all(right_pipe.write, {8u});
    write_all(second_left_pipe.write, {7u, 0u});
    write_all(second_right_pipe.write, {8u});
    left.drain_ready(Id::Stdout);
    left.drain_ready(Id::Stderr);
    right.drain_ready(Id::Stdout);
    right.drain_ready(Id::Stderr);
    require(left.snapshot() == right.snapshot(), "snapshots are not deterministic");
}

}  // namespace

int main() {
    try {
        test_fragmented_eagain_eof_and_snapshot();
        test_cap_boundary_and_failure_is_terminal();
        test_validation_and_premature_success();
        test_deterministic_snapshots();
    } catch (const std::exception& error) {
        std::cerr << "pipe_pump_harness_failure: " << error.what() << '\n';
        return 1;
    }
    std::cout << "pipe_pump_harness_ok zero_authority=1\n";
    return 0;
}
