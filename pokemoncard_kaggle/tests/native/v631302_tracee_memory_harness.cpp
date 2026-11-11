#include "TraceeMemory.h"

#include <array>
#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace capture = evaluation_v6_3_1::capture_v2;

namespace {

constexpr std::size_t kPageBytes = 4096u;
constexpr std::size_t kFixedLength = 64u;
constexpr std::string_view kString = "capture-v2-tracee-memory";
constexpr std::array<std::uint8_t, kFixedLength> kFixedBytes = [] {
    std::array<std::uint8_t, kFixedLength> bytes{};
    for (std::size_t index = 0u; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::uint8_t>('A' + (index % 26u));
    }
    return bytes;
}();

struct ChildReport final {
    std::uintptr_t fixed_address = 0u;
    std::size_t fixed_length = 0u;
    std::uintptr_t string_address = 0u;
    std::size_t string_length_with_nul = 0u;
    std::uintptr_t no_nul_address = 0u;
    std::size_t no_nul_length = 0u;
    std::uintptr_t partial_address = 0u;
};

class StoppedChild final {
public:
    explicit StoppedChild(pid_t pid) noexcept : pid_(pid) {}
    ~StoppedChild() noexcept {
        if (pid_ <= 0) {
            return;
        }
        static_cast<void>(::kill(pid_, SIGKILL));
        int status = 0;
        while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {
        }
    }

    StoppedChild(const StoppedChild&) = delete;
    StoppedChild& operator=(const StoppedChild&) = delete;

    [[nodiscard]] pid_t pid() const noexcept { return pid_; }

private:
    pid_t pid_ = -1;
};

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void write_exact(int descriptor, const void* data, std::size_t length) {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::size_t offset = 0u;
    while (offset < length) {
        const ssize_t count = ::write(descriptor, bytes + offset, length - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        require(count > 0, "child report write failed");
        offset += static_cast<std::size_t>(count);
    }
}

void read_exact(int descriptor, void* data, std::size_t length) {
    auto* bytes = static_cast<std::uint8_t*>(data);
    std::size_t offset = 0u;
    while (offset < length) {
        const ssize_t count = ::read(descriptor, bytes + offset, length - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        require(count > 0, "child report read failed");
        offset += static_cast<std::size_t>(count);
    }
}

int child_main(int report_writer) {
    void* mapping = ::mmap(
        nullptr,
        2u * kPageBytes,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0);
    if (mapping == MAP_FAILED) {
        return 120;
    }

    auto* base = static_cast<std::uint8_t*>(mapping);
    auto* fixed = base + kPageBytes - (kFixedLength / 2u);
    std::memcpy(fixed, kFixedBytes.data(), kFixedBytes.size());

    std::array<char, kString.size() + 1u> string_bytes{};
    std::memcpy(string_bytes.data(), kString.data(), kString.size());
    string_bytes[kString.size()] = '\0';

    std::array<std::uint8_t, 8u> no_nul{};
    no_nul.fill(static_cast<std::uint8_t>('x'));

    ChildReport report{
        reinterpret_cast<std::uintptr_t>(fixed),
        kFixedLength,
        reinterpret_cast<std::uintptr_t>(string_bytes.data()),
        string_bytes.size(),
        reinterpret_cast<std::uintptr_t>(no_nul.data()),
        no_nul.size(),
        reinterpret_cast<std::uintptr_t>(base + (2u * kPageBytes) - 1u),
    };
    write_exact(report_writer, &report, sizeof(report));
    static_cast<void>(::close(report_writer));
    if (::raise(SIGSTOP) != 0) {
        return 121;
    }
    for (;;) {
        static_cast<void>(::pause());
    }
}

StoppedChild launch_child(ChildReport& report) {
    int report_pipe[2]{};
    require(::pipe(report_pipe) == 0, "report pipe failed");
    const pid_t pid = ::fork();
    require(pid >= 0, "fork failed");
    if (pid == 0) {
        static_cast<void>(::close(report_pipe[0]));
        const int result = child_main(report_pipe[1]);
        _exit(result);
    }

    static_cast<void>(::close(report_pipe[1]));
    try {
        read_exact(report_pipe[0], &report, sizeof(report));
        require(::close(report_pipe[0]) == 0, "report pipe close failed");
    } catch (...) {
        static_cast<void>(::close(report_pipe[0]));
        static_cast<void>(::kill(pid, SIGKILL));
        int status = 0;
        while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
        }
        throw;
    }

    int status = 0;
    require(::waitpid(pid, &status, WUNTRACED) == pid, "stopped child wait failed");
    require(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP, "child did not stop");
    return StoppedChild(pid);
}

template <typename Operation>
void require_rejected(Operation&& operation, capture::SupervisorFailure expected, const char* message) {
    bool rejected = false;
    try {
        operation();
    } catch (const capture::SupervisorError& error) {
        rejected = error.failure() == expected;
    }
    require(rejected, message);
}

template <typename Operation>
void require_any_rejection(Operation&& operation, const char* message) {
    bool rejected = false;
    try {
        operation();
    } catch (const capture::SupervisorError&) {
        rejected = true;
    }
    require(rejected, message);
}

bool unavailable(const capture::SupervisorError& error) {
    return error.failure() == capture::SupervisorFailure::SystemFailure &&
           (error.system_errno() == ENOSYS || error.system_errno() == EPERM ||
            error.system_errno() == EACCES);
}

void test_valid_reads(pid_t pid, const ChildReport& report) {
    capture::TraceeMemory memory(pid);
    const std::vector<std::uint8_t> fixed = memory.exact_bytes(
        report.fixed_address,
        report.fixed_length,
        report.fixed_length);
    require(fixed.size() == kFixedBytes.size(), "fixed read length mismatch");
    require(std::equal(fixed.begin(), fixed.end(), kFixedBytes.begin()), "fixed read bytes mismatch");
    const std::string string = memory.nul_terminated_string(
        report.string_address,
        report.string_length_with_nul);
    require(string == kString, "NUL-terminated read mismatch");
    const std::vector<std::uint8_t> repeated = memory.exact_bytes(
        report.fixed_address,
        report.fixed_length,
        report.fixed_length);
    require(repeated == fixed, "repeated successful read changed bytes");
}

void test_failure_mutations(pid_t pid, const ChildReport& report) {
    require_rejected(
        [&] { static_cast<void>(capture::TraceeMemory(pid).exact_bytes(0u, 1u, 1u)); },
        capture::SupervisorFailure::InvalidRequest,
        "null remote address was accepted");
    require_rejected(
        [&] { static_cast<void>(capture::TraceeMemory(pid).exact_bytes(report.fixed_address, 0u, 1u)); },
        capture::SupervisorFailure::InvalidRequest,
        "zero exact length was accepted");
    require_rejected(
        [&] { static_cast<void>(capture::TraceeMemory(pid).exact_bytes(report.fixed_address, 2u, 1u)); },
        capture::SupervisorFailure::ResourceLimit,
        "over-cap exact length was accepted");
    require_rejected(
        [&] {
            static_cast<void>(capture::TraceeMemory(pid).exact_bytes(
                std::numeric_limits<std::uintptr_t>::max(),
                2u,
                2u));
        },
        capture::SupervisorFailure::InvalidRequest,
        "address arithmetic overflow was accepted");
    require_any_rejection(
        [&] {
            static_cast<void>(capture::TraceeMemory(pid).exact_bytes(
                report.partial_address,
                2u,
                2u));
        },
        "partial read was accepted");
    require_rejected(
        [&] {
            static_cast<void>(capture::TraceeMemory(pid).nul_terminated_string(
                report.no_nul_address,
                report.no_nul_length));
        },
        capture::SupervisorFailure::ProtocolViolation,
        "missing NUL was accepted");

    capture::TraceeMemory terminal(pid);
    require_rejected(
        [&] { static_cast<void>(terminal.exact_bytes(0u, 1u, 1u)); },
        capture::SupervisorFailure::InvalidRequest,
        "terminal mutation was not rejected");
    require_rejected(
        [&] {
            static_cast<void>(terminal.exact_bytes(
                report.fixed_address,
                report.fixed_length,
                report.fixed_length));
        },
        capture::SupervisorFailure::ProtocolViolation,
        "failed reader was reusable");
    require(terminal.state() == capture::TraceeMemory::State::Failed, "failed state was not retained");
}

}  // namespace

int main() {
    try {
        ChildReport report{};
        StoppedChild child = launch_child(report);
        try {
            test_valid_reads(child.pid(), report);
            test_failure_mutations(child.pid(), report);
        } catch (const capture::SupervisorError& error) {
            if (unavailable(error)) {
                std::cout << "tracee_memory_harness_skipped process_vm_readv_unavailable=1 errno="
                          << error.system_errno() << '\n';
                return 77;
            }
            throw;
        }
    } catch (const std::exception& error) {
        std::cerr << "tracee memory harness failure: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "tracee_memory_harness_ok zero_authority=1\n";
    return EXIT_SUCCESS;
}
