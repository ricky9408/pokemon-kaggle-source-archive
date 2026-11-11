#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "LaunchEngine.h"
#include "PtraceExecAuthenticator.h"
#include "PtraceOpenSupervisor.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/SHA256.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <type_traits>
#include <unistd.h>
#include <vector>

namespace capture = evaluation_v6_3_1::capture_v2;
using Byte = std::uint8_t;

static_assert(
    capture::RuntimeObserverLimits{}.maximum_unique_runtime_bytes == 4'294'967'296ull);
static_assert(
    capture::RuntimeObserverLimits{}.maximum_authenticated_runtime_bytes == 17'179'869'184ull);
static_assert(!std::is_copy_constructible_v<capture::CompletedNativeCaptureObservations>);
static_assert(std::is_move_constructible_v<capture::CompletedNativeCaptureObservations>);
static_assert(!std::is_move_assignable_v<capture::CompletedNativeCaptureObservations>);

namespace {

constexpr std::string_view kTraceePath = "/work/tracee";
constexpr std::string_view kRuntimeTraceePath = "/work/runtime-tracee";
constexpr std::string_view kRuntimePrimaryPath = "/work/libclang-cpp.so.16";
constexpr std::string_view kRuntimeInterpreterPath = "/lib64/ld-linux-x86-64.so.2";
constexpr std::string_view kRuntimeLibcPath = "/lib/x86_64-linux-gnu/libc.so.6";
constexpr std::string_view kFixture = "int value = 7;\n";

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

class TempTree final {
public:
    TempTree() {
        std::array<char, 64> pattern{};
        constexpr std::string_view prefix = "/tmp/v631302-launch-engine-XXXXXX";
        std::copy(prefix.begin(), prefix.end(), pattern.begin());
        require(::mkdtemp(pattern.data()) != nullptr, "mkdtemp failed");
        path_ = pattern.data();
        std::filesystem::create_directory(path_ / "original");
        std::filesystem::create_directory(path_ / "stage");
        require(::chmod((path_ / "stage").c_str(), 0700) == 0, "stage chmod failed");
    }

    ~TempTree() { std::filesystem::remove_all(path_); }

    TempTree(const TempTree&) = delete;
    TempTree& operator=(const TempTree&) = delete;

    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

void write_all(int descriptor, const std::uint8_t* bytes, std::size_t length) {
    std::size_t offset = 0u;
    while (offset < length) {
        const ssize_t written = ::write(descriptor, bytes + offset, length - offset);
        if (written > 0) {
            offset += static_cast<std::size_t>(written);
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        throw std::runtime_error("write failed");
    }
}

std::vector<std::uint8_t> read_all(const std::filesystem::path& path) {
    const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    require(descriptor >= 0, "open source failed");
    std::vector<std::uint8_t> bytes;
    std::array<std::uint8_t, 64u * 1024u> buffer{};
    for (;;) {
        const ssize_t count = ::read(descriptor, buffer.data(), buffer.size());
        if (count > 0) {
            const auto length = static_cast<std::size_t>(count);
            bytes.insert(bytes.end(), buffer.begin(), buffer.begin() + length);
            continue;
        }
        if (count == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        static_cast<void>(::close(descriptor));
        throw std::runtime_error("read source failed");
    }
    require(::close(descriptor) == 0, "close source failed");
    return bytes;
}

void copy_immutable_file(
    const std::filesystem::path& source,
    const std::filesystem::path& destination,
    mode_t mode) {
    const std::vector<std::uint8_t> bytes = read_all(source);
    const int descriptor = ::open(
        destination.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);
    require(descriptor >= 0, "create immutable original failed");
    try {
        write_all(descriptor, bytes.data(), bytes.size());
        require(::fchmod(descriptor, mode) == 0, "immutable original chmod failed");
        require(::fsync(descriptor) == 0, "immutable original fsync failed");
        require(::close(descriptor) == 0, "immutable original close failed");
    } catch (...) {
        static_cast<void>(::close(descriptor));
        throw;
    }
}

capture::Sha256Digest sha256(const std::vector<std::uint8_t>& bytes) {
    llvm::SHA256 hasher;
    hasher.update(llvm::ArrayRef<std::uint8_t>(bytes.data(), bytes.size()));
    return hasher.final();
}

int open_original_root(const TempTree& tree) {
    return ::open(
        (tree.path() / "original").c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
}

std::vector<capture::RetainedInputSpec> retained_specs(
    int original_root,
    const std::string& collector_original_path) {
    return {
        {original_root, collector_original_path, "bin/collector", {1u}, 0555u},
        {original_root, "runtime-interpreter", "lib/ld-linux-x86-64.so.2", {6u}, 0444u},
        {original_root, "runtime-libc", "lib/libc.so.6", {8u}, 0444u},
        {original_root, "runtime-primary", "lib/libclang-cpp.so.16", {7u, 8u}, 0444u},
        {original_root, "Export.cpp", "src/Export.cpp", {2u, 3u}, 0444u},
    };
}

void append_cbor_head(std::vector<Byte>& output, Byte major, std::uint64_t value) {
    if (value < 24u) {
        output.push_back(static_cast<Byte>((major << 5u) | static_cast<Byte>(value)));
        return;
    }
    if (value <= 0xffu) {
        output.push_back(static_cast<Byte>((major << 5u) | 24u));
        output.push_back(static_cast<Byte>(value));
        return;
    }
    if (value <= 0xffffu) {
        output.push_back(static_cast<Byte>((major << 5u) | 25u));
        output.push_back(static_cast<Byte>(value >> 8u));
        output.push_back(static_cast<Byte>(value));
        return;
    }
    if (value <= 0xffffffffULL) {
        output.push_back(static_cast<Byte>((major << 5u) | 26u));
        for (int shift = 24; shift >= 0; shift -= 8) {
            output.push_back(static_cast<Byte>(value >> static_cast<unsigned>(shift)));
        }
        return;
    }
    output.push_back(static_cast<Byte>((major << 5u) | 27u));
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<Byte>(value >> static_cast<unsigned>(shift)));
    }
}

void append_cbor_uint(std::vector<Byte>& output, std::uint64_t value) {
    append_cbor_head(output, 0u, value);
}

void append_cbor_bytes(std::vector<Byte>& output, const Byte* data, std::size_t size) {
    append_cbor_head(output, 2u, size);
    output.insert(output.end(), data, data + size);
}

void append_cbor_text(std::vector<Byte>& output, const std::string& value) {
    append_cbor_head(output, 3u, value.size());
    output.insert(output.end(), value.begin(), value.end());
}

void append_cbor_array(std::vector<Byte>& output, std::size_t size) {
    append_cbor_head(output, 4u, size);
}

std::vector<Byte> path_profile_for() {
    std::vector<Byte> output;
    append_cbor_array(output, 4u);
    append_cbor_uint(output, 2u);
    append_cbor_text(output, "/src");
    append_cbor_text(output, "/work");
    append_cbor_text(output, "/bin");
    return output;
}

std::vector<Byte> collector_profile_for_testing(
    const capture::Sha256Digest& collector_digest,
    const capture::Sha256Digest& libclang_digest) {
    std::vector<Byte> output;
    append_cbor_array(output, 8u);
    append_cbor_bytes(output, collector_digest.data(), collector_digest.size());
    append_cbor_text(output, "collector-profile-v1");
    append_cbor_bytes(output, libclang_digest.data(), libclang_digest.size());
    append_cbor_uint(output, 16u);
    append_cbor_uint(output, 2u);
    append_cbor_array(output, 0u);
    const std::array<Byte, 32u> exact_statistics_root = {0x16u};
    append_cbor_bytes(
        output, exact_statistics_root.data(), exact_statistics_root.size());
    append_cbor_array(output, 0u);
    return output;
}

std::vector<std::string> requested_argv() {
    return {
        "/bin/clang-tool",
        "-std=c++20",
        "-fsyntax-only",
        "-nostdinc",
        "-I",
        "/src",
        "/src/Export.cpp",
        "-resource-dir=/lib/clang/16",
        "--no-default-config",
    };
}

std::vector<Byte> capture_context_for() {
    std::vector<Byte> output;
    append_cbor_array(output, 3u);
    append_cbor_uint(output, 1u);
    append_cbor_text(output, "src/Export.cpp");
    const std::vector<Byte> profile = path_profile_for();
    output.insert(output.end(), profile.begin(), profile.end());
    return output;
}

std::string lowercase_hex(const std::vector<Byte>& bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string output;
    output.reserve(bytes.size() * 2u);
    for (const Byte byte : bytes) {
        output.push_back(kDigits[byte >> 4u]);
        output.push_back(kDigits[byte & 0x0fu]);
    }
    return output;
}

std::vector<std::string> expected_collector_launch_argv() {
    std::vector<std::string> output = {
        "/bin/collector",
        "--protocol=631302",
        "--level=2",
        "--primary-source=/src/Export.cpp",
        "--capture-context-v1-cbor-hex=" + lowercase_hex(capture_context_for()),
        "--",
    };
    const std::vector<std::string> inner = requested_argv();
    output.insert(output.end(), inner.begin(), inner.end());
    return output;
}

std::vector<Byte> public_rows_cbor(
    const std::vector<capture::NamespaceFileExpectation>& rows) {
    std::vector<Byte> output;
    append_cbor_array(output, rows.size());
    for (const capture::NamespaceFileExpectation& row : rows) {
        append_cbor_array(output, 5u);
        append_cbor_text(output, row.namespace_relative_path);
        append_cbor_array(output, row.role_codes.size());
        for (const std::uint32_t role : row.role_codes) {
            append_cbor_uint(output, role);
        }
        append_cbor_uint(output, row.normalized_mode);
        append_cbor_uint(output, row.byte_length);
        append_cbor_bytes(output, row.sha256.data(), row.sha256.size());
    }
    return output;
}

capture::HarnessExpectations structural_harness_expectations(
    const capture::Sha256Digest& digest_value,
    std::uint64_t byte_length) {
    const std::vector<Byte> build_id = {0x63u, 0x13u, 0x02u, 0x01u};
    return {
        {byte_length, digest_value, build_id},
        {byte_length, digest_value, build_id},
        {byte_length, digest_value, build_id},
    };
}

struct LaunchFixtureInputs final {
    capture::ValidatedPrelaunchPlan plan;
    capture::LaunchRuntimeConfiguration runtime;
};

capture::NamespaceFileExpectation namespace_row(
    const std::string& path,
    std::vector<std::uint32_t> roles,
    std::uint32_t mode,
    const std::vector<std::uint8_t>& bytes);

LaunchFixtureInputs request_for(
    const TempTree& tree,
    const std::string& collector_original_path,
    const capture::Sha256Digest* collector_digest_override = nullptr,
    bool runtime_limits = false) {
    const std::vector<std::uint8_t> collector =
        read_all(tree.path() / "original" / collector_original_path);
    const std::vector<std::uint8_t> interpreter =
        read_all(tree.path() / "original" / "runtime-interpreter");
    const std::vector<std::uint8_t> libc =
        read_all(tree.path() / "original" / "runtime-libc");
    const std::vector<std::uint8_t> libclang =
        read_all(tree.path() / "original" / "runtime-primary");
    const std::vector<std::uint8_t> fixture(kFixture.begin(), kFixture.end());
    const capture::Sha256Digest collector_digest =
        collector_digest_override == nullptr
            ? sha256(collector)
            : *collector_digest_override;
    const capture::Sha256Digest libclang_digest = sha256(libclang);
    const std::vector<capture::NamespaceFileExpectation> rows = {
        {"bin/collector", {1u}, 0555u, static_cast<std::uint64_t>(collector.size()), collector_digest},
        namespace_row("lib/ld-linux-x86-64.so.2", {6u}, 0444u, interpreter),
        namespace_row("lib/libc.so.6", {8u}, 0444u, libc),
        namespace_row("lib/libclang-cpp.so.16", {7u, 8u}, 0444u, libclang),
        namespace_row("src/Export.cpp", {2u, 3u}, 0444u, fixture),
    };
    const std::vector<Byte> expected_collector_gnu_build_id_descriptor = {
        0x63u, 0x13u, 0x02u, 0x01u};
    capture::Sha256Digest32 validated_prelaunch_expectations_root{};
    validated_prelaunch_expectations_root.fill(0xa5u);
    capture::RawPrelaunchRequest raw = capture::RawPrelaunchRequest::copy_from(
        "collector-profile-v1",
        expected_collector_gnu_build_id_descriptor,
        validated_prelaunch_expectations_root,
        collector_profile_for_testing(collector_digest, libclang_digest),
        capture::ValidatedPrelaunchPlan::kFrozenArgvGrammarVersionV1,
        capture::ValidatedPrelaunchPlan::kFrozenArgvGrammarSha256V1,
        path_profile_for(),
        "work",
        "src/Export.cpp",
        public_rows_cbor(rows),
        requested_argv(),
        structural_harness_expectations(
            collector_digest,
            static_cast<std::uint64_t>(collector.size())));
    return LaunchFixtureInputs{
        capture::ValidatedPrelaunchPlan::validate(std::move(raw)),
        capture::LaunchRuntimeConfiguration{
            (tree.path() / "stage").string(),
            runtime_limits ? 64u * 1024u * 1024u : 1u << 20u,
            capture::kRawCollectorCaptureMaxBytesV1,
            4u * 1024u * 1024u,
            16u * 1024u * 1024u,
            runtime_limits ? 20'000u : 10'000u,
            runtime_limits ? 20'000u : 10'000u,
            runtime_limits ? 20'000u : 10'000u,
            runtime_limits ? 64u * 1024u * 1024u : 1u << 20u,
        },
    };
}

capture::NamespaceFileExpectation namespace_row(
    const std::string& path,
    std::vector<std::uint32_t> roles,
    std::uint32_t mode,
    const std::vector<std::uint8_t>& bytes) {
    return capture::NamespaceFileExpectation{
        path,
        std::move(roles),
        mode,
        static_cast<std::uint64_t>(bytes.size()),
        sha256(bytes),
    };
}

LaunchFixtureInputs runtime_request_for(const TempTree& tree) {
    return request_for(tree, "runtime-collector", nullptr, true);
}

std::unique_ptr<capture::PreparedLaunch> prepare_fixture(
    capture::RetainedInputSet retained,
    LaunchFixtureInputs inputs) {
    return capture::LaunchEngine::prepare(
        std::move(retained),
        std::move(inputs.plan),
        std::move(inputs.runtime));
}

bool syscall_available(long number, long first_argument, long second_argument) {
    errno = 0;
    const long result = ::syscall(number, first_argument, second_argument);
    if (result >= 0) {
        static_cast<void>(::close(static_cast<int>(result)));
        return true;
    }
    return errno != ENOSYS && errno != EPERM;
}

bool clone3_available() {
    errno = 0;
    const long result = ::syscall(SYS_clone3, nullptr, 0u);
    if (result >= 0) {
        throw std::runtime_error("clone3 probe unexpectedly created a child");
    }
    return errno != ENOSYS && errno != EPERM;
}

bool pidfd_available() {
    return syscall_available(SYS_pidfd_open, static_cast<long>(::getpid()), 0L);
}

bool pidfd_getfd_available() {
    const long raw_pidfd = ::syscall(SYS_pidfd_open, static_cast<long>(::getpid()), 0L);
    if (raw_pidfd < 0) {
        return false;
    }
    const int pidfd = static_cast<int>(raw_pidfd);
    const long duplicate = ::syscall(SYS_pidfd_getfd, pidfd, STDOUT_FILENO, 0u);
    const int saved_errno = errno;
    static_cast<void>(::close(pidfd));
    if (duplicate >= 0) {
        static_cast<void>(::close(static_cast<int>(duplicate)));
        return true;
    }
    errno = saved_errno;
    return false;
}

[[noreturn]] void skip_kernel_features(bool clone3, bool pidfd, bool pidfd_getfd) {
    std::cout << "launch_engine_skipped clone3_unavailable=" << (!clone3 ? 1 : 0)
              << " pidfd_unavailable=" << (!pidfd ? 1 : 0)
              << " pidfd_getfd_unavailable=" << (!pidfd_getfd ? 1 : 0)
              << " zero_authority=1\n";
    std::exit(77);
}

void run_valid(const TempTree& tree, const std::vector<std::uint8_t>& collector) {
    const int root = open_original_root(tree);
    require(root >= 0, "open original root failed");
    try {
        auto retained = capture::RetainedInputSet::acquire(
            retained_specs(root, "collector"));
        const auto digest = sha256(collector);
        auto prepared = prepare_fixture(
            std::move(retained), request_for(tree, "collector"));
        auto stopped = capture::PtraceExecAuthenticator::reach_authenticated_exec(
            std::move(prepared), 10'000u);
        capture::PreparedLaunch& launch = stopped->launch();
        require(launch.ready_record().root_device != 0u, "ready root device is zero");
        require(launch.ready_record().root_inode != 0u, "ready root inode is zero");
        require(
            launch.ready_record().working_directory_device != 0u,
            "ready cwd device is zero");
        require(
            launch.ready_record().working_directory_inode != 0u,
            "ready cwd inode is zero");
        require(
            launch.ready_record().collector_byte_length == collector.size(),
            "ready collector length changed");
        require(launch.ready_record().collector_sha256 == digest, "ready collector digest changed");
        const auto fixture_digest = sha256(
            std::vector<std::uint8_t>(kFixture.begin(), kFixture.end()));
        require(launch.namespace_identity_rows().size() == 5u,
                "namespace identity coverage changed");
        constexpr std::array<std::string_view, 5u> expected_paths = {
            "bin/collector",
            "lib/ld-linux-x86-64.so.2",
            "lib/libc.so.6",
            "lib/libclang-cpp.so.16",
            "src/Export.cpp",
        };
        constexpr std::array<std::uint32_t, 5u> expected_modes = {
            0555u, 0444u, 0444u, 0444u, 0444u};
        static const std::array<std::vector<std::uint32_t>, 5u> expected_roles = {
            std::vector<std::uint32_t>{1u},
            std::vector<std::uint32_t>{6u},
            std::vector<std::uint32_t>{8u},
            std::vector<std::uint32_t>{7u, 8u},
            std::vector<std::uint32_t>{2u, 3u},
        };
        require(
            launch.expected_namespace_files().size() == expected_paths.size(),
            "expected namespace topology width changed");
        for (std::size_t index = 0u; index < expected_paths.size(); ++index) {
            const auto& row = launch.namespace_identity_rows()[index];
            const auto& expectation = launch.expected_namespace_files()[index];
            require(
                row.namespace_relative_path == expected_paths[index] &&
                    row.file_type_code == 1u &&
                    row.normalized_mode == expected_modes[index] &&
                    expectation.namespace_relative_path == expected_paths[index] &&
                    expectation.role_codes == expected_roles[index] &&
                    expectation.normalized_mode == expected_modes[index] &&
                    expectation.byte_length == row.byte_length &&
                    expectation.sha256 == row.sha256 &&
                    row.inode != 0u,
                "exact five-object namespace identity row changed");
            for (std::size_t prior = 0u; prior < index; ++prior) {
                const auto& previous = launch.namespace_identity_rows()[prior];
                require(
                    row.device_major != previous.device_major ||
                        row.device_minor != previous.device_minor ||
                        row.inode != previous.inode,
                    "namespace identity rows alias");
            }
        }
        require(
            launch.namespace_identity_rows()[0].byte_length == collector.size() &&
                launch.namespace_identity_rows()[0].sha256 == digest,
            "collector namespace identity row changed");
        require(
            launch.namespace_identity_rows()[4].byte_length == kFixture.size() &&
                launch.namespace_identity_rows()[4].sha256 == fixture_digest,
            "primary-source namespace identity row changed");
        require(
            stopped->observation().executable_sha256() == digest,
            "exec-stop collector digest changed");
        require(
            stopped->observation().argv() == expected_collector_launch_argv() &&
                stopped->observation().argv() == launch.expected_argv(),
            "exec-stop collector wrapper argv changed");
        require(
            stopped->observation().cwd_device() == launch.ready_record().working_directory_device &&
                stopped->observation().cwd_inode() == launch.ready_record().working_directory_inode,
            "exec-stop cwd identity changed");
        const capture::CompletedOpenTraceSlice slice =
            capture::PtraceOpenSupervisor::run_open_receipt_slice_for_testing(
            std::move(stopped),
            capture::ReceiptContextExpectation{
                "src/Export.cpp", path_profile_for()},
            capture::PtraceOpenLimits{10'000u, 4096u, 1u << 20u, 16u, 1'000'000u});
        require(slice.actual_open_rows.size() == 3u, "tracee did not produce three actual opens");
        constexpr std::array<capture::Amendment8OpenPhase, 3> expected_phases = {
            capture::Amendment8OpenPhase::PreDriver,
            capture::Amendment8OpenPhase::Driver,
            capture::Amendment8OpenPhase::Cc1,
        };
        for (std::size_t index = 0u; index < slice.actual_open_rows.size(); ++index) {
            const capture::ActualOpenObservation& row = slice.actual_open_rows[index];
            require(row.observation_sequence == index, "actual-open sequence changed");
            require(row.phase == expected_phases[index], "actual-open phase changed");
            require(
                row.namespace_relative_path == "src/Export.cpp",
                "actual-open namespace path changed");
            require(row.normalized_mode == 0444u, "actual-open normalized mode changed");
            require(row.byte_length == kFixture.size(), "actual-open byte length changed");
            require(row.sha256 == fixture_digest, "actual-open digest changed");
            require(
                (row.open_flags & static_cast<std::uint64_t>(O_CLOEXEC | O_NOFOLLOW)) ==
                    static_cast<std::uint64_t>(O_CLOEXEC | O_NOFOLLOW),
                "actual-open flags changed");
        }
        require(
            slice.syscall_pairs.state == capture::SyscallPairTracker::State::Finalized &&
                slice.syscall_pairs.active_entries.empty(),
            "syscall pairing did not finalize");
        require(!slice.exact_receipt_stream.empty(), "receipt stream is empty");
        require(
            slice.final_receipt.primary_source_relative_path == "src/Export.cpp",
            "receipt parser returned the wrong source path");
        require(
            std::string(slice.stdout_bytes.begin(), slice.stdout_bytes.end()) == "tracee-ok\n",
            "tracee stdout changed");
    } catch (...) {
        static_cast<void>(::close(root));
        throw;
    }
    require(::close(root) == 0, "close original root failed");
}

void run_runtime_valid(const TempTree& tree) {
    const int root = open_original_root(tree);
    require(root >= 0, "open original root for runtime trace failed");
    try {
        auto retained = capture::RetainedInputSet::acquire(
            retained_specs(root, "runtime-collector"));
        auto prepared = prepare_fixture(
            std::move(retained), runtime_request_for(tree));
        auto stopped = capture::PtraceExecAuthenticator::reach_authenticated_exec(
            std::move(prepared), 20'000u);
        const capture::CompletedNativeCaptureObservations slice =
            capture::PtraceOpenSupervisor::run_completed_observations_for_testing(
            std::move(stopped),
            capture::ReceiptContextExpectation{
                "src/Export.cpp", path_profile_for()},
            capture::PtraceOpenLimits{
                20'000u,
                4096u,
                32u * 1024u * 1024u,
                64u,
                1'000'000u});

        const capture::CompletedRuntimeObservation& runtime = slice.runtime_observation();
        const capture::CompletedNamespaceObservation& namespace_observation =
            slice.namespace_observation();
        const capture::CompletedExecStopObservation& exec_stop =
            slice.exec_stop_observation();
        const capture::CompletedTerminationObservation& termination =
            slice.termination_observation();
        require(
            namespace_observation.ready_record.status == capture::LaunchReadyStatus::Ready &&
                namespace_observation.namespace_identity_rows.size() == 5u,
            "completed namespace observations were not retained");
        require(
            exec_stop.argv == expected_collector_launch_argv() &&
                exec_stop.proc_exe_byte_length > 0u &&
                !exec_stop.cwd_proc_link.empty() &&
                exec_stop.cwd_device == namespace_observation.ready_record.working_directory_device &&
                exec_stop.cwd_inode == namespace_observation.ready_record.working_directory_inode &&
                exec_stop.zero_capability_sets && exec_stop.no_new_privileges &&
                exec_stop.user_id == 0u && exec_stop.group_id == 0u &&
                exec_stop.empty_supplementary_groups,
            "completed exec-stop observations were not retained");
        require(
            WIFEXITED(termination.raw_wait_status) && termination.exit_status == 0u &&
                termination.stderr_bytes.empty(),
            "completed termination observations were not retained");
        constexpr std::array<std::string_view, 4> expected_paths = {
            "bin/collector",
            "lib/ld-linux-x86-64.so.2",
            "lib/libc.so.6",
            "lib/libclang-cpp.so.16",
        };
        require(
            runtime.runtime_object_rows.size() == expected_paths.size(),
            "runtime object closure changed");
        for (std::size_t index = 0u; index < expected_paths.size(); ++index) {
            require(
                runtime.runtime_object_rows[index].namespace_relative_path ==
                    expected_paths[index],
                "runtime object ordering or path changed");
            require(
                runtime.runtime_object_rows[index].byte_length > 0u,
                "runtime object has zero byte length");
        }
        require(
            runtime.primary_clang_cpp_record.namespace_relative_path ==
                "lib/libclang-cpp.so.16",
            "runtime primary record path changed");
        require(
            runtime.primary_clang_cpp_record.elf_soname ==
                std::vector<std::uint8_t>{'l', 'i', 'b', 'c', 'l', 'a', 'n', 'g', '-',
                                          'c', 'p', 'p', '.', 's', 'o', '.', '1', '6'},
            "runtime primary SONAME changed");
        require(
            runtime.primary_clang_cpp_record.elf_build_id ==
                std::vector<std::uint8_t>{0x63u, 0x13u, 0x02u, 0x16u},
            "runtime primary GNU build ID changed");
        require(
            runtime.elf_interpreter_record.namespace_relative_path ==
                "lib/ld-linux-x86-64.so.2",
            "runtime interpreter record path changed");

        require(
            runtime.runtime_observation_rows.size() == expected_paths.size(),
            "runtime observation closure changed");
        std::array<bool, expected_paths.size()> observed_indices{};
        for (std::size_t sequence = 0u;
             sequence < runtime.runtime_observation_rows.size();
             ++sequence) {
            const capture::RuntimeObservationEvidence& observation =
                runtime.runtime_observation_rows[sequence];
            require(
                observation.observation_sequence == sequence,
                "runtime observation sequence changed");
            require(
                observation.runtime_object_index < expected_paths.size(),
                "runtime observation object index is out of range");
            const std::size_t object_index = static_cast<std::size_t>(
                observation.runtime_object_index);
            require(
                !observed_indices[object_index],
                "runtime object was represented by multiple first observations");
            observed_indices[object_index] = true;
            require(
                observation.device != 0u && observation.inode != 0u,
                "runtime observation lacks device/inode identity");
            const std::string& path =
                runtime.runtime_object_rows[object_index].namespace_relative_path;
            if (path == "bin/collector") {
                require(
                    observation.observation_kind ==
                        capture::RuntimeObservationKind::PtraceExecProcExe,
                    "collector was not bound through proc exe");
                require(
                    observation.file_offset == 0u &&
                        observation.mapping_length == 0u &&
                        observation.protection_flags == 0u,
                    "collector exec observation contains mapping fields");
            } else {
                require(
                    observation.observation_kind ==
                            capture::RuntimeObservationKind::PtraceMmapFdProtExec ||
                        observation.observation_kind ==
                            capture::RuntimeObservationKind::ProcMapFilesProtExec,
                    "runtime mapping used an unsupported observation kind");
                require(
                    observation.mapping_length > 0u &&
                        (observation.protection_flags & 0x4u) != 0u,
                    "runtime mapping lacks executable extent");
                if (path == "lib/libclang-cpp.so.16") {
                    require(
                        observation.observation_kind ==
                            capture::RuntimeObservationKind::PtraceMmapFdProtExec,
                        "runtime primary bypassed FD-backed mmap observation");
                }
            }
        }
        require(
            std::all_of(observed_indices.begin(), observed_indices.end(), [](bool value) {
                return value;
            }),
            "runtime observation indices are incomplete");

        require(
            slice.open_receipt().syscall_pairs.state ==
                    capture::SyscallPairTracker::State::Finalized &&
                slice.open_receipt().syscall_pairs.active_entries.empty(),
            "runtime syscall pairing did not finalize");
        require(
            !slice.open_receipt().actual_open_rows.empty(),
            "runtime trace produced no actual opens");
        require(
            !slice.open_receipt().exact_receipt_stream.empty(),
            "runtime receipt stream is empty");
        require(
            slice.open_receipt().final_receipt.primary_source_relative_path ==
                "src/Export.cpp",
            "runtime receipt parser returned the wrong source path");
        require(
            std::string(
                slice.open_receipt().stdout_bytes.begin(),
                slice.open_receipt().stdout_bytes.end()) == "tracee-ok\n",
            "runtime tracee stdout changed");
    } catch (...) {
        static_cast<void>(::close(root));
        throw;
    }
    require(::close(root) == 0, "close runtime original root failed");
}

void run_wrong_digest(const TempTree& tree, const std::vector<std::uint8_t>& collector) {
    const int root = open_original_root(tree);
    require(root >= 0, "open original root for mutation failed");
    try {
        auto retained = capture::RetainedInputSet::acquire(
            retained_specs(root, "collector"));
        auto digest = sha256(collector);
        digest[0] ^= 0xffu;
        bool rejected = false;
        try {
            static_cast<void>(prepare_fixture(
                std::move(retained), request_for(tree, "collector", &digest)));
        } catch (const capture::SupervisorError&) {
            rejected = true;
        }
        require(rejected, "wrong collector digest produced a prepared launch");
    } catch (...) {
        static_cast<void>(::close(root));
        throw;
    }
    require(::close(root) == 0, "close mutation root failed");
}

void run_invalid_stdout_cap(
    const TempTree& tree,
    std::size_t stdout_cap) {
    const int root = open_original_root(tree);
    require(root >= 0, "open original root for stdout-cap rejection failed");
    try {
        auto retained = capture::RetainedInputSet::acquire(
            retained_specs(root, "collector"));
        LaunchFixtureInputs inputs = request_for(tree, "collector");
        inputs.runtime.stdout_byte_cap = stdout_cap;
        bool rejected = false;
        try {
            static_cast<void>(prepare_fixture(
                std::move(retained), std::move(inputs)));
        } catch (const capture::SupervisorError& error) {
            require(
                error.failure() == capture::SupervisorFailure::InvalidRequest,
                "invalid stdout cap returned the wrong failure");
            rejected = true;
        }
        require(rejected, "non-frozen stdout cap produced a prepared launch");
    } catch (...) {
        static_cast<void>(::close(root));
        throw;
    }
    require(::close(root) == 0, "close stdout-cap root failed");
}

void require_child_reaped(pid_t child_pid) {
    int status = 0;
    errno = 0;
    require(
        ::waitpid(child_pid, &status, WNOHANG | __WALL) == -1 && errno == ECHILD,
        "failed supervisor path did not synchronously reap its child");
}

void run_runtime_mapping_missing(const TempTree& tree) {
    const int root = open_original_root(tree);
    require(root >= 0, "open original root for runtime-role rejection failed");
    try {
        auto retained = capture::RetainedInputSet::acquire(
            retained_specs(root, "collector"));
        auto prepared = prepare_fixture(
            std::move(retained), request_for(tree, "collector"));
        auto stopped = capture::PtraceExecAuthenticator::reach_authenticated_exec(
            std::move(prepared), 10'000u);
        const pid_t child_pid = stopped->launch().child_pid();
        capture::PtraceOpenLimits limits{
            10'000u, 4096u, 1u << 20u, 16u, 1'000'000u};
        bool rejected = false;
        try {
            static_cast<void>(capture::PtraceOpenSupervisor::run_completed_observations_for_testing(
                std::move(stopped),
                capture::ReceiptContextExpectation{
                    "src/Export.cpp", path_profile_for()},
                limits));
        } catch (const capture::SupervisorError& error) {
            require(
                error.failure() == capture::SupervisorFailure::ProtocolViolation,
                "missing runtime mappings returned the wrong failure");
            rejected = true;
        }
        require(rejected, "missing runtime mappings produced a completed slice");
        require_child_reaped(child_pid);
    } catch (...) {
        static_cast<void>(::close(root));
        throw;
    }
    require(::close(root) == 0, "close runtime-role rejection root failed");
}

void run_rejected_mode(
    const TempTree& tree,
    const std::string& mode,
    capture::SupervisorFailure expected_failure,
    std::uint64_t timeout_milliseconds) {
    const int root = open_original_root(tree);
    require(root >= 0, "open original root for rejected mode failed");
    try {
        const std::string collector_original_path = "collector-" + mode;
        auto retained = capture::RetainedInputSet::acquire(
            retained_specs(root, collector_original_path));
        auto prepared = prepare_fixture(
            std::move(retained), request_for(tree, collector_original_path));
        auto stopped = capture::PtraceExecAuthenticator::reach_authenticated_exec(
            std::move(prepared), 10'000u);
        const pid_t child_pid = stopped->launch().child_pid();
        bool rejected = false;
        try {
            static_cast<void>(
                capture::PtraceOpenSupervisor::run_open_receipt_slice_for_testing(
                std::move(stopped),
                capture::ReceiptContextExpectation{
                    "src/Export.cpp", path_profile_for()},
                capture::PtraceOpenLimits{
                    timeout_milliseconds, 4096u, 1u << 20u, 16u, 1'000'000u}));
        } catch (const capture::SupervisorError& error) {
            require(error.failure() == expected_failure, "rejected mode returned the wrong failure");
            rejected = true;
        }
        require(rejected, "rejected tracee mode produced a completed slice");
        require_child_reaped(child_pid);
    } catch (...) {
        static_cast<void>(::close(root));
        throw;
    }
    require(::close(root) == 0, "close rejected-mode root failed");
}

}  // namespace

int main() {
    try {
        TempTree tree;
        const auto collector_source = std::filesystem::path(kTraceePath);
        copy_immutable_file(collector_source, tree.path() / "original" / "collector", 0555);
        constexpr std::array<std::string_view, 6u> rejected_modes = {
            "hang", "fork", "eventfd", "chdir", "fd3-alias", "exit-open-receipt"};
        for (const std::string_view mode : rejected_modes) {
            copy_immutable_file(
                std::filesystem::path("/work/tracee-" + std::string(mode)),
                tree.path() / "original" / ("collector-" + std::string(mode)),
                0555);
        }
        copy_immutable_file(
            std::filesystem::path(kRuntimeTraceePath),
            tree.path() / "original" / "runtime-collector",
            0555);
        copy_immutable_file(
            std::filesystem::path(kRuntimePrimaryPath),
            tree.path() / "original" / "runtime-primary",
            0444);
        copy_immutable_file(
            std::filesystem::canonical(std::filesystem::path(kRuntimeInterpreterPath)),
            tree.path() / "original" / "runtime-interpreter",
            0444);
        copy_immutable_file(
            std::filesystem::canonical(std::filesystem::path(kRuntimeLibcPath)),
            tree.path() / "original" / "runtime-libc",
            0444);
        const std::filesystem::path fixture_path = tree.path() / "original" / "Export.cpp";
        const int fixture_descriptor = ::open(
            fixture_path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0444);
        require(fixture_descriptor >= 0, "create fixture failed");
        try {
            write_all(
                fixture_descriptor,
                reinterpret_cast<const std::uint8_t*>(kFixture.data()),
                kFixture.size());
            require(::fchmod(fixture_descriptor, 0444) == 0, "fixture chmod failed");
            require(::fsync(fixture_descriptor) == 0, "fixture fsync failed");
            require(::close(fixture_descriptor) == 0, "fixture close failed");
        } catch (...) {
            static_cast<void>(::close(fixture_descriptor));
            throw;
        }

        const auto collector = read_all(tree.path() / "original" / "collector");
        run_invalid_stdout_cap(
            tree, capture::kRawCollectorCaptureMaxBytesV1 - 1u);
        run_invalid_stdout_cap(
            tree, capture::kRawCollectorCaptureMaxBytesV1 + 1u);

        const bool clone3 = clone3_available();
        const bool pidfd = pidfd_available();
        const bool pidfd_getfd = pidfd && pidfd_getfd_available();
        if (!clone3 || !pidfd || !pidfd_getfd) {
            skip_kernel_features(clone3, pidfd, pidfd_getfd);
        }

        run_valid(tree, collector);
        run_runtime_valid(tree);
        run_runtime_mapping_missing(tree);
        run_rejected_mode(
            tree, "hang", capture::SupervisorFailure::TraceTimeout, 100u);
        run_rejected_mode(
            tree, "fork", capture::SupervisorFailure::ProtocolViolation, 10'000u);
        run_rejected_mode(
            tree, "eventfd", capture::SupervisorFailure::ProtocolViolation, 10'000u);
        run_rejected_mode(
            tree, "chdir", capture::SupervisorFailure::ProtocolViolation, 10'000u);
        run_rejected_mode(
            tree, "fd3-alias", capture::SupervisorFailure::ProtocolViolation, 10'000u);
        run_rejected_mode(
            tree,
            "exit-open-receipt",
            capture::SupervisorFailure::ProtocolViolation,
            10'000u);
        run_wrong_digest(tree, collector);
    } catch (const std::exception& error) {
        std::cerr << "launch_engine_harness_failure: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "launch_engine_harness_ok zero_authority=1\n";
    return EXIT_SUCCESS;
}
