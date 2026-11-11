// Nonproduction fixture target for the binding-required Private Bridge V3
// native-to-Python parity test.  It is compiled only with
// EVALUATION_V631302_PRIVATE_BRIDGE_V3_TEST_ONLY and cannot enter a production
// native target.
#if !defined(EVALUATION_V631302_PRIVATE_BRIDGE_V3_TEST_ONLY)
#error "Private Bridge V3 fixture access is test-only"
#endif

#include "CaptureOutcome.h"
#include "PrelaunchContext.h"
#include "PrivateBridgeEncoder.h"
#if defined(EVALUATION_V631302_PRODUCTION_CAPTURE_BRIDGE_TEST_ONLY)
#include "CaptureSession.h"
#include "ProductionCaptureBridge.h"
#include "RetainedInputs.h"
#endif

#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/SHA256.h"

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <new>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace {

bool g_track_allocations = false;
bool g_fail_next_allocation = false;
std::size_t g_tracked_allocations = 0u;

}  // namespace

void* operator new(std::size_t size) {
    if (g_track_allocations) {
        ++g_tracked_allocations;
    }
    if (std::exchange(g_fail_next_allocation, false)) {
        throw std::bad_alloc();
    }
    if (void* memory = std::malloc(size); memory != nullptr) {
        return memory;
    }
    throw std::bad_alloc();
}

void* operator new[](std::size_t size) {
    return ::operator new(size);
}

void operator delete(void* memory) noexcept {
    std::free(memory);
}

void operator delete(void* memory, std::size_t) noexcept {
    std::free(memory);
}

void operator delete[](void* memory) noexcept {
    std::free(memory);
}

void operator delete[](void* memory, std::size_t) noexcept {
    std::free(memory);
}

namespace evaluation_v6_3_1::capture_v2 {

// This type exists only in this nonproduction harness.  The production headers
// grant access only when the explicit fixture compilation define is present.
class PrivateBridgeV3FixtureAccess final {
public:
    static ComponentFacts component(
        std::uint64_t byte_length,
        Sha256Digest sha256,
        std::vector<std::uint8_t> build_id) {
        return ComponentFacts(byte_length, sha256, std::move(build_id));
    }

    static HarnessObservation harness(
        ComponentFacts entry,
        ComponentFacts interpreter,
        ComponentFacts supervisor) {
        return HarnessObservation(
            std::move(entry), std::move(interpreter), std::move(supervisor));
    }

    static ValidatedPrelaunchContext context(
        ValidatedPrelaunchPlan plan,
        OwnedFd retained_working_directory_fd,
        WorkDirectoryIdentity retained_working_directory_identity,
        Sha256Digest private_context_binding_digest) {
        return ValidatedPrelaunchContext(
            std::move(plan), std::move(retained_working_directory_fd),
            retained_working_directory_identity,
            private_context_binding_digest);
    }

    static CompletedNativeCaptureObservations observations(
        CompletedNamespaceObservation namespace_observation,
        CompletedExecStopObservation exec_stop_observation,
        CompletedOpenTraceSlice open_receipt,
        CompletedRuntimeObservation runtime_observation,
        CompletedTerminationObservation termination_observation,
        Sha256Digest private_context_binding_digest) {
        return CompletedNativeCaptureObservations(
            std::move(namespace_observation), std::move(exec_stop_observation),
            std::move(open_receipt), std::move(runtime_observation),
            std::move(termination_observation), private_context_binding_digest);
    }

    static CompletedNativeCaptureSuccess success(
        ValidatedPrelaunchContext context,
        CompletedNativeCaptureObservations observations,
        HarnessObservation harness_observation) {
        return CompletedNativeCaptureSuccess(
            CaptureSessionSuccessAuthority{}, std::move(context),
            std::move(observations), std::move(harness_observation));
    }

    static void set_profile_label(
        CompletedNativeCaptureSuccess& success,
        std::string value) {
        std::string& label = const_cast<std::string&>(
            success.context_.collector_profile_build_label_text().value());
        label = std::move(value);
    }

    static void clear_stdout(CompletedNativeCaptureSuccess& success) noexcept {
        success.observations_.open_receipt_.stdout_bytes.clear();
    }

    static void break_private_binding(
        CompletedNativeCaptureSuccess& success) noexcept {
        success.observations_.private_context_binding_digest_[0] ^= 0xffu;
    }

#if defined(EVALUATION_V631302_PRODUCTION_CAPTURE_BRIDGE_TEST_ONLY)
    static void inject_capture_session_outcome(
        CaptureSession& session,
        CaptureSessionOutcome outcome,
        std::size_t& run_count) {
        session.fixture_outcome_.emplace(std::move(outcome));
        session.fixture_run_count_ = &run_count;
    }
#endif
};

}  // namespace evaluation_v6_3_1::capture_v2

namespace capture = evaluation_v6_3_1::capture_v2;

namespace {

using Byte = std::uint8_t;

constexpr std::string_view kProfileLabel =
    "636f6c6c6563746f722d6275696c64";

[[noreturn]] void fail(std::string_view message) {
    std::cerr << "private_bridge_v3_fixture_failure: " << message << '\n';
    std::exit(1);
}

void require(bool condition, std::string_view message) {
    if (!condition) {
        fail(message);
    }
}

std::vector<Byte> read_bytes(const char* path) {
    std::ifstream input(path, std::ios::binary);
    require(static_cast<bool>(input), "fixture input cannot be opened");
    const std::vector<char> raw(
        (std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    std::vector<Byte> result;
    result.reserve(raw.size());
    for (const char value : raw) {
        result.push_back(static_cast<Byte>(static_cast<unsigned char>(value)));
    }
    return result;
}

void write_bytes(const char* path, std::span<const Byte> value) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    require(static_cast<bool>(output), "fixture output cannot be opened");
    output.write(
        reinterpret_cast<const char*>(value.data()),
        static_cast<std::streamsize>(value.size()));
    require(static_cast<bool>(output), "fixture output could not be written");
}

capture::Sha256Digest digest(std::string_view value) {
    const auto* data = reinterpret_cast<const Byte*>(value.data());
    return llvm::SHA256::hash(llvm::ArrayRef<Byte>(data, value.size()));
}

void append_head(std::vector<Byte>& output, Byte major, std::uint64_t value) {
    const Byte prefix = static_cast<Byte>(major << 5u);
    if (value < 24u) {
        output.push_back(static_cast<Byte>(prefix | static_cast<Byte>(value)));
    } else if (value <= 0xffu) {
        output.push_back(static_cast<Byte>(prefix | 24u));
        output.push_back(static_cast<Byte>(value));
    } else if (value <= 0xffffu) {
        output.push_back(static_cast<Byte>(prefix | 25u));
        output.push_back(static_cast<Byte>(value >> 8u));
        output.push_back(static_cast<Byte>(value));
    } else if (value <= 0xffffffffULL) {
        output.push_back(static_cast<Byte>(prefix | 26u));
        for (int shift = 24; shift >= 0; shift -= 8) {
            output.push_back(static_cast<Byte>(
                value >> static_cast<unsigned>(shift)));
        }
    } else {
        output.push_back(static_cast<Byte>(prefix | 27u));
        for (int shift = 56; shift >= 0; shift -= 8) {
            output.push_back(static_cast<Byte>(
                value >> static_cast<unsigned>(shift)));
        }
    }
}

void append_uint(std::vector<Byte>& output, std::uint64_t value) {
    append_head(output, 0u, value);
}

void append_bytes(std::vector<Byte>& output, std::span<const Byte> value) {
    append_head(output, 2u, value.size());
    output.insert(output.end(), value.begin(), value.end());
}

void append_text(std::vector<Byte>& output, std::string_view value) {
    append_head(output, 3u, value.size());
    const auto* data = reinterpret_cast<const Byte*>(value.data());
    output.insert(output.end(), data, data + value.size());
}

void append_array(std::vector<Byte>& output, std::size_t size) {
    append_head(output, 4u, size);
}

std::vector<Byte> path_profile_cbor() {
    std::vector<Byte> value;
    append_array(value, 4u);
    append_uint(value, 2u);
    append_text(value, "/src");
    append_text(value, "/work");
    append_text(value, "/bin");
    return value;
}

void append_file_row(
    std::vector<Byte>& output,
    std::string_view path,
    std::initializer_list<std::uint64_t> roles,
    std::uint64_t mode,
    std::uint64_t byte_length,
    const capture::Sha256Digest& sha256) {
    append_array(output, 5u);
    append_text(output, path);
    append_array(output, roles.size());
    for (const std::uint64_t role : roles) {
        append_uint(output, role);
    }
    append_uint(output, mode);
    append_uint(output, byte_length);
    append_bytes(output, sha256);
}

std::vector<Byte> public_file_rows_cbor() {
    std::vector<Byte> value;
    append_array(value, 5u);
    append_file_row(value, "bin/collector", {1u}, 0555u, 17u, digest("collector"));
    append_file_row(value, "lib/ld-linux-x86-64.so.2", {6u}, 0444u, 19u, digest("loader"));
    append_file_row(value, "lib/libc.so.6", {8u}, 0444u, 25u, digest("libc"));
    append_file_row(value, "lib/libclang-cpp.so.16", {7u, 8u}, 0444u, 21u, digest("clang"));
    append_file_row(value, "src/Export.cpp", {2u, 3u}, 0444u, 23u, digest("primary"));
    return value;
}

capture::ComponentExpectation component_expectation(
    std::uint64_t byte_length,
    std::string_view digest_label,
    std::vector<Byte> build_id) {
    return {byte_length, digest(digest_label), std::move(build_id)};
}

capture::HarnessExpectations harness_expectations() {
    return {
        component_expectation(41u, "entry", {0x00u, 0x01u, 0x00u, 0xffu}),
        component_expectation(43u, "interpreter", {0x00u, 0x80u, 0xaau}),
        component_expectation(41u, "entry", {0x00u, 0x01u, 0x00u, 0xffu}),
    };
}

capture::HarnessObservation harness_observation() {
    return capture::PrivateBridgeV3FixtureAccess::harness(
        capture::PrivateBridgeV3FixtureAccess::component(
            41u, digest("entry"), {0x00u, 0x01u, 0x00u, 0xffu}),
        capture::PrivateBridgeV3FixtureAccess::component(
            43u, digest("interpreter"), {0x00u, 0x80u, 0xaau}),
        capture::PrivateBridgeV3FixtureAccess::component(
            41u, digest("entry"), {0x00u, 0x01u, 0x00u, 0xffu}));
}

capture::RuntimeObjectEvidence runtime_object(
    std::string path,
    std::vector<Byte> soname,
    std::uint64_t byte_length,
    std::string_view digest_label,
    std::vector<Byte> build_id) {
    return {
        std::move(path), std::move(soname), byte_length, digest(digest_label),
        std::move(build_id),
    };
}

capture::CompletedRuntimeObservation runtime_observation() {
    const auto collector = runtime_object(
        "bin/collector", {}, 17u, "collector", {0x00u, 0xabu});
    const auto loader = runtime_object(
        "lib/ld-linux-x86-64.so.2", {}, 19u, "loader",
        {'l', 'o', 'a', 'd', 'e', 'r', '-', 'b', 'u', 'i', 'l', 'd'});
    const auto libc = runtime_object(
        "lib/libc.so.6", {'l', 'i', 'b', 'c', '.', 's', 'o', '.', '6'}, 25u,
        "libc", {'l', 'i', 'b', 'c', '-', 'b', 'u', 'i', 'l', 'd'});
    const auto primary = runtime_object(
        "lib/libclang-cpp.so.16",
        {'l', 'i', 'b', 'c', 'l', 'a', 'n', 'g', '-', 'c', 'p', 'p', '.', 's', 'o', '.', '1', '6'},
        21u, "clang", {'c', 'l', 'a', 'n', 'g', '-', 'b', 'u', 'i', 'l', 'd'});
    return {
        primary,
        loader,
        {collector, loader, libc, primary},
        {
            {0u, capture::RuntimeObservationKind::PtraceExecProcExe, 0u, 100u, 200u, 0u, 0u, 0u},
            {1u, capture::RuntimeObservationKind::PtraceMmapFdProtExec, 1u, 102u, 202u, 0u, 19u, 5u},
            {2u, capture::RuntimeObservationKind::PtraceMmapFdProtExec, 2u, 103u, 203u, 0u, 25u, 5u},
            {3u, capture::RuntimeObservationKind::ProcMapFilesProtExec, 3u, 104u, 204u, 0u, 21u, 5u},
        },
    };
}

capture::CompletedNamespaceObservation namespace_observation() {
    return {
        {},
        {
            {"bin/collector", 0u, 100u, 200u, 1u, 0555u, 17u, digest("collector")},
            {"lib/ld-linux-x86-64.so.2", 0u, 102u, 202u, 1u, 0444u, 19u, digest("loader")},
            {"lib/libc.so.6", 0u, 103u, 203u, 1u, 0444u, 25u, digest("libc")},
            {"lib/libclang-cpp.so.16", 0u, 104u, 204u, 1u, 0444u, 21u, digest("clang")},
            {"src/Export.cpp", 0u, 101u, 201u, 1u, 0444u, 23u, digest("primary")},
        },
    };
}

std::uint64_t read_big_endian_u64(std::span<const Byte> bytes) {
    require(bytes.size() == 8u, "receipt length field has the wrong width");
    std::uint64_t value = 0u;
    for (const Byte byte : bytes) {
        value = (value << 8u) | byte;
    }
    return value;
}

capture::CompletedOpenTraceSlice open_receipt(
    const capture::ValidatedPrelaunchPlan& plan,
    std::vector<Byte> receipt_stream,
    std::vector<Byte> stdout_bytes) {
    capture::ReceiptStreamParser parser(capture::ReceiptContextExpectation{
        plan.primary_source(), plan.path_profile_cbor_bytes()});
    std::size_t offset = 0u;
    while (offset < receipt_stream.size()) {
        require(
            receipt_stream.size() - offset >= 16u,
            "receipt fixture has a truncated frame header");
        const std::uint64_t payload_length = read_big_endian_u64(
            std::span<const Byte>(receipt_stream).subspan(offset + 8u, 8u));
        require(
            payload_length <= receipt_stream.size() - offset - 16u,
            "receipt fixture has a truncated frame payload");
        const std::size_t frame_size =
            16u + static_cast<std::size_t>(payload_length);
        const std::span<const Byte> frame =
            std::span<const Byte>(receipt_stream).subspan(offset, frame_size);
        parser.observe_fd3_write(
            frame, static_cast<std::int64_t>(frame.size()), 4096u, false);
        offset += frame_size;
    }
    parser.append_drained_fd3_bytes(receipt_stream);
    parser.finish_fd3_eof();
    require(parser.complete(), "receipt fixture did not complete exactly");
    capture::ReceiptFinalValues final_receipt = parser.final_values();
    require(
        parser.exact_stream_bytes() == receipt_stream,
        "receipt parser changed the exact fixture bytes");
    return {
        {
            {0u, capture::Amendment8OpenPhase::Driver, "src/Export.cpp", 0u, 101u, 201u, 0444u, 23u, digest("primary")},
            {1u, capture::Amendment8OpenPhase::Cc1, "src/Export.cpp", 0u, 101u, 201u, 0444u, 23u, digest("primary")},
        },
        {},
        std::move(final_receipt),
        std::move(receipt_stream),
        std::move(stdout_bytes),
    };
}

capture::CompletedNativeCaptureSuccess make_success(
    const std::vector<Byte>& collector_profile,
    const std::vector<Byte>& receipt_stream,
    const std::vector<Byte>& stdout_bytes,
    const std::vector<Byte>& root_bytes,
    int* retained_working_directory_fd_out = nullptr) {
    require(root_bytes.size() == capture::Sha256Digest32{}.size(), "root must be 32 bytes");
    capture::Sha256Digest32 root{};
    for (std::size_t index = 0u; index < root.size(); ++index) {
        root[index] = root_bytes[index];
    }
    capture::RawPrelaunchRequest raw = capture::RawPrelaunchRequest::copy_from(
        std::string(kProfileLabel), {0x00u, 0xabu}, root, collector_profile,
        capture::ValidatedPrelaunchPlan::kFrozenArgvGrammarVersionV1,
        capture::ValidatedPrelaunchPlan::kFrozenArgvGrammarSha256V1,
        path_profile_cbor(), "work", "src/Export.cpp",
        public_file_rows_cbor(),
        {
            "/bin/clang-tool",
            "-std=c++20",
            "-fsyntax-only",
            "-nostdinc",
            "-I",
            "/src",
            "/src/Export.cpp",
            "-resource-dir=/lib/clang/16",
            "--no-default-config",
        },
        harness_expectations());
    capture::ValidatedPrelaunchPlan plan =
        capture::ValidatedPrelaunchPlan::validate(std::move(raw));
    const std::vector<std::string> expected_launch =
        plan.collector_launch_argv();
    capture::CompletedOpenTraceSlice receipt = open_receipt(
        plan, receipt_stream, stdout_bytes);
    capture::Sha256Digest private_context_binding{};
    private_context_binding.fill(0x5au);
    const int retained_working_directory_fd = ::open(
        "/tmp", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(
        retained_working_directory_fd >= 0,
        "retained work-directory fixture could not be opened");
    struct stat work_stat {};
    require(
        ::fstat(retained_working_directory_fd, &work_stat) == 0,
        "retained work-directory fixture could not be identified");
    const capture::WorkDirectoryIdentity work_identity{
        static_cast<std::uint64_t>(work_stat.st_dev),
        static_cast<std::uint64_t>(work_stat.st_ino)};
    if (retained_working_directory_fd_out != nullptr) {
        *retained_working_directory_fd_out = retained_working_directory_fd;
    }
    capture::ValidatedPrelaunchContext context =
        capture::PrivateBridgeV3FixtureAccess::context(
            std::move(plan), capture::OwnedFd(retained_working_directory_fd),
            work_identity, private_context_binding);
    capture::CompletedExecStopObservation exec{};
    exec.argv = expected_launch;
    exec.cwd_device = work_identity.device;
    exec.cwd_inode = work_identity.inode;
    exec.proc_exe_byte_length = 17u;
    exec.proc_exe_sha256 = digest("collector");
    capture::CompletedTerminationObservation termination{};
    termination.exit_status = 0u;
    capture::CompletedNativeCaptureObservations observations =
        capture::PrivateBridgeV3FixtureAccess::observations(
            namespace_observation(), std::move(exec),
            std::move(receipt), runtime_observation(),
            std::move(termination), private_context_binding);
    return capture::PrivateBridgeV3FixtureAccess::success(
        std::move(context), std::move(observations), harness_observation());
}

void require_consumed_fd(int descriptor) {
    errno = 0;
    require(
        ::fcntl(descriptor, F_GETFD) == -1 && errno == EBADF,
        "encoder return left the success-owned custody descriptor open");
}

void run_contract_case(
    std::string_view mode,
    const std::vector<Byte>& collector_profile,
    const std::vector<Byte>& receipt_stream,
    const std::vector<Byte>& stdout_bytes,
    const std::vector<Byte>& root) {
    int retained_fd = -1;
    capture::CompletedNativeCaptureSuccess success = make_success(
        collector_profile, receipt_stream, stdout_bytes, root, &retained_fd);

    using capture::private_bridge_v3::EncodeFailureCode;
    EncodeFailureCode expected = EncodeFailureCode::kInternalEncodingFailure;
    bool expect_success = false;
    bool check_allocation_count = true;
    std::size_t expected_allocations = 0u;
    if (mode == "success") {
        expect_success = true;
        expected_allocations = 1u;
    } else if (mode == "profile-label") {
        capture::PrivateBridgeV3FixtureAccess::set_profile_label(
            success, std::string(1u, static_cast<char>(0x01)));
        expected = EncodeFailureCode::kProfileLabelInvalid;
    } else if (mode == "stdout") {
        capture::PrivateBridgeV3FixtureAccess::clear_stdout(success);
        expected = EncodeFailureCode::kStdoutLengthInvalid;
    } else if (mode == "invariant") {
        capture::PrivateBridgeV3FixtureAccess::break_private_binding(success);
        // The validator's diagnostic SupervisorError may allocate its message;
        // that allocation is not an output allocation and is library-specific.
        check_allocation_count = false;
        expected = EncodeFailureCode::kInvalidSuccessInvariant;
    } else if (mode == "size") {
        capture::private_bridge_v3::set_encode_test_fault(
            capture::private_bridge_v3::EncodeTestFault::kEncodedSizeOverflow);
        expected = EncodeFailureCode::kEncodedSizeOverflow;
    } else if (mode == "allocation") {
        g_fail_next_allocation = true;
        expected_allocations = 1u;
        expected = EncodeFailureCode::kAllocationFailure;
    } else if (mode == "internal") {
        capture::private_bridge_v3::set_encode_test_fault(
            capture::private_bridge_v3::EncodeTestFault::kInternalEncodingFailure);
        expected_allocations = 1u;
        expected = EncodeFailureCode::kInternalEncodingFailure;
    } else {
        fail("unknown encoder contract case");
    }

    g_tracked_allocations = 0u;
    g_track_allocations = true;
    auto result = capture::private_bridge_v3::encode_private_capture_bridge_v3(
        std::move(success));
    g_track_allocations = false;
    g_fail_next_allocation = false;

    require_consumed_fd(retained_fd);
    if (check_allocation_count) {
        require(
            g_tracked_allocations == expected_allocations,
            "encoder allocation count differs from the frozen contract");
    }
    if (expect_success) {
        require(result.has_value(), "valid success returned an encoding failure");
        require(
            !std::move(result).take_value().empty(),
            "valid success returned empty bridge bytes");
        return;
    }
    require(!result.has_value(), "failure case returned bridge bytes");
    require(result.error().code == expected, "failure case returned the wrong code");
}

#if defined(EVALUATION_V631302_PRODUCTION_CAPTURE_BRIDGE_TEST_ONLY)
capture::RetainedInputSet retained_input_fixture(
    std::string_view collector_path,
    std::string_view primary_path) {
    const std::size_t separator = collector_path.rfind('/');
    require(separator != std::string_view::npos &&
                separator + 1u < collector_path.size(),
            "production fixture path has no parent");
    const std::string parent(collector_path.substr(0u, separator));
    const std::string collector_filename(collector_path.substr(separator + 1u));
    const std::string expected_primary_prefix = parent + "/";
    require(primary_path.starts_with(expected_primary_prefix),
            "production fixture files have different parents");
    const std::string primary_filename(
        primary_path.substr(expected_primary_prefix.size()));
    const int root = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(root >= 0, "production fixture parent could not be opened");
    capture::RetainedInputSet retained = capture::RetainedInputSet::acquire(
        {
            capture::RetainedInputSpec{
                root, collector_filename, "bin/collector", {1u}, 0555u},
            capture::RetainedInputSpec{
                root, primary_filename, "src/Export.cpp", {2u, 3u}, 0444u},
        });
    require(::close(root) == 0, "production fixture parent could not be closed");
    return retained;
}

capture::CaptureSession fixture_session(
    std::string_view collector_path,
    std::string_view primary_path) {
    return capture::CaptureSession(
        {}, retained_input_fixture(collector_path, primary_path),
        capture::CaptureSessionLimits{});
}

void run_production_bridge_case(
    std::string_view mode,
    std::string_view retained_collector_path,
    std::string_view retained_primary_path,
    const std::vector<Byte>& collector_profile,
    const std::vector<Byte>& receipt_stream,
    const std::vector<Byte>& stdout_bytes,
    const std::vector<Byte>& root) {
    std::size_t run_count = 0u;
    capture::CaptureSession session = fixture_session(
        retained_collector_path, retained_primary_path);
    int success_owned_fd = -1;

    if (mode == "production-session-failure") {
        capture::NativeCaptureFailureBuilder builder(
            capture::FailureStage::Harness,
            capture::FailureCode::Harness,
            73);
        builder.record_cleanup_errno(74);
        require(builder.set_raw_wait_status(75), "failure wait status was not set");
        const std::array<Byte, 3u> diagnostic = {0x61u, 0x62u, 0x63u};
        require(builder.append_stderr(diagnostic), "failure stderr was not retained");
        capture::PrivateBridgeV3FixtureAccess::inject_capture_session_outcome(
            session,
            capture::CaptureSessionOutcome(
                std::in_place_type<capture::NativeCaptureFailure>,
                std::move(builder).finish()),
            run_count);
    } else {
        capture::CompletedNativeCaptureSuccess success = make_success(
            collector_profile,
            receipt_stream,
            stdout_bytes,
            root,
            &success_owned_fd);
        capture::PrivateBridgeV3FixtureAccess::inject_capture_session_outcome(
            session,
            capture::CaptureSessionOutcome(
                std::in_place_type<capture::CompletedNativeCaptureSuccess>,
                std::move(success)),
            run_count);
        if (mode == "production-encoder-failure") {
            capture::private_bridge_v3::set_encode_test_fault(
                capture::private_bridge_v3::EncodeTestFault::kInternalEncodingFailure);
        } else {
            require(mode == "production-success", "unknown production bridge case");
        }
    }

    g_tracked_allocations = 0u;
    g_track_allocations = true;
    capture::ProductionCaptureBridgeResult result =
        capture::run_production_capture_bridge_v3(std::move(session));
    g_track_allocations = false;
    require(run_count == 1u, "production boundary did not run the session exactly once");

    if (mode == "production-session-failure") {
        require(
            std::holds_alternative<capture::NativeCaptureFailure>(result),
            "session failure escaped its outer alternative");
        require(g_tracked_allocations == 0u, "session failure invoked the encoder");
        const capture::NativeCaptureFailure& failure =
            std::get<capture::NativeCaptureFailure>(result);
        require(
            failure.stage() == capture::FailureStage::Harness &&
                failure.code() == capture::FailureCode::Harness &&
                failure.primary_errno() == 73 &&
                failure.cleanup_errno() == 74 &&
                failure.raw_wait_status() == 75 &&
                failure.stderr_total_bytes() == 3u,
            "session failure changed across the production boundary");
        return;
    }

    require_consumed_fd(success_owned_fd);
    require(
        std::holds_alternative<capture::EncodeResult>(result),
        "encoder result escaped its outer alternative");
    capture::EncodeResult encoded =
        std::get<capture::EncodeResult>(std::move(result));
    if (g_tracked_allocations != 1u) {
        std::cerr << "production_bridge_tracked_allocations="
                  << g_tracked_allocations << '\n';
        fail("production boundary did not invoke one encoder");
    }
    if (mode == "production-success") {
        require(encoded.has_value(), "production success returned encoder failure");
        require(!std::move(encoded).take_value().empty(),
                "production success returned empty bytes");
    } else {
        require(!encoded.has_value(), "encoder failure became success");
        require(
            encoded.error().code ==
                capture::private_bridge_v3::EncodeFailureCode::kInternalEncodingFailure,
            "encoder failure discriminator changed");
    }
}
#endif

}  // namespace

using PrivateEncodeFunction = capture::private_bridge_v3::EncodeResult (*)(
    capture::CompletedNativeCaptureSuccess) noexcept;

static_assert(std::is_same_v<
              decltype(&capture::private_bridge_v3::encode_private_capture_bridge_v3),
              PrivateEncodeFunction>);
static_assert(std::is_same_v<
              decltype(std::declval<const capture::CompletedNativeCaptureSuccess&>()
                           .validated_prelaunch_context()),
              const capture::ValidatedPrelaunchContext&>);
static_assert(std::is_invocable_v<
              PrivateEncodeFunction,
              capture::CompletedNativeCaptureSuccess&&>);
static_assert(!std::is_invocable_v<
              PrivateEncodeFunction,
              capture::CompletedNativeCaptureSuccess&>);
static_assert(!std::is_invocable_v<
              PrivateEncodeFunction,
              capture::NativeCaptureFailure&&>);
#if defined(EVALUATION_V631302_PRODUCTION_CAPTURE_BRIDGE_TEST_ONLY)
using ProductionBridgeFunction = capture::ProductionCaptureBridgeResult (*)(
    capture::CaptureSession&&) noexcept;
static_assert(std::is_same_v<
              decltype(&capture::run_production_capture_bridge_v3),
              ProductionBridgeFunction>);
static_assert(!std::is_copy_constructible_v<capture::ProductionCaptureBridgeResult>);
static_assert(std::is_nothrow_move_constructible_v<capture::ProductionCaptureBridgeResult>);
#endif

int main(int argc, char** argv) {
    if (argc != 7 && argc != 8) {
        fail("usage: harness PROFILE STDOUT RECEIPT ROOT BRIDGE_A BRIDGE_B [CONTRACT_CASE]");
    }
    const std::vector<Byte> collector_profile = read_bytes(argv[1]);
    const std::vector<Byte> stdout_bytes = read_bytes(argv[2]);
    const std::vector<Byte> receipt_stream = read_bytes(argv[3]);
    const std::vector<Byte> root = read_bytes(argv[4]);

    if (argc == 8) {
#if defined(EVALUATION_V631302_PRODUCTION_CAPTURE_BRIDGE_TEST_ONLY)
        if (std::string_view(argv[7]).starts_with("production-")) {
            run_production_bridge_case(
                argv[7], argv[1], argv[2], collector_profile, receipt_stream,
                stdout_bytes, root);
            std::cout << "production_bridge_ok case=" << argv[7]
                      << " zero_authority=1\n";
            return 0;
        }
#endif
        run_contract_case(
            argv[7], collector_profile, receipt_stream, stdout_bytes, root);
        std::cout << "private_bridge_v3_contract_ok case=" << argv[7]
                  << " zero_authority=1\n";
        return 0;
    }

    auto first_result = capture::private_bridge_v3::encode_private_capture_bridge_v3(
        make_success(collector_profile, receipt_stream, stdout_bytes, root));
    auto second_result = capture::private_bridge_v3::encode_private_capture_bridge_v3(
        make_success(collector_profile, receipt_stream, stdout_bytes, root));
    require(first_result.has_value(), "first success did not encode");
    require(second_result.has_value(), "second success did not encode");
    const std::vector<Byte> first = std::move(first_result).take_value();
    const std::vector<Byte> second = std::move(second_result).take_value();
    require(first == second, "equal fixture successes produced different bridge bytes");
    write_bytes(argv[5], first);
    write_bytes(argv[6], second);
    std::cout << "private_bridge_v3_fixture_harness_ok zero_authority=1\n";
    return 0;
}
