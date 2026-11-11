#include "PrelaunchContext.h"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <type_traits>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

namespace capture = evaluation_v6_3_1::capture_v2;

namespace {

using Byte = std::uint8_t;

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "requirement_failed=" << message << '\n';
        std::exit(1);
    }
}

void append_head(std::vector<Byte>& output, Byte major, std::uint64_t value) {
    if (value < 24u) {
        output.push_back(static_cast<Byte>((major << 5u) | static_cast<Byte>(value)));
    } else if (value <= 0xffu) {
        output.push_back(static_cast<Byte>((major << 5u) | 24u));
        output.push_back(static_cast<Byte>(value));
    } else if (value <= 0xffffu) {
        output.push_back(static_cast<Byte>((major << 5u) | 25u));
        output.push_back(static_cast<Byte>(value >> 8u));
        output.push_back(static_cast<Byte>(value));
    } else if (value <= 0xffffffffULL) {
        output.push_back(static_cast<Byte>((major << 5u) | 26u));
        for (int shift = 24; shift >= 0; shift -= 8) {
            output.push_back(static_cast<Byte>(value >> static_cast<unsigned>(shift)));
        }
    } else {
        std::abort();
    }
}

void append_uint(std::vector<Byte>& output, std::uint64_t value) { append_head(output, 0u, value); }
void append_bytes(std::vector<Byte>& output, const std::vector<Byte>& value) {
    append_head(output, 2u, value.size());
    output.insert(output.end(), value.begin(), value.end());
}
void append_text(std::vector<Byte>& output, const std::string& value) {
    append_head(output, 3u, value.size());
    output.insert(output.end(), value.begin(), value.end());
}
void append_array(std::vector<Byte>& output, std::size_t length) { append_head(output, 4u, length); }

std::vector<Byte> path_profile() {
    std::vector<Byte> value;
    append_array(value, 4u);
    append_uint(value, 2u);
    append_text(value, "/src");
    append_text(value, "/work");
    append_text(value, "/bin");
    return value;
}

std::vector<Byte> collector_profile(const std::string& label) {
    std::vector<Byte> value;
    append_array(value, 8u);
    append_bytes(value, std::vector<Byte>(32u, 0x11u));
    append_text(value, label);
    append_bytes(value, std::vector<Byte>(32u, 0x14u));
    append_uint(value, 16u);
    append_uint(value, 2u);
    append_array(value, 0u);
    append_bytes(value, std::vector<Byte>(32u, 0x16u));
    append_array(value, 0u);
    return value;
}

void append_file_row(
    std::vector<Byte>& output,
    const std::string& path,
    const std::vector<std::uint64_t>& roles,
    std::uint64_t mode,
    std::uint64_t byte_length,
    Byte digest_byte) {
    append_array(output, 5u);
    append_text(output, path);
    append_array(output, roles.size());
    for (const std::uint64_t role : roles) {
        append_uint(output, role);
    }
    append_uint(output, mode);
    append_uint(output, byte_length);
    append_bytes(output, std::vector<Byte>(32u, digest_byte));
}

std::vector<Byte> public_rows() {
    std::vector<Byte> value;
    append_array(value, 5u);
    append_file_row(value, "bin/collector", {1u}, 0555u, 17u, 0x11u);
    append_file_row(
        value, "lib/ld-linux-x86-64.so.2", {6u}, 0444u, 19u, 0x12u);
    append_file_row(value, "lib/libc.so.6", {8u}, 0444u, 25u, 0x13u);
    append_file_row(
        value, "lib/libclang-cpp.so.16", {7u, 8u}, 0444u, 21u, 0x14u);
    append_file_row(value, "src/Export.cpp", {2u, 3u}, 0444u, 23u, 0x15u);
    return value;
}

capture::Sha256Digest digest(Byte value) {
    capture::Sha256Digest result{};
    result.fill(value);
    return result;
}

capture::ComponentExpectation component_expectation(Byte value) {
    return {
        100u + value,
        digest(value),
        {0x63u, 0x13u, 0x02u, value},
    };
}

capture::HarnessExpectations harness_expectations() {
    return {
        component_expectation(1u),
        component_expectation(2u),
        component_expectation(3u),
    };
}

capture::OwnedFd open_work_fd(
    const std::filesystem::path& work,
    capture::WorkDirectoryIdentity& identity) {
    const int descriptor = ::open(work.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    require(descriptor >= 0, "open working directory");
    struct stat status {};
    require(::fstat(descriptor, &status) == 0, "fstat working directory");
    identity = {
        static_cast<std::uint64_t>(status.st_dev),
        static_cast<std::uint64_t>(status.st_ino),
    };
    return capture::OwnedFd(descriptor);
}

capture::RawPrelaunchRequest request(
    const std::string& mutation,
    std::vector<Byte>* caller_owned_gnu_descriptor = nullptr,
    capture::Sha256Digest32* caller_owned_prelaunch_root = nullptr) {
    std::string profile_build_label = "collector-profile-v1";
    std::string profile_embedded_label = profile_build_label;
    std::vector<Byte> expected_gnu_descriptor = {0x63u, 0x13u, 0x02u};
    capture::Sha256Digest32 validated_prelaunch_expectations_root = digest(0xa5u);
    std::vector<Byte> collector = collector_profile(profile_embedded_label);
    bool collector_is_explicit = false;
    std::vector<Byte> profile = path_profile();
    std::vector<Byte> rows = public_rows();
    std::vector<std::string> argv = {
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
    auto expectations = harness_expectations();
    std::uint64_t version = capture::ValidatedPrelaunchPlan::kFrozenArgvGrammarVersionV1;
    capture::Sha256Digest grammar = capture::ValidatedPrelaunchPlan::kFrozenArgvGrammarSha256V1;
    std::string relative = "work";
    std::string primary = "src/Export.cpp";

    if (mutation == "grammar") {
        version = 2u;
    } else if (mutation == "grammar_digest") {
        grammar[0] ^= 0xffu;
    } else if (mutation == "noncanonical_cbor") {
        collector = {0x98u, 0x01u, 0x1au, 0x00u, 0x09u, 0xa1u, 0xe6u};
        collector_is_explicit = true;
    } else if (mutation == "cbor_map") {
        collector = {0xa0u};
        collector_is_explicit = true;
    } else if (mutation == "profile_label_mismatch") {
        profile_build_label = "collector-profile-v2";
    } else if (mutation == "profile_label_empty") {
        profile_build_label.clear();
    } else if (mutation == "profile_label_nul") {
        profile_build_label.push_back('\0');
    } else if (mutation == "label_ascii_max") {
        profile_build_label.assign(1u * 1024u * 1024u, 'x');
        profile_embedded_label = profile_build_label;
    } else if (mutation == "label_ascii_over") {
        profile_build_label.assign((1u * 1024u * 1024u) + 1u, 'x');
        profile_embedded_label = profile_build_label;
    } else if (mutation == "label_non_ascii") {
        profile_build_label.assign(1u, static_cast<char>(0x80));
        profile_embedded_label = profile_build_label;
    } else if (mutation == "profile_label_non_ascii") {
        profile_embedded_label.assign(1u, static_cast<char>(0x80));
    } else if (mutation == "descriptor_oversize") {
        expected_gnu_descriptor.assign(65'536u, 0x5au);
    } else if (mutation == "prelaunch_root_change") {
        validated_prelaunch_expectations_root[0] ^= 0xffu;
    } else if (mutation == "path") {
        relative = "other";
    } else if (mutation == "relative") {
        relative = "v631302/../work";
    } else if (mutation == "primary") {
        primary = "work/not-source.cc";
    } else if (mutation == "argv") {
        argv[1] = "@response";
    } else if (mutation == "rows") {
        rows = {0x80u};
    } else if (mutation == "harness") {
        expectations.capture_interpreter_component.build_id.assign(
            65'536u, 0x5au);
    } else if (mutation == "harness_empty") {
        expectations.capture_interpreter_component.build_id.clear();
    } else if (mutation == "binding_change") {
        ++expectations.native_supervisor_component.byte_length;
    }
    if (!collector_is_explicit) {
        collector = collector_profile(profile_embedded_label);
    }
    if (caller_owned_gnu_descriptor != nullptr) {
        *caller_owned_gnu_descriptor = std::move(expected_gnu_descriptor);
        if (caller_owned_prelaunch_root != nullptr) {
            *caller_owned_prelaunch_root = validated_prelaunch_expectations_root;
        }
        return capture::RawPrelaunchRequest::copy_from(
            profile_build_label, *caller_owned_gnu_descriptor,
            validated_prelaunch_expectations_root, collector, version, grammar,
            profile, relative, primary,
            rows, argv, expectations);
    }
    return capture::RawPrelaunchRequest::copy_from(
        profile_build_label, expected_gnu_descriptor, validated_prelaunch_expectations_root,
        collector, version, grammar,
        profile, relative, primary, rows, argv, expectations);
}

void wait_for_child(pid_t child, bool expect_success) {
    int status = 0;
    require(::waitpid(child, &status, 0) == child, "wait work-directory child");
    if (expect_success) {
        require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "work-directory child failed");
    }
}

capture::ValidatedPrelaunchContext bind_via_scm_rights(
    capture::ValidatedPrelaunchPlan&& plan,
    const std::filesystem::path& work) {
    capture::WorkDirectoryIdentity expected_identity{};
    capture::OwnedFd child_directory = open_work_fd(work, expected_identity);
    auto pair = capture::WorkDirectoryCustodySocketPair::create_production(
        capture::MonotonicDeadline::from_milliseconds(2000u));
    const pid_t child = ::fork();
    require(child >= 0, "fork work-directory child");
    if (child == 0) {
        try {
            auto child_endpoint = std::move(pair).take_child_for_child();
            static_cast<void>(
                std::move(child_endpoint).handoff_and_await_context_commit(
                    child_directory.get()));
            _exit(0);
        } catch (...) {
            _exit(2);
        }
    }
    try {
        auto parent_endpoint = std::move(pair).take_parent_for_parent(child);
        capture::ValidatedPrelaunchContext context =
            std::move(plan).bind_work_directory_custody(std::move(parent_endpoint));
        require(
            context.retained_working_directory_identity() == expected_identity,
            "context retained the wrong directory identity");
        wait_for_child(child, true);
        return context;
    } catch (...) {
        static_cast<void>(::kill(child, SIGKILL));
        wait_for_child(child, false);
        throw;
    }
}

bool rejects_missing_custody() {
    auto pair = capture::WorkDirectoryCustodySocketPair::create_production(
        capture::MonotonicDeadline::from_milliseconds(250u));
    const pid_t child = ::fork();
    require(child >= 0, "fork missing-custody child");
    if (child == 0) {
        try {
            auto child_endpoint = std::move(pair).take_child_for_child();
            static_cast<void>(child_endpoint);
            _exit(0);
        } catch (...) {
            _exit(3);
        }
    }
    bool rejected = false;
    try {
        auto parent_endpoint = std::move(pair).take_parent_for_parent(child);
        static_cast<void>(
            capture::ValidatedPrelaunchPlan::validate(request("ok"))
                .bind_work_directory_custody(std::move(parent_endpoint)));
    } catch (const std::exception&) {
        rejected = true;
    }
    wait_for_child(child, true);
    return rejected;
}

bool rejects(const std::string& mutation) {
    try {
        if (mutation == "custody_missing") {
            return rejects_missing_custody();
        } else {
            static_cast<void>(capture::ValidatedPrelaunchPlan::validate(request(mutation)));
        }
        return false;
    } catch (const capture::SupervisorError&) {
        return true;
    }
}

void run(const std::string& mutation) {
    static_assert(!std::is_copy_constructible_v<capture::RawPrelaunchRequest>);
    static_assert(!std::is_copy_assignable_v<capture::RawPrelaunchRequest>);
    static_assert(std::is_nothrow_move_constructible_v<capture::RawPrelaunchRequest>);
    static_assert(!std::is_copy_constructible_v<capture::ValidatedPrelaunchContext>);
    static_assert(!std::is_copy_assignable_v<capture::ValidatedPrelaunchContext>);
    static_assert(std::is_nothrow_move_constructible_v<capture::ValidatedPrelaunchContext>);
    static_assert(!std::is_move_assignable_v<capture::ValidatedPrelaunchContext>);
    static_assert(std::is_nothrow_move_constructible_v<capture::ValidatedPrelaunchPlan>);
    static_assert(!std::is_move_assignable_v<capture::ValidatedPrelaunchPlan>);
    static_assert(!std::is_copy_constructible_v<capture::ValidatedPrelaunchContextSlot>);
    static_assert(!std::is_move_constructible_v<capture::ValidatedPrelaunchContextSlot>);
    static_assert(!std::is_same_v<
                  capture::ValidatedCollectorProfileBuildLabelText,
                  capture::ExactGnuBuildIdDescriptorBytes>);
    static_assert(!std::is_constructible_v<
                  capture::ValidatedCollectorProfileBuildLabelText,
                  std::vector<Byte>>);
    static_assert(!std::is_constructible_v<
                  capture::ExactGnuBuildIdDescriptorBytes,
                  std::string>);
    static_assert(!std::is_constructible_v<capture::ValidatedPrelaunchContext,
                                           capture::ValidatedPrelaunchPlan&&,
                                           capture::OwnedFd,
                                           capture::WorkDirectoryIdentity,
                                           capture::Sha256Digest>);

    const std::filesystem::path root = std::filesystem::temp_directory_path() /
        ("v631302-prelaunch-context-" + std::to_string(static_cast<long>(::getpid())));
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root / "work");
    const std::filesystem::path work = root / "work";
    if (mutation != "ok" && mutation != "ownership" && mutation != "digest" &&
        mutation != "label_ascii_max" && mutation != "harness_empty") {
        require(rejects(mutation), "adversarial request was accepted");
        std::cout << "prelaunch_context_harness_ok mutation=" << mutation << " zero_authority=1\n";
        std::filesystem::remove_all(root);
        return;
    }

    std::vector<Byte> caller_gnu_descriptor;
    capture::Sha256Digest32 caller_prelaunch_root{};
    const std::string plan_mutation =
        mutation == "harness_empty" ? mutation : "ok";
    capture::ValidatedPrelaunchPlan plan =
        capture::ValidatedPrelaunchPlan::validate(
            request(plan_mutation, &caller_gnu_descriptor, &caller_prelaunch_root));
    require(plan.working_directory_relative_path() == "work",
            "plan working-directory getter mismatch");
    require(plan.namespace_relative_cwd() == "work",
            "plan namespace-relative cwd getter mismatch");
    require(plan.primary_source() == "src/Export.cpp", "plan primary-source getter mismatch");
    require(plan.path_profile().version == 2u,
            "plan path-profile version mismatch");
    require(plan.path_profile().source_absolute_prefix == "/src",
            "plan path-profile getter mismatch");
    require(plan.public_file_rows().size() == 5u, "plan public-file-row getter mismatch");
    require(plan.requested_argv().size() == 9u, "plan argv getter mismatch");
    require(plan.harness_expectations().capture_entry_component.byte_length == 101u,
            "plan did not retain authoritative harness expectations");
    capture::ValidatedPrelaunchContext context =
        bind_via_scm_rights(std::move(plan), work);
    require(
        context.collector_profile_build_label_text().value() ==
            "collector-profile-v1",
        "profile build label changed");
    require(
        context.expected_collector_gnu_build_id_descriptor_bytes().value() ==
            caller_gnu_descriptor,
        "initial deep-owned GNU descriptor mismatch");
    caller_gnu_descriptor[0] ^= 0xffu;
    caller_prelaunch_root[0] ^= 0xffu;
    require(
        context.expected_collector_gnu_build_id_descriptor_bytes().value()[0] ==
            0x63u,
        "caller descriptor mutation escaped ownership");
    require(context.path_profile().work_absolute_prefix == "/work", "decoded work path mismatch");
    require(context.public_file_rows().size() == 5u, "decoded public rows mismatch");
    require(context.harness_expectations().native_supervisor_component.build_id.size() == 4u,
            "context did not retain authoritative harness expectations");
    if (mutation == "harness_empty") {
        require(
            context.harness_expectations()
                .capture_interpreter_component.build_id.empty(),
            "empty harness build ID was not retained");
    }
    require(context.retained_working_directory_fd() >= 0, "retained FD was lost");

    if (mutation == "digest") {
        capture::ValidatedPrelaunchContext equal =
            bind_via_scm_rights(
                capture::ValidatedPrelaunchPlan::validate(request("ok")), work);
        capture::ValidatedPrelaunchContext different =
            bind_via_scm_rights(
                capture::ValidatedPrelaunchPlan::validate(request("binding_change")), work);
        capture::ValidatedPrelaunchContext root_different =
            bind_via_scm_rights(
                capture::ValidatedPrelaunchPlan::validate(request("prelaunch_root_change")), work);
        require(context.has_same_private_binding(equal), "binding digest is not deterministic");
        require(!context.has_same_private_binding(different), "binding digest omits caller expectations");
        require(!context.has_same_private_binding(root_different),
                "binding digest omits the prelaunch expectations root");
        capture::ValidatedPrelaunchContext moved = std::move(equal);
        require(moved.has_same_private_binding(context), "move changed private binding");
    }
    std::cout << "prelaunch_context_harness_ok mutation=" << mutation << " zero_authority=1\n";
    std::filesystem::remove_all(root);
}

}  // namespace

int main(int argc, char** argv) {
    run(argc == 2 ? argv[1] : "ok");
    return 0;
}
