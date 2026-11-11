#include "ProcInspector.h"

#if !defined(__linux__)
#error "ProcInspector is a Linux-only Capture V2 component"
#endif

#include "OwnedFd.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/SHA256.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <limits>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {
namespace {

constexpr std::size_t kReadBufferBytes = 64u * 1024u;

[[noreturn]] void fail(SupervisorFailure failure, std::string message, int error = 0) {
    throw SupervisorError(failure, std::move(message), error);
}

std::string proc_directory_path(pid_t pid) {
    if (pid <= 0) {
        fail(SupervisorFailure::InvalidRequest, "stopped process pid must be positive");
    }
    return "/proc/" + std::to_string(static_cast<std::intmax_t>(pid));
}

void validate_requirement(const StoppedProcessRequirement& requirement) {
    static_cast<void>(proc_directory_path(requirement.pid));
    if (requirement.expected_argv.empty()) {
        fail(SupervisorFailure::InvalidRequest, "expected argv must be nonempty");
    }
    if (!requirement.require_empty_environment) {
        fail(SupervisorFailure::InvalidRequest, "empty environment must be required");
    }
    if (requirement.limits.maximum_cmdline_bytes == 0u ||
        requirement.limits.maximum_environ_bytes == 0u ||
        requirement.limits.maximum_status_bytes == 0u ||
        requirement.limits.maximum_cwd_link_bytes == 0u ||
        requirement.limits.maximum_executable_bytes == 0u) {
        fail(SupervisorFailure::InvalidRequest, "proc inspection limits must be positive");
    }
    if (requirement.expected_executable_byte_length >
        requirement.limits.maximum_executable_bytes) {
        fail(SupervisorFailure::InvalidRequest, "expected executable exceeds configured limit");
    }
    std::size_t encoded_argv_bytes = 0;
    for (const std::string& argument : requirement.expected_argv) {
        if (argument.find('\0') != std::string::npos) {
            fail(SupervisorFailure::InvalidRequest, "expected argv contains NUL");
        }
        if (argument.size() >= requirement.limits.maximum_cmdline_bytes ||
            encoded_argv_bytes > requirement.limits.maximum_cmdline_bytes - argument.size() - 1u) {
            fail(SupervisorFailure::InvalidRequest, "expected argv exceeds configured limit");
        }
        encoded_argv_bytes += argument.size() + 1u;
    }
}

OwnedFd open_proc_member(int proc_directory_fd, const char* member, int flags);
std::vector<std::uint8_t> read_bounded_binary(
    int descriptor, std::size_t maximum_bytes, const char* member);

std::string_view trim_horizontal_whitespace(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1u);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
        value.remove_suffix(1u);
    }
    return value;
}

std::string_view require_single_status_value(std::string_view status, std::string_view key) {
    std::optional<std::string_view> found;
    std::size_t offset = 0u;
    while (offset < status.size()) {
        const std::size_t end = status.find('\n', offset);
        const std::size_t line_end = end == std::string_view::npos ? status.size() : end;
        const std::string_view line = status.substr(offset, line_end - offset);
        if (line.starts_with(key)) {
            if (found.has_value()) {
                fail(SupervisorFailure::ProtocolViolation, "stopped process status field is duplicated");
            }
            found = trim_horizontal_whitespace(line.substr(key.size()));
        }
        if (end == std::string_view::npos) {
            break;
        }
        offset = end + 1u;
    }
    if (!found.has_value()) {
        fail(SupervisorFailure::ProtocolViolation, "stopped process status field is missing");
    }
    return *found;
}

bool is_zero_hexadecimal(std::string_view value) {
    if (value.empty()) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](char character) {
        return character == '0';
    });
}

std::uint32_t parse_decimal_id(std::string_view token) {
    if (token.empty()) {
        fail(SupervisorFailure::ProtocolViolation, "stopped process status id is empty");
    }
    std::uint64_t value = 0u;
    const auto [end, error] = std::from_chars(token.data(), token.data() + token.size(), value);
    if (error != std::errc{} || end != token.data() + token.size() ||
        value > std::numeric_limits<std::uint32_t>::max()) {
        fail(SupervisorFailure::ProtocolViolation, "stopped process status id is malformed");
    }
    return static_cast<std::uint32_t>(value);
}

std::array<std::uint32_t, 4> parse_four_ids(std::string_view value) {
    std::array<std::uint32_t, 4> ids{};
    for (std::size_t index = 0u; index < ids.size(); ++index) {
        value = trim_horizontal_whitespace(value);
        if (value.empty()) {
            fail(SupervisorFailure::ProtocolViolation, "stopped process status id row is short");
        }
        const std::size_t separator = value.find_first_of(" \t");
        const std::string_view token = value.substr(0u, separator);
        ids[index] = parse_decimal_id(token);
        value = separator == std::string_view::npos
            ? std::string_view{}
            : value.substr(separator);
    }
    if (!trim_horizontal_whitespace(value).empty()) {
        fail(SupervisorFailure::ProtocolViolation, "stopped process status id row is long");
    }
    return ids;
}

struct PrivilegeObservation final {
    bool zero_capability_sets = false;
    bool no_new_privileges = false;
    std::uint32_t user_id = 0u;
    std::uint32_t group_id = 0u;
    bool empty_supplementary_groups = false;
};

PrivilegeObservation inspect_privilege_state(
    int proc_directory_fd, const StoppedProcessRequirement& requirement) {
    const std::vector<std::uint8_t> bytes = read_bounded_binary(
        open_proc_member(proc_directory_fd, "status", O_RDONLY).get(),
        requirement.limits.maximum_status_bytes,
        "status");
    const std::string status(bytes.begin(), bytes.end());
    constexpr std::array<std::string_view, 5> capability_keys = {
        "CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"};
    bool zero_capability_sets = true;
    for (const std::string_view key : capability_keys) {
        zero_capability_sets = zero_capability_sets &&
            is_zero_hexadecimal(require_single_status_value(status, key));
    }
    const bool no_new_privileges = require_single_status_value(status, "NoNewPrivs:") == "1";

    const auto user_ids = parse_four_ids(require_single_status_value(status, "Uid:"));
    const auto group_ids = parse_four_ids(require_single_status_value(status, "Gid:"));
    const bool uniform_user_id = std::all_of(
        user_ids.begin(), user_ids.end(), [&](std::uint32_t value) {
            return value == user_ids.front();
        });
    const bool uniform_group_id = std::all_of(
        group_ids.begin(), group_ids.end(), [&](std::uint32_t value) {
            return value == group_ids.front();
        });
    const bool empty_supplementary_groups =
        require_single_status_value(status, "Groups:").empty();

    if ((requirement.require_zero_capability_sets && !zero_capability_sets) ||
        (requirement.require_no_new_privileges && !no_new_privileges) ||
        (requirement.expected_user_id.has_value() &&
         (!uniform_user_id || user_ids.front() != *requirement.expected_user_id)) ||
        (requirement.expected_group_id.has_value() &&
         (!uniform_group_id || group_ids.front() != *requirement.expected_group_id)) ||
        (requirement.require_empty_supplementary_groups && !empty_supplementary_groups)) {
        fail(SupervisorFailure::ProtocolViolation, "stopped process privilege state differs from requirement");
    }
    return PrivilegeObservation{
        zero_capability_sets,
        no_new_privileges,
        user_ids.front(),
        group_ids.front(),
        empty_supplementary_groups,
    };
}

OwnedFd open_proc_directory(pid_t pid) {
    const std::string path = proc_directory_path(pid);
    const int descriptor = ::open(
        path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW);
    if (descriptor < 0) {
        fail(SupervisorFailure::SystemFailure, "open stopped process proc directory failed", errno);
    }
    return OwnedFd(descriptor);
}

OwnedFd open_proc_member(int proc_directory_fd, const char* member, int flags) {
    const int descriptor = ::openat(proc_directory_fd, member, flags | O_CLOEXEC | O_NOCTTY);
    if (descriptor < 0) {
        fail(SupervisorFailure::SystemFailure, "open stopped process proc member failed", errno);
    }
    return OwnedFd(descriptor);
}

std::vector<std::uint8_t> read_bounded_binary(
    int descriptor, std::size_t maximum_bytes, const char* member) {
    std::vector<std::uint8_t> bytes;
    bytes.reserve(std::min(maximum_bytes, kReadBufferBytes));
    std::array<std::uint8_t, kReadBufferBytes> buffer{};
    for (;;) {
        const ssize_t count = ::read(descriptor, buffer.data(), buffer.size());
        if (count > 0) {
            const std::size_t length = static_cast<std::size_t>(count);
            if (length > maximum_bytes || bytes.size() > maximum_bytes - length) {
                fail(SupervisorFailure::ResourceLimit, std::string(member) + " exceeds configured limit");
            }
            bytes.insert(bytes.end(), buffer.data(), buffer.data() + length);
            continue;
        }
        if (count == 0) {
            return bytes;
        }
        if (errno == EINTR) {
            continue;
        }
        fail(SupervisorFailure::SystemFailure, std::string("read ") + member + " failed", errno);
    }
}

void require_stopped_process(int proc_directory_fd) {
    constexpr std::size_t kMaximumStatBytes = 4096u;
    const std::vector<std::uint8_t> bytes = read_bounded_binary(
        open_proc_member(proc_directory_fd, "stat", O_RDONLY).get(),
        kMaximumStatBytes,
        "stat");
    if (bytes.empty()) {
        fail(SupervisorFailure::ProtocolViolation, "stopped process stat is empty");
    }

    const std::string stat(bytes.begin(), bytes.end());
    const std::size_t command_end = stat.rfind(')');
    if (command_end == std::string::npos || command_end + 3u >= stat.size() ||
        stat[command_end + 1u] != ' ' || stat[command_end + 3u] != ' ') {
        fail(SupervisorFailure::ProtocolViolation, "stopped process stat is malformed");
    }
    const char state = stat[command_end + 2u];
    if (state != 'T' && state != 't') {
        fail(SupervisorFailure::ProtocolViolation, "process is not stopped for inspection");
    }
}

std::vector<std::string> parse_exact_nul_argv(const std::vector<std::uint8_t>& bytes) {
    if (bytes.empty() || bytes.back() != 0u) {
        fail(SupervisorFailure::ProtocolViolation, "cmdline is not exactly NUL-terminated");
    }
    std::vector<std::string> argv;
    std::size_t start = 0;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (bytes[index] != 0u) {
            continue;
        }
        argv.emplace_back(
            reinterpret_cast<const char*>(bytes.data() + start), index - start);
        start = index + 1u;
    }
    if (start != bytes.size() || argv.empty()) {
        fail(SupervisorFailure::ProtocolViolation, "cmdline has trailing parse ambiguity");
    }
    return argv;
}

struct ExecutableIdentity final {
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    std::uint64_t byte_length = 0;
    std::uint64_t link_count = 0;
    std::uint32_t mode = 0;
    std::int64_t modification_seconds = 0;
    std::int64_t modification_nanoseconds = 0;
    std::int64_t change_seconds = 0;
    std::int64_t change_nanoseconds = 0;

    friend bool operator==(const ExecutableIdentity&, const ExecutableIdentity&) = default;
};

ExecutableIdentity executable_identity(int descriptor, const char* message) {
    struct stat status {};
    if (::fstat(descriptor, &status) != 0) {
        fail(SupervisorFailure::SystemFailure, message, errno);
    }
    if (!S_ISREG(status.st_mode) || status.st_size < 0) {
        fail(SupervisorFailure::ProtocolViolation, "stopped process executable is not a regular sized file");
    }
    return ExecutableIdentity{
        static_cast<std::uint64_t>(status.st_dev),
        static_cast<std::uint64_t>(status.st_ino),
        static_cast<std::uint64_t>(status.st_size),
        static_cast<std::uint64_t>(status.st_nlink),
        static_cast<std::uint32_t>(status.st_mode),
        static_cast<std::int64_t>(status.st_mtim.tv_sec),
        static_cast<std::int64_t>(status.st_mtim.tv_nsec),
        static_cast<std::int64_t>(status.st_ctim.tv_sec),
        static_cast<std::int64_t>(status.st_ctim.tv_nsec),
    };
}

Sha256Digest hash_exact_executable(int descriptor, std::uint64_t byte_length) {
    llvm::SHA256 hasher;
    std::array<std::uint8_t, kReadBufferBytes> buffer{};
    std::uint64_t offset = 0;
    while (offset < byte_length) {
        const std::uint64_t remaining = byte_length - offset;
        const std::size_t requested = static_cast<std::size_t>(
            std::min<std::uint64_t>(remaining, static_cast<std::uint64_t>(buffer.size())));
        const ssize_t count = ::pread(
            descriptor, buffer.data(), requested, static_cast<off_t>(offset));
        if (count > 0) {
            const std::size_t length = static_cast<std::size_t>(count);
            hasher.update(llvm::ArrayRef<std::uint8_t>(buffer.data(), length));
            offset += static_cast<std::uint64_t>(length);
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        fail(SupervisorFailure::ProtocolViolation, "executable ended before committed length", errno);
    }
    return hasher.final();
}

std::pair<std::uint64_t, std::uint64_t> inspect_expected_cwd(
    int proc_directory_fd, const StoppedProcessRequirement& requirement) {
    OwnedFd cwd = open_proc_member(proc_directory_fd, "cwd", O_PATH | O_DIRECTORY);
    struct stat status {};
    if (::fstat(cwd.get(), &status) != 0) {
        fail(SupervisorFailure::SystemFailure, "fstat stopped process cwd failed", errno);
    }
    if (static_cast<std::uint64_t>(status.st_dev) != requirement.expected_cwd_device ||
        static_cast<std::uint64_t>(status.st_ino) != requirement.expected_cwd_inode) {
        fail(SupervisorFailure::ProtocolViolation, "stopped process cwd identity differs from requirement");
    }
    return {
        static_cast<std::uint64_t>(status.st_dev),
        static_cast<std::uint64_t>(status.st_ino)};
}

std::string inspect_cwd_proc_link(
    int proc_directory_fd,
    std::size_t maximum_bytes) {
    if (maximum_bytes == std::numeric_limits<std::size_t>::max()) {
        fail(SupervisorFailure::InvalidRequest,
             "stopped process cwd link bound cannot be represented");
    }
    std::vector<char> bytes(maximum_bytes + 1u);
    const ssize_t count = ::readlinkat(
        proc_directory_fd, "cwd", bytes.data(), bytes.size());
    if (count < 0) {
        fail(SupervisorFailure::SystemFailure,
             "readlink stopped process cwd failed", errno);
    }
    if (count == 0 || static_cast<std::size_t>(count) > maximum_bytes) {
        fail(SupervisorFailure::ResourceLimit,
             "stopped process cwd link is empty or exceeds its bound");
    }
    return std::string(bytes.data(), static_cast<std::size_t>(count));
}

}  // namespace

ProcInspector::ProcInspector(StoppedProcessRequirement requirement)
    : requirement_(std::move(requirement)) {
    validate_requirement(requirement_);
}

const StoppedProcessObservation& ProcInspector::authenticate() {
    if (state_ != State::Ready) {
        state_ = State::Failed;
        fail(SupervisorFailure::ProtocolViolation, "proc inspector is not ready to authenticate");
    }
    try {
        OwnedFd proc_directory = open_proc_directory(requirement_.pid);
        require_stopped_process(proc_directory.get());
        const std::vector<std::uint8_t> cmdline = read_bounded_binary(
            open_proc_member(proc_directory.get(), "cmdline", O_RDONLY).get(),
            requirement_.limits.maximum_cmdline_bytes,
            "cmdline");
        std::vector<std::string> argv = parse_exact_nul_argv(cmdline);
        if (argv != requirement_.expected_argv) {
            fail(SupervisorFailure::ProtocolViolation, "stopped process argv differs from requirement");
        }

        const std::vector<std::uint8_t> environ = read_bounded_binary(
            open_proc_member(proc_directory.get(), "environ", O_RDONLY).get(),
            requirement_.limits.maximum_environ_bytes,
            "environ");
        if (!environ.empty()) {
            fail(SupervisorFailure::ProtocolViolation, "stopped process environment is not empty");
        }

        OwnedFd executable = open_proc_member(proc_directory.get(), "exe", O_RDONLY);
        const ExecutableIdentity before = executable_identity(executable.get(), "fstat executable before hash failed");
        if (before.byte_length > requirement_.limits.maximum_executable_bytes ||
            before.byte_length != requirement_.expected_executable_byte_length) {
            fail(SupervisorFailure::ProtocolViolation, "stopped process executable length differs from requirement");
        }
        const Sha256Digest digest = hash_exact_executable(executable.get(), before.byte_length);
        const ExecutableIdentity after = executable_identity(executable.get(), "fstat executable after hash failed");
        if (after != before) {
            fail(SupervisorFailure::ProtocolViolation, "stopped process executable changed during hash");
        }
        if (digest != requirement_.expected_executable_sha256) {
            fail(SupervisorFailure::ProtocolViolation, "stopped process executable digest differs from requirement");
        }

        const auto [cwd_device, cwd_inode] = inspect_expected_cwd(proc_directory.get(), requirement_);
        std::string cwd_proc_link = inspect_cwd_proc_link(
            proc_directory.get(),
            requirement_.limits.maximum_cwd_link_bytes);
        const PrivilegeObservation privileges =
            inspect_privilege_state(proc_directory.get(), requirement_);
        require_stopped_process(proc_directory.get());
        StoppedProcessObservation observation(
            requirement_.pid,
            std::move(argv),
            before.byte_length,
            digest,
            cwd_device,
            cwd_inode,
            std::move(cwd_proc_link),
            privileges.zero_capability_sets,
            privileges.no_new_privileges,
            privileges.user_id,
            privileges.group_id,
            privileges.empty_supplementary_groups);
        observation_.emplace(std::move(observation));
        state_ = State::Authenticated;
        return *observation_;
    } catch (...) {
        state_ = State::Failed;
        throw;
    }
}

const StoppedProcessObservation& ProcInspector::observation() const {
    if (state_ != State::Authenticated || !observation_.has_value()) {
        fail(SupervisorFailure::ProtocolViolation, "proc inspector has no authenticated observation");
    }
    return *observation_;
}

}  // namespace evaluation_v6_3_1::capture_v2
