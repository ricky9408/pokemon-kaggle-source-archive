#include "RuntimeObserver.h"

#if !defined(__linux__)
#error "RuntimeObserver is a Linux-only Capture V2 component"
#endif

#include "ElfMetadata.h"
#include "OpenPathResolver.h"
#include "OwnedFd.h"
#include "PidfdOpenedFile.h"
#include "ProcMapsParser.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/SHA256.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <dirent.h>
#include <fcntl.h>
#include <limits>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {
namespace {

constexpr std::uint32_t kCollectorRole = 1u;
constexpr std::uint32_t kInterpreterRole = 6u;
constexpr std::uint32_t kClangCppRole = 7u;
constexpr std::uint32_t kRuntimeDependencyRole = 8u;
constexpr std::uint64_t kProtExec = 4u;
constexpr std::size_t kReadChunkBytes = 4u * 1024u;

[[noreturn]] void fail(SupervisorFailure failure, std::string message, int error = 0) {
    throw SupervisorError(failure, std::move(message), error);
}

bool has_role(const NamespaceFileExpectation& row, std::uint32_t role) {
    return std::binary_search(row.role_codes.begin(), row.role_codes.end(), role);
}

bool runtime_role(const NamespaceFileExpectation& row) {
    return has_role(row, kCollectorRole) || has_role(row, kInterpreterRole) ||
           has_role(row, kClangCppRole) || has_role(row, kRuntimeDependencyRole);
}

struct RuntimeFileIdentity final {
    std::uint64_t device = 0u;
    std::uint64_t inode = 0u;
    std::uint64_t byte_length = 0u;
    std::uint64_t link_count = 0u;
    std::uint32_t mode = 0u;
    std::int64_t modification_seconds = 0;
    std::int64_t modification_nanoseconds = 0;
    std::int64_t change_seconds = 0;
    std::int64_t change_nanoseconds = 0;

    friend bool operator==(const RuntimeFileIdentity&, const RuntimeFileIdentity&) = default;
};

RuntimeFileIdentity file_identity(int descriptor, const char* field) {
    struct stat status {};
    if (::fstat(descriptor, &status) != 0) {
        fail(SupervisorFailure::SystemFailure, std::string("fstat ") + field + " failed", errno);
    }
    if (!S_ISREG(status.st_mode) || status.st_size <= 0) {
        fail(SupervisorFailure::ProtocolViolation, std::string(field) + " is not a sized regular file");
    }
    return RuntimeFileIdentity{
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

Sha256Digest hash_file(
    int descriptor,
    std::uint64_t byte_length,
    const MonotonicDeadline& deadline) {
    llvm::SHA256 hasher;
    std::array<std::uint8_t, kReadChunkBytes> bytes{};
    std::uint64_t offset = 0u;
    while (offset < byte_length) {
        if (deadline.expired()) {
            fail(SupervisorFailure::TraceTimeout, "runtime file hash deadline expired");
        }
        const std::size_t requested = static_cast<std::size_t>(
            std::min<std::uint64_t>(byte_length - offset, bytes.size()));
        const ssize_t count = ::pread(
            descriptor, bytes.data(), requested, static_cast<off_t>(offset));
        if (count > 0) {
            const std::size_t length = static_cast<std::size_t>(count);
            hasher.update(llvm::ArrayRef<std::uint8_t>(bytes.data(), length));
            offset += static_cast<std::uint64_t>(length);
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        fail(SupervisorFailure::ProtocolViolation, "runtime file ended before committed length", errno);
    }
    return hasher.final();
}

struct OpenedRuntimeFile final {
    OwnedFd descriptor;
    RuntimeFileIdentity identity;
    Sha256Digest sha256{};
};

OpenedRuntimeFile authenticate_opened_runtime_file(
    OwnedFd descriptor,
    std::uint64_t maximum_bytes,
    const MonotonicDeadline& deadline,
    const char* field) {
    const RuntimeFileIdentity before = file_identity(descriptor.get(), field);
    if (before.byte_length > maximum_bytes) {
        fail(SupervisorFailure::ResourceLimit, std::string(field) + " exceeds byte limit");
    }
    const Sha256Digest digest = hash_file(descriptor.get(), before.byte_length, deadline);
    const RuntimeFileIdentity after = file_identity(descriptor.get(), field);
    if (after != before) {
        fail(SupervisorFailure::ProtocolViolation, std::string(field) + " changed during hash");
    }
    return OpenedRuntimeFile{std::move(descriptor), before, digest};
}

std::vector<char> read_small_proc_file(
    const std::string& path,
    const char* field,
    const MonotonicDeadline& deadline) {
    OwnedFd descriptor(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW));
    if (!descriptor) {
        fail(SupervisorFailure::TraceFailure, std::string("open ") + field + " failed", errno);
    }
    std::vector<char> bytes(8193u, '\0');
    std::size_t offset = 0u;
    for (;;) {
        if (deadline.expired()) {
            fail(SupervisorFailure::TraceTimeout, std::string(field) + " deadline expired");
        }
        const ssize_t count = ::read(
            descriptor.get(), bytes.data() + offset, bytes.size() - 1u - offset);
        if (count > 0) {
            offset += static_cast<std::size_t>(count);
            if (offset == bytes.size() - 1u) {
                fail(SupervisorFailure::ResourceLimit, std::string(field) + " exceeds byte limit");
            }
            continue;
        }
        if (count == 0) {
            bytes.resize(offset);
            return bytes;
        }
        if (errno == EINTR) {
            continue;
        }
        fail(SupervisorFailure::TraceFailure, std::string("read ") + field + " failed", errno);
    }
}

std::uint64_t parse_unique_proc_decimal_field(
    std::span<const char> bytes,
    std::string_view name,
    const char* field) {
    const std::string_view contents(bytes.data(), bytes.size());
    std::optional<std::uint64_t> value;
    std::size_t offset = 0u;
    while (offset < contents.size()) {
        const std::size_t end = contents.find('\n', offset);
        const std::string_view line = contents.substr(
            offset, end == std::string_view::npos ? contents.size() - offset : end - offset);
        offset = end == std::string_view::npos ? contents.size() : end + 1u;
        if (!line.starts_with(name)) {
            continue;
        }
        if (value.has_value()) {
            fail(SupervisorFailure::ProtocolViolation, std::string(field) + " is duplicated");
        }
        std::string_view decimal = line.substr(name.size());
        while (!decimal.empty() && (decimal.front() == ' ' || decimal.front() == '\t')) {
            decimal.remove_prefix(1u);
        }
        std::uint64_t parsed = 0u;
        const auto [parsed_end, error] = std::from_chars(
            decimal.data(), decimal.data() + decimal.size(), parsed, 10);
        if (decimal.empty() || error != std::errc{} ||
            parsed_end != decimal.data() + decimal.size()) {
            fail(SupervisorFailure::ProtocolViolation, std::string(field) + " is malformed");
        }
        value = parsed;
    }
    if (!value.has_value()) {
        fail(SupervisorFailure::ProtocolViolation, std::string(field) + " is missing");
    }
    return *value;
}

void require_pidfd_targets_pid(
    int pidfd,
    pid_t pid,
    const MonotonicDeadline& deadline) {
    const std::string path = "/proc/self/fdinfo/" + std::to_string(pidfd);
    const std::vector<char> bytes = read_small_proc_file(
        path, "runtime pidfd info", deadline);
    const std::uint64_t observed = parse_unique_proc_decimal_field(
        bytes, "Pid:", "runtime pidfd target");
    if (observed != static_cast<std::uint64_t>(pid)) {
        fail(SupervisorFailure::ProtocolViolation, "runtime pidfd targets a different process");
    }
}

void require_single_task(pid_t pid, const MonotonicDeadline& deadline) {
    const std::string path = "/proc/" + std::to_string(pid) + "/task";
    DIR* raw = ::opendir(path.c_str());
    if (raw == nullptr) {
        fail(SupervisorFailure::TraceFailure, "open runtime task directory failed", errno);
    }
    std::unique_ptr<DIR, decltype(&::closedir)> directory(raw, &::closedir);
    std::vector<pid_t> tids;
    errno = 0;
    for (;;) {
        if (deadline.expired()) {
            fail(SupervisorFailure::TraceTimeout, "runtime task directory deadline expired");
        }
        dirent* entry = ::readdir(directory.get());
        if (entry == nullptr) {
            if (errno != 0) {
                fail(SupervisorFailure::TraceFailure, "read runtime task directory failed", errno);
            }
            break;
        }
        const std::string_view name(entry->d_name);
        if (name == "." || name == "..") {
            continue;
        }
        std::uint64_t value = 0u;
        const auto [end, error] = std::from_chars(
            name.data(), name.data() + name.size(), value, 10);
        if (error != std::errc{} || end != name.data() + name.size() ||
            value == 0u || value > static_cast<std::uint64_t>(std::numeric_limits<pid_t>::max())) {
            fail(SupervisorFailure::TraceFailure, "runtime task directory has an invalid entry");
        }
        tids.push_back(static_cast<pid_t>(value));
        errno = 0;
    }
    if (tids.size() != 1u || tids.front() != pid) {
        fail(SupervisorFailure::ProtocolViolation, "runtime process is not a single stopped task");
    }
}

void require_stopped(
    pid_t pid,
    int pidfd,
    const MonotonicDeadline& deadline) {
    require_pidfd_targets_pid(pidfd, pid, deadline);
    require_single_task(pid, deadline);
    const std::string path = "/proc/" + std::to_string(pid) + "/stat";
    const std::vector<char> stat_bytes = read_small_proc_file(
        path, "stopped runtime process stat", deadline);
    const std::string_view stat(stat_bytes.data(), stat_bytes.size());
    const std::size_t command_end = stat.rfind(')');
    if (command_end == std::string_view::npos || command_end + 3u >= stat.size() ||
        stat[command_end + 1u] != ' ' || stat[command_end + 3u] != ' ' ||
        (stat[command_end + 2u] != 'T' && stat[command_end + 2u] != 't')) {
        fail(SupervisorFailure::ProtocolViolation, "runtime process is not stopped");
    }
    const std::string status_path = "/proc/" + std::to_string(pid) + "/status";
    const std::vector<char> status = read_small_proc_file(
        status_path, "stopped runtime process status", deadline);
    const std::uint64_t tracer = parse_unique_proc_decimal_field(
        status, "TracerPid:", "runtime tracer pid");
    if (tracer != static_cast<std::uint64_t>(::getpid())) {
        fail(SupervisorFailure::ProtocolViolation, "runtime process is not ptrace-stopped by this supervisor");
    }
}

std::vector<std::uint8_t> read_proc_maps(
    pid_t pid,
    std::size_t maximum_bytes,
    const MonotonicDeadline& deadline) {
    const std::string path = "/proc/" + std::to_string(pid) + "/maps";
    OwnedFd descriptor(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW));
    if (!descriptor) {
        fail(SupervisorFailure::TraceFailure, "open stopped runtime maps failed", errno);
    }
    std::vector<std::uint8_t> output;
    output.reserve(std::min<std::size_t>(maximum_bytes, kReadChunkBytes));
    std::array<std::uint8_t, kReadChunkBytes> bytes{};
    for (;;) {
        if (deadline.expired()) {
            fail(SupervisorFailure::TraceTimeout, "runtime maps read deadline expired");
        }
        const ssize_t count = ::read(descriptor.get(), bytes.data(), bytes.size());
        if (count > 0) {
            const std::size_t length = static_cast<std::size_t>(count);
            if (length > maximum_bytes || output.size() > maximum_bytes - length) {
                fail(SupervisorFailure::ResourceLimit, "runtime maps snapshot exceeds byte limit");
            }
            output.insert(output.end(), bytes.data(), bytes.data() + length);
            continue;
        }
        if (count == 0) {
            return output;
        }
        if (errno == EINTR) {
            continue;
        }
        fail(SupervisorFailure::TraceFailure, "read stopped runtime maps failed", errno);
    }
}

std::string map_files_entry_name(std::uint64_t start, std::uint64_t end) {
    std::array<char, 4u * sizeof(std::uint64_t) + 2u> buffer{};
    const auto first = std::to_chars(buffer.data(), buffer.data() + buffer.size(), start, 16);
    if (first.ec != std::errc{} || first.ptr == buffer.data() + buffer.size()) {
        fail(SupervisorFailure::ProtocolViolation, "format map_files start address failed");
    }
    *first.ptr = '-';
    const auto second = std::to_chars(
        first.ptr + 1, buffer.data() + buffer.size(), end, 16);
    if (second.ec != std::errc{}) {
        fail(SupervisorFailure::ProtocolViolation, "format map_files end address failed");
    }
    return std::string(buffer.data(), second.ptr);
}

struct PendingRuntimeObservation final {
    RuntimeObservationKind kind = RuntimeObservationKind::PtraceExecProcExe;
    std::string path;
    std::uint64_t device = 0u;
    std::uint64_t inode = 0u;
    std::uint64_t file_offset = 0u;
    std::uint64_t mapping_length = 0u;
    std::uint64_t protection_flags = 0u;
};

OwnedFd duplicate_validated_pidfd(int descriptor) {
    if (descriptor < 0) {
        fail(SupervisorFailure::InvalidRequest, "runtime pidfd is invalid");
    }
    const int duplicate = ::fcntl(descriptor, F_DUPFD_CLOEXEC, 0);
    if (duplicate < 0) {
        fail(SupervisorFailure::SystemFailure, "duplicate runtime pidfd failed", errno);
    }
    return OwnedFd(duplicate);
}

}  // namespace

class RuntimeObserver::Impl final {
public:
    Impl(
        pid_t stopped_pid,
        int validated_pidfd,
        std::string collector_namespace_relative_path,
        std::vector<NamespaceFileExpectation> namespace_files,
        const MonotonicDeadline& deadline,
        RuntimeObserverLimits limits)
        : pid_(stopped_pid),
          pidfd_(duplicate_validated_pidfd(validated_pidfd)),
          collector_path_(std::move(collector_namespace_relative_path)),
          limits_(limits) {
        if (pid_ <= 0 || !pidfd_ || !is_normalized_relative_path(collector_path_) ||
            limits_.maximum_runtime_file_bytes == 0u ||
            limits_.maximum_unique_runtime_bytes == 0u ||
            limits_.maximum_authenticated_runtime_bytes == 0u ||
            limits_.maximum_proc_maps_bytes == 0u ||
            limits_.maximum_proc_maps_line_bytes == 0u ||
            limits_.maximum_executable_mapping_rows == 0u ||
            limits_.maximum_runtime_objects == 0u || namespace_files.empty()) {
            fail(SupervisorFailure::InvalidRequest, "runtime observer request is invalid");
        }
        for (NamespaceFileExpectation& row : namespace_files) {
            if (!is_normalized_relative_path(row.namespace_relative_path) ||
                !std::is_sorted(row.role_codes.begin(), row.role_codes.end()) ||
                std::adjacent_find(row.role_codes.begin(), row.role_codes.end()) !=
                    row.role_codes.end()) {
                fail(SupervisorFailure::InvalidRequest, "runtime namespace row is malformed");
            }
            const auto [iterator, inserted] = namespace_.emplace(
                row.namespace_relative_path, std::move(row));
            (void)iterator;
            if (!inserted) {
                fail(SupervisorFailure::InvalidRequest, "runtime namespace paths are duplicated");
            }
        }
        const auto collector = namespace_.find(collector_path_);
        if (collector == namespace_.end() || !has_role(collector->second, kCollectorRole)) {
            fail(SupervisorFailure::InvalidRequest, "runtime collector path lacks collector role");
        }
        require_exact_role_count(kCollectorRole, "collector");
        require_exact_role_count(kInterpreterRole, "interpreter");
        require_exact_role_count(kClangCppRole, "primary clang");
        const std::string collector_role_path = path_for_exact_role(kCollectorRole);
        const std::string interpreter_role_path = path_for_exact_role(kInterpreterRole);
        const std::string clang_role_path = path_for_exact_role(kClangCppRole);
        if (collector_role_path != collector_path_ ||
            collector_role_path == interpreter_role_path ||
            collector_role_path == clang_role_path ||
            interpreter_role_path == clang_role_path) {
            fail(SupervisorFailure::InvalidRequest, "runtime distinguished roles are not path-distinct");
        }
        require_stopped(pid_, pidfd_.get(), deadline);
    }

    void mark_failed() noexcept { failed_ = true; }

    void observe_exec_proc_exe(const MonotonicDeadline& deadline) {
        require_active();
        require_stopped(pid_, pidfd_.get(), deadline);
        if (exec_observed_) {
            fail(SupervisorFailure::ProtocolViolation, "collector exec was observed more than once");
        }
        const std::string proc_directory_path = "/proc/" + std::to_string(pid_);
        OwnedFd proc_directory(::open(
            proc_directory_path.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW));
        if (!proc_directory) {
            fail(SupervisorFailure::TraceFailure, "open runtime proc directory failed", errno);
        }
        OwnedFd executable(::openat(
            proc_directory.get(), "exe", O_RDONLY | O_CLOEXEC | O_NOCTTY));
        if (!executable) {
            fail(SupervisorFailure::TraceFailure, "open stopped runtime proc exe failed", errno);
        }
        OpenedRuntimeFile file = authenticate_opened_runtime_file(
            std::move(executable),
            authentication_cap_for(collector_path_),
            deadline,
            "runtime proc exe");
        consume_authenticated_bytes(file.identity.byte_length);
        add_observation(
            collector_path_,
            file,
            RuntimeObservationKind::PtraceExecProcExe,
            0u,
            0u,
            0u,
            deadline);
        const auto collector = objects_.find(collector_path_);
        if (collector == objects_.end() || collector->second.interpreter.empty()) {
            fail(SupervisorFailure::ProtocolViolation, "collector ELF has no exact PT_INTERP");
        }
        const std::string absolute_interpreter(
            collector->second.interpreter.begin(), collector->second.interpreter.end());
        interpreter_path_ = OpenPathResolver::resolve(
            absolute_interpreter,
            OpenPathResolver::SyscallFamily::Open,
            OpenPathResolver::kAtFdcwd,
            ".");
        const auto interpreter = namespace_.find(interpreter_path_);
        if (interpreter == namespace_.end() ||
            !has_role(interpreter->second, kInterpreterRole)) {
            fail(SupervisorFailure::ProtocolViolation, "PT_INTERP does not select the frozen interpreter row");
        }
        exec_observed_ = true;
    }

    void observe_mmap_fd(
        int child_fd,
        const std::string& path,
        std::uint64_t expected_device,
        std::uint64_t expected_inode,
        std::uint64_t file_offset,
        std::uint64_t mapping_length,
        std::uint64_t protection_flags,
        const MonotonicDeadline& deadline) {
        require_active();
        require_stopped(pid_, pidfd_.get(), deadline);
        if (!exec_observed_ || child_fd < 0 || mapping_length == 0u ||
            (protection_flags & kProtExec) == 0u || !is_normalized_relative_path(path)) {
            fail(SupervisorFailure::InvalidRequest, "runtime mmap observation is invalid");
        }
        PidfdOpenedFile opened = PidfdOpenedFile::duplicate_stopped_child_file(
            pidfd_.get(), child_fd, authentication_cap_for(path), deadline);
        const PidfdOpenedFileObservation& source = opened.observation();
        consume_authenticated_bytes(source.byte_length);
        if (source.device != expected_device || source.inode != expected_inode) {
            fail(
                SupervisorFailure::ProtocolViolation,
                "runtime mmap descriptor identity differs from FD tracker");
        }
        OwnedFd descriptor(::fcntl(opened.descriptor(), F_DUPFD_CLOEXEC, 0));
        if (!descriptor) {
            fail(SupervisorFailure::SystemFailure, "duplicate runtime mmap evidence failed", errno);
        }
        const RuntimeFileIdentity identity = file_identity(
            descriptor.get(), "runtime mmap evidence");
        if (identity.device != source.device || identity.inode != source.inode ||
            identity.byte_length != source.byte_length || identity.mode != source.mode) {
            fail(SupervisorFailure::ProtocolViolation, "runtime mmap duplicate identity changed");
        }
        OpenedRuntimeFile file{
            std::move(descriptor),
            identity,
            source.sha256,
        };
        add_observation(
            path,
            file,
            RuntimeObservationKind::PtraceMmapFdProtExec,
            file_offset,
            mapping_length,
            protection_flags,
            deadline);
    }

    void rescan_proc_map_files(const MonotonicDeadline& deadline) {
        require_active();
        require_stopped(pid_, pidfd_.get(), deadline);
        if (!exec_observed_) {
            fail(SupervisorFailure::ProtocolViolation, "runtime map scan preceded exec observation");
        }
        const std::vector<std::uint8_t> maps = read_proc_maps(
            pid_, limits_.maximum_proc_maps_bytes, deadline);
        const std::vector<ExecutableFileMapping> mappings =
            ProcMapsParser::parse_executable_file_mappings(
                maps,
                limits_.maximum_executable_mapping_rows,
                limits_.maximum_proc_maps_line_bytes);
        const std::string directory_path =
            "/proc/" + std::to_string(pid_) + "/map_files";
        OwnedFd directory(::open(
            directory_path.c_str(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW));
        if (!directory) {
            fail(SupervisorFailure::TraceFailure, "open stopped runtime map_files failed", errno);
        }
        for (const ExecutableFileMapping& mapping : mappings) {
            const std::string path = OpenPathResolver::resolve(
                mapping.diagnostic_absolute_path,
                OpenPathResolver::SyscallFamily::Open,
                OpenPathResolver::kAtFdcwd,
                ".");
            const auto expected = namespace_.find(path);
            if (expected == namespace_.end() || !runtime_role(expected->second)) {
                fail(SupervisorFailure::ProtocolViolation, "executable map is outside the frozen runtime namespace");
            }
            const std::string entry = map_files_entry_name(
                mapping.start_address, mapping.end_address);
            OwnedFd mapped(::openat(
                directory.get(), entry.c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY));
            if (!mapped) {
                fail(SupervisorFailure::TraceFailure, "open exact stopped map_files object failed", errno);
            }
            OpenedRuntimeFile file = authenticate_opened_runtime_file(
                std::move(mapped),
                authentication_cap_for(path),
                deadline,
                "runtime map_files object");
            consume_authenticated_bytes(file.identity.byte_length);
            if (static_cast<std::uint64_t>(major(file.identity.device)) != mapping.device_major ||
                static_cast<std::uint64_t>(minor(file.identity.device)) != mapping.device_minor ||
                file.identity.inode != mapping.inode) {
                fail(SupervisorFailure::ProtocolViolation, "map_files identity differs from maps snapshot");
            }
            add_observation(
                path,
                file,
                RuntimeObservationKind::ProcMapFilesProtExec,
                mapping.file_offset,
                mapping.mapping_length(),
                mapping.protection_flags,
                deadline);
        }
    }

    CompletedRuntimeObservation finalize() {
        require_active();
        if (!exec_observed_ || objects_.size() != observations_.size() ||
            objects_.empty() || objects_.size() > limits_.maximum_runtime_objects) {
            fail(SupervisorFailure::ProtocolViolation, "runtime observation is incomplete");
        }
        const auto primary_path = path_for_exact_role(kClangCppRole);
        const auto interpreter_path = path_for_exact_role(kInterpreterRole);
        const auto collector_path = path_for_exact_role(kCollectorRole);
        if (interpreter_path != interpreter_path_ || collector_path != collector_path_ ||
            !objects_.contains(primary_path) || !objects_.contains(interpreter_path) ||
            !objects_.contains(collector_path) ||
            objects_.at(primary_path).evidence.elf_soname !=
                std::vector<std::uint8_t>{'l', 'i', 'b', 'c', 'l', 'a', 'n', 'g', '-',
                                          'c', 'p', 'p', '.', 's', 'o', '.', '1', '6'}) {
            fail(SupervisorFailure::ProtocolViolation, "runtime primary/interpreter/collector closure is incomplete");
        }

        CompletedRuntimeObservation result{};
        result.runtime_object_rows.reserve(objects_.size());
        std::map<std::string, std::uint64_t> indices;
        for (const auto& [path, object] : objects_) {
            const std::uint64_t index = static_cast<std::uint64_t>(
                result.runtime_object_rows.size());
            indices.emplace(path, index);
            result.runtime_object_rows.push_back(object.evidence);
        }
        result.primary_clang_cpp_record = objects_.at(primary_path).evidence;
        result.elf_interpreter_record = objects_.at(interpreter_path).evidence;
        result.runtime_observation_rows.reserve(observations_.size());
        for (std::size_t sequence = 0u; sequence < observations_.size(); ++sequence) {
            const PendingRuntimeObservation& observation = observations_[sequence];
            result.runtime_observation_rows.push_back(RuntimeObservationEvidence{
                static_cast<std::uint64_t>(sequence),
                observation.kind,
                indices.at(observation.path),
                observation.device,
                observation.inode,
                observation.file_offset,
                observation.mapping_length,
                observation.protection_flags,
            });
        }
        return result;
    }

private:
    struct RuntimeObjectState final {
        RuntimeObjectEvidence evidence;
        std::vector<std::uint8_t> interpreter;
    };

    std::uint64_t remaining_authenticated_bytes() const {
        if (authenticated_runtime_bytes_ > limits_.maximum_authenticated_runtime_bytes) {
            fail(SupervisorFailure::ProtocolViolation, "runtime authenticated-byte counter overflowed");
        }
        return limits_.maximum_authenticated_runtime_bytes - authenticated_runtime_bytes_;
    }

    std::uint64_t remaining_unique_bytes() const {
        if (unique_runtime_bytes_ > limits_.maximum_unique_runtime_bytes) {
            fail(SupervisorFailure::ProtocolViolation, "runtime unique-byte counter overflowed");
        }
        return limits_.maximum_unique_runtime_bytes - unique_runtime_bytes_;
    }

    std::uint64_t authentication_cap_for(const std::string& path) const {
        std::uint64_t cap = std::min(
            limits_.maximum_runtime_file_bytes, remaining_authenticated_bytes());
        if (!objects_.contains(path)) {
            cap = std::min(cap, remaining_unique_bytes());
        }
        if (cap == 0u) {
            fail(SupervisorFailure::ResourceLimit, "runtime byte budget is exhausted");
        }
        return cap;
    }

    void consume_authenticated_bytes(std::uint64_t byte_length) {
        if (byte_length > remaining_authenticated_bytes()) {
            fail(SupervisorFailure::ResourceLimit, "runtime authenticated-byte budget exceeded");
        }
        authenticated_runtime_bytes_ += byte_length;
    }

    void consume_unique_bytes(std::uint64_t byte_length) {
        if (byte_length > remaining_unique_bytes()) {
            fail(SupervisorFailure::ResourceLimit, "runtime unique-byte budget exceeded");
        }
        unique_runtime_bytes_ += byte_length;
    }

    void reauthenticate_after_metadata(
        const OpenedRuntimeFile& file,
        const MonotonicDeadline& deadline) {
        const std::uint64_t cap = remaining_authenticated_bytes();
        if (file.identity.byte_length > cap) {
            fail(SupervisorFailure::ResourceLimit, "runtime post-metadata byte budget exceeded");
        }
        const Sha256Digest digest = hash_file(
            file.descriptor.get(), file.identity.byte_length, deadline);
        consume_authenticated_bytes(file.identity.byte_length);
        const RuntimeFileIdentity after = file_identity(
            file.descriptor.get(), "after runtime ELF metadata");
        if (after != file.identity || digest != file.sha256) {
            fail(SupervisorFailure::ProtocolViolation, "runtime object changed during ELF metadata inspection");
        }
    }

    void require_active() const {
        if (failed_) {
            fail(SupervisorFailure::ProtocolViolation, "runtime observer is terminally failed");
        }
    }

    void require_exact_role_count(std::uint32_t role, const char* field) const {
        const std::size_t count = static_cast<std::size_t>(std::count_if(
            namespace_.begin(), namespace_.end(), [&](const auto& item) {
                return has_role(item.second, role);
            }));
        if (count != 1u) {
            fail(SupervisorFailure::InvalidRequest, std::string("runtime ") + field + " role is not unique");
        }
    }

    std::string path_for_exact_role(std::uint32_t role) const {
        for (const auto& [path, row] : namespace_) {
            if (has_role(row, role)) {
                return path;
            }
        }
        fail(SupervisorFailure::ProtocolViolation, "required runtime role disappeared");
    }

    void add_observation(
        const std::string& path,
        const OpenedRuntimeFile& file,
        RuntimeObservationKind kind,
        std::uint64_t file_offset,
        std::uint64_t mapping_length,
        std::uint64_t protection_flags,
        const MonotonicDeadline& deadline) {
        const auto expected = namespace_.find(path);
        if (expected == namespace_.end() || !runtime_role(expected->second) ||
            file.identity.byte_length != expected->second.byte_length ||
            file.sha256 != expected->second.sha256 ||
            (file.identity.mode & static_cast<std::uint32_t>(07777u)) !=
                expected->second.normalized_mode) {
            fail(SupervisorFailure::ProtocolViolation, "runtime object differs from frozen namespace row");
        }
        const ElfMetadataObservation metadata = ElfMetadata::inspect_linux_amd64(
            file.descriptor.get(),
            limits_.maximum_runtime_file_bytes,
            deadline);
        reauthenticate_after_metadata(file, deadline);
        const RuntimeObjectEvidence evidence{
            path,
            metadata.soname,
            file.identity.byte_length,
            file.sha256,
            metadata.build_id,
        };
        const auto found = objects_.find(path);
        if (found != objects_.end()) {
            if (found->second.evidence != evidence ||
                found->second.interpreter != metadata.interpreter) {
                fail(SupervisorFailure::ProtocolViolation, "runtime object metadata changed across observations");
            }
            return;
        }
        if (objects_.size() >= limits_.maximum_runtime_objects) {
            fail(SupervisorFailure::ResourceLimit, "runtime object cap exceeded");
        }
        consume_unique_bytes(file.identity.byte_length);
        if (kind == RuntimeObservationKind::PtraceExecProcExe) {
            if (path != collector_path_ || file_offset != 0u || mapping_length != 0u ||
                protection_flags != 0u) {
                fail(SupervisorFailure::ProtocolViolation, "collector exec runtime observation is invalid");
            }
        } else if (mapping_length == 0u || (protection_flags & kProtExec) == 0u) {
            fail(SupervisorFailure::ProtocolViolation, "runtime mapping observation lacks executable protection");
        }
        objects_.emplace(path, RuntimeObjectState{evidence, metadata.interpreter});
        observations_.push_back(PendingRuntimeObservation{
            kind,
            path,
            file.identity.device,
            file.identity.inode,
            file_offset,
            mapping_length,
            protection_flags,
        });
    }

    pid_t pid_ = -1;
    OwnedFd pidfd_;
    std::string collector_path_;
    RuntimeObserverLimits limits_{};
    std::map<std::string, NamespaceFileExpectation> namespace_;
    std::map<std::string, RuntimeObjectState> objects_;
    std::vector<PendingRuntimeObservation> observations_;
    std::string interpreter_path_;
    bool exec_observed_ = false;
    bool failed_ = false;
    std::uint64_t unique_runtime_bytes_ = 0u;
    std::uint64_t authenticated_runtime_bytes_ = 0u;
};

RuntimeObserver::RuntimeObserver(
    pid_t stopped_pid,
    int validated_pidfd,
    std::string collector_namespace_relative_path,
    std::vector<NamespaceFileExpectation> namespace_files,
    const MonotonicDeadline& deadline,
    RuntimeObserverLimits limits)
    : impl_(std::make_unique<Impl>(
          stopped_pid,
          validated_pidfd,
          std::move(collector_namespace_relative_path),
          std::move(namespace_files),
          deadline,
          limits)) {}

RuntimeObserver::~RuntimeObserver() = default;
RuntimeObserver::RuntimeObserver(RuntimeObserver&&) noexcept = default;
RuntimeObserver& RuntimeObserver::operator=(RuntimeObserver&&) noexcept = default;

void RuntimeObserver::observe_exec_proc_exe(const MonotonicDeadline& deadline) {
    try {
        impl_->observe_exec_proc_exe(deadline);
    } catch (...) {
        impl_->mark_failed();
        throw;
    }
}

void RuntimeObserver::observe_mmap_fd(
    int child_fd,
    const std::string& namespace_relative_path,
    std::uint64_t expected_device,
    std::uint64_t expected_inode,
    std::uint64_t file_offset,
    std::uint64_t mapping_length,
    std::uint64_t protection_flags,
    const MonotonicDeadline& deadline) {
    try {
        impl_->observe_mmap_fd(
            child_fd,
            namespace_relative_path,
            expected_device,
            expected_inode,
            file_offset,
            mapping_length,
            protection_flags,
            deadline);
    } catch (...) {
        impl_->mark_failed();
        throw;
    }
}

void RuntimeObserver::rescan_proc_map_files(const MonotonicDeadline& deadline) {
    try {
        impl_->rescan_proc_map_files(deadline);
    } catch (...) {
        impl_->mark_failed();
        throw;
    }
}

CompletedRuntimeObservation RuntimeObserver::finalize() {
    try {
        return impl_->finalize();
    } catch (...) {
        impl_->mark_failed();
        throw;
    }
}

}  // namespace evaluation_v6_3_1::capture_v2
