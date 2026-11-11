#include "HarnessObserver.h"

#if !defined(__linux__)
#error "HarnessObserver is a Linux-only Capture V2 component"
#endif

#include "ElfMetadata.h"
#include "OwnedFd.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/SHA256.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {
namespace {

constexpr std::size_t kHashBufferBytes = 64u * 1024u;
constexpr std::size_t kMetadataReadBytes = 4096u;
constexpr std::size_t kMaximumExecfnBytes = 4096u;

[[noreturn]] void fail(SupervisorFailure failure, std::string message, int error = 0) {
    throw SupervisorError(failure, std::move(message), error);
}

void require_live_deadline(const MonotonicDeadline& deadline) {
    if (deadline.expired()) {
        fail(SupervisorFailure::TraceTimeout, "harness observation deadline expired");
    }
}

void require_limits(const HarnessObserverLimits& limits) {
    if (limits.maximum_component_bytes == 0u || limits.maximum_proc_maps_bytes == 0u ||
        limits.maximum_proc_maps_lines == 0u || limits.maximum_proc_maps_line_bytes == 0u ||
        limits.maximum_build_id_bytes == 0u || limits.maximum_build_id_bytes > 65'535u) {
        fail(SupervisorFailure::InvalidRequest, "harness observer limits are invalid");
    }
}

void require_direct_native_execfn(const MonotonicDeadline& deadline) {
    require_live_deadline(deadline);
    const unsigned long raw_execfn = ::getauxval(AT_EXECFN);
    if (raw_execfn == 0ul) {
        fail(SupervisorFailure::ProtocolViolation, "AT_EXECFN is missing");
    }
    const char* const execfn = reinterpret_cast<const char*>(raw_execfn);
    const std::size_t execfn_length = ::strnlen(execfn, kMaximumExecfnBytes + 1u);
    if (execfn_length == 0u || execfn_length > kMaximumExecfnBytes || execfn[0] != '/') {
        fail(SupervisorFailure::ProtocolViolation, "AT_EXECFN is not a bounded absolute path");
    }
    std::array<char, kMaximumExecfnBytes + 1u> executable_path{};
    const ssize_t executable_length = ::readlink(
        "/proc/self/exe", executable_path.data(), kMaximumExecfnBytes);
    if (executable_length <= 0 ||
        static_cast<std::size_t>(executable_length) != execfn_length ||
        std::memcmp(executable_path.data(), execfn, execfn_length) != 0) {
        fail(SupervisorFailure::ProtocolViolation,
             "capture entry is an unsupported script, wrapper, alias, or interpreter chain");
    }
}

struct StableFileIdentity final {
    std::uint64_t device = 0u;
    std::uint64_t inode = 0u;
    std::uint64_t byte_length = 0u;
    std::uint64_t link_count = 0u;
    std::uint32_t mode = 0u;
    std::int64_t modification_seconds = 0;
    std::int64_t modification_nanoseconds = 0;
    std::int64_t change_seconds = 0;
    std::int64_t change_nanoseconds = 0;

    friend bool operator==(const StableFileIdentity&, const StableFileIdentity&) = default;
};

struct RawComponentFacts final {
    std::uint64_t byte_length = 0u;
    Sha256Digest sha256{};
    std::vector<std::uint8_t> build_id;
};

StableFileIdentity observe_regular_file(
    int descriptor,
    std::uint64_t maximum_bytes,
    const char* field) {
    struct stat status {};
    if (::fstat(descriptor, &status) != 0) {
        fail(SupervisorFailure::SystemFailure, std::string("fstat ") + field + " failed", errno);
    }
    if (!S_ISREG(status.st_mode) || status.st_size <= 0 ||
        static_cast<std::uint64_t>(status.st_size) > maximum_bytes ||
        static_cast<std::uintmax_t>(status.st_size) >
            static_cast<std::uintmax_t>(std::numeric_limits<off_t>::max())) {
        fail(SupervisorFailure::ProtocolViolation,
             std::string(field) + " is not an admissible sized regular file");
    }
    return StableFileIdentity{
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

Sha256Digest hash_exact_file(
    int descriptor,
    std::uint64_t byte_length,
    const MonotonicDeadline& deadline,
    const char* field) {
    llvm::SHA256 hasher;
    std::array<std::uint8_t, kHashBufferBytes> buffer{};
    std::uint64_t offset = 0u;
    while (offset < byte_length) {
        require_live_deadline(deadline);
        const std::size_t requested = static_cast<std::size_t>(
            std::min<std::uint64_t>(byte_length - offset, buffer.size()));
        const ssize_t count = ::pread(
            descriptor, buffer.data(), requested, static_cast<off_t>(offset));
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            fail(SupervisorFailure::SystemFailure, std::string("pread ") + field + " failed", errno);
        }
        if (static_cast<std::size_t>(count) != requested) {
            fail(SupervisorFailure::ProtocolViolation,
                 std::string(field) + " changed or short-read during hash");
        }
        hasher.update(llvm::ArrayRef<std::uint8_t>(buffer.data(), requested));
        offset += static_cast<std::uint64_t>(requested);
    }
    std::uint8_t extra = 0u;
    for (;;) {
        require_live_deadline(deadline);
        const ssize_t count = ::pread(
            descriptor, &extra, 1u, static_cast<off_t>(byte_length));
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            fail(SupervisorFailure::SystemFailure,
                 std::string("pread EOF probe ") + field + " failed", errno);
        }
        if (count != 0) {
            fail(SupervisorFailure::ProtocolViolation,
                 std::string(field) + " grew beyond committed length");
        }
        return hasher.final();
    }
}

void pread_exact(
    int descriptor,
    std::uint64_t offset,
    void* destination,
    std::size_t length,
    std::uint64_t file_length,
    const MonotonicDeadline& deadline,
    const char* field) {
    if (offset > file_length || length > file_length - offset ||
        offset > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max())) {
        fail(SupervisorFailure::ProtocolViolation, std::string(field) + " is out of range");
    }
    std::size_t completed = 0u;
    while (completed < length) {
        require_live_deadline(deadline);
        const ssize_t count = ::pread(
            descriptor,
            static_cast<std::uint8_t*>(destination) + completed,
            length - completed,
            static_cast<off_t>(offset + completed));
        if (count > 0) {
            completed += static_cast<std::size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        fail(SupervisorFailure::ProtocolViolation, std::string("read ") + field + " failed", errno);
    }
}

std::uint64_t add_checked(std::uint64_t left, std::uint64_t right, const char* field) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        fail(SupervisorFailure::ProtocolViolation, std::string(field) + " overflows");
    }
    return left + right;
}

std::uint64_t align_four(std::uint64_t value, const char* field) {
    return add_checked(value, 3u, field) & ~std::uint64_t{3u};
}

struct BuildIdNote final {
    std::uint64_t descriptor_offset = 0u;
    std::uint64_t descriptor_length = 0u;

    friend bool operator==(const BuildIdNote&, const BuildIdNote&) = default;
};

void scan_note_region(
    int descriptor,
    std::uint64_t region_offset,
    std::uint64_t region_length,
    std::uint64_t file_length,
    std::size_t maximum_build_id_bytes,
    const MonotonicDeadline& deadline,
    std::vector<BuildIdNote>& notes) {
    if (region_offset > file_length || region_length > file_length - region_offset) {
        fail(SupervisorFailure::ProtocolViolation, "ELF note region exceeds file");
    }
    std::uint64_t cursor = 0u;
    while (cursor < region_length) {
        if (region_length - cursor < sizeof(Elf64_Nhdr)) {
            fail(SupervisorFailure::ProtocolViolation, "ELF note header is truncated");
        }
        Elf64_Nhdr note{};
        pread_exact(
            descriptor, add_checked(region_offset, cursor, "ELF note offset"), &note, sizeof(note),
            file_length, deadline, "ELF note header");
        cursor = add_checked(cursor, sizeof(note), "ELF note cursor");
        const std::uint64_t name_padded = align_four(note.n_namesz, "ELF note name");
        const std::uint64_t descriptor_padded = align_four(note.n_descsz, "ELF note descriptor");
        const std::uint64_t note_end = add_checked(
            add_checked(cursor, name_padded, "ELF note name"), descriptor_padded,
            "ELF note descriptor");
        if (note_end > region_length) {
            fail(SupervisorFailure::ProtocolViolation, "ELF note payload is truncated");
        }
        if (note.n_type == NT_GNU_BUILD_ID && note.n_namesz == 4u &&
            note.n_descsz > 0u && note.n_descsz <= maximum_build_id_bytes) {
            std::array<std::uint8_t, 4> name{};
            pread_exact(
                descriptor, add_checked(region_offset, cursor, "GNU note name"), name.data(), name.size(),
                file_length, deadline, "GNU note name");
            constexpr std::array<std::uint8_t, 4> kGnuName = {'G', 'N', 'U', 0u};
            if (name == kGnuName) {
                notes.push_back(BuildIdNote{
                    add_checked(
                        add_checked(region_offset, cursor, "GNU note descriptor"), name_padded,
                        "GNU note descriptor"),
                    note.n_descsz});
            }
        } else if (note.n_type == NT_GNU_BUILD_ID && note.n_namesz == 4u) {
            fail(SupervisorFailure::ProtocolViolation, "GNU build ID length is invalid");
        }
        cursor = note_end;
    }
}

void require_exactly_one_gnu_build_id(
    int descriptor,
    const StableFileIdentity& identity,
    const HarnessObserverLimits& limits,
    const MonotonicDeadline& deadline) {
    Elf64_Ehdr header{};
    pread_exact(
        descriptor, 0u, &header, sizeof(header), identity.byte_length, deadline, "ELF header");
    if (std::memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 ||
        header.e_ident[EI_CLASS] != ELFCLASS64 || header.e_ident[EI_DATA] != ELFDATA2LSB ||
        header.e_ident[EI_VERSION] != EV_CURRENT || header.e_version != EV_CURRENT ||
        header.e_machine != EM_X86_64 || header.e_ehsize != sizeof(Elf64_Ehdr) ||
        header.e_phentsize != sizeof(Elf64_Phdr) || header.e_phnum == 0u ||
        header.e_phnum == PN_XNUM || header.e_phnum > 4096u) {
        fail(SupervisorFailure::ProtocolViolation, "component is not frozen Linux/amd64 ELF64");
    }
    const std::uint64_t program_bytes =
        static_cast<std::uint64_t>(header.e_phnum) * sizeof(Elf64_Phdr);
    if (header.e_phoff > identity.byte_length || program_bytes > identity.byte_length - header.e_phoff) {
        fail(SupervisorFailure::ProtocolViolation, "ELF program headers exceed file");
    }
    std::vector<BuildIdNote> notes;
    for (std::size_t index = 0u; index < header.e_phnum; ++index) {
        Elf64_Phdr program{};
        pread_exact(
            descriptor,
            header.e_phoff + static_cast<std::uint64_t>(index) * sizeof(program), &program,
            sizeof(program), identity.byte_length, deadline, "ELF program header");
        if (program.p_type == PT_NOTE) {
            scan_note_region(
                descriptor, program.p_offset, program.p_filesz, identity.byte_length,
                limits.maximum_build_id_bytes, deadline, notes);
        }
    }
    if (header.e_shoff != 0u || header.e_shnum != 0u) {
        if (header.e_shoff == 0u || header.e_shentsize != sizeof(Elf64_Shdr) ||
            header.e_shnum == SHN_XINDEX) {
            fail(SupervisorFailure::ProtocolViolation, "ELF section headers are malformed");
        }
        const std::uint64_t section_bytes =
            static_cast<std::uint64_t>(header.e_shnum) * sizeof(Elf64_Shdr);
        if (header.e_shoff > identity.byte_length ||
            section_bytes > identity.byte_length - header.e_shoff) {
            fail(SupervisorFailure::ProtocolViolation, "ELF section headers exceed file");
        }
        for (std::size_t index = 0u; index < header.e_shnum; ++index) {
            Elf64_Shdr section{};
            pread_exact(
                descriptor,
                header.e_shoff + static_cast<std::uint64_t>(index) * sizeof(section), &section,
                sizeof(section), identity.byte_length, deadline, "ELF section header");
            if (section.sh_type == SHT_NOTE) {
                scan_note_region(
                    descriptor, section.sh_offset, section.sh_size, identity.byte_length,
                    limits.maximum_build_id_bytes, deadline, notes);
            }
        }
    }
    std::sort(notes.begin(), notes.end(), [](const BuildIdNote& left, const BuildIdNote& right) {
        return left.descriptor_offset < right.descriptor_offset ||
               (left.descriptor_offset == right.descriptor_offset &&
                left.descriptor_length < right.descriptor_length);
    });
    notes.erase(std::unique(notes.begin(), notes.end()), notes.end());
    if (notes.size() != 1u) {
        fail(SupervisorFailure::ProtocolViolation,
             "component must contain exactly one physical GNU build ID note");
    }
}

RawComponentFacts observe_component(
    int descriptor,
    const HarnessObserverLimits& limits,
    const MonotonicDeadline& deadline,
    const char* field,
    bool require_dynamic_entry,
    bool require_loader_without_interpreter) {
    const StableFileIdentity before = observe_regular_file(
        descriptor, limits.maximum_component_bytes, field);
    const Sha256Digest digest = hash_exact_file(descriptor, before.byte_length, deadline, field);
    const ElfMetadataObservation metadata = ElfMetadata::inspect_linux_amd64(
        descriptor, limits.maximum_component_bytes, deadline,
        ElfMetadataLimits{
            4096u, 65'536u, 16u * 1024u * 1024u, 65'535u, 65'535u,
            limits.maximum_build_id_bytes});
    require_exactly_one_gnu_build_id(descriptor, before, limits, deadline);
    if (metadata.build_id.empty() || metadata.build_id.size() > limits.maximum_build_id_bytes) {
        fail(SupervisorFailure::ProtocolViolation, std::string(field) + " lacks a GNU build ID");
    }
    if (require_dynamic_entry && metadata.interpreter.empty()) {
        fail(SupervisorFailure::ProtocolViolation,
             "capture entry is static ELF or an unsupported launcher");
    }
    if (require_loader_without_interpreter && !metadata.interpreter.empty()) {
        fail(SupervisorFailure::ProtocolViolation,
             "mapped loader contains an unsupported interpreter chain");
    }
    const StableFileIdentity after = observe_regular_file(
        descriptor, limits.maximum_component_bytes, field);
    if (after != before) {
        fail(SupervisorFailure::ProtocolViolation,
             std::string(field) + " changed during component observation");
    }
    return RawComponentFacts{before.byte_length, digest, std::move(metadata.build_id)};
}

std::vector<std::uint8_t> read_proc_maps(
    const HarnessObserverLimits& limits,
    const MonotonicDeadline& deadline) {
    OwnedFd maps(::open("/proc/self/maps", O_RDONLY | O_CLOEXEC | O_NOCTTY));
    if (!maps) {
        fail(SupervisorFailure::SystemFailure, "open /proc/self/maps failed", errno);
    }
    std::vector<std::uint8_t> bytes;
    bytes.reserve(std::min<std::size_t>(limits.maximum_proc_maps_bytes, kMetadataReadBytes));
    std::array<std::uint8_t, kMetadataReadBytes> buffer{};
    for (;;) {
        require_live_deadline(deadline);
        const ssize_t count = ::read(maps.get(), buffer.data(), buffer.size());
        if (count > 0) {
            if (static_cast<std::size_t>(count) > limits.maximum_proc_maps_bytes - bytes.size()) {
                fail(SupervisorFailure::ResourceLimit, "/proc/self/maps exceeds byte cap");
            }
            bytes.insert(bytes.end(), buffer.begin(), buffer.begin() + count);
            continue;
        }
        if (count == 0) {
            break;
        }
        if (errno != EINTR) {
            fail(SupervisorFailure::SystemFailure, "read /proc/self/maps failed", errno);
        }
    }
    if (bytes.empty() || bytes.back() != static_cast<std::uint8_t>('\n')) {
        fail(SupervisorFailure::ProtocolViolation, "/proc/self/maps is incomplete");
    }
    return bytes;
}

std::uint64_t parse_unsigned(std::string_view text, int base, const char* field) {
    if (text.empty()) {
        fail(SupervisorFailure::ProtocolViolation, std::string(field) + " is empty");
    }
    std::uint64_t result = 0u;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), result, base);
    if (error != std::errc{} || end != text.data() + text.size()) {
        fail(SupervisorFailure::ProtocolViolation, std::string(field) + " is malformed");
    }
    return result;
}

std::string_view take_token(std::string_view& value, const char* field) {
    while (!value.empty() && value.front() == ' ') {
        value.remove_prefix(1u);
    }
    if (value.empty()) {
        fail(SupervisorFailure::ProtocolViolation, std::string(field) + " is missing");
    }
    const std::size_t end = value.find(' ');
    const std::string_view token = value.substr(0u, end);
    value = end == std::string_view::npos ? std::string_view{} : value.substr(end);
    return token;
}

std::pair<std::uint64_t, std::uint64_t> parse_pair(
    std::string_view value, char separator, int base, const char* field) {
    const std::size_t separator_index = value.find(separator);
    if (separator_index == std::string_view::npos || separator_index == 0u ||
        value.find(separator, separator_index + 1u) != std::string_view::npos) {
        fail(SupervisorFailure::ProtocolViolation, std::string(field) + " is malformed");
    }
    return {parse_unsigned(value.substr(0u, separator_index), base, field),
            parse_unsigned(value.substr(separator_index + 1u), base, field)};
}

void require_permissions(std::string_view permissions) {
    if (permissions.size() != 4u ||
        (permissions[0] != 'r' && permissions[0] != '-') ||
        (permissions[1] != 'w' && permissions[1] != '-') ||
        (permissions[2] != 'x' && permissions[2] != '-') ||
        (permissions[3] != 'p' && permissions[3] != 's')) {
        fail(SupervisorFailure::ProtocolViolation, "proc maps permissions are malformed");
    }
}

struct LoaderMapping final {
    std::uint64_t start = 0u;
    std::uint64_t end = 0u;
    std::uint64_t file_offset = 0u;
    std::uint64_t device_major = 0u;
    std::uint64_t device_minor = 0u;
    std::uint64_t inode = 0u;
    std::string path;

    friend bool operator==(const LoaderMapping&, const LoaderMapping&) = default;
};

LoaderMapping find_loader_mapping(
    std::span<const std::uint8_t> bytes,
    std::uint64_t at_base,
    const HarnessObserverLimits& limits) {
    const std::string_view maps(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    std::optional<LoaderMapping> result;
    std::uint64_t previous_end = 0u;
    bool have_previous = false;
    std::size_t offset = 0u;
    std::size_t line_count = 0u;
    while (offset < maps.size()) {
        const std::size_t end = maps.find('\n', offset);
        if (end == std::string_view::npos) {
            fail(SupervisorFailure::ProtocolViolation, "proc maps line is unterminated");
        }
        const std::string_view line = maps.substr(offset, end - offset);
        offset = end + 1u;
        if (line.empty() || line.size() > limits.maximum_proc_maps_line_bytes ||
            ++line_count > limits.maximum_proc_maps_lines) {
            fail(SupervisorFailure::ResourceLimit, "proc maps line exceeds configured limits");
        }
        std::string_view remaining = line;
        const auto [start, finish] = parse_pair(
            take_token(remaining, "proc maps address"), '-', 16, "proc maps address");
        if (start >= finish || (have_previous && start < previous_end)) {
            fail(SupervisorFailure::ProtocolViolation, "proc maps address order is invalid");
        }
        previous_end = finish;
        have_previous = true;
        require_permissions(take_token(remaining, "proc maps permissions"));
        const std::uint64_t file_offset = parse_unsigned(
            take_token(remaining, "proc maps file offset"), 16, "proc maps file offset");
        const auto [device_major, device_minor] = parse_pair(
            take_token(remaining, "proc maps device"), ':', 16, "proc maps device");
        const std::uint64_t inode = parse_unsigned(
            take_token(remaining, "proc maps inode"), 10, "proc maps inode");
        while (!remaining.empty() && remaining.front() == ' ') {
            remaining.remove_prefix(1u);
        }
        if (at_base < start || at_base >= finish) {
            continue;
        }
        if (result.has_value() || inode == 0u || remaining.empty() || remaining.front() != '/' ||
            remaining.ends_with(" (deleted)")) {
            fail(SupervisorFailure::ProtocolViolation,
                 "AT_BASE does not identify one live file-backed loader mapping");
        }
        result = LoaderMapping{
            start, finish, file_offset, device_major, device_minor, inode, std::string(remaining)};
    }
    if (!result.has_value()) {
        fail(SupervisorFailure::ProtocolViolation, "AT_BASE loader mapping is missing");
    }
    return *result;
}

std::string map_files_path(const LoaderMapping& mapping) {
    char path[128]{};
    const int written = ::snprintf(
        path, sizeof(path), "/proc/self/map_files/%llx-%llx",
        static_cast<unsigned long long>(mapping.start),
        static_cast<unsigned long long>(mapping.end));
    if (written < 0 || static_cast<std::size_t>(written) >= sizeof(path)) {
        fail(SupervisorFailure::ProtocolViolation, "format loader map_files path failed");
    }
    return std::string(path);
}

void require_mapping_matches_descriptor(const LoaderMapping& mapping, int descriptor) {
    struct stat status {};
    if (::fstat(descriptor, &status) != 0) {
        fail(SupervisorFailure::SystemFailure, "fstat loader map_files descriptor failed", errno);
    }
    if (!S_ISREG(status.st_mode) ||
        static_cast<std::uint64_t>(major(status.st_dev)) != mapping.device_major ||
        static_cast<std::uint64_t>(minor(status.st_dev)) != mapping.device_minor ||
        static_cast<std::uint64_t>(status.st_ino) != mapping.inode) {
        fail(SupervisorFailure::ProtocolViolation,
             "loader map_files descriptor identity differs from AT_BASE mapping");
    }
}

void require_component_matches(
    const ComponentFacts& observed,
    const ComponentExpectation& expected,
    const char* field) {
    if (expected.byte_length == 0u || expected.build_id.empty() ||
        observed.byte_length() != expected.byte_length || observed.sha256() != expected.sha256 ||
        observed.build_id() != expected.build_id) {
        fail(SupervisorFailure::ProtocolViolation,
             std::string(field) + " expectation differs from native observation");
    }
}

}  // namespace

ComponentExpectation ComponentExpectation::exact(const ComponentFacts& observed) {
    return ComponentExpectation{
        observed.byte_length(), observed.sha256(), observed.build_id()};
}

HarnessExpectations HarnessExpectations::exact_from(const HarnessObservation& observed) {
    return HarnessExpectations{
        ComponentExpectation::exact(observed.capture_entry_component()),
        ComponentExpectation::exact(observed.capture_interpreter_component()),
        ComponentExpectation::exact(observed.native_supervisor_component()),
    };
}

HarnessObservation HarnessObserver::observe_direct_dynamic_elf_supervisor(
    const MonotonicDeadline& deadline,
    HarnessObserverLimits limits) {
    require_limits(limits);
    require_live_deadline(deadline);
    require_direct_native_execfn(deadline);
    OwnedFd entry(::open("/proc/self/exe", O_RDONLY | O_CLOEXEC | O_NOCTTY));
    if (!entry) {
        fail(SupervisorFailure::SystemFailure, "open /proc/self/exe failed", errno);
    }
    RawComponentFacts entry_raw = observe_component(
        entry.get(), limits, deadline, "capture entry", true, false);

    const unsigned long raw_at_base = ::getauxval(AT_BASE);
    if (raw_at_base == 0ul) {
        fail(SupervisorFailure::ProtocolViolation,
             "capture entry has no dynamically mapped AT_BASE loader");
    }
    const std::uint64_t at_base = static_cast<std::uint64_t>(raw_at_base);
    const LoaderMapping before_mapping = find_loader_mapping(
        read_proc_maps(limits, deadline), at_base, limits);
    OwnedFd loader(::open(
        map_files_path(before_mapping).c_str(), O_RDONLY | O_CLOEXEC | O_NOCTTY));
    if (!loader) {
        fail(SupervisorFailure::SystemFailure,
             "open exact AT_BASE loader map_files object failed", errno);
    }
    require_mapping_matches_descriptor(before_mapping, loader.get());
    RawComponentFacts loader_raw = observe_component(
        loader.get(), limits, deadline, "capture interpreter", false, true);
    require_mapping_matches_descriptor(before_mapping, loader.get());
    const LoaderMapping after_mapping = find_loader_mapping(
        read_proc_maps(limits, deadline), at_base, limits);
    if (after_mapping != before_mapping) {
        fail(SupervisorFailure::ProtocolViolation,
             "AT_BASE loader mapping changed during observation");
    }
    ComponentFacts entry_facts{
        entry_raw.byte_length, entry_raw.sha256, std::move(entry_raw.build_id)};
    ComponentFacts loader_facts{
        loader_raw.byte_length, loader_raw.sha256, std::move(loader_raw.build_id)};
    ComponentFacts supervisor_facts{
        entry_facts.byte_length(), entry_facts.sha256(), entry_facts.build_id()};
    return HarnessObservation{
        std::move(entry_facts), std::move(loader_facts), std::move(supervisor_facts)};
}

void HarnessObserver::cross_check_expectations(
    const HarnessObservation& observed,
    const HarnessExpectations& expectations) {
    require_component_matches(
        observed.capture_entry_component(), expectations.capture_entry_component,
        "capture entry component");
    require_component_matches(
        observed.capture_interpreter_component(), expectations.capture_interpreter_component,
        "capture interpreter component");
    require_component_matches(
        observed.native_supervisor_component(), expectations.native_supervisor_component,
        "native supervisor component");
}

}  // namespace evaluation_v6_3_1::capture_v2
