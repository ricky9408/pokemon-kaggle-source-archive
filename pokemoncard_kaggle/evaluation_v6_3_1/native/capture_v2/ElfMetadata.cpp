#include "ElfMetadata.h"

#if !defined(__linux__)
#error "ElfMetadata is a Linux-only Capture V2 component"
#endif

#include "SupervisorTypes.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <limits>
#include <optional>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {
namespace {

constexpr std::size_t kReadChunkBytes = 4096u;
constexpr std::size_t kProtocolMetadataStringMaxBytes = 65'535u;

[[noreturn]] void fail(SupervisorFailure failure, std::string message, int error = 0) {
    throw SupervisorError(failure, std::move(message), error);
}

void require_time(const MonotonicDeadline& deadline) {
    if (deadline.expired()) {
        fail(SupervisorFailure::TraceTimeout, "ELF metadata deadline expired");
    }
}

std::uint64_t add_checked(std::uint64_t left, std::uint64_t right, const char* field) {
    if (right > std::numeric_limits<std::uint64_t>::max() - left) {
        fail(SupervisorFailure::ProtocolViolation, std::string(field) + " overflows");
    }
    return left + right;
}

std::uint64_t multiply_checked(
    std::uint64_t left, std::uint64_t right, const char* field) {
    if (left != 0u && right > std::numeric_limits<std::uint64_t>::max() / left) {
        fail(SupervisorFailure::ProtocolViolation, std::string(field) + " overflows");
    }
    return left * right;
}

std::uint64_t align_four(std::uint64_t value, const char* field) {
    return add_checked(value, 3u, field) & ~std::uint64_t{3u};
}

void require_file_range(
    std::uint64_t offset,
    std::uint64_t length,
    std::uint64_t file_length,
    const char* field) {
    if (offset > file_length || length > file_length - offset) {
        fail(SupervisorFailure::ProtocolViolation, std::string(field) + " exceeds ELF file");
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
    require_file_range(offset, static_cast<std::uint64_t>(length), file_length, field);
    if (offset > static_cast<std::uint64_t>(std::numeric_limits<off_t>::max())) {
        fail(SupervisorFailure::ProtocolViolation, std::string(field) + " offset exceeds off_t");
    }
    std::size_t completed = 0u;
    while (completed < length) {
        require_time(deadline);
        const std::uint64_t current_offset = add_checked(
            offset, static_cast<std::uint64_t>(completed), field);
        const ssize_t count = ::pread(
            descriptor,
            static_cast<std::uint8_t*>(destination) + completed,
            std::min(length - completed, kReadChunkBytes),
            static_cast<off_t>(current_offset));
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

template <typename T>
T read_object(
    int descriptor,
    std::uint64_t offset,
    std::uint64_t file_length,
    const MonotonicDeadline& deadline,
    const char* field) {
    T value{};
    pread_exact(
        descriptor, offset, &value, sizeof(value), file_length, deadline, field);
    return value;
}

std::vector<std::uint8_t> read_bytes(
    int descriptor,
    std::uint64_t offset,
    std::size_t length,
    std::uint64_t file_length,
    const MonotonicDeadline& deadline,
    const char* field) {
    std::vector<std::uint8_t> bytes(length);
    if (!bytes.empty()) {
        pread_exact(
            descriptor, offset, bytes.data(), bytes.size(), file_length, deadline, field);
    }
    return bytes;
}

std::vector<std::uint8_t> read_terminated_bytes(
    int descriptor,
    std::uint64_t offset,
    std::uint64_t available,
    std::size_t maximum_length,
    std::uint64_t file_length,
    const MonotonicDeadline& deadline,
    const char* field) {
    if (available == 0u) {
        fail(SupervisorFailure::ProtocolViolation, std::string(field) + " has no terminator range");
    }
    std::vector<std::uint8_t> output;
    output.reserve(std::min<std::size_t>(maximum_length, kReadChunkBytes));
    std::array<std::uint8_t, kReadChunkBytes> buffer{};
    std::uint64_t consumed = 0u;
    while (consumed < available) {
        const std::uint64_t remaining = available - consumed;
        const std::size_t requested = static_cast<std::size_t>(
            std::min<std::uint64_t>(remaining, buffer.size()));
        pread_exact(
            descriptor,
            add_checked(offset, consumed, field),
            buffer.data(),
            requested,
            file_length,
            deadline,
            field);
        for (std::size_t index = 0u; index < requested; ++index) {
            if (buffer[index] == 0u) {
                if (output.empty()) {
                    fail(SupervisorFailure::ProtocolViolation, std::string(field) + " is empty");
                }
                return output;
            }
            if (output.size() == maximum_length) {
                fail(SupervisorFailure::ResourceLimit, std::string(field) + " exceeds configured limit");
            }
            output.push_back(buffer[index]);
        }
        consumed += static_cast<std::uint64_t>(requested);
    }
    fail(SupervisorFailure::ProtocolViolation, std::string(field) + " lacks terminating NUL");
}

void merge_unique_bytes(
    std::optional<std::vector<std::uint8_t>>& target,
    std::vector<std::uint8_t> candidate,
    const char* field) {
    if (target.has_value() && *target != candidate) {
        fail(SupervisorFailure::ProtocolViolation, std::string(field) + " entries conflict");
    }
    if (!target.has_value()) {
        target.emplace(std::move(candidate));
    }
}

std::optional<std::uint64_t> virtual_range_to_file_offset(
    std::uint64_t virtual_address,
    std::uint64_t length,
    const std::vector<Elf64_Phdr>& program_headers) {
    if (length == 0u) {
        fail(SupervisorFailure::ProtocolViolation, "ELF virtual range is empty");
    }
    std::optional<std::uint64_t> result;
    for (const Elf64_Phdr& header : program_headers) {
        if (header.p_type != PT_LOAD || virtual_address < header.p_vaddr) {
            continue;
        }
        const std::uint64_t delta = virtual_address - header.p_vaddr;
        if (delta >= header.p_filesz || length > header.p_filesz - delta) {
            continue;
        }
        const std::uint64_t candidate = add_checked(header.p_offset, delta, "ELF virtual address");
        if (result.has_value() && *result != candidate) {
            fail(SupervisorFailure::ProtocolViolation, "ELF virtual address mapping is ambiguous");
        }
        result = candidate;
    }
    return result;
}

void inspect_note_region(
    int descriptor,
    std::uint64_t region_offset,
    std::uint64_t region_length,
    std::uint64_t file_length,
    const MonotonicDeadline& deadline,
    const ElfMetadataLimits& limits,
    std::optional<std::vector<std::uint8_t>>& build_id) {
    require_file_range(region_offset, region_length, file_length, "ELF note region");
    if (region_length > limits.maximum_metadata_bytes) {
        fail(SupervisorFailure::ResourceLimit, "ELF note region exceeds metadata limit");
    }
    std::uint64_t cursor = 0u;
    while (cursor < region_length) {
        if (region_length - cursor < sizeof(Elf64_Nhdr)) {
            fail(SupervisorFailure::ProtocolViolation, "ELF note header is truncated");
        }
        const Elf64_Nhdr note = read_object<Elf64_Nhdr>(
            descriptor,
            add_checked(region_offset, cursor, "ELF note header"),
            file_length,
            deadline,
            "ELF note header");
        cursor = add_checked(cursor, sizeof(Elf64_Nhdr), "ELF note cursor");
        const std::uint64_t aligned_name = align_four(note.n_namesz, "ELF note name");
        const std::uint64_t aligned_description =
            align_four(note.n_descsz, "ELF note descriptor");
        const std::uint64_t note_end = add_checked(
            add_checked(cursor, aligned_name, "ELF note name"),
            aligned_description,
            "ELF note descriptor");
        if (note_end > region_length) {
            fail(SupervisorFailure::ProtocolViolation, "ELF note payload is truncated");
        }
        if (note.n_type == NT_GNU_BUILD_ID && note.n_namesz == 4u) {
            const std::vector<std::uint8_t> name = read_bytes(
                descriptor,
                add_checked(region_offset, cursor, "ELF note name"),
                4u,
                file_length,
                deadline,
                "ELF note name");
            constexpr std::array<std::uint8_t, 4> kGnuName = {'G', 'N', 'U', 0u};
            if (std::equal(name.begin(), name.end(), kGnuName.begin(), kGnuName.end())) {
                if (note.n_descsz == 0u ||
                    note.n_descsz > limits.maximum_build_id_bytes) {
                    fail(SupervisorFailure::ProtocolViolation, "GNU build ID length is invalid");
                }
                merge_unique_bytes(
                    build_id,
                    read_bytes(
                        descriptor,
                        add_checked(
                            add_checked(region_offset, cursor, "ELF note descriptor"),
                            aligned_name,
                            "ELF note descriptor"),
                        note.n_descsz,
                        file_length,
                        deadline,
                        "GNU build ID"),
                    "GNU build ID");
            }
        }
        cursor = note_end;
    }
}

}  // namespace

ElfMetadataObservation ElfMetadata::inspect_linux_amd64(
    int authenticated_descriptor,
    std::uint64_t positive_maximum_file_bytes,
    const MonotonicDeadline& deadline,
    ElfMetadataLimits limits) {
    if (authenticated_descriptor < 0 || positive_maximum_file_bytes == 0u ||
        limits.maximum_program_headers == 0u || limits.maximum_section_headers == 0u ||
        limits.maximum_metadata_bytes == 0u || limits.maximum_interpreter_bytes == 0u ||
        limits.maximum_soname_bytes == 0u || limits.maximum_build_id_bytes == 0u) {
        fail(SupervisorFailure::InvalidRequest, "ELF metadata request is invalid");
    }
    if (limits.maximum_interpreter_bytes > kProtocolMetadataStringMaxBytes ||
        limits.maximum_soname_bytes > kProtocolMetadataStringMaxBytes ||
        limits.maximum_build_id_bytes > kProtocolMetadataStringMaxBytes) {
        fail(SupervisorFailure::InvalidRequest, "ELF metadata limit exceeds protocol maximum");
    }
    require_time(deadline);
    struct stat status {};
    if (::fstat(authenticated_descriptor, &status) != 0) {
        fail(SupervisorFailure::SystemFailure, "fstat ELF descriptor failed", errno);
    }
    if (!S_ISREG(status.st_mode) || status.st_size <= 0 ||
        static_cast<std::uint64_t>(status.st_size) > positive_maximum_file_bytes) {
        fail(SupervisorFailure::ProtocolViolation, "ELF descriptor is not an admissible regular file");
    }
    const std::uint64_t file_length = static_cast<std::uint64_t>(status.st_size);
    const Elf64_Ehdr elf = read_object<Elf64_Ehdr>(
        authenticated_descriptor, 0u, file_length, deadline, "ELF header");
    if (std::memcmp(elf.e_ident, ELFMAG, SELFMAG) != 0 ||
        elf.e_ident[EI_CLASS] != ELFCLASS64 || elf.e_ident[EI_DATA] != ELFDATA2LSB ||
        elf.e_ident[EI_VERSION] != EV_CURRENT || elf.e_version != EV_CURRENT ||
        elf.e_machine != EM_X86_64 || elf.e_ehsize != sizeof(Elf64_Ehdr) ||
        elf.e_phentsize != sizeof(Elf64_Phdr) || elf.e_phnum == PN_XNUM ||
        elf.e_phnum == 0u) {
        fail(SupervisorFailure::ProtocolViolation, "ELF header is not frozen Linux/amd64 ELF64");
    }
    if (elf.e_phnum > limits.maximum_program_headers) {
        fail(SupervisorFailure::ResourceLimit, "ELF program-header count exceeds limit");
    }
    const std::uint64_t program_table_bytes = multiply_checked(
        elf.e_phnum, sizeof(Elf64_Phdr), "ELF program-header table");
    if (program_table_bytes > limits.maximum_metadata_bytes) {
        fail(SupervisorFailure::ResourceLimit, "ELF program-header table exceeds metadata limit");
    }
    require_file_range(
        elf.e_phoff, program_table_bytes, file_length, "ELF program-header table");
    std::vector<Elf64_Phdr> program_headers;
    program_headers.reserve(elf.e_phnum);
    for (std::size_t index = 0u; index < elf.e_phnum; ++index) {
        program_headers.push_back(read_object<Elf64_Phdr>(
            authenticated_descriptor,
            add_checked(
                elf.e_phoff,
                multiply_checked(index, sizeof(Elf64_Phdr), "ELF program header"),
                "ELF program header"),
            file_length,
            deadline,
            "ELF program header"));
    }

    std::optional<std::vector<std::uint8_t>> interpreter;
    std::optional<std::uint64_t> dynamic_string_virtual_address;
    std::optional<std::uint64_t> dynamic_string_size;
    std::vector<std::uint64_t> soname_indices;
    std::optional<std::vector<std::uint8_t>> build_id;
    for (const Elf64_Phdr& header : program_headers) {
        if (header.p_type == PT_INTERP) {
            if (header.p_filesz < 2u || header.p_filesz > limits.maximum_interpreter_bytes + 1u) {
                fail(SupervisorFailure::ProtocolViolation, "PT_INTERP length is invalid");
            }
            std::vector<std::uint8_t> bytes = read_bytes(
                authenticated_descriptor,
                header.p_offset,
                static_cast<std::size_t>(header.p_filesz),
                file_length,
                deadline,
                "PT_INTERP");
            if (bytes.back() != 0u ||
                std::find(bytes.begin(), bytes.end() - 1, 0u) != bytes.end() - 1) {
                fail(SupervisorFailure::ProtocolViolation, "PT_INTERP is not exactly NUL-terminated");
            }
            bytes.pop_back();
            if (interpreter.has_value()) {
                fail(SupervisorFailure::ProtocolViolation, "ELF contains more than one PT_INTERP");
            }
            interpreter.emplace(std::move(bytes));
        } else if (header.p_type == PT_NOTE) {
            inspect_note_region(
                authenticated_descriptor,
                header.p_offset,
                header.p_filesz,
                file_length,
                deadline,
                limits,
                build_id);
        } else if (header.p_type == PT_DYNAMIC) {
            if (header.p_filesz == 0u || header.p_filesz % sizeof(Elf64_Dyn) != 0u ||
                header.p_filesz > limits.maximum_metadata_bytes) {
                fail(SupervisorFailure::ProtocolViolation, "PT_DYNAMIC length is invalid");
            }
            require_file_range(header.p_offset, header.p_filesz, file_length, "PT_DYNAMIC");
            const std::optional<std::uint64_t> loaded_dynamic_offset =
                virtual_range_to_file_offset(
                    header.p_vaddr, header.p_filesz, program_headers);
            if (!loaded_dynamic_offset.has_value() ||
                *loaded_dynamic_offset != header.p_offset) {
                fail(SupervisorFailure::ProtocolViolation, "PT_DYNAMIC is not wholly file-backed by PT_LOAD");
            }
            bool terminated = false;
            for (std::uint64_t offset = 0u; offset < header.p_filesz;
                 offset += sizeof(Elf64_Dyn)) {
                const Elf64_Dyn dynamic = read_object<Elf64_Dyn>(
                    authenticated_descriptor,
                    add_checked(header.p_offset, offset, "PT_DYNAMIC entry"),
                    file_length,
                    deadline,
                    "PT_DYNAMIC entry");
                if (dynamic.d_tag == DT_NULL) {
                    terminated = true;
                    break;
                }
                if (dynamic.d_tag == DT_STRTAB) {
                    const std::uint64_t candidate = dynamic.d_un.d_ptr;
                    if (dynamic_string_virtual_address.has_value() &&
                        *dynamic_string_virtual_address != candidate) {
                        fail(SupervisorFailure::ProtocolViolation, "DT_STRTAB entries conflict");
                    }
                    dynamic_string_virtual_address = candidate;
                } else if (dynamic.d_tag == DT_STRSZ) {
                    const std::uint64_t candidate = dynamic.d_un.d_val;
                    if (dynamic_string_size.has_value() && *dynamic_string_size != candidate) {
                        fail(SupervisorFailure::ProtocolViolation, "DT_STRSZ entries conflict");
                    }
                    dynamic_string_size = candidate;
                } else if (dynamic.d_tag == DT_SONAME) {
                    soname_indices.push_back(dynamic.d_un.d_val);
                }
            }
            if (!terminated) {
                fail(SupervisorFailure::ProtocolViolation, "PT_DYNAMIC lacks DT_NULL");
            }
        }
    }

    if (elf.e_shoff != 0u || elf.e_shnum != 0u) {
        if (elf.e_shoff == 0u || elf.e_shentsize != sizeof(Elf64_Shdr)) {
            fail(SupervisorFailure::ProtocolViolation, "ELF section-header table is malformed");
        }
        std::uint64_t section_count = elf.e_shnum;
        if (section_count == 0u) {
            const Elf64_Shdr zero = read_object<Elf64_Shdr>(
                authenticated_descriptor,
                elf.e_shoff,
                file_length,
                deadline,
                "ELF extended section count");
            section_count = zero.sh_size;
        }
        if (section_count == 0u || section_count > limits.maximum_section_headers) {
            fail(SupervisorFailure::ResourceLimit, "ELF section-header count exceeds limit");
        }
        const std::uint64_t section_table_bytes = multiply_checked(
            section_count, sizeof(Elf64_Shdr), "ELF section-header table");
        if (section_table_bytes > limits.maximum_metadata_bytes) {
            fail(SupervisorFailure::ResourceLimit, "ELF section-header table exceeds metadata limit");
        }
        require_file_range(
            elf.e_shoff, section_table_bytes, file_length, "ELF section-header table");
        for (std::uint64_t index = 0u; index < section_count; ++index) {
            const Elf64_Shdr section = read_object<Elf64_Shdr>(
                authenticated_descriptor,
                add_checked(
                    elf.e_shoff,
                    multiply_checked(index, sizeof(Elf64_Shdr), "ELF section header"),
                    "ELF section header"),
                file_length,
                deadline,
                "ELF section header");
            if (section.sh_type == SHT_NOTE) {
                inspect_note_region(
                    authenticated_descriptor,
                    section.sh_offset,
                    section.sh_size,
                    file_length,
                    deadline,
                    limits,
                    build_id);
            }
        }
    }

    std::optional<std::vector<std::uint8_t>> soname;
    if (!soname_indices.empty()) {
        if (!dynamic_string_virtual_address.has_value() || !dynamic_string_size.has_value() ||
            *dynamic_string_size == 0u) {
            fail(SupervisorFailure::ProtocolViolation, "DT_SONAME lacks dynamic string table");
        }
        const std::optional<std::uint64_t> string_table_offset =
            virtual_range_to_file_offset(
                *dynamic_string_virtual_address,
                *dynamic_string_size,
                program_headers);
        if (!string_table_offset.has_value()) {
            fail(SupervisorFailure::ProtocolViolation, "DT_STRTAB is not file-backed");
        }
        for (const std::uint64_t index : soname_indices) {
            if (index >= *dynamic_string_size) {
                fail(SupervisorFailure::ProtocolViolation, "DT_SONAME index is out of range");
            }
            merge_unique_bytes(
                soname,
                read_terminated_bytes(
                    authenticated_descriptor,
                    add_checked(*string_table_offset, index, "DT_SONAME"),
                    *dynamic_string_size - index,
                    limits.maximum_soname_bytes,
                    file_length,
                    deadline,
                    "DT_SONAME"),
                "DT_SONAME");
        }
    }

    require_time(deadline);
    return ElfMetadataObservation{
        interpreter.value_or(std::vector<std::uint8_t>{}),
        soname.value_or(std::vector<std::uint8_t>{}),
        build_id.value_or(std::vector<std::uint8_t>{}),
    };
}

}  // namespace evaluation_v6_3_1::capture_v2
