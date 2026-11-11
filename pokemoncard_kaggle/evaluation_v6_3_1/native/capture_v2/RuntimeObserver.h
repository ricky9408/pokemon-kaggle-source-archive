#ifndef EVALUATION_V6_3_1_CAPTURE_V2_RUNTIME_OBSERVER_H
#define EVALUATION_V6_3_1_CAPTURE_V2_RUNTIME_OBSERVER_H

#if !defined(__linux__)
#error "RuntimeObserver is a Linux-only Capture V2 component"
#endif

#include "LaunchEngine.h"
#include "SupervisorTypes.h"
#include "Timeout.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace evaluation_v6_3_1::capture_v2 {

enum class RuntimeObservationKind : std::uint64_t {
    PtraceExecProcExe = 1u,
    PtraceMmapFdProtExec = 2u,
    ProcMapFilesProtExec = 3u,
};

struct RuntimeObjectEvidence final {
    std::string namespace_relative_path;
    std::vector<std::uint8_t> elf_soname;
    std::uint64_t byte_length = 0u;
    Sha256Digest sha256{};
    std::vector<std::uint8_t> elf_build_id;

    friend bool operator==(const RuntimeObjectEvidence&,
                           const RuntimeObjectEvidence&) = default;
};

struct RuntimeObservationEvidence final {
    std::uint64_t observation_sequence = 0u;
    RuntimeObservationKind observation_kind = RuntimeObservationKind::PtraceExecProcExe;
    std::uint64_t runtime_object_index = 0u;
    std::uint64_t device = 0u;
    std::uint64_t inode = 0u;
    std::uint64_t file_offset = 0u;
    std::uint64_t mapping_length = 0u;
    std::uint64_t protection_flags = 0u;

    friend bool operator==(const RuntimeObservationEvidence&,
                           const RuntimeObservationEvidence&) = default;
};

struct CompletedRuntimeObservation final {
    RuntimeObjectEvidence primary_clang_cpp_record;
    RuntimeObjectEvidence elf_interpreter_record;
    std::vector<RuntimeObjectEvidence> runtime_object_rows;
    std::vector<RuntimeObservationEvidence> runtime_observation_rows;
};

struct RuntimeObserverLimits final {
    std::uint64_t maximum_runtime_file_bytes = 1024u * 1024u * 1024u;
    std::uint64_t maximum_unique_runtime_bytes = 4ull * 1024ull * 1024ull * 1024ull;
    std::uint64_t maximum_authenticated_runtime_bytes =
        16ull * 1024ull * 1024ull * 1024ull;
    std::size_t maximum_proc_maps_bytes = 16u * 1024u * 1024u;
    std::size_t maximum_proc_maps_line_bytes = 64u * 1024u;
    std::size_t maximum_executable_mapping_rows = 65'536u;
    std::size_t maximum_runtime_objects = 4096u;
};

// Collects only stopped-process runtime evidence. It never reopens a namespace
// pathname: executable mmap evidence comes from pidfd_getfd, and fallback
// evidence comes from the exact /proc/<pid>/map_files mapping object.
class RuntimeObserver final {
public:
    RuntimeObserver(
        pid_t stopped_pid,
        int validated_pidfd,
        std::string collector_namespace_relative_path,
        std::vector<NamespaceFileExpectation> namespace_files,
        const MonotonicDeadline& deadline,
        RuntimeObserverLimits limits = {});
    ~RuntimeObserver();

    RuntimeObserver(const RuntimeObserver&) = delete;
    RuntimeObserver& operator=(const RuntimeObserver&) = delete;
    RuntimeObserver(RuntimeObserver&&) noexcept;
    RuntimeObserver& operator=(RuntimeObserver&&) noexcept;

    void observe_exec_proc_exe(const MonotonicDeadline& deadline);
    void observe_mmap_fd(
        int child_fd,
        const std::string& namespace_relative_path,
        std::uint64_t expected_device,
        std::uint64_t expected_inode,
        std::uint64_t file_offset,
        std::uint64_t mapping_length,
        std::uint64_t protection_flags,
        const MonotonicDeadline& deadline);
    void rescan_proc_map_files(const MonotonicDeadline& deadline);

    [[nodiscard]] CompletedRuntimeObservation finalize();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_RUNTIME_OBSERVER_H
