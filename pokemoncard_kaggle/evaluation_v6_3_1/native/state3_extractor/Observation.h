#ifndef EVALUATION_V6_3_1_NATIVE_STATE3_EXTRACTOR_OBSERVATION_H
#define EVALUATION_V6_3_1_NATIVE_STATE3_EXTRACTOR_OBSERVATION_H

#include "CborWriter.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace evaluation_v6_3_1::native {

struct FrontendState {
    std::vector<std::string> effective_cc1_argv;
    std::string target_triple;
    std::string language_standard;
    std::string resource_directory;
    std::string sysroot;
};

struct PhysicalInput {
    std::uint8_t origin = 0;
    std::string path;
    std::uint32_t activation_count = 0;
};

struct VirtualInput {
    std::uint8_t kind = 0;
    std::string logical_name;
    std::string bytes;
    std::uint32_t activation_count = 0;
};

struct CalleeDescriptor {
    std::string declaration_kind;
    std::string qualified_name;
    std::string raw_qual_type;
    std::uint8_t linkage = 0;
    std::uint8_t origin = 0;
};

struct InvocationOccurrence {
    std::vector<std::uint32_t> anchor_ast_path;
    std::uint8_t invocation_kind = 0;
    std::uint8_t resolution_kind = 0;
    std::vector<CalleeDescriptor> callees;
};

struct DefinitionObservation {
    std::string declaration_kind;
    std::string qualified_name;
    std::string raw_qual_type;
    std::uint8_t linkage = 0;
    std::vector<std::uint32_t> target_indices;
    std::string virtual_path;
    std::uint64_t begin_offset = 0;
    std::uint64_t end_offset_exclusive = 0;
    std::vector<InvocationOccurrence> invocations;
};

struct Observation {
    std::uint32_t tu_ordinal = 0;
    std::string primary_source_virtual_path;
    FrontendState frontend;
    PhysicalInput primary;
    std::vector<PhysicalInput> dependencies;
    std::string predefines_bytes;
    std::vector<VirtualInput> virtual_inputs;
    std::vector<DefinitionObservation> definitions;
    std::array<std::uint32_t, 14> coverage{};
};

void canonicalize(Observation& observation);
std::vector<CborWriter::Byte> encode_observation(const Observation& observation);

}  // namespace evaluation_v6_3_1::native

#endif  // EVALUATION_V6_3_1_NATIVE_STATE3_EXTRACTOR_OBSERVATION_H
