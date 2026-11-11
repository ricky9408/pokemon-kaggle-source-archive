#include "Observation.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/SHA256.h"

#include <algorithm>
#include <stdexcept>
#include <string_view>
#include <tuple>

namespace evaluation_v6_3_1::native {
namespace {

using Bytes = std::vector<CborWriter::Byte>;

void write_strings(CborWriter& writer, const std::vector<std::string>& values) {
    writer.write_array(values.size());
    for (const std::string& value : values) {
        writer.write_text(value);
    }
}

void write_uints(CborWriter& writer, const std::vector<std::uint32_t>& values) {
    writer.write_array(values.size());
    for (std::uint32_t value : values) {
        writer.write_uint(value);
    }
}

void write_descriptor(CborWriter& writer, const CalleeDescriptor& descriptor) {
    writer.write_array(5);
    writer.write_text(descriptor.declaration_kind);
    writer.write_text(descriptor.qualified_name);
    writer.write_text(descriptor.raw_qual_type);
    writer.write_uint(descriptor.linkage);
    writer.write_uint(descriptor.origin);
}

Bytes descriptor_key(const CalleeDescriptor& descriptor) {
    CborWriter writer;
    write_descriptor(writer, descriptor);
    return writer.bytes();
}

void write_descriptors(CborWriter& writer, const std::vector<CalleeDescriptor>& descriptors) {
    writer.write_array(descriptors.size());
    for (const CalleeDescriptor& descriptor : descriptors) {
        write_descriptor(writer, descriptor);
    }
}

Bytes invocation_descriptor_key(const InvocationOccurrence& invocation) {
    CborWriter writer;
    writer.write_array(3);
    writer.write_uint(invocation.invocation_kind);
    writer.write_uint(invocation.resolution_kind);
    write_descriptors(writer, invocation.callees);
    return writer.bytes();
}

bool invocation_less(const InvocationOccurrence& left,
                     const InvocationOccurrence& right) {
    if (left.anchor_ast_path != right.anchor_ast_path) {
        return std::lexicographical_compare(
            left.anchor_ast_path.begin(), left.anchor_ast_path.end(),
            right.anchor_ast_path.begin(), right.anchor_ast_path.end());
    }
    if (left.invocation_kind != right.invocation_kind) {
        return left.invocation_kind < right.invocation_kind;
    }
    if (left.resolution_kind != right.resolution_kind) {
        return left.resolution_kind < right.resolution_kind;
    }
    return invocation_descriptor_key(left) < invocation_descriptor_key(right);
}

void write_invocations(CborWriter& writer,
                       const std::vector<InvocationOccurrence>& invocations) {
    writer.write_array(invocations.size());
    for (std::size_t ordinal = 0; ordinal < invocations.size(); ++ordinal) {
        const InvocationOccurrence& invocation = invocations[ordinal];
        writer.write_array(5);
        writer.write_uint(ordinal);
        write_uints(writer, invocation.anchor_ast_path);
        writer.write_uint(invocation.invocation_kind);
        writer.write_uint(invocation.resolution_kind);
        write_descriptors(writer, invocation.callees);
    }
}

Bytes definition_key(const DefinitionObservation& definition) {
    CborWriter writer;
    writer.write_array(8);
    writer.write_text(definition.declaration_kind);
    writer.write_text(definition.qualified_name);
    writer.write_text(definition.raw_qual_type);
    writer.write_uint(definition.linkage);
    write_uints(writer, definition.target_indices);
    writer.write_text(definition.virtual_path);
    writer.write_uint(definition.begin_offset);
    writer.write_uint(definition.end_offset_exclusive);
    return writer.bytes();
}

Bytes virtual_key(const VirtualInput& input) {
    CborWriter writer;
    writer.write_array(4);
    writer.write_uint(input.kind);
    writer.write_text(input.logical_name);
    writer.write_uint(input.bytes.size());
    const auto* begin = reinterpret_cast<const std::uint8_t*>(input.bytes.data());
    const auto digest = llvm::SHA256::hash(llvm::ArrayRef<std::uint8_t>(begin, input.bytes.size()));
    writer.write_bytes(std::string_view(reinterpret_cast<const char*>(digest.data()),
                                        digest.size()));
    return writer.bytes();
}

template <typename T, typename Key>
void sort_unique(std::vector<T>& values, Key key, const char* label) {
    std::sort(values.begin(), values.end(), [&](const T& left, const T& right) {
        return key(left) < key(right);
    });
    for (std::size_t index = 1; index < values.size(); ++index) {
        if (key(values[index - 1]) == key(values[index])) {
            throw std::invalid_argument(std::string("duplicate canonical ") + label);
        }
    }
}

}  // namespace

void canonicalize(Observation& observation) {
    for (DefinitionObservation& definition : observation.definitions) {
        std::sort(definition.target_indices.begin(), definition.target_indices.end());
        if (std::adjacent_find(definition.target_indices.begin(),
                               definition.target_indices.end()) !=
            definition.target_indices.end()) {
            throw std::invalid_argument("duplicate target index");
        }
        for (InvocationOccurrence& invocation : definition.invocations) {
            sort_unique(invocation.callees, descriptor_key, "callee descriptor");
        }
        // Equal invocation payloads are distinct semantic facts. They remain
        // adjacent so the later reducer can preserve their occurrence count.
        std::stable_sort(definition.invocations.begin(), definition.invocations.end(),
                         invocation_less);
    }
    sort_unique(observation.definitions, definition_key, "definition observation");
    std::sort(observation.dependencies.begin(), observation.dependencies.end(),
              [](const PhysicalInput& left, const PhysicalInput& right) {
                  return std::tie(left.origin, left.path) <
                         std::tie(right.origin, right.path);
              });
    for (std::size_t index = 1; index < observation.dependencies.size(); ++index) {
        if (std::tie(observation.dependencies[index - 1].origin,
                     observation.dependencies[index - 1].path) ==
            std::tie(observation.dependencies[index].origin,
                     observation.dependencies[index].path)) {
            throw std::invalid_argument("duplicate canonical dependency observation");
        }
    }
    sort_unique(observation.virtual_inputs, virtual_key, "virtual input observation");
}

std::vector<CborWriter::Byte> encode_observation(const Observation& observation) {
    CborWriter writer;
    writer.write_array(11);
    writer.write_uint(631302);
    writer.write_uint(2);
    writer.write_uint(observation.tu_ordinal);
    writer.write_text(observation.primary_source_virtual_path);

    writer.write_array(11);
    write_strings(writer, observation.frontend.effective_cc1_argv);
    writer.write_text(observation.frontend.target_triple);
    writer.write_uint(2);
    writer.write_text(observation.frontend.language_standard);
    writer.write_text(observation.frontend.resource_directory);
    writer.write_text(observation.frontend.sysroot);
    for (int index = 0; index < 5; ++index) {
        writer.write_uint(0);
    }

    writer.write_array(3);
    writer.write_uint(observation.primary.origin);
    writer.write_text(observation.primary.path);
    writer.write_uint(observation.primary.activation_count);

    writer.write_array(observation.dependencies.size());
    for (std::size_t ordinal = 0; ordinal < observation.dependencies.size(); ++ordinal) {
        const PhysicalInput& dependency = observation.dependencies[ordinal];
        writer.write_array(4);
        writer.write_uint(ordinal);
        writer.write_uint(dependency.origin);
        writer.write_text(dependency.path);
        writer.write_uint(dependency.activation_count);
    }

    writer.write_bytes(observation.predefines_bytes);

    writer.write_array(observation.virtual_inputs.size());
    for (std::size_t ordinal = 0; ordinal < observation.virtual_inputs.size(); ++ordinal) {
        const VirtualInput& input = observation.virtual_inputs[ordinal];
        writer.write_array(5);
        writer.write_uint(ordinal);
        writer.write_uint(input.kind);
        writer.write_text(input.logical_name);
        writer.write_bytes(input.bytes);
        writer.write_uint(input.activation_count);
    }

    writer.write_array(observation.definitions.size());
    for (std::size_t ordinal = 0; ordinal < observation.definitions.size(); ++ordinal) {
        const DefinitionObservation& definition = observation.definitions[ordinal];
        writer.write_array(10);
        writer.write_uint(ordinal);
        writer.write_text(definition.declaration_kind);
        writer.write_text(definition.qualified_name);
        writer.write_text(definition.raw_qual_type);
        writer.write_uint(definition.linkage);
        write_uints(writer, definition.target_indices);
        writer.write_text(definition.virtual_path);
        writer.write_uint(definition.begin_offset);
        writer.write_uint(definition.end_offset_exclusive);
        write_invocations(writer, definition.invocations);
    }

    writer.write_array(observation.coverage.size());
    for (std::uint32_t count : observation.coverage) {
        writer.write_uint(count);
    }
    return writer.bytes();
}

}  // namespace evaluation_v6_3_1::native
