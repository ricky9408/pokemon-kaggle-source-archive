from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from evaluation_v6_3_1.eir_prebinding import eir_canonical_cbor_decode
from evaluation_v6_3_1.eir_state3_semantics import (
    validate_definition_instance_observations,
    validate_extractor_tu_observation_v2,
)


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "debian:bookworm-slim"


HARNESS = r'''
#include "Observation.h"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using evaluation_v6_3_1::native::CalleeDescriptor;
using evaluation_v6_3_1::native::DefinitionObservation;
using evaluation_v6_3_1::native::InvocationOccurrence;
using evaluation_v6_3_1::native::Observation;
using evaluation_v6_3_1::native::VirtualInput;
using evaluation_v6_3_1::native::canonicalize;
using evaluation_v6_3_1::native::encode_observation;

static std::string hex(const std::vector<std::uint8_t>& bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (std::uint8_t byte : bytes) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 0x0f]);
    }
    return result;
}

static CalleeDescriptor callee(const char* name) {
    return {"FunctionDecl", name, "void ()", 1, 1};
}

static InvocationOccurrence invocation(const char* name, std::uint8_t kind = 1) {
    InvocationOccurrence result;
    result.anchor_ast_path = {0, 2};
    result.invocation_kind = kind;
    result.resolution_kind = 1;
    result.callees.push_back(callee(name));
    return result;
}

static DefinitionObservation definition(
    const char* name,
    std::vector<std::uint32_t> target_indices,
    std::vector<InvocationOccurrence> invocations) {
    DefinitionObservation result;
    result.declaration_kind = "FunctionDecl";
    result.qualified_name = name;
    result.raw_qual_type = "void ()";
    result.linkage = 1;
    result.target_indices = std::move(target_indices);
    result.virtual_path = std::string("/v631302/src/") + name + ".cc";
    result.begin_offset = 10;
    result.end_offset_exclusive = 40;
    result.invocations = std::move(invocations);
    return result;
}

static Observation valid_observation(bool reverse_insertion_order) {
    Observation result;
    result.tu_ordinal = 7;
    result.primary_source_virtual_path = "/v631302/src/main.cc";
    result.frontend.effective_cc1_argv = {
        "/v631302/toolchain/bin/clang", "-cc1", "-triple", "x86_64-pc-linux-gnu"};
    result.frontend.target_triple = "x86_64-pc-linux-gnu";
    result.frontend.language_standard = "c++20";
    result.frontend.resource_directory = "/v631302/toolchain/lib/clang";
    result.frontend.sysroot = "/v631302/toolchain/sysroot";
    result.primary = {1, "/v631302/src/main.cc", 1};
    result.predefines_bytes = "#define __cplusplus 202002L\n";
    result.coverage = {4, 4, 3, 3, 2, 2, 2, 2, 3, 3, 0, 0, 0, 0};

    const auto dependency_source =
        evaluation_v6_3_1::native::PhysicalInput{1, "/v631302/src/z.h", 2};
    const auto dependency_runtime =
        evaluation_v6_3_1::native::PhysicalInput{2, "/v631302/toolchain/include/runtime.h", 1};
    result.dependencies = {dependency_runtime, dependency_source};

    const VirtualInput builtin{1, "<built-in>", "__cplusplus 202002L", 1};
    const VirtualInput command_line{2, "<command-line>", "-DTEST", 1};
    result.virtual_inputs = {command_line, builtin};

    auto duplicate_first = invocation("helper");
    auto duplicate_second = invocation("helper");
    auto distinct = invocation("other", 2);
    auto alpha = definition("alpha", {3}, {distinct, duplicate_second, duplicate_first});
    auto beta = definition("beta", {2, 1}, {});
    result.definitions = {beta, alpha};

    if (!reverse_insertion_order) {
        std::reverse(result.dependencies.begin(), result.dependencies.end());
        std::reverse(result.virtual_inputs.begin(), result.virtual_inputs.end());
        std::reverse(result.definitions.begin(), result.definitions.end());
        std::reverse(result.definitions[0].invocations.begin(), result.definitions[0].invocations.end());
    }
    canonicalize(result);
    return result;
}

static int expect_invalid_callee() {
    Observation observation = valid_observation(true);
    auto duplicate = invocation("helper");
    duplicate.callees.push_back(callee("helper"));
    observation.definitions[0].invocations = {duplicate};
    try {
        canonicalize(observation);
    } catch (const std::invalid_argument& error) {
        std::cout << error.what() << '\n';
        return 0;
    }
    return 1;
}

static int expect_invalid_target_indices() {
    Observation observation = valid_observation(true);
    observation.definitions[0].target_indices = {4, 4};
    try {
        canonicalize(observation);
    } catch (const std::invalid_argument& error) {
        std::cout << error.what() << '\n';
        return 0;
    }
    return 1;
}

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    const std::string mode = argv[1];
    if (mode == "valid-a") {
        std::cout << hex(encode_observation(valid_observation(false))) << '\n';
        return 0;
    }
    if (mode == "valid-b") {
        std::cout << hex(encode_observation(valid_observation(true))) << '\n';
        return 0;
    }
    if (mode == "invalid-callee") return expect_invalid_callee();
    if (mode == "invalid-target") return expect_invalid_target_indices();
    return 3;
}
'''


@pytest.fixture(scope="module")
def native_observation_outputs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is required for the Linux/amd64 native observation test")

    work = tmp_path_factory.mktemp("native-observation")
    (work / "harness.cpp").write_text(HARNESS, encoding="utf-8")
    command = [
        docker,
        "run",
        "--rm",
        "--platform",
        "linux/amd64",
        "-v",
        f"{ROOT}:/src:ro",
        "-v",
        f"{work}:/work",
        "-w",
        "/work",
        IMAGE,
        "bash",
        "-ceu",
        "apt-get update >/dev/null && "
        "apt-get install -y --no-install-recommends clang-16 llvm-16-dev >/dev/null && "
        "llvm_flags=\"$(llvm-config-16 --cxxflags)\" && "
        "llvm_flags=\"${llvm_flags//-std=c++14/}\" && "
        "clang++-16 -std=c++20 -Wall -Wextra -Werror -pedantic ${llvm_flags} -fexceptions "
        "/src/evaluation_v6_3_1/native/state3_extractor/CborWriter.cpp "
        "/src/evaluation_v6_3_1/native/state3_extractor/Observation.cpp "
        "harness.cpp -I /src/evaluation_v6_3_1/native/state3_extractor "
        "$(llvm-config-16 --ldflags --libs support --system-libs) -o harness && "
        "./harness valid-a > valid-a.hex && "
        "./harness valid-b > valid-b.hex && "
        "./harness invalid-callee > invalid-callee.txt && "
        "./harness invalid-target > invalid-target.txt",
    ]
    subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return {
        name: (work / name).read_text(encoding="ascii").strip()
        for name in ("valid-a.hex", "valid-b.hex", "invalid-callee.txt", "invalid-target.txt")
    }


def test_native_observation_has_exact_header_width_and_valid_definition_rows(
    native_observation_outputs: dict[str, str],
) -> None:
    decoded = eir_canonical_cbor_decode(bytes.fromhex(native_observation_outputs["valid-a.hex"]))

    assert len(decoded) == 11
    assert decoded[:2] == [631302, 2]
    assert len(decoded[4]) == 11
    assert len(decoded[5]) == 3
    assert all(len(row) == 4 for row in decoded[6])
    assert all(len(row) == 5 for row in decoded[8])
    assert all(len(row) == 10 for row in decoded[9])
    assert all(len(invocation) == 5 for row in decoded[9] for invocation in row[9])
    assert all(
        len(descriptor) == 5
        for row in decoded[9]
        for invocation in row[9]
        for descriptor in invocation[4]
    )
    assert len(decoded[10]) == 14
    assert validate_extractor_tu_observation_v2(decoded) == decoded
    assert validate_definition_instance_observations(decoded[9]) == decoded[9]


def test_native_observation_canonicalizes_order_and_dense_ordinals(
    native_observation_outputs: dict[str, str],
) -> None:
    decoded = eir_canonical_cbor_decode(bytes.fromhex(native_observation_outputs["valid-a.hex"]))

    assert [row[0] for row in decoded[6]] == [0, 1]
    assert [row[1] for row in decoded[6]] == [1, 2]
    assert [row[0] for row in decoded[8]] == [0, 1]
    assert [row[0] for row in decoded[9]] == [0, 1]
    beta, alpha = decoded[9]
    assert beta[2] == "beta"
    assert beta[5] == [1, 2]
    assert alpha[2] == "alpha"
    assert alpha[5] == [3]
    assert [row[0] for row in alpha[9]] == [0, 1, 2]


def test_native_observation_retains_duplicate_invocation_payloads_as_adjacent_rows(
    native_observation_outputs: dict[str, str],
) -> None:
    decoded = eir_canonical_cbor_decode(bytes.fromhex(native_observation_outputs["valid-a.hex"]))
    invocations = next(row[9] for row in decoded[9] if row[2] == "alpha")

    assert len(invocations) == 3
    assert invocations[0][1:] == invocations[1][1:]
    assert invocations[0][0] == 0
    assert invocations[1][0] == 1
    assert invocations[2][0] == 2


def test_native_observation_rejects_duplicate_callees_and_target_indices(
    native_observation_outputs: dict[str, str],
) -> None:
    assert native_observation_outputs["invalid-callee.txt"] == "duplicate canonical callee descriptor"
    assert native_observation_outputs["invalid-target.txt"] == "duplicate target index"


def test_native_observation_bytes_are_insertion_order_independent(
    native_observation_outputs: dict[str, str],
) -> None:
    assert native_observation_outputs["valid-a.hex"] == native_observation_outputs["valid-b.hex"]
