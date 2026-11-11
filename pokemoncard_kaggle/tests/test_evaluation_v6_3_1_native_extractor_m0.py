from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from evaluation_v6_3_1.eir_prebinding import eir_canonical_cbor_decode, eir_canonical_cbor_encode
from evaluation_v6_3_1.eir_state3_semantics import (
    decode_extractor_tu_observation_v2_bytes,
    validate_definition_instance_observations,
    validate_extractor_tu_observation_v2,
)


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "pokemon-v631302-clang16-dev:20260802"
EXTRACTOR = "/v631302/bin/v631302-native-extractor"
PRIMARY = "/v631302/src/simple.cc"
COMPILER = "/v631302/toolchain/bin/clang++"
FROZEN_TARGET_ROWS = (
    ROOT / "strategy/evaluation_v6_3_1_entropy_static_closure_sourcebound_20260721.json"
)


@dataclass(frozen=True)
class DockerBuild:
    docker: str
    work: Path


def _run_checked(command: list[str]) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert result.returncode == 0, (
        f"command failed ({result.returncode}): {command!r}\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )
    return result


def _target_fixture_source() -> str:
    report = json.loads(FROZEN_TARGET_ROWS.read_text(encoding="utf-8"))
    rows = report["details"]["compiler_derived_dispatch_proof"]["targets"]
    assert len(rows) == 116
    assert [row["index"] for row in rows] == list(range(116))

    declarations: list[str] = ["struct State {};", "struct FunctionTableType {"]
    for signature in sorted({row["qual_type"] for row in rows}):
        assert signature.startswith("void (") and signature.endswith(")")
        parameters = signature[len("void (") : -1]
        declarations.append(f"    void push_back(void (*)({parameters})) {{}}")
    declarations.extend(("};", "FunctionTableType FunctionTable;"))
    for row in rows:
        signature = row["qual_type"]
        assert signature.startswith("void (") and signature.endswith(")")
        parameters = signature[len("void (") : -1]
        declarations.append(f"void {row['name']}({parameters}) {{}}")
    declarations.append("void InitializeBattleFunction() {")
    declarations.extend(f"    FunctionTable.push_back({row['name']});" for row in rows)
    declarations.append("}")
    return "\n".join(declarations) + "\n"


@pytest.fixture(scope="module")
def docker_build(tmp_path_factory: pytest.TempPathFactory) -> DockerBuild:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker is unavailable; skipped Linux/amd64 native extractor integration test")

    image_check = subprocess.run(
        [docker, "image", "inspect", "--format", "{{.Architecture}}", IMAGE],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if image_check.returncode != 0 or image_check.stdout.strip() != b"amd64":
        pytest.skip(
            f"Docker image {IMAGE!r} is unavailable as linux/amd64; native extractor integration test skipped"
        )

    work = tmp_path_factory.mktemp("native-extractor-m0")
    docker_prefix = [
        docker,
        "run",
        "--rm",
        "--network",
        "none",
        "--platform",
        "linux/amd64",
        "-v",
        f"{ROOT}:/src:ro",
        "-v",
        f"{work}:/work:rw",
        "-w",
        "/work",
        IMAGE,
    ]
    _run_checked(
        docker_prefix
        + [
            "cmake",
            "-S",
            "/src/evaluation_v6_3_1/native/state3_extractor",
            "-B",
            "/work/build",
            "-G",
            "Ninja",
            "-DCMAKE_BUILD_TYPE=Release",
        ]
    )
    _run_checked(
        docker_prefix
        + [
            "cmake",
            "--build",
            "/work/build",
            "--target",
            "v631302-native-extractor",
            "--",
            "-j2",
        ]
    )
    binary = work / "build/bin/v631302-native-extractor"
    assert binary.is_file()
    return DockerBuild(docker=docker, work=work)


def _run_extractor(
    context: DockerBuild,
    source_directory: Path,
    *,
    primary: str = PRIMARY,
    compiler_arguments: tuple[str, ...] = (
        "-std=c++20",
        "-fsyntax-only",
        "-nostdinc",
        "-I",
        "/v631302/src",
        PRIMARY,
    ),
    working_directory: str = "/v631302/work",
) -> subprocess.CompletedProcess[bytes]:
    command = [
        context.docker,
        "run",
        "--rm",
        "--network",
        "none",
        "--platform",
        "linux/amd64",
        "--read-only",
        "--tmpfs",
        "/v631302/work:rw,noexec,nosuid,size=64m",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
        "-e",
        "LD_LIBRARY_PATH=/opt/llvm-build/lib",
        "-v",
        f"{source_directory}:/v631302/src:ro",
        "-v",
        f"{context.work / 'build/bin'}:/v631302/bin:ro",
        "-w",
        working_directory,
        IMAGE,
        EXTRACTOR,
        "--protocol=631302",
        "--observation-version=2",
        "--tu-ordinal=0",
        f"--compiler-entry={COMPILER}",
        f"--primary-source={primary}",
        "--",
        *compiler_arguments,
    ]
    return subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _assert_success(result: subprocess.CompletedProcess[bytes]) -> list[object]:
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert result.stderr == b""
    assert result.stdout
    decoded = decode_extractor_tu_observation_v2_bytes(result.stdout)
    assert eir_canonical_cbor_encode(decoded) == result.stdout
    assert validate_extractor_tu_observation_v2(decoded) == decoded
    return decoded


def _run_source(
    context: DockerBuild,
    tmp_path: Path,
    source_text: str,
    *,
    filename: str = "case.cc",
) -> subprocess.CompletedProcess[bytes]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = tmp_path / filename
    source.write_text(source_text, encoding="utf-8")
    return _run_extractor(
        context,
        tmp_path,
        primary=f"/v631302/src/{filename}",
        compiler_arguments=(
            "-std=c++20",
            "-fsyntax-only",
            "-nostdinc",
            f"/v631302/src/{filename}",
        ),
    )


def _definition(observation: list[object], name: str) -> list[object]:
    return next(row for row in observation[9] if row[2] == name)


def _invocation_names(definition: list[object]) -> list[str]:
    return [
        descriptor[1]
        for invocation in definition[9]
        for descriptor in invocation[4]
    ]


def _assert_empty_protocol_failure(
    result: subprocess.CompletedProcess[bytes],
    *,
    diagnostic: bytes | None = None,
) -> None:
    assert result.returncode == 66
    assert result.stdout == b""
    assert result.stderr.startswith(b"V631302_M0_ERROR:")
    if diagnostic is not None:
        assert result.stderr == b"V631302_M0_ERROR:" + diagnostic + b"\n"


def test_simple_fixture_is_byte_identical_in_fresh_read_only_containers(
    docker_build: DockerBuild,
) -> None:
    source = ROOT / "tests/fixtures/evaluation_v6_3_1/state3_extractor"
    first = _run_extractor(docker_build, source)
    second = _run_extractor(docker_build, source)
    first_observation = _assert_success(first)
    second_observation = _assert_success(second)

    assert first.stdout == second.stdout
    assert first_observation == second_observation
    assert len(first_observation[9]) == 4
    assert sum(len(row[9]) for row in first_observation[9]) == 3
    assert first_observation[10] == [2, 2, 2, 2, 0, 0, 4, 4, 3, 3, 0, 0, 0, 0]
    assert validate_definition_instance_observations(first_observation[9]) == first_observation[9]


def test_frozen_target_registry_fixture_reconstructs_all_target_indices(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    source = tmp_path / "target-registry"
    source.mkdir()
    primary = source / "target_registry.cc"
    primary.write_text(_target_fixture_source(), encoding="utf-8")

    result = _run_extractor(
        docker_build,
        source,
        primary="/v631302/src/target_registry.cc",
        compiler_arguments=(
            "-std=c++20",
            "-fsyntax-only",
            "-nostdinc",
            "/v631302/src/target_registry.cc",
        ),
    )
    observation = _assert_success(result)
    target_indices = [index for row in observation[9] for index in row[5]]

    assert sorted(target_indices) == list(range(116))
    assert len(target_indices) == 116
    assert observation[10][6:8] == [124, 124]
    assert observation[10][8:12] == [116, 116, 0, 0]


def test_cli_protocol_failure_contract_is_fixed(docker_build: DockerBuild) -> None:
    source = ROOT / "tests/fixtures/evaluation_v6_3_1/state3_extractor"
    result = _run_extractor(docker_build, source, compiler_arguments=())
    assert result.returncode == 66
    assert result.stdout == b""
    assert result.stderr == b"V631302_M0_ERROR:M0_CLI_INVALID\n"


def test_working_directory_failure_contract_is_fixed(docker_build: DockerBuild) -> None:
    source = ROOT / "tests/fixtures/evaluation_v6_3_1/state3_extractor"
    result = _run_extractor(docker_build, source, working_directory="/")
    assert result.returncode == 66
    assert result.stdout == b""
    assert result.stderr == b"V631302_M0_ERROR:M0_WORKING_DIRECTORY_INVALID\n"


def test_frontend_failure_contract_is_fixed(docker_build: DockerBuild) -> None:
    source = ROOT / "tests/fixtures/evaluation_v6_3_1/state3_extractor"
    result = _run_extractor(
        docker_build,
        source,
        primary="/v631302/src/missing.cc",
        compiler_arguments=(
            "-std=c++20",
            "-fsyntax-only",
            "-nostdinc",
            "-I",
            "/v631302/src",
            "/v631302/src/missing.cc",
        ),
    )
    assert result.returncode == 65
    assert result.stdout == b""
    assert result.stderr == b"V631302_M0_ERROR:M0_FRONTEND_FAILED\n"


def test_semantic_diagnostic_is_a_frontend_failure(docker_build: DockerBuild, tmp_path: Path) -> None:
    result = _run_source(
        docker_build,
        tmp_path,
        "int invalid_semantics() { return missing_name; }\n",
    )
    assert result.returncode == 65
    assert result.stdout == b""
    assert result.stderr == b"V631302_M0_ERROR:M0_FRONTEND_FAILED\n"


def test_nontrivial_temporary_cleanup_fails_closed(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    source = tmp_path / "implicit-cleanup"
    source.mkdir()
    primary = source / "cleanup.cc"
    primary.write_text(
        "struct Value { Value() {} ~Value() {} };\n"
        "Value make_value() { return Value{}; }\n",
        encoding="utf-8",
    )

    result = _run_extractor(
        docker_build,
        source,
        primary="/v631302/src/cleanup.cc",
        compiler_arguments=(
            "-std=c++20",
            "-fsyntax-only",
            "-nostdinc",
            "/v631302/src/cleanup.cc",
        ),
    )

    assert result.returncode == 66
    assert result.stdout == b""
    assert result.stderr == b"V631302_M0_ERROR:M0_INVOCATION_INVENTORY_INCOMPLETE\n"


def test_nontrivial_parameter_cleanup_fails_closed(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    source = tmp_path / "parameter-cleanup"
    source.mkdir()
    primary = source / "parameter.cc"
    primary.write_text(
        "struct Value { Value() {} ~Value() {} };\n"
        "void consume(Value value) { (void)value; }\n",
        encoding="utf-8",
    )

    result = _run_extractor(
        docker_build,
        source,
        primary="/v631302/src/parameter.cc",
        compiler_arguments=(
            "-std=c++20",
            "-fsyntax-only",
            "-nostdinc",
            "/v631302/src/parameter.cc",
        ),
    )

    assert result.returncode == 66
    assert result.stdout == b""
    assert result.stderr == b"V631302_M0_ERROR:M0_INVOCATION_INVENTORY_INCOMPLETE\n"


def test_builtin_without_authenticated_registry_fails_at_origin_resolution(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    source = tmp_path / "builtin-origin"
    source.mkdir()
    primary = source / "builtin.cc"
    primary.write_text(
        "int absolute_value(int value) { return __builtin_abs(value); }\n",
        encoding="utf-8",
    )

    result = _run_extractor(
        docker_build,
        source,
        primary="/v631302/src/builtin.cc",
        compiler_arguments=(
            "-std=c++20",
            "-fsyntax-only",
            "-nostdinc",
            "/v631302/src/builtin.cc",
        ),
    )

    assert result.returncode == 66
    assert result.stdout == b""
    assert result.stderr == b"V631302_M0_ERROR:M0_CALLEE_ORIGIN_UNSUPPORTED\n"


def test_attribute_only_prefix_macro_preserves_exact_raw_span(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    source = tmp_path / "attribute-prefix"
    source.mkdir()
    primary = source / "attribute.cc"
    source_text = (
        '#define EXPORTED __attribute__((visibility("default")))\n'
        "EXPORTED int exported() { return 7; }\n"
    )
    primary.write_text(source_text, encoding="utf-8")

    observation = _assert_success(
        _run_extractor(
            docker_build,
            source,
            primary="/v631302/src/attribute.cc",
            compiler_arguments=(
                "-std=c++20",
                "-fsyntax-only",
                "-nostdinc",
                "/v631302/src/attribute.cc",
            ),
        )
    )
    definition = next(row for row in observation[9] if row[2] == "exported")
    raw = primary.read_bytes()[definition[7] : definition[8]]

    assert raw == b"EXPORTED int exported() { return 7; }"


@pytest.mark.parametrize(
    "source_text",
    (
        "#define BAD_PREFIX inline\nBAD_PREFIX int rejected() { return 1; }\n",
        (
            '#define ATTR __attribute__((visibility("default")))\n'
            "#define BAD_PREFIX inline ATTR\n"
            "BAD_PREFIX int rejected() { return 1; }\n"
        ),
        "#define BODY { return 1; }\nint rejected() BODY\n",
    ),
)
def test_nonattribute_prefix_and_macro_body_spans_fail_closed(
    docker_build: DockerBuild,
    tmp_path: Path,
    source_text: str,
) -> None:
    source = tmp_path / "invalid-span"
    source.mkdir()
    primary = source / "invalid.cc"
    primary.write_text(source_text, encoding="utf-8")

    result = _run_extractor(
        docker_build,
        source,
        primary="/v631302/src/invalid.cc",
        compiler_arguments=(
            "-std=c++20",
            "-fsyntax-only",
            "-nostdinc",
            "/v631302/src/invalid.cc",
        ),
    )

    assert result.returncode == 66
    assert result.stdout == b""
    assert result.stderr == b"V631302_M0_ERROR:M0_DEFINITION_SPAN_UNSUPPORTED\n"


def test_unevaluated_call_contexts_do_not_emit_runtime_invocations(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    result = _run_source(
        docker_build,
        tmp_path,
        "int probe() { return 7; }\n"
        "int unevaluated_contexts() {\n"
        "    using Result = decltype(probe());\n"
        "    (void)sizeof(probe());\n"
        "    (void)noexcept(probe());\n"
        "    return sizeof(Result);\n"
        "}\n",
    )

    observation = _assert_success(result)
    assert _invocation_names(_definition(observation, "unevaluated_contexts")) == []


def test_evaluated_counterpart_emits_the_direct_runtime_invocation(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    result = _run_source(
        docker_build,
        tmp_path,
        "int probe() { return 7; }\n"
        "int evaluated_context() { return probe(); }\n",
    )

    observation = _assert_success(result)
    definition = _definition(observation, "evaluated_context")
    assert _invocation_names(definition) == ["probe"]
    assert definition[9][0][2] == 1


def test_requires_expression_is_unevaluated_while_adjacent_call_is_runtime(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    result = _run_source(
        docker_build,
        tmp_path,
        "int probe() { return 7; }\n"
        "template <typename T> concept CanProbe = requires { probe(); };\n"
        "int requires_and_runtime() {\n"
        "    static_assert(CanProbe<int>);\n"
        "    return probe();\n"
        "}\n",
    )

    observation = _assert_success(result)
    assert _invocation_names(_definition(observation, "requires_and_runtime")) == [
        "probe"
    ]


def test_va_arg_builtin_form_fails_invocation_closure(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    result = _run_source(
        docker_build,
        tmp_path,
        "int consume(__builtin_va_list values) {\n"
        "    return __builtin_va_arg(values, int);\n"
        "}\n",
    )

    _assert_empty_protocol_failure(
        result,
        diagnostic=b"M0_INVOCATION_INVENTORY_INCOMPLETE",
    )


def test_unused_stored_default_argument_is_not_a_runtime_use(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    result = _run_source(
        docker_build,
        tmp_path,
        "int default_value() { return 7; }\n"
        "int with_default(int value = default_value()) { return value; }\n"
        "int explicit_argument() { return with_default(9); }\n",
    )

    observation = _assert_success(result)
    assert _invocation_names(_definition(observation, "with_default")) == []
    assert _invocation_names(_definition(observation, "explicit_argument")) == [
        "with_default"
    ]


def test_concrete_default_argument_uses_are_use_scoped_or_fail_closed(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    result = _run_source(
        docker_build,
        tmp_path,
        "int default_value() { return 7; }\n"
        "int with_default(int value = default_value()) { return value; }\n"
        "int one_default_use() { return with_default(); }\n"
        "int two_default_uses() { return with_default() + with_default(); }\n",
    )

    if result.returncode == 66:
        _assert_empty_protocol_failure(
            result,
            diagnostic=b"M0_INVOCATION_INVENTORY_INCOMPLETE",
        )
        return

    observation = _assert_success(result)
    assert _invocation_names(_definition(observation, "with_default")) == []
    for name, expected_count in (("one_default_use", 2), ("two_default_uses", 4)):
        definition = _definition(observation, name)
        assert len(definition[9]) == expected_count
        names = _invocation_names(definition)
        assert names.count("with_default") == expected_count // 2
        assert names.count("default_value") == expected_count // 2
        anchors = [tuple(invocation[1]) for invocation in definition[9]]
        assert len(set(anchors)) == len(anchors)


def test_if_constexpr_discarded_statement_is_not_runtime_evaluated_but_discarded_value_is(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    result = _run_source(
        docker_build,
        tmp_path,
        "int probe() { return 7; }\n"
        "int discarded_statement() {\n"
        "    if constexpr (false) { return probe(); }\n"
        "    return 0;\n"
        "}\n"
        "int discarded_value_expression() {\n"
        "    (void)probe();\n"
        "    return 0;\n"
        "}\n",
    )

    observation = _assert_success(result)
    assert _invocation_names(_definition(observation, "discarded_statement")) == []
    assert _invocation_names(_definition(observation, "discarded_value_expression")) == [
        "probe"
    ]


def test_if_constexpr_init_is_evaluated_and_ordinary_if_keeps_both_runtime_paths(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    result = _run_source(
        docker_build,
        tmp_path,
        "int probe() { return 7; }\n"
        "int left() { return 1; }\n"
        "int right() { return 2; }\n"
        "int constexpr_init() {\n"
        "    if constexpr (int value = probe(); true) { return value; }\n"
        "}\n"
        "int ordinary_if(bool condition) {\n"
        "    if (condition) { return left(); }\n"
        "    return right();\n"
        "}\n",
    )

    observation = _assert_success(result)
    assert _invocation_names(_definition(observation, "constexpr_init")) == ["probe"]
    assert _invocation_names(_definition(observation, "ordinary_if")) == [
        "left",
        "right",
    ]


@pytest.mark.parametrize(
    "source_text",
    (
        (
            "int probe() { return 7; }\n"
            "using UnevaluatedLambda = decltype([]() { return probe(); });\n"
        ),
        (
            "int probe() { return 7; }\n"
            "void unused_default_lambda(int = []() { return probe(); }()) {}\n"
        ),
        (
            "int probe() { return 7; }\n"
            "int discarded_lambda() {\n"
            "    if constexpr (false) {\n"
            "        auto function = []() { return probe(); };\n"
            "        return function();\n"
            "    }\n"
            "    return 0;\n"
            "}\n"
        ),
    ),
)
def test_nested_definition_contexts_fail_closed_instead_of_emitting_runtime_rows(
    docker_build: DockerBuild,
    tmp_path: Path,
    source_text: str,
) -> None:
    result = _run_source(docker_build, tmp_path, source_text)
    _assert_empty_protocol_failure(
        result,
        diagnostic=b"M0_INVOCATION_INVENTORY_INCOMPLETE",
    )


def test_consteval_call_is_not_runtime_but_runtime_constexpr_call_is(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    result = _run_source(
        docker_build,
        tmp_path,
        "consteval int immediate() { return 7; }\n"
        "constexpr int reusable(int value) { return value; }\n"
        "int immediate_use() { return immediate(); }\n"
        "int runtime_use(int value) { return reusable(value); }\n",
    )

    observation = _assert_success(result)
    assert _invocation_names(_definition(observation, "immediate_use")) == []
    assert _invocation_names(_definition(observation, "runtime_use")) == ["reusable"]


def test_consteval_function_body_does_not_emit_runtime_invocations(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    observation = _assert_success(
        _run_source(
            docker_build,
            tmp_path,
            "constexpr int compile_time_helper() { return 7; }\n"
            "consteval int immediate_body() { return compile_time_helper(); }\n"
            "int runtime_wrapper() { return immediate_body(); }\n",
        )
    )
    assert _invocation_names(_definition(observation, "immediate_body")) == []
    assert _invocation_names(_definition(observation, "runtime_wrapper")) == []


def test_dependent_context_fails_closed_before_origin_resolution(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    result = _run_source(
        docker_build,
        tmp_path,
        "template <typename T> int dependent_context() { return T::call(); }\n",
    )

    _assert_empty_protocol_failure(
        result,
        diagnostic=b"M0_INVOCATION_INVENTORY_INCOMPLETE",
    )


def test_unknown_indirect_call_target_fails_closed(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    result = _run_source(
        docker_build,
        tmp_path,
        "int unknown_call_target(int (*function)()) { return function(); }\n",
    )

    _assert_empty_protocol_failure(
        result,
        diagnostic=b"M0_INVOCATION_INVENTORY_INCOMPLETE",
    )


def test_typeid_operand_is_unevaluated_or_the_context_fails_closed(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    result = _run_source(
        docker_build,
        tmp_path,
        "namespace std { class type_info {}; }\n"
        "int probe() { return 7; }\n"
        "int typeid_context() { (void)typeid(probe()); return 0; }\n",
    )

    if result.returncode == 66:
        _assert_empty_protocol_failure(
            result,
            diagnostic=b"M0_INVOCATION_INVENTORY_INCOMPLETE",
        )
        return

    observation = _assert_success(result)
    assert _invocation_names(_definition(observation, "typeid_context")) == []


def test_potentially_evaluated_typeid_fails_invocation_closure(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    result = _run_source(
        docker_build,
        tmp_path,
        "namespace std { class type_info {}; }\n"
        "struct Base { virtual void marker(); };\n"
        "int dynamic_typeid(Base& value) { (void)typeid(value); return 0; }\n",
    )

    _assert_empty_protocol_failure(
        result,
        diagnostic=b"M0_INVOCATION_INVENTORY_INCOMPLETE",
    )


@pytest.mark.parametrize(
    ("case_name", "source_text"),
    (
        (
            "implicit-copy-move",
            "struct Value { Value() {} };\n"
            "Value copy_move() { Value value; return value; }\n",
        ),
        (
            "implicit-destructor",
            "struct Value { ~Value() {} };\n"
            "int automatic_destructor() { Value value; return 0; }\n",
        ),
        (
            "new-delete",
            "int allocation() { int* value = new int(1); delete value; return 0; }\n",
        ),
        (
            "user-conversion",
            "struct Value { operator int() const { return 1; } };\n"
            "int conversion() { Value value; return value; }\n",
        ),
    ),
)
def test_implicit_runtime_invocation_forms_fail_closed(
    docker_build: DockerBuild,
    tmp_path: Path,
    case_name: str,
    source_text: str,
) -> None:
    result = _run_source(docker_build, tmp_path / case_name, source_text)
    _assert_empty_protocol_failure(
        result,
        diagnostic=b"M0_INVOCATION_INVENTORY_INCOMPLETE",
    )


def test_nontrivial_by_value_parameter_copy_fails_closed(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    result = _run_source(
        docker_build,
        tmp_path,
        "struct Value { Value(const Value&) {} };\n"
        "int consume(Value value) { return 0; }\n",
    )
    _assert_empty_protocol_failure(
        result,
        diagnostic=b"M0_INVOCATION_INVENTORY_INCOMPLETE",
    )


def test_structured_binding_generated_activity_fails_closed(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    result = _run_source(
        docker_build,
        tmp_path,
        "struct Pair { Pair() {} Pair(const Pair&) {} int left; int right; };\n"
        "int decompose() { Pair pair; auto [left, right] = pair; return left + right; }\n",
    )
    _assert_empty_protocol_failure(
        result,
        diagnostic=b"M0_INVOCATION_INVENTORY_INCOMPLETE",
    )


@pytest.mark.parametrize(
    ("case_name", "source_text"),
    (
        (
            "static-local",
            "int local_static() { static int value = 1; return value; }\n",
        ),
        (
            "throw-expression",
            "int throwing() { throw 1; }\n",
        ),
        (
            "try-statement",
            "int trying() { try { return 1; } catch (...) { return 0; } }\n",
        ),
        (
            "dynamic-cast",
            "struct Base { virtual void marker(); };\n"
            "struct Derived : Base {};\n"
            "Derived* cast(Base* value) { return dynamic_cast<Derived*>(value); }\n",
        ),
        (
            "cleanup-attribute",
            "void cleanup(int*);\n"
            "int cleanup_variable() { int value __attribute__((cleanup(cleanup))) = 0; "
            "return value; }\n",
        ),
        (
            "startup-attribute",
            "__attribute__((constructor)) void startup() {}\n",
        ),
        (
            "record-array-construction",
            "struct Value { Value() {} };\n"
            "int record_array() { Value values[2]; return 0; }\n",
        ),
    ),
)
def test_additional_hidden_runtime_forms_fail_at_invocation_stage(
    docker_build: DockerBuild,
    tmp_path: Path,
    case_name: str,
    source_text: str,
) -> None:
    result = _run_source(docker_build, tmp_path / case_name, source_text)
    _assert_empty_protocol_failure(
        result,
        diagnostic=b"M0_INVOCATION_INVENTORY_INCOMPLETE",
    )


def test_vla_bound_call_fails_at_invocation_stage(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    result = _run_source(
        docker_build,
        tmp_path,
        "int probe() { return 2; }\n"
        "int variable_length_array() { int values[probe()]; return values[0]; }\n",
    )
    _assert_empty_protocol_failure(
        result,
        diagnostic=b"M0_INVOCATION_INVENTORY_INCOMPLETE",
    )


@pytest.mark.parametrize(
    "body",
    (
        "using Values = int[probe()]; return sizeof(Values);",
        "return sizeof(int[probe()]);",
    ),
)
def test_vla_type_contexts_fail_at_invocation_stage(
    docker_build: DockerBuild,
    tmp_path: Path,
    body: str,
) -> None:
    result = _run_source(
        docker_build,
        tmp_path,
        "int probe() { return 2; }\n"
        f"int variable_length_type() {{ {body} }}\n",
    )
    _assert_empty_protocol_failure(
        result,
        diagnostic=b"M0_INVOCATION_INVENTORY_INCOMPLETE",
    )


@pytest.mark.parametrize(
    "source_text",
    (
        "int probe() { return 7; }\nint global_value = probe();\n",
        "struct Value { ~Value() {} };\nValue global_value;\n",
        'asm("");\n',
    ),
)
def test_translation_unit_runtime_activity_fails_at_invocation_stage(
    docker_build: DockerBuild,
    tmp_path: Path,
    source_text: str,
) -> None:
    result = _run_source(docker_build, tmp_path, source_text)
    _assert_empty_protocol_failure(
        result,
        diagnostic=b"M0_INVOCATION_INVENTORY_INCOMPLETE",
    )


def test_constant_initialized_trivial_global_does_not_create_a_runtime_invocation(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    observation = _assert_success(
        _run_source(
            docker_build,
            tmp_path,
            "int global_value = 7;\nint read_global() { return global_value; }\n",
        )
    )
    assert _invocation_names(_definition(observation, "read_global")) == []


def test_range_for_desugaring_fails_closed(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    result = _run_source(
        docker_build,
        tmp_path,
        "int range_for() { int values[2] = {1, 2}; int total = 0; "
        "for (int value : values) { total += value; } return total; }\n",
    )
    _assert_empty_protocol_failure(
        result,
        diagnostic=b"M0_INVOCATION_INVENTORY_INCOMPLETE",
    )


def test_member_construction_is_inventoried_in_constructor_and_callsite(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    observation = _assert_success(
        _run_source(
            docker_build,
            tmp_path,
            "struct Member { Member() {} };\n"
            "struct Container { Member member; Container() {} };\n"
            "int build_container() { Container value; return 0; }\n",
        )
    )
    assert _invocation_names(_definition(observation, "Container::Container")) == [
        "Member::Member"
    ]
    assert _invocation_names(_definition(observation, "build_container")) == [
        "Container::Container"
    ]


@pytest.mark.parametrize(
    "compiler_prefix",
    (
        ("-fopenmp",),
        ("-fblocks",),
        ("-x", "objective-c++"),
    ),
)
def test_unsupported_runtime_language_modes_are_rejected(
    docker_build: DockerBuild,
    tmp_path: Path,
    compiler_prefix: tuple[str, ...],
) -> None:
    primary = tmp_path / "case.cc"
    primary.write_text("int plain_cpp() { return 0; }\n", encoding="utf-8")
    result = _run_extractor(
        docker_build,
        tmp_path,
        primary="/v631302/src/case.cc",
        compiler_arguments=(
            "-std=c++20",
            "-fsyntax-only",
            "-nostdinc",
            *compiler_prefix,
            "/v631302/src/case.cc",
        ),
    )
    _assert_empty_protocol_failure(
        result,
        diagnostic=b"M0_FRONTEND_ACTION_UNSUPPORTED",
    )


def test_frontend_diagnostic_precedes_inventory_failure(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    result = _run_source(
        docker_build,
        tmp_path,
        "int indirect(int (*function)()) { return function(); }\n"
        "int invalid_semantics() { return missing_name; }\n",
    )
    assert result.returncode == 65
    assert result.stdout == b""
    assert result.stderr == b"V631302_M0_ERROR:M0_FRONTEND_FAILED\n"


@pytest.mark.parametrize(
    ("case_name", "source_text", "returncode", "stderr"),
    (
        (
            "repeat-inventory",
            "int indirect(int (*function)()) { return function(); }\n",
            66,
            b"V631302_M0_ERROR:M0_INVOCATION_INVENTORY_INCOMPLETE\n",
        ),
        (
            "repeat-origin",
            "int builtin(int value) { return __builtin_abs(value); }\n",
            66,
            b"V631302_M0_ERROR:M0_CALLEE_ORIGIN_UNSUPPORTED\n",
        ),
        (
            "repeat-frontend",
            "int invalid_semantics() { return missing_name; }\n",
            65,
            b"V631302_M0_ERROR:M0_FRONTEND_FAILED\n",
        ),
    ),
)
def test_failure_selection_is_byte_identical_across_fresh_processes(
    docker_build: DockerBuild,
    tmp_path: Path,
    case_name: str,
    source_text: str,
    returncode: int,
    stderr: bytes,
) -> None:
    source = tmp_path / case_name
    first = _run_source(docker_build, source, source_text)
    second = _run_source(docker_build, source, source_text)

    assert (first.returncode, first.stdout, first.stderr) == (
        second.returncode,
        second.stdout,
        second.stderr,
    )
    assert first.returncode == returncode
    assert first.stdout == b""
    assert first.stderr == stderr


def test_coroutine_protocol_activity_fails_closed(
    docker_build: DockerBuild,
    tmp_path: Path,
) -> None:
    result = _run_source(
        docker_build,
        tmp_path,
        "namespace std {\n"
        "    template <typename R, typename... Args> struct coroutine_traits {\n"
        "        using promise_type = typename R::promise_type;\n"
        "    };\n"
        "    template <typename Promise = void> struct coroutine_handle;\n"
        "    template <> struct coroutine_handle<void> {\n"
        "        static coroutine_handle from_address(void*) noexcept;\n"
        "    };\n"
        "    template <typename Promise> struct coroutine_handle {\n"
        "        static coroutine_handle from_address(void*) noexcept;\n"
        "        operator coroutine_handle<void>() const noexcept;\n"
        "    };\n"
        "}\n"
        "struct SuspendNever {\n"
        "    bool await_ready() const noexcept { return true; }\n"
        "    void await_suspend(std::coroutine_handle<>) const noexcept {}\n"
        "    void await_resume() const noexcept {}\n"
        "};\n"
        "struct Task {\n"
        "    struct promise_type {\n"
        "        Task get_return_object();\n"
        "        SuspendNever initial_suspend() noexcept;\n"
        "        SuspendNever final_suspend() noexcept;\n"
        "        void return_void() noexcept;\n"
        "        void unhandled_exception() noexcept;\n"
        "    };\n"
        "};\n"
        "Task coroutine_activity() { co_return; }\n",
    )

    _assert_empty_protocol_failure(
        result,
        diagnostic=b"M0_INVOCATION_INVENTORY_INCOMPLETE",
    )
