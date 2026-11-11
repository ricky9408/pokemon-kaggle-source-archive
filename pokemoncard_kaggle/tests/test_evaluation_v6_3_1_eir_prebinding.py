from copy import deepcopy
from hashlib import sha256

import pytest

from evaluation_v6_3_1.canonical_trace_codec import canonical_cbor_encode
from evaluation_v6_3_1.eir_prebinding import (
    CANDIDATE_EIR_SCHEMA_UNAVAILABLE,
    DS_SITE_ID,
    ENVIRONMENT,
    FIXED_TARGET_ROOT,
    OPEN_EVIDENCE_REQUIREMENTS,
    STRUCTURAL_ONLY_EVIDENCE_SCOPE,
    ZERO32,
    EIRPrebindingError,
    ValidatorState,
    backend_matcher_root,
    build_compiler_prebinding,
    candidate_eir_hash,
    compiler_prebinding_bytes,
    compiler_semantics_root,
    decode_compiler_prebinding,
    eir_canonical_cbor_decode,
    eir_canonical_cbor_encode,
    function_definition_digest,
    helper_id,
    helper_site_id,
    qtid_ascii_v1,
    target_site_id,
    toolchain_runtime_root,
    validate_backend_matcher_registry,
    validate_compiler_prebinding,
    validate_compiler_prebinding_bytes,
    validate_compiler_semantics_manifest,
    validate_external_terminal_registry,
    validate_helper_declaration_rows,
    validator_state,
    zero_authority_status,
)


TARGET_PROJECTION = """\
0|ActivateEffect2|void (State &)
1|ActivateEffectEachSelected|void (State &, int)
2|ActivateEffectForEach|void (State &, int)
3|ActivateEffectMultiple|void (State &, int)
4|ActivateSkillEffect|void (State &)
5|AfterAbility|void (State &)
6|AfterAttack|void (State &)
7|AfterAttack2|void (State &)
8|AfterAttack3|void (State &)
9|AfterAttack4|void (State &)
10|AfterAttackDamageChangeCoin|void (State &)
11|AfterAttackDamageChangeCoinUntilTail|void (State &)
12|AfterAttackDamageChangeTargetCountEnemyCoin|void (State &)
13|AfterAttackDamageCoin|void (State &, int)
14|AfterAttackTrigger|void (State &)
15|AfterBreakIfCoinHead|void (State &)
16|AfterBreakIfCoinTail|void (State &)
17|AfterBreakIfCoinTailMulti|void (State &, int)
18|AfterBurnProc|void (State &, int)
19|AfterDeckToTrashCoinUntilTail|void (State &)
20|AfterEffect|void (State &)
21|AfterPlay|void (State &)
22|AfterRefresh|void (State &)
23|AfterResetupActivePokemon|void (State &, int)
24|AfterRetreat|void (State &)
25|AfterSetupActivePokemon|void (State &)
26|AfterSkipIfCoinTail|void (State &)
27|AfterSleepProc|void (State &, int)
28|AfterTriggerAbility|void (State &, int)
29|AttackCoinProc|void (State &, int)
30|AttackCoinProc2|void (State &)
31|AttackDamage|void (State &)
32|AttackDamageCoin|void (State &, int)
33|AttackEffect|void (State &)
34|AttackEffects|void (State &, bool)
35|AttackNoDamageCoin|void (State &, int)
36|BothSetupActivePokemon|void (State &)
37|BurnProc|void (State &, int)
38|CoinLuckyBonus|void (State &, int)
39|CoinPrize|void (State &, int, int)
40|ConfuseProc|void (State &)
41|EffectAttackDamage|void (State &, int, int)
42|EffectAttackNoDamageCoin|void (State &, int, int)
43|EnemySelectedWhichEffect|void (State &)
44|KOProc|void (State &)
45|KOProc2|void (State &)
46|KOProc3|void (State &)
47|MainSelect|void (State &)
48|ParalyzeProc|void (State &)
49|PokemonCheckup|void (State &)
50|PokemonCheckupEnd|void (State &)
51|PreSetupActivePokemon|void (State &, int)
52|ResolveTriggerStack|void (State &, int)
53|SelectActivePokemon|void (State &, int)
54|SelectBenchMaxTrash|void (State &, int)
55|SelectCoinSingle|void (State &, int)
56|SelectDamageCounterAny|void (State &)
57|SelectDamageMulti|void (State &)
58|SelectedActivate|void (State &)
59|SelectedActivateAbility|void (State &)
60|SelectedAddDamageCounterSwitchAny|void (State &, int)
61|SelectedAttackDamageChangePutDamageCounter|void (State &)
62|SelectedAttackId|void (State &, int)
63|SelectedBenchMaxTrash|void (State &)
64|SelectedBurn|void (State &)
65|SelectedCardOrAttachedCard|void (State &)
66|SelectedCoinSingle|void (State &, int)
67|SelectedCoinUntilTail|void (State &, int)
68|SelectedDamageCounterAny|void (State &)
69|SelectedDamageMulti|void (State &)
70|SelectedDamageMultiAll|void (State &)
71|SelectedDisableAttack|void (State &, int)
72|SelectedDrawCount|void (State &, int)
73|SelectedEffectTarget|void (State &)
74|SelectedEnergyTarget|void (State &)
75|SelectedEvolveTarget|void (State &)
76|SelectedFirstEffect|void (State &)
77|SelectedIsFirst|void (State &)
78|SelectedLuckyBonus|void (State &, int)
79|SelectedMain|void (State &)
80|SelectedMoreDevolve|void (State &)
81|SelectedMulligan|void (State &, int)
82|SelectedPokemonEnergy|void (State &)
83|SelectedPokemonEnergyLoop|void (State &, int)
84|SelectedPrize|void (State &)
85|SelectedRecoverSpecialCondition|void (State &, int)
86|SelectedRemoveDamageCounter|void (State &)
87|SelectedRemoveDamageCounterSwitchAny|void (State &, int)
88|SelectedSecondAttack|void (State &)
89|SelectedSetupActivePokemon|void (State &, int)
90|SelectedSetupBenchPokemon|void (State &, int)
91|SelectedSkillOrder|void (State &, int)
92|SelectedSpecialCondition|void (State &)
93|SelectedSwitchPokemon|void (State &)
94|SelectedToolMaxTrash|void (State &)
95|SelectedToolTarget|void (State &)
96|SelectedWhichEffect|void (State &)
97|SelectLuckyBonus|void (State &, int)
98|SelectPokemonEnergyLoop|void (State &, int)
99|SelectPrize|void (State &, int, int, int)
100|SelectedRetreat2|void (State &)
101|SelectSwitchPokemon|void (State &, int, int)
102|SelectToolMaxTrash|void (State &, int, int)
103|SeparatorProc|void (State &)
104|SetupActivePokemon|void (State &, int)
105|SetupBenchPokemon|void (State &, int)
106|SetupGame|void (State &)
107|SleepProc|void (State &, int)
108|StartSetupBench|void (State &)
109|ToMain|void (State &)
110|ToolCountProc|void (State &)
111|TurnEnd2|void (State &)
112|TurnStart|void (State &)
113|ReservedFunction|void ()
114|ReservedFunction2|void ()
115|ReservedFunction3|void ()"""


def _error(code, function, *args, **kwargs):
    with pytest.raises(EIRPrebindingError) as raised:
        function(*args, **kwargs)
    assert raised.value.code == code


def _target_rows() -> list[list[object]]:
    rows = []
    for line in TARGET_PROJECTION.splitlines():
        index, name, raw_type = line.split("|", 2)
        rows.append([int(index), name, raw_type, qtid_ascii_v1(raw_type)])
    return rows


def _declaration(name: str) -> list[object]:
    return [
        "FunctionDecl",
        name,
        "unsigned int ()",
        "unsigned int()",
        1,
        ZERO32,
    ]


def _parts() -> dict[str, object]:
    source_root = sha256(b"opened source").digest()
    static_closure = sha256(b"static closure artifact").digest()
    compiler_path = "/v631302/toolchain/bin/clang"
    extractor_path = "/v631302/toolchain/bin/extractor"
    compiler_digest = sha256(b"compiler bytes").digest()
    extractor_digest = sha256(b"extractor bytes").digest()
    runtime = [
        1,
        compiler_path,
        extractor_path,
        ["linux-gnu", "amd64", 1, 64, 8],
        [
            [compiler_path, 1, 0o755, 14, compiler_digest, ""],
            [extractor_path, 1, 0o755, 15, extractor_digest, ""],
        ],
    ]
    runtime_root = toolchain_runtime_root(runtime)
    semantics = [
        2,
        runtime_root,
        source_root,
        "/v631302/work",
        "/v631302/src",
        "/v631302/toolchain",
        deepcopy(ENVIRONMENT),
        [
            1,
            0,
            0,
            0,
            0,
            [
                [1, compiler_path, compiler_digest],
                [2, extractor_path, extractor_digest],
            ],
        ],
        [
            [
                0,
                "/v631302/src/engine.cc",
                [compiler_path, "-c", "/v631302/src/engine.cc"],
                [extractor_path, "/v631302/src/engine.cc"],
            ]
        ],
    ]
    semantics_root = compiler_semantics_root(semantics)
    backend = [
        1,
        semantics_root,
        [
            [1, 1, 1, "CallExpr", _declaration("BackendA")],
            [2, 1, 1, "CXXMemberCallExpr", _declaration("BackendB")],
        ],
    ]
    backend_root = backend_matcher_root(backend)
    terminal_payloads = [
        [1, _declaration("BackendA"), 1],
        [1, _declaration("BackendB"), 2],
    ]
    terminal_payloads.sort(key=lambda item: canonical_cbor_encode(item[1]))
    terminals = [
        1,
        semantics_root,
        backend_root,
        [
            [ordinal, terminal_class, declaration, backend_code, 1, backend_root]
            for ordinal, (terminal_class, declaration, backend_code) in enumerate(terminal_payloads)
        ],
    ]
    targets = _target_rows()
    helper_identity = helper_id(
        source_root,
        1,
        ZERO32,
        "SelectCoinUntilTail",
        "void(State&,int)",
    )
    helper_digest = function_definition_digest(b"void SelectCoinUntilTail(State&, int) {}")
    helpers = [
        [
            0,
            helper_identity,
            "SelectCoinUntilTail",
            "void (State &, int)",
            "void(State&,int)",
            1,
            ZERO32,
            helper_digest,
            [0],
        ]
    ]
    scans = []
    for target in targets:
        invocations = []
        if target[0] == 0:
            invocations = [[0, [0], 0, 1, 1, 1, [[1, helper_identity]]]]
        scans.append(
            [
                0,
                [0, target[0]],
                function_definition_digest(f"target:{target[0]}".encode()),
                [0],
                sum(row[5] for row in invocations),
                invocations,
            ]
        )
    scans.append(
        [
            0,
            [1, helper_identity],
            helper_digest,
            [0],
            1,
            [[0, [1], 0, 1, 1, 1, [[2, 0]]]],
        ]
    )
    scans.sort(key=lambda row: canonical_cbor_encode(row[1]))
    for ordinal, scan in enumerate(scans):
        scan[0] = ordinal
    return {
        "source_root": source_root,
        "target_root": FIXED_TARGET_ROOT,
        "static_closure": static_closure,
        "runtime": runtime,
        "semantics": semantics,
        "backend": backend,
        "terminals": terminals,
        "targets": targets,
        "helpers": helpers,
        "scans": scans,
    }


def _build(parts: dict[str, object]) -> list[object]:
    return build_compiler_prebinding(
        parts["source_root"],
        parts["target_root"],
        parts["static_closure"],
        parts["runtime"],
        parts["semantics"],
        parts["backend"],
        parts["terminals"],
        parts["targets"],
        parts["helpers"],
        parts["scans"],
    )


def _scan(scans: list[list[object]], function_ref: list[object]) -> list[object]:
    return next(row for row in scans if row[1] == function_ref)


def test_qtid_vectors_and_target_55_vector_remain_exact() -> None:
    vectors = {
        "void (State &, int)": "void(State&,int)",
        "const std::vector< Foo * > &": "const std::vector<Foo*>&",
        "unsigned long int": "unsigned long int",
        "void () const noexcept": "void()const noexcept",
        "int [ 32 ]": "int[32]",
        "Alias :: Nested < const T * , 4 > &&": "Alias::Nested<const T*,4>&&",
    }
    for raw_type, identity in vectors.items():
        assert qtid_ascii_v1(raw_type) == identity
    _error("QUAL_TYPE_SPLIT_PUNCTUATOR", qtid_ascii_v1, "A - > B")
    _error("QUAL_TYPE_NON_ASCII", qtid_ascii_v1, "café")
    _error("QUAL_TYPE_INVALID_COMMA", qtid_ascii_v1, "int, int")

    assert target_site_id(
        FIXED_TARGET_ROOT,
        55,
        "SelectCoinSingle",
        "void(State&,int)",
        0,
    ).hex() == "45ece5458816d604cc9048eb59b11dceb9a1bfbc4a0ecb3dd1948af057a1f9ad"
    assert sha256(
        DS_SITE_ID
        + canonical_cbor_encode(
            [FIXED_TARGET_ROOT, 55, "SelectCoinSingle", "void (State &, int)", 0]
        )
    ).hexdigest() == "dcef8a4f6fedf3836097939c334f40759c0ce950b0fe839204f0c98a42f0d122"


def test_helper_site_kdf_remains_domain_separated_and_ordinal_bound() -> None:
    identity = helper_id(
        sha256(b"source").digest(),
        1,
        ZERO32,
        "SelectCoinUntilTail",
        "void(State&,int)",
    )
    assert helper_site_id(identity, 0) == helper_site_id(identity, 0)
    assert helper_site_id(identity, 0) != helper_site_id(identity, 1)
    assert helper_site_id(identity, 0) != target_site_id(
        FIXED_TARGET_ROOT,
        55,
        "SelectCoinSingle",
        "void(State&,int)",
        0,
    )


def test_v2_golden_component_and_prebinding_roots() -> None:
    artifact = _build(_parts())
    assert len(artifact) == 14
    assert artifact[:2] == [631302, 2]
    assert [root.hex() for root in artifact[12]] == [
        "94d86291bf43f6e6db7fc256b2fd41c2a07323c3e365e1fe4cdba9b0b22e5db5",
        "12c7fc7feacfbccc577da6c9ee78c1ce3c830462ba8bddffd9e703ecda216e93",
        "8f8e27bc6234c3e99ddd46a675a0bbee8504c90b44e1bfb25ee2c0c33dedba2c",
        "5cb6e7982e1a7572f870f9aedc1bb2c75de746129cefc8a55ff3f1ca85cdeef9",
        "391d868115f14943253254aaa7a3131800ca89fac22a41f9611c26b5111bef81",
        "9f85ce0871fa1cdcf0c67843ec56f46ccca8a81e8de16a5723abc6fa2d5f9ee3",
        "b00fca41ce2bb0e68023b5ad533c651b20396bd837e80d9608c73cf054ccbafc",
        "a172c651f9a46f28cab16b3eca79d532de115641a6ef69973ab50457c409bae2",
        "6922bd4e20819b1c6b01e31f989d7d950c4769d95972eef0fe7251062dd7ad69",
        "d57984c4887a73fb3fc6177313efae19d6842cfbc3033ea9c750b8f086228dbd",
    ]
    assert artifact[13].hex() == "8c039fe248bed39aa355c578c372c1896229d2bf462bb9ba860c4c7dd305d578"

    result = validate_compiler_prebinding(artifact)
    assert result.state is ValidatorState.STRUCTURAL_CLOSURE_VALID
    assert result.prebinding_root == artifact[13]
    encoded = compiler_prebinding_bytes(
        *_parts().values()
    )
    assert validate_compiler_prebinding_bytes(encoded).prebinding_root == artifact[13]


def test_v1_is_rejected_without_compatibility_path() -> None:
    _error("PREBINDING_SCHEMA_INVALID", validate_compiler_prebinding, [631302, 1, [], [], [], [], []])
    _error(
        "PREBINDING_INVALID_TYPE",
        decode_compiler_prebinding,
        canonical_cbor_encode({"not": "an array-only wire value"}),
    )


def test_prebinding_binds_exact_utf8_without_unicode_normalization() -> None:
    decomposed = "Cafe\u0301"
    composed = "Caf\u00e9"
    decomposed_parts = _parts()
    composed_parts = _parts()
    decomposed_parts["runtime"][3][0] = decomposed
    composed_parts["runtime"][3][0] = composed

    def rebind(parts: dict[str, object]) -> bytes:
        runtime_root = toolchain_runtime_root(parts["runtime"])
        parts["semantics"][1] = runtime_root
        semantics_root = compiler_semantics_root(parts["semantics"])
        parts["backend"][1] = semantics_root
        backend_root = backend_matcher_root(parts["backend"])
        parts["terminals"][1] = semantics_root
        parts["terminals"][2] = backend_root
        for terminal in parts["terminals"][3]:
            terminal[5] = backend_root
        encoded = compiler_prebinding_bytes(*parts.values())
        assert decode_compiler_prebinding(encoded)[5][3][0] == parts["runtime"][3][0]
        return encoded

    decomposed_bytes = rebind(decomposed_parts)
    composed_bytes = rebind(composed_parts)
    assert decomposed_bytes != composed_bytes


def test_public_eir_cbor_decoder_preserves_exact_decomposed_utf8() -> None:
    decomposed = "Cafe\u0301"
    encoded = eir_canonical_cbor_encode([decomposed, [b"\x00", 7]])

    decoded = eir_canonical_cbor_decode(encoded)

    assert decoded == [decomposed, [b"\x00", 7]]
    assert decoded[0].encode("utf-8") == decomposed.encode("utf-8")
    assert eir_canonical_cbor_encode(decoded) == encoded
    assert eir_canonical_cbor_encode(["Caf\u00e9"]) != eir_canonical_cbor_encode([decomposed])


def test_public_eir_cbor_decoder_rejects_trailing_stdout() -> None:
    _error(
        "PREBINDING_CANONICAL_ENCODING",
        eir_canonical_cbor_decode,
        eir_canonical_cbor_encode([]) + b"\x00",
    )


@pytest.mark.parametrize(
    "raw,code",
    [
        (b"\x18\x01", "PREBINDING_CANONICAL_ENCODING"),
        (b"\x00", "PREBINDING_INVALID_TYPE"),
        (b"\x40", "PREBINDING_INVALID_TYPE"),
        (b"\x60", "PREBINDING_INVALID_TYPE"),
        (b"\xa0", "PREBINDING_INVALID_TYPE"),
        (b"\xc0", "PREBINDING_INVALID_TYPE"),
        (b"\xf4", "PREBINDING_INVALID_TYPE"),
    ],
)
def test_public_eir_cbor_decoder_rejects_non_arrays_only_wire_forms(raw: bytes, code: str) -> None:
    _error(code, eir_canonical_cbor_decode, raw)


@pytest.mark.parametrize(
    "raw",
    [
        b"\x18\x01",  # non-short uint(1)
        b"\x20",  # negative integer
        b"\xa0",  # map
        b"\xf4",  # simple false
        b"\xf6",  # null
        b"\x9f\xff",  # indefinite array
        b"\x80\x00",  # canonical empty array plus trailing bytes
    ],
)
def test_wire_profile_rejects_noncanonical_or_forbidden_cbor(raw: bytes) -> None:
    with pytest.raises(EIRPrebindingError):
        decode_compiler_prebinding(raw)


@pytest.mark.parametrize("field", ["source", "static", "runtime", "backend", "target", "scan", "component", "final"])
def test_single_field_mutations_fail_closed(field: str) -> None:
    artifact = _build(_parts())
    mutated = deepcopy(artifact)
    if field == "source":
        mutated[2] = sha256(b"changed source").digest()
    elif field == "static":
        mutated[4] = sha256(b"changed closure").digest()
    elif field == "runtime":
        mutated[5][4][0][4] = sha256(b"changed compiler").digest()
    elif field == "backend":
        mutated[7][2][0][3] = "CXXOperatorCallExpr"
    elif field == "target":
        mutated[9][55][1] = "ChangedTarget"
    elif field == "scan":
        mutated[11][0][2] = sha256(b"changed definition").digest()
    elif field == "component":
        mutated[12][8] = sha256(b"changed scan root").digest()
    else:
        mutated[13] = sha256(b"changed prebinding root").digest()
    with pytest.raises(EIRPrebindingError):
        validate_compiler_prebinding(mutated)


def test_helper_closure_rejects_unreachable_missing_and_unknown_nodes() -> None:
    parts = _parts()
    target_zero = _scan(parts["scans"], [0, 0])
    target_zero[4] = 0
    target_zero[5] = []
    _error("GRAPH_CLOSURE_INVALID", _build, parts)

    parts = _parts()
    parts["scans"].pop()
    _error("FUNCTION_SCAN_INVALID", _build, parts)

    parts = _parts()
    helper_identity = parts["helpers"][0][1]
    helper_scan = _scan(parts["scans"], [1, helper_identity])
    helper_scan[5][0][6] = [[2, 99]]
    _error("GRAPH_CLOSURE_INVALID", _build, parts)

    parts = _parts()
    helper_identity = parts["helpers"][0][1]
    helper_scan = _scan(parts["scans"], [1, helper_identity])
    helper_scan[5][0][4] = 2
    _error("UNRESOLVED_REACHABLE_CALL", _build, parts)


def test_scan_grouping_dense_slots_and_counts_fail_closed() -> None:
    parts = _parts()
    target_zero = _scan(parts["scans"], [0, 0])
    target_zero[5][0][2] = 1
    _error("PREBINDING_DENSE_ORDINAL_INVALID", _build, parts)

    parts = _parts()
    target_zero = _scan(parts["scans"], [0, 0])
    target_zero[4] = 2
    _error("FUNCTION_SCAN_INVALID", _build, parts)

    parts = _parts()
    target_zero = _scan(parts["scans"], [0, 0])
    target_zero[5][0][0] = 1
    _error("PREBINDING_DENSE_ORDINAL_INVALID", _build, parts)

    parts = _parts()
    target_zero = _scan(parts["scans"], [0, 0])
    duplicate_group = deepcopy(target_zero[5][0])
    duplicate_group[0] = 1
    duplicate_group[2] = 1
    target_zero[4] = 2
    target_zero[5].append(duplicate_group)
    _error("PREBINDING_ORDER_INVALID", _build, parts)


def test_backend_and_terminal_coherence_is_exact() -> None:
    parts = _parts()
    parts["backend"][2][0][0] = 2
    _error("BACKEND_REGISTRY_INVALID", validate_backend_matcher_registry, parts["backend"])

    parts = _parts()
    parts["backend"][2].append([3, 1, 1, "CallExpr", _declaration("BackendC")])
    _error("BACKEND_REGISTRY_INVALID", validate_backend_matcher_registry, parts["backend"])

    parts = _parts()
    parts["terminals"][3][0][5] = sha256(b"wrong evidence").digest()
    _error(
        "TERMINAL_COHERENCE_INVALID",
        validate_external_terminal_registry,
        parts["terminals"],
        backend_registry=parts["backend"],
        expected_compiler_semantics_root=parts["backend"][1],
        expected_backend_matcher_root=parts["terminals"][2],
        expected_toolchain_runtime_root=parts["runtime"] and parts["semantics"][1],
    )

    parts = _parts()
    parts["terminals"][3] = []
    _error("TERMINAL_COHERENCE_INVALID", validate_external_terminal_registry, parts["terminals"])

    parts = _parts()
    parts["terminals"][3][0][2] = _declaration("DifferentBackend")
    _error("PREBINDING_ORDER_INVALID", _build, parts)

    parts = _parts()
    parts["terminals"][3][0][2] = _declaration("Backend0")
    _error("TERMINAL_COHERENCE_INVALID", _build, parts)


@pytest.mark.parametrize(
    ("argument", "code"),
    [
        ("@args.rsp", "RESPONSE_FILE_SYNTAX_FORBIDDEN"),
        ("-DVALUE=@args", "RESPONSE_FILE_SYNTAX_FORBIDDEN"),
        ("--config", "COMPILER_CONFIG_FILE_FORBIDDEN"),
        ("--config=clang.cfg", "COMPILER_CONFIG_FILE_FORBIDDEN"),
        ("--configuration=clang.cfg", "COMPILER_CONFIG_FILE_FORBIDDEN"),
        ("--config-system-dir=/tmp", "COMPILER_CONFIG_FILE_FORBIDDEN"),
        ("--config-user-dir=/tmp", "COMPILER_CONFIG_FILE_FORBIDDEN"),
        ("-", "STDIN_INPUT_FORBIDDEN"),
    ],
)
def test_forbidden_argv_forms(argument: str, code: str) -> None:
    parts = _parts()
    parts["semantics"][8][0][2].append(argument)
    _error(
        code,
        validate_compiler_semantics_manifest,
        parts["semantics"],
        runtime_manifest=parts["runtime"],
        expected_source_root=parts["source_root"],
    )


def test_execution_policy_and_argv0_fail_closed() -> None:
    parts = _parts()
    parts["semantics"][7][1] = 1
    _error("PREBINDING_SCHEMA_INVALID", _build, parts)

    parts = _parts()
    parts["semantics"][8][0][2][0] = "/bin/sh"
    _error("UNLISTED_EXECUTABLE", _build, parts)

    parts = _parts()
    parts["semantics"][7][5].append([3, "/bin/sh", sha256(b"sh").digest()])
    _error("PREBINDING_SCHEMA_INVALID", _build, parts)


def test_helper_declaration_id_scope_tu_and_definition_rules() -> None:
    parts = _parts()
    parts["helpers"][0][1] = sha256(b"wrong helper").digest()
    _error("HELPER_ID_MISMATCH", _build, parts)

    parts = _parts()
    parts["helpers"][0][6] = sha256(b"nonzero scope").digest()
    _error("HELPER_SCOPE_INVALID", _build, parts)

    parts = _parts()
    parts["helpers"][0][8] = [1]
    _error("PREBINDING_SCHEMA_INVALID", _build, parts)

    _error(
        "NON_CONTIGUOUS_DEFINITION_BYTES",
        function_definition_digest,
        b"macro definition",
        contiguous=False,
    )


def test_helper_normalized_identity_cannot_hide_different_raw_types() -> None:
    parts = _parts()
    first = parts["helpers"][0]
    second = deepcopy(first)
    second[0] = 1
    second[3] = "void(State &,int)"
    second[5] = 2
    second[6] = sha256(b"tu-local scope").digest()
    second[1] = helper_id(
        parts["source_root"],
        second[5],
        second[6],
        second[2],
        second[4],
    )
    parts["helpers"] = sorted([first, second], key=lambda row: row[1])
    for ordinal, helper in enumerate(parts["helpers"]):
        helper[0] = ordinal
    _error(
        "HELPER_DECLARATION_INVALID",
        validate_helper_declaration_rows,
        parts["helpers"],
        source_root=parts["source_root"],
        target_seed_rows=parts["targets"],
        valid_tu_ordinals={0},
    )


def test_state_lattice_is_monotonic_and_never_authorizing() -> None:
    assert validator_state(
        byte_valid=True,
        structural_closure_valid=False,
        compiler_recomputed=False,
        external_evidence_valid=False,
    ) is ValidatorState.BYTE_VALID
    _error(
        "VALIDATOR_EVIDENCE_UNAVAILABLE",
        validator_state,
        byte_valid=True,
        structural_closure_valid=True,
        compiler_recomputed=False,
        external_evidence_valid=False,
    )
    _error(
        "VALIDATOR_EVIDENCE_UNAVAILABLE",
        validator_state,
        byte_valid=True,
        structural_closure_valid=True,
        compiler_recomputed=True,
        external_evidence_valid=True,
    )
    _error(
        "VALIDATOR_STATE_NON_MONOTONIC",
        validator_state,
        byte_valid=True,
        structural_closure_valid=False,
        compiler_recomputed=True,
        external_evidence_valid=False,
    )

    validation = validate_compiler_prebinding(_build(_parts()))
    assert validation.state is ValidatorState.STRUCTURAL_CLOSURE_VALID
    assert validation.evidence_scope == STRUCTURAL_ONLY_EVIDENCE_SCOPE
    assert validation.open_evidence_requirements == OPEN_EVIDENCE_REQUIREMENTS
    assert not validation.compiler_recomputed
    assert not validation.external_evidence_valid
    assert not any(
        (
            validation.authority,
            validation.engine_wiring_authority,
            validation.upload_authority,
            validation.permit_authority,
            validation.holdout_access_authority,
            validation.agent_modification_authority,
        )
    )
    status = zero_authority_status()
    assert status["state"] == "ZERO_AUTHORITY"
    assert not any(value for key, value in status.items() if key != "state")


def test_candidate_eir_hash_fails_until_v2_roots_have_a_reviewed_mapping() -> None:
    binding = [631302, 2, 1] + [sha256(f"root:{index}".encode()).digest() for index in range(12)]
    _error(CANDIDATE_EIR_SCHEMA_UNAVAILABLE, candidate_eir_hash, binding)
