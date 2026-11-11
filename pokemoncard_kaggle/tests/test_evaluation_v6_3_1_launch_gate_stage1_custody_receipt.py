from __future__ import annotations

from copy import deepcopy
from hashlib import sha256

import pytest

from evaluation_v6_3_1.canonical_trace_codec import canonical_cbor_decode, canonical_cbor_encode
from evaluation_v6_3_1.launch_gate_stage1_custody_receipt import (
    BODY_FIELD_COUNT,
    BODY_FIELD_NAMES,
    DOMAIN_PREFIX,
    EMPTY_BLOB_SHA256,
    EXTRACTION_ARGV,
    EXTRACTION_ENVP,
    IMAGE_ID_SHA256,
    PAGE_SHA256,
    RAW_OBJECT_SHA256,
    Stage1CustodyReceiptError,
    consume_stage1_extraction_custody_receipt,
    diagnostic_encode_fixture_receipt,
    recompute_stage1_extraction_custody_root,
)


def _object(*, inode: int, size: int, mode: int = 0o100444) -> list[int]:
    return [1, 8, 1, inode, mode, 1000, 1000, 1, size]


def _file(*, inode: int, size: int, digest: bytes, mode: int = 0o100444) -> list[object]:
    return [_object(inode=inode, size=size, mode=mode), digest]


def _directory(*, inode: int) -> list[object]:
    return [_object(inode=inode, size=4096, mode=0o040700), 0x794C7630, 11, 22, 0]


def _mount(*, mount_class: int, mount_id: int) -> list[object]:
    if mount_class == 1:
        return [
            mount_class,
            mount_id,
            0,
            8,
            1,
            b"/",
            b"/",
            [b"relatime", b"rw"],
            [],
            b"overlay",
            b"overlay",
            [b"lowerdir=/lower", b"rw", b"upperdir=/upper", b"workdir=/work"],
            0x794C7630,
            11,
            22,
            0,
            b"1 0 8:1 / / rw,relatime - overlay overlay rw,lowerdir=/lower,upperdir=/upper,workdir=/work",
        ]
    return [
        mount_class,
        mount_id,
        1,
        0,
        42,
        b"/",
        b"/proc",
        [b"rw"],
        [],
        b"proc",
        b"proc",
        [b"rw"],
        0x9FA0,
        33,
        44,
        0,
        b"2 1 0:42 / /proc rw - proc proc rw",
    ]


def _root_custody(*, root_inode: int = 100) -> list[object]:
    return [
        _mount(mount_class=1, mount_id=1),
        _object(inode=root_inode, size=4096, mode=0o040755),
    ]


def _cwd(*, inode: int) -> list[int]:
    return [1, 8, 1, inode]


def _census(*, include_child: bool, child_starttime: int = 200) -> list[object]:
    rows: list[object] = [[1, 100, [[1, _cwd(inode=100)]]]]
    if include_child:
        rows.append([2, child_starttime, [[2, _cwd(inode=200)]]])
    return rows


def _body() -> list[object]:
    raw = _file(inode=300, size=8688, digest=RAW_OBJECT_SHA256)
    page = _file(inode=301, size=4096, digest=PAGE_SHA256)
    return [
        IMAGE_ID_SHA256,
        _file(inode=302, size=12345, digest=b"c" * 32, mode=0o100555),
        [9, 10, 11],
        [12, 13, 14],
        _root_custody(),
        _mount(mount_class=2, mount_id=2),
        _directory(inode=200),
        raw,
        _file(inode=303, size=12, digest=b"e" * 32, mode=0o100555),
        _file(inode=304, size=12, digest=b"o" * 32, mode=0o100555),
        list(EXTRACTION_ARGV),
        list(EXTRACTION_ENVP),
        [
            0xC000003E,
            0x40000000,
            0x80000000,
            0x7FFF0000,
            [56, 57, 58, 80, 81, 155, 165, 166, 272, 308, 428, 429, 430, 431, 432, 433, 435, 442],
            b"s" * 32,
        ],
        _census(include_child=False),
        _census(include_child=False),
        2,
        200,
        [1, 2],
        _census(include_child=True),
        _census(include_child=True),
        [1, 0],
        _root_custody(),
        _mount(mount_class=2, mount_id=2),
        _directory(inode=200),
        raw,
        page,
        [
            [b"LaunchGateV1.o", raw],
            [b"LaunchGateV1.page", page],
        ],
        [0, EMPTY_BLOB_SHA256],
        [0, EMPTY_BLOB_SHA256],
        [_census(include_child=False), _census(include_child=False)],
        [1000, 1000],
    ]


def _receipt(body: list[object] | tuple[object, ...] | None = None) -> bytes:
    return diagnostic_encode_fixture_receipt(_body() if body is None else body)


def _unvalidated_receipt(body: list[object]) -> bytes:
    root = sha256(DOMAIN_PREFIX + canonical_cbor_encode(body)).digest()
    return canonical_cbor_encode([631302, 2, body, root])


def test_valid_fixture_is_immutable_and_zero_authority() -> None:
    raw = _receipt()
    result = consume_stage1_extraction_custody_receipt(raw)

    assert result.zero_authority is True
    assert result.authority is False
    assert result.calibration_upload_authorized is False
    assert result.production_upload_authorized is False
    assert result.holdout_access_authorized is False
    assert result.agent_modification_authorized is False
    assert result.permit_authority is False
    assert result.custodian_profile_frozen is False
    assert result.seccomp_bpf_profile_frozen is False
    assert result.tool_ownership_profiles_frozen is False
    assert result.receipt_v1_retired_invalid is True
    assert result.stage1_closure is False
    assert result.state == "NO_UPLOAD"
    assert BODY_FIELD_COUNT == len(BODY_FIELD_NAMES) == len(result.body)
    assert type(result.body) is tuple
    assert result.canonical_body == canonical_cbor_encode(result.body)
    with pytest.raises(AttributeError):
        result.root = b"x" * 32  # type: ignore[misc]


@pytest.mark.parametrize(
    ("name", "mutate"),
    [
        ("image", lambda b: b.__setitem__(0, b"x" * 32)),
        ("custodian", lambda b: b[1].__setitem__(1, b"x" * 31)),
        ("pid_namespace", lambda b: b[2].__setitem__(0, -1)),
        ("mount_namespace", lambda b: b[3].__setitem__(1, "text")),
        ("root_mount_class", lambda b: b[4][0].__setitem__(0, 99)),
        ("mount_options", lambda b: b[4][0].__setitem__(7, [b"ro"])),
        ("mount_raw_line", lambda b: b[4][0].__setitem__(16, b"1 0 8:1 / / ro - overlay overlay ro")),
        ("root_super_options", lambda b: b[4][0].__setitem__(11, [b"rw"])),
        ("root_object_inode", lambda b: b[4][1].__setitem__(3, 999)),
        ("root_object_type", lambda b: b[4][1].__setitem__(4, 0o100755)),
        ("proc_profile", lambda b: b[5].__setitem__(9, b"tmpfs")),
        ("directory", lambda b: b[6][0].__setitem__(3, 999)),
        ("directory_mode", lambda b: b[6][0].__setitem__(4, 0o040755)),
        ("directory_mount", lambda b: b[6][0].__setitem__(0, 99)),
        ("raw_object_hash", lambda b: b[7].__setitem__(1, b"x" * 32)),
        ("raw_object_mode", lambda b: b[7][0].__setitem__(4, 0o100644)),
        ("raw_object_owner", lambda b: b[7][0].__setitem__(5, 1001)),
        ("env_executable", lambda b: b.__setitem__(8, {"not": "an array"})),
        ("objcopy_executable", lambda b: b[9].__setitem__(0, [])),
        ("argv", lambda b: b[10].__setitem__(0, b"/wrong")),
        ("envp", lambda b: b[11].append(b"EXTRA=1")),
        ("seccomp", lambda b: b[12][4].__setitem__(0, 59)),
        ("census_pid_order", lambda b: b[13][0].__setitem__(0, 0)),
        ("child_pid", lambda b: b.__setitem__(15, 3)),
        ("child_starttime", lambda b: b.__setitem__(16, 201)),
        ("child_security", lambda b: b[17].__setitem__(0, 0)),
        ("barrier_census", lambda b: b[18][1].__setitem__(0, 3)),
        ("wait_result", lambda b: b[20].__setitem__(1, 1)),
        ("post_mount", lambda b: b[21][0].__setitem__(1, 3)),
        ("post_directory", lambda b: b[23][0].__setitem__(3, 201)),
        ("post_raw_object", lambda b: b[24].__setitem__(1, b"x" * 32)),
        ("page", lambda b: b[25].__setitem__(1, b"x" * 32)),
        ("page_mode", lambda b: b[25][0].__setitem__(4, 0o100644)),
        ("page_owner", lambda b: b[25][0].__setitem__(6, 1001)),
        ("final_listing_order", lambda b: b[26].reverse()),
        ("stdout_digest", lambda b: b[27].__setitem__(1, b"x" * 32)),
        ("stdout_nonempty", lambda b: b.__setitem__(27, [1, b"x" * 32])),
        ("pid1_cwd_changed", lambda b: b[18][0][2][0][1].__setitem__(3, 999)),
        ("post_census_pair", lambda b: b[29][1].append([3, 300, [[3, _cwd(inode=300)]]])),
        ("build_principal_shape", lambda b: b.__setitem__(30, [1000])),
        ("build_principal_owner", lambda b: b[30].__setitem__(0, 1001)),
    ],
)
def test_each_structural_category_fails_closed(name: str, mutate) -> None:
    body = deepcopy(_body())
    mutate(body)
    with pytest.raises(Stage1CustodyReceiptError):
        consume_stage1_extraction_custody_receipt(_unvalidated_receipt(body))


def test_root_domain_and_wrapper_are_exact() -> None:
    body = _body()
    raw = _receipt(body)
    result = consume_stage1_extraction_custody_receipt(raw)
    assert result.root == recompute_stage1_extraction_custody_root(result.body)
    assert DOMAIN_PREFIX == b"V631302_STAGE1_EXTRACTION_CUSTODY_RECEIPT_V2\x00"
    assert canonical_cbor_decode(raw)[1] == 2

    decoded = list(canonical_cbor_decode(raw))
    decoded[3] = b"x" * 32
    with pytest.raises(Stage1CustodyReceiptError, match="RECEIPT_ROOT_MISMATCH"):
        consume_stage1_extraction_custody_receipt(canonical_cbor_encode(decoded))


def test_retired_v1_receipt_is_rejection_only() -> None:
    body_v1 = _body()[:-1]
    root_v1 = sha256(
        b"V631302_STAGE1_EXTRACTION_CUSTODY_RECEIPT_V1\x00"
        + canonical_cbor_encode(body_v1)
    ).digest()
    raw_v1 = canonical_cbor_encode([631302, 1, body_v1, root_v1])
    with pytest.raises(Stage1CustodyReceiptError, match="RECEIPT_WRAPPER_VERSION"):
        consume_stage1_extraction_custody_receipt(raw_v1)


def test_pid1_same_mount_wrong_inode_is_rejected() -> None:
    body = deepcopy(_body())
    for index in (13, 14, 18, 19):
        body[index][0][2][0][1][3] = 999
    for census in body[29]:
        census[0][2][0][1][3] = 999
    with pytest.raises(Stage1CustodyReceiptError, match="RECEIPT_CENSUS_CWD"):
        consume_stage1_extraction_custody_receipt(_unvalidated_receipt(body))


def test_pid2_same_mount_wrong_inode_is_rejected() -> None:
    body = deepcopy(_body())
    body[18][1][2][0][1][3] = 999
    body[19][1][2][0][1][3] = 999
    with pytest.raises(Stage1CustodyReceiptError, match="RECEIPT_CENSUS_CWD"):
        consume_stage1_extraction_custody_receipt(_unvalidated_receipt(body))


def test_extraction_directory_size_may_change_but_stable_identity_may_not() -> None:
    body = deepcopy(_body())
    body[23][0][8] = 8192
    result = consume_stage1_extraction_custody_receipt(_unvalidated_receipt(body))
    assert result.body[6][0][8] == 4096
    assert result.body[23][0][8] == 8192


def test_root_and_extraction_object_alias_is_rejected() -> None:
    body = deepcopy(_body())
    extraction_key = body[6][0][:4]
    body[4][1][:4] = extraction_key
    body[21][1][:4] = extraction_key
    for index in (13, 14, 18, 19):
        body[index][0][2][0][1] = list(extraction_key)
    for census in body[29]:
        census[0][2][0][1] = list(extraction_key)
    with pytest.raises(Stage1CustodyReceiptError, match="RECEIPT_ROOT_EXTRACTION_ALIAS"):
        consume_stage1_extraction_custody_receipt(_unvalidated_receipt(body))


def test_setuid_tool_and_raw_page_alias_are_rejected() -> None:
    setuid_body = deepcopy(_body())
    setuid_body[1][0][4] = 0o104555
    with pytest.raises(Stage1CustodyReceiptError, match="RECEIPT_FILE_PRIVILEGED_MODE"):
        consume_stage1_extraction_custody_receipt(_unvalidated_receipt(setuid_body))

    alias_body = deepcopy(_body())
    alias_body[25][0][:4] = alias_body[24][0][:4]
    alias_body[26][1][1][0][:4] = alias_body[24][0][:4]
    with pytest.raises(Stage1CustodyReceiptError, match="RECEIPT_RAW_PAGE_ALIAS"):
        consume_stage1_extraction_custody_receipt(_unvalidated_receipt(alias_body))


def test_extraction_owner_and_each_privileged_tool_mode_are_rejected() -> None:
    owner_body = deepcopy(_body())
    owner_body[6][0][5] = 1001
    owner_body[23][0][5] = 1001
    with pytest.raises(Stage1CustodyReceiptError, match="RECEIPT_DIRECTORY_OWNERSHIP"):
        consume_stage1_extraction_custody_receipt(_unvalidated_receipt(owner_body))

    for field, mode in ((1, 0o104555), (8, 0o102555), (9, 0o104555)):
        privileged_body = deepcopy(_body())
        privileged_body[field][0][4] = mode
        with pytest.raises(Stage1CustodyReceiptError, match="RECEIPT_FILE_PRIVILEGED_MODE"):
            consume_stage1_extraction_custody_receipt(_unvalidated_receipt(privileged_body))


@pytest.mark.parametrize(
    ("left", "right"),
    [
        (1, 8),
        (8, 9),
        (1, 6),
        (1, 24),
        (8, 25),
    ],
)
def test_tool_and_mutable_artifact_object_aliases_are_rejected(left: int, right: int) -> None:
    body = deepcopy(_body())
    right_object = body[right][0]
    body[left][0][:4] = right_object[:4]
    with pytest.raises(Stage1CustodyReceiptError, match="RECEIPT_OBJECT_ALIAS"):
        consume_stage1_extraction_custody_receipt(_unvalidated_receipt(body))


@pytest.mark.parametrize(
    "raw",
    [
        lambda: _receipt() + b"\x00",
        lambda: canonical_cbor_encode([631302, 2, _body(), b"x" * 32]) + b"newline",
        lambda: canonical_cbor_encode({1: 2}),
        lambda: canonical_cbor_encode([631302, 2, _body(), b"x" * 32, 0]),
    ],
)
def test_trailing_multiple_and_non_array_values_fail(raw) -> None:
    with pytest.raises(Stage1CustodyReceiptError):
        consume_stage1_extraction_custody_receipt(raw())
