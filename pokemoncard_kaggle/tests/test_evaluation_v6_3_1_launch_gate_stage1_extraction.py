from __future__ import annotations

import json
import hashlib
import os
import subprocess
from pathlib import Path

import pytest
import evaluation_v6_3_1.launch_gate_stage1_extraction as extraction

from evaluation_v6_3_1.launch_gate_stage1_extraction import (
    AUTHORITY,
    AUTHORITATIVE_EXTRACTION_CONTROLLER_AVAILABLE,
    CALIBRATION_UPLOAD_AUTHORITY,
    CUSTODY_CONTROLLER_PROFILE_STATE,
    GATE_DISCARD_NAME,
    GATE_EXTRACTION_DIRECTORY,
    GATE_OBJECT_NAME,
    GATE_OBJECT_SHA256,
    GATE_OBJECT_SIZE,
    GATE_PAGE_NAME,
    GATE_PAGE_SHA256,
    GATE_PAGE_SIZE,
    GATE_PAGE_TMP_NAME,
    LaunchGateExtractionError,
    PRODUCTION_UPLOAD_AUTHORITY,
    STAGE1_EXTRACTION_CUSTODY_STATE,
    TOOLCHAIN_FREEZE_AUTHORITY,
    TOOLCHAIN_STATE,
    ZERO_AUTHORITY,
    diagnostic_extract_launch_gate_page_v1,
    extract_launch_gate_page_v1,
    gate_extraction_argv_v1,
    validate_launch_gate_extraction_v1,
)


REPOSITORY = Path(__file__).resolve().parents[1]
IMAGE_ID = "sha256:38634214ff91fc0007016cdf04d9f05d9289880fe8d30c4d66b0c284095460dd"
HISTORICAL_REWRITTEN_OBJECT_SHA256 = bytes.fromhex(
    "03415b9a358835c76fe310017486bdc0e1ecb430945858583c2ada1398448e9c"
)


def test_frozen_gnu_extraction_argv_and_authority() -> None:
    assert gate_extraction_argv_v1() == (
        "/usr/bin/env",
        "-i",
        "PATH=/usr/bin:/bin",
        "LC_ALL=C",
        "LANG=C",
        "TZ=UTC",
        "SOURCE_DATE_EPOCH=0",
        "HOME=/nonexistent",
        "DEBUGINFOD_URLS=",
        "/usr/bin/objcopy",
        "--input-target=elf64-x86-64",
        "--output-target=elf64-x86-64",
        "--dump-section",
        ".text.launch_gate_v1=LaunchGateV1.page.tmp",
        "LaunchGateV1.o",
        "LaunchGateV1.objcopy-discard.o",
    )
    assert ZERO_AUTHORITY is True
    assert AUTHORITY is False
    assert CALIBRATION_UPLOAD_AUTHORITY is False
    assert PRODUCTION_UPLOAD_AUTHORITY is False
    assert TOOLCHAIN_FREEZE_AUTHORITY is False
    assert TOOLCHAIN_STATE == "DO_NOT_FREEZE_TOOLCHAIN"
    assert CUSTODY_CONTROLLER_PROFILE_STATE == "DO_NOT_FREEZE_CUSTODY_CONTROLLER"
    assert STAGE1_EXTRACTION_CUSTODY_STATE == "OPEN"
    assert AUTHORITATIVE_EXTRACTION_CONTROLLER_AVAILABLE is False
    assert GATE_EXTRACTION_DIRECTORY == Path("/work/stage1/gate-extract")
    assert GATE_OBJECT_NAME == "LaunchGateV1.o"
    assert GATE_PAGE_NAME == "LaunchGateV1.page"
    assert GATE_PAGE_TMP_NAME == "LaunchGateV1.page.tmp"
    assert GATE_DISCARD_NAME == "LaunchGateV1.objcopy-discard.o"
    assert GATE_OBJECT_SIZE == 8688
    assert GATE_PAGE_SIZE == 4096
    assert GATE_OBJECT_SHA256.hex() == (
        "c20ea3a183f40c61ca3396771fb92cb948cc603b81e966486996f48bab84a530"
    )
    assert HISTORICAL_REWRITTEN_OBJECT_SHA256.hex() == (
        "03415b9a358835c76fe310017486bdc0e1ecb430945858583c2ada1398448e9c"
    )
    assert GATE_OBJECT_SHA256 != HISTORICAL_REWRITTEN_OBJECT_SHA256


def test_extraction_validation_requires_immutable_bytes() -> None:
    result = validate_launch_gate_extraction_v1(bytearray(), b"")  # type: ignore[arg-type]

    assert not result.valid
    assert result.issues[0].code == "GATE_EXTRACTION_BYTES_REQUIRED"
    assert not result.authority


def test_execution_rejects_noncanonical_path_before_launch(tmp_path: Path) -> None:
    with pytest.raises(LaunchGateExtractionError) as caught:
        diagnostic_extract_launch_gate_page_v1(tmp_path)

    assert caught.value.code == "GATE_EXTRACTION_DIRECTORY_PATH_INVALID"


@pytest.mark.parametrize("timeout", [0, -1, True, 1.0, "1"])
def test_execution_rejects_invalid_timeout(timeout: object) -> None:
    with pytest.raises(LaunchGateExtractionError) as caught:
        diagnostic_extract_launch_gate_page_v1(GATE_EXTRACTION_DIRECTORY, timeout_seconds=timeout)  # type: ignore[arg-type]

    assert caught.value.code == "GATE_EXTRACTION_TIMEOUT_INVALID"


def test_authoritative_python_entry_requires_native_custodian(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_launch(*args: object, **kwargs: object) -> None:
        raise AssertionError("retired Python entry attempted process launch")

    monkeypatch.setattr(extraction.subprocess, "run", forbidden_launch)
    with pytest.raises(LaunchGateExtractionError) as caught:
        extract_launch_gate_page_v1(GATE_EXTRACTION_DIRECTORY)

    assert caught.value.code == "GATE_EXTRACTION_NATIVE_CUSTODIAN_REQUIRED"


@pytest.mark.docker_smoke
def test_pinned_linux_amd64_named_discard_preserves_raw_object_and_rejects_legacy_route(
    tmp_path: Path,
) -> None:
    inspected = subprocess.run(
        ["docker", "image", "inspect", IMAGE_ID, "--format", "{{.Id}}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if inspected.returncode != 0:
        pytest.skip("pinned Stage-1 image is unavailable")
    assert inspected.stdout.strip() == IMAGE_ID

    harness = """from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
from evaluation_v6_3_1.launch_gate_stage1_extraction import (
    LaunchGateExtractionError,
    diagnostic_extract_launch_gate_page_v1,
    validate_launch_gate_extraction_v1,
)

SOURCE = '/repo/evaluation_v6_3_1/native/capture_v2/LaunchGateV1.S'

def assemble(directory):
    directory.mkdir(parents=True, mode=0o700)
    subprocess.run([
        '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'LC_ALL=C', 'LANG=C',
        'TZ=UTC', 'SOURCE_DATE_EPOCH=0', '/usr/bin/clang-16',
        '--target=x86_64-unknown-linux-gnu', '-c', '-x', 'assembler',
        '-fintegrated-as', '-Wa,--noexecstack', '-o',
        'LaunchGateV1.o', SOURCE,
    ], cwd=directory, check=True)
    os.chmod(directory / 'LaunchGateV1.o', 0o444)

def reset_exact():
    exact = Path('/work/stage1/gate-extract')
    if exact.exists():
        shutil.rmtree(exact)
    assemble(exact)
    return exact

codes = {}

d = reset_exact()
os.chmod(d / 'LaunchGateV1.o', 0o644)
try:
    diagnostic_extract_launch_gate_page_v1(d)
except LaunchGateExtractionError as exc:
    codes['wrong_mode'] = exc.code

d = reset_exact()
(d / 'LaunchGateV1.page').write_bytes(b'x')
try:
    diagnostic_extract_launch_gate_page_v1(d)
except LaunchGateExtractionError as exc:
    codes['preexisting_page'] = exc.code

d = reset_exact()
os.link(d / 'LaunchGateV1.o', '/work/LaunchGateV1.alias')
try:
    diagnostic_extract_launch_gate_page_v1(d)
except LaunchGateExtractionError as exc:
    codes['hardlink'] = exc.code
os.unlink('/work/LaunchGateV1.alias')

d = reset_exact()
raw_before = (d / 'LaunchGateV1.o').read_bytes()
execution = diagnostic_extract_launch_gate_page_v1(d)
raw_after = (d / 'LaunchGateV1.o').read_bytes()
page = (d / 'LaunchGateV1.page').read_bytes()
Path('/out/LaunchGateV1.o').write_bytes(raw_after)
Path('/out/LaunchGateV1.page').write_bytes(page)

legacy = Path('/work/stage1/legacy-omitted-output')
assemble(legacy)
legacy_before = (legacy / 'LaunchGateV1.o').read_bytes()
legacy_run = subprocess.run([
    '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'LC_ALL=C', 'LANG=C',
    'TZ=UTC', 'SOURCE_DATE_EPOCH=0', 'HOME=/nonexistent',
    'DEBUGINFOD_URLS=', '/usr/bin/objcopy',
    '--input-target=elf64-x86-64', '--dump-section',
    '.text.launch_gate_v1=LaunchGateV1.page', 'LaunchGateV1.o',
], cwd=legacy, check=False, capture_output=True)
legacy_after = (legacy / 'LaunchGateV1.o').read_bytes()
legacy_page = (legacy / 'LaunchGateV1.page').read_bytes()
legacy_validation = validate_launch_gate_extraction_v1(legacy_after, legacy_page)

print(json.dumps({
    'codes': codes,
    'positive': {
        'raw_before_size': len(raw_before),
        'raw_before_sha256': hashlib.sha256(raw_before).hexdigest(),
        'raw_after_size': len(raw_after),
        'raw_after_sha256': hashlib.sha256(raw_after).hexdigest(),
        'page_size': len(page),
        'page_sha256': hashlib.sha256(page).hexdigest(),
        'page_mode': oct(os.stat(d / 'LaunchGateV1.page').st_mode & 0o777),
        'entries': sorted(path.name for path in d.iterdir()),
        'execution_authority': execution.authority,
    },
    'legacy': {
        'returncode': legacy_run.returncode,
        'raw_before_sha256': hashlib.sha256(legacy_before).hexdigest(),
        'raw_after_size': len(legacy_after),
        'raw_after_sha256': hashlib.sha256(legacy_after).hexdigest(),
        'page_sha256': hashlib.sha256(legacy_page).hexdigest(),
        'validation_valid': legacy_validation.valid,
        'validation_issue': legacy_validation.issues[0].code,
    },
}, sort_keys=True))
"""
    extraction_command = [
        "docker",
        "run",
        "--rm",
        "--platform",
        "linux/amd64",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        "/work:rw,noexec,nosuid,nodev,size=16m",
        "--mount",
        f"type=bind,src={REPOSITORY},dst=/repo,readonly",
        "--mount",
        f"type=bind,src={tmp_path},dst=/out",
        IMAGE_ID,
        "/usr/bin/env",
        "-i",
        "PATH=/usr/bin:/bin",
        "PYTHONPATH=/repo",
        "PYTHONDONTWRITEBYTECODE=1",
        "/usr/bin/python3",
        "-c",
        harness,
    ]
    extracted = subprocess.run(extraction_command, check=False, capture_output=True, text=True)
    assert extracted.returncode == 0, extracted.stderr
    payload = json.loads(extracted.stdout)
    assert payload["codes"] == {
        "hardlink": "GATE_EXTRACTION_OBJECT_LINK_COUNT_INVALID",
        "preexisting_page": "GATE_EXTRACTION_DIRECTORY_NOT_FRESH",
        "wrong_mode": "GATE_EXTRACTION_OBJECT_MODE_INVALID",
    }

    positive = payload["positive"]
    assert positive == {
        "entries": ["LaunchGateV1.o", "LaunchGateV1.page"],
        "execution_authority": False,
        "page_mode": "0o444",
        "page_sha256": GATE_PAGE_SHA256.hex(),
        "page_size": GATE_PAGE_SIZE,
        "raw_after_sha256": GATE_OBJECT_SHA256.hex(),
        "raw_after_size": GATE_OBJECT_SIZE,
        "raw_before_sha256": GATE_OBJECT_SHA256.hex(),
        "raw_before_size": GATE_OBJECT_SIZE,
    }

    legacy = payload["legacy"]
    assert legacy["returncode"] == 0
    assert legacy["raw_before_sha256"] == GATE_OBJECT_SHA256.hex()
    assert legacy["raw_after_size"] == 8776
    assert legacy["raw_after_sha256"] == HISTORICAL_REWRITTEN_OBJECT_SHA256.hex()
    assert legacy["page_sha256"] == GATE_PAGE_SHA256.hex()
    assert legacy["validation_valid"] is False
    assert legacy["validation_issue"] == "GATE_EXTRACTION_OBJECT_SIZE_MISMATCH"

    object_bytes = (tmp_path / "LaunchGateV1.o").read_bytes()
    page = (tmp_path / "LaunchGateV1.page").read_bytes()
    result = validate_launch_gate_extraction_v1(object_bytes, page)
    assert result.valid
    assert result.evidence is not None
    assert result.evidence.object_sha256 == GATE_OBJECT_SHA256
    assert result.evidence.page_sha256 == GATE_PAGE_SHA256
    assert not result.authority


def _install_controller_harness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    create_page: bool = True,
    create_discard: bool = True,
    command_mutation: object = None,
) -> tuple[Path, Path, Path, list[tuple[str, ...]]]:
    """Install a tiny exact-directory controller harness.

    The real pinned-image test above remains the integration test.  These
    tests patch only the subprocess, exact identities, validator, and
    renameat2 boundary so each mutation is deterministic and exercises the
    controller's ordering rather than GNU objcopy behavior.
    """

    directory = tmp_path / "gate-extract"
    directory.mkdir(mode=0o700)
    object_path = directory / "LaunchGateV1.o"
    object_bytes = b"object"
    page_bytes = b"page"
    discard_bytes = b"discard"
    object_path.write_bytes(object_bytes)
    object_path.chmod(0o444)

    monkeypatch.setattr(extraction, "GATE_EXTRACTION_DIRECTORY", directory)
    monkeypatch.setattr(extraction, "GATE_OBJECT_SIZE", len(object_bytes))
    monkeypatch.setattr(extraction, "GATE_OBJECT_SHA256", hashlib.sha256(object_bytes).digest())
    monkeypatch.setattr(extraction, "GATE_PAGE_SIZE", len(page_bytes))
    monkeypatch.setattr(extraction, "GATE_PAGE_SHA256", hashlib.sha256(page_bytes).digest())

    calls: list[tuple[str, ...]] = []

    def fake_run(argv: list[str] | tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(tuple(argv))
        assert kwargs["cwd"] == str(directory)
        if create_page:
            (directory / extraction.GATE_PAGE_TMP_NAME).write_bytes(page_bytes)
            (directory / extraction.GATE_PAGE_TMP_NAME).chmod(0o644)
        if create_discard:
            (directory / extraction.GATE_DISCARD_NAME).write_bytes(discard_bytes)
            (directory / extraction.GATE_DISCARD_NAME).chmod(0o644)
        if command_mutation is not None:
            command_mutation(directory)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(extraction.subprocess, "run", fake_run)

    def fake_validate(
        candidate_object: bytes,
        candidate_page: bytes,
    ) -> extraction.LaunchGateExtractionValidationResultV1:
        if candidate_object != object_bytes:
            issue = extraction.LaunchGateStage1Issue(
                "GATE_EXTRACTION_OBJECT_HASH_MISMATCH", "test object mismatch"
            )
            return extraction.LaunchGateExtractionValidationResultV1(False, (issue,))
        if candidate_page != page_bytes:
            issue = extraction.LaunchGateStage1Issue(
                "GATE_EXTRACTION_PAGE_HASH_MISMATCH", "test page mismatch"
            )
            return extraction.LaunchGateExtractionValidationResultV1(False, (issue,))
        evidence = extraction.LaunchGateExtractionEvidenceV1(
            object_sha256=hashlib.sha256(candidate_object).digest(),
            page_sha256=hashlib.sha256(candidate_page).digest(),
            object_size=len(candidate_object),
            page_size=len(candidate_page),
            gate_code_size=extraction.GATE_CODE_SIZE,
        )
        return extraction.LaunchGateExtractionValidationResultV1(
            valid=True,
            issues=(),
            evidence=evidence,
        )

    monkeypatch.setattr(extraction, "validate_launch_gate_extraction_v1", fake_validate)

    def fake_rename(directory_fd: int) -> None:
        os.rename(
            directory / extraction.GATE_PAGE_TMP_NAME,
            directory / extraction.GATE_PAGE_NAME,
        )

    monkeypatch.setattr(extraction, "_rename_noreplace", fake_rename)
    return directory, object_path, directory / extraction.GATE_PAGE_TMP_NAME, calls


def _assert_controller_error(
    directory: Path,
    expected_code: str,
) -> LaunchGateExtractionError:
    with pytest.raises(LaunchGateExtractionError) as caught:
        extraction.diagnostic_extract_launch_gate_page_v1(directory)
    assert caught.value.code == expected_code
    return caught.value


def test_controller_rejects_symlink_input_without_launch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    directory, object_path, _, calls = _install_controller_harness(tmp_path, monkeypatch)
    target = tmp_path / "outside.o"
    target.write_bytes(b"object")
    object_path.unlink()
    object_path.symlink_to(target)

    _assert_controller_error(directory, "GATE_EXTRACTION_OBJECT_OPEN_FAILED")
    assert calls == []


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        (
            lambda directory: (
                (directory / extraction.GATE_PAGE_TMP_NAME).unlink(),
                (directory / extraction.GATE_PAGE_TMP_NAME).symlink_to(directory.parent / "page"),
            ),
            "GATE_EXTRACTION_PAGE_TMP_OPEN_FAILED",
        ),
        (
            lambda directory: (
                (directory / extraction.GATE_DISCARD_NAME).unlink(),
                (directory / extraction.GATE_DISCARD_NAME).symlink_to(directory.parent / "discard"),
            ),
            "GATE_EXTRACTION_DISCARD_OPEN_FAILED",
        ),
    ],
    ids=["symlink-page", "symlink-discard"],
)
def test_controller_rejects_symlink_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: object,
    expected_code: str,
) -> None:
    directory, _, _, _ = _install_controller_harness(
        tmp_path,
        monkeypatch,
        command_mutation=mutation,
    )
    _assert_controller_error(directory, expected_code)


def test_controller_rejects_preexisting_discard_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory, _, _, calls = _install_controller_harness(tmp_path, monkeypatch)
    (directory / extraction.GATE_DISCARD_NAME).write_bytes(b"stale")

    _assert_controller_error(directory, "GATE_EXTRACTION_DIRECTORY_NOT_FRESH")
    assert calls == []


@pytest.mark.parametrize("kind", ["size", "hash", "retired-rewritten-03415"], ids=["size", "hash", "retired-03415"])
def test_controller_rejects_wrong_object_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    directory, _, _, _ = _install_controller_harness(tmp_path, monkeypatch)
    if kind == "size":
        monkeypatch.setattr(extraction, "GATE_OBJECT_SIZE", 7)
    else:
        retired_digest = HISTORICAL_REWRITTEN_OBJECT_SHA256
        monkeypatch.setattr(extraction, "GATE_OBJECT_SHA256", retired_digest)

    expected = (
        "GATE_EXTRACTION_OBJECT_SIZE_INVALID"
        if kind == "size"
        else "GATE_EXTRACTION_OBJECT_HASH_MISMATCH"
    )
    _assert_controller_error(directory, expected)


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        (
            lambda directory: (
                (directory / extraction.GATE_OBJECT_NAME).chmod(0o644),
                (directory / extraction.GATE_OBJECT_NAME).write_bytes(b"mutat!"),
                (directory / extraction.GATE_OBJECT_NAME).chmod(0o444),
            ),
            "GATE_EXTRACTION_OBJECT_CHANGED",
        ),
        (
            lambda directory: (
                (directory / extraction.GATE_OBJECT_NAME).rename(
                    directory.parent / "moved-object.o"
                ),
                (directory / extraction.GATE_OBJECT_NAME).write_bytes(b"object"),
                (directory / extraction.GATE_OBJECT_NAME).chmod(0o444),
            ),
            "GATE_EXTRACTION_OBJECT_CHANGED",
        ),
    ],
    ids=["input-byte-replacement", "input-inode-replacement"],
)
def test_controller_reauthenticates_input_after_extraction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: object,
    expected_code: str,
) -> None:
    directory, _, _, _ = _install_controller_harness(
        tmp_path,
        monkeypatch,
        command_mutation=mutation,
    )
    _assert_controller_error(directory, expected_code)
    assert not (directory / extraction.GATE_PAGE_NAME).exists()


def test_controller_reauthenticates_directory_path_after_extraction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    replacement = tmp_path / "replaced-gate-extract"

    def replace_directory(directory: Path) -> None:
        directory.rename(replacement)
        directory.mkdir(mode=0o700)
        replacement_object = directory / extraction.GATE_OBJECT_NAME
        replacement_object.write_bytes(b"object")
        replacement_object.chmod(0o444)

    directory, _, _, _ = _install_controller_harness(
        tmp_path,
        monkeypatch,
        command_mutation=replace_directory,
    )
    _assert_controller_error(directory, "GATE_EXTRACTION_DIRECTORY_PATH_MISMATCH")


@pytest.mark.parametrize(
    ("create_page", "create_discard", "expected_code"),
    [
        (False, True, "GATE_EXTRACTION_DIRECTORY_CONTAMINATED"),
        (True, False, "GATE_EXTRACTION_DIRECTORY_CONTAMINATED"),
    ],
    ids=["missing-page", "missing-discard"],
)
def test_controller_rejects_missing_outputs_before_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    create_page: bool,
    create_discard: bool,
    expected_code: str,
) -> None:
    directory, _, _, _ = _install_controller_harness(
        tmp_path,
        monkeypatch,
        create_page=create_page,
        create_discard=create_discard,
    )
    _assert_controller_error(directory, expected_code)


def test_controller_rejects_shared_discard_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def share_discard(directory: Path) -> None:
        discard = directory / extraction.GATE_DISCARD_NAME
        discard.unlink()
        shared_target = directory.parent / "shared-discard.o"
        shared_target.write_bytes(b"discard")
        os.link(shared_target, discard)

    directory, _, _, _ = _install_controller_harness(
        tmp_path,
        monkeypatch,
        command_mutation=share_discard,
    )
    _assert_controller_error(directory, "GATE_EXTRACTION_DISCARD_LINK_COUNT_INVALID")


def test_controller_rejects_mutated_page_before_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def mutate_page(directory: Path) -> None:
        (directory / extraction.GATE_PAGE_TMP_NAME).write_bytes(b"fail")

    directory, _, _, _ = _install_controller_harness(
        tmp_path,
        monkeypatch,
        command_mutation=mutate_page,
    )
    _assert_controller_error(directory, "GATE_EXTRACTION_PAGE_HASH_MISMATCH")
    assert not (directory / extraction.GATE_PAGE_NAME).exists()


def test_controller_rejects_oversized_page_before_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def oversize_page(directory: Path) -> None:
        (directory / extraction.GATE_PAGE_TMP_NAME).write_bytes(b"page!")

    directory, _, _, _ = _install_controller_harness(
        tmp_path,
        monkeypatch,
        command_mutation=oversize_page,
    )
    _assert_controller_error(directory, "GATE_EXTRACTION_PAGE_TMP_INVALID")


def test_controller_rejects_extra_post_extraction_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def add_extra(directory: Path) -> None:
        (directory / "unexpected").write_bytes(b"extra")

    directory, _, _, _ = _install_controller_harness(
        tmp_path,
        monkeypatch,
        command_mutation=add_extra,
    )
    _assert_controller_error(directory, "GATE_EXTRACTION_DIRECTORY_CONTAMINATED")


def test_controller_rejects_extra_final_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory, _, _, _ = _install_controller_harness(tmp_path, monkeypatch)

    def commit_with_extra(directory_fd: int) -> None:
        os.rename(
            directory / extraction.GATE_PAGE_TMP_NAME,
            directory / extraction.GATE_PAGE_NAME,
        )
        (directory / "unexpected").write_bytes(b"extra")

    monkeypatch.setattr(extraction, "_rename_noreplace", commit_with_extra)
    _assert_controller_error(directory, "GATE_EXTRACTION_FINAL_DIRECTORY_INVALID")
    assert (directory / extraction.GATE_PAGE_NAME).exists()


def test_controller_rename_failure_has_no_fallback_or_page_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory, _, _, _ = _install_controller_harness(tmp_path, monkeypatch)
    fallback_calls: list[str] = []

    def fail_renameat2(directory_fd: int) -> None:
        raise LaunchGateExtractionError(
            "GATE_EXTRACTION_RENAMEAT2_INCAPABLE", "test renameat2 failure"
        )

    def forbidden_fallback(*args: object, **kwargs: object) -> None:
        fallback_calls.append("fallback")
        raise AssertionError("page commit used a rename fallback")

    monkeypatch.setattr(extraction, "_rename_noreplace", fail_renameat2)
    monkeypatch.setattr(extraction.os, "replace", forbidden_fallback)
    monkeypatch.setattr(extraction.os, "rename", forbidden_fallback)
    _assert_controller_error(directory, "GATE_EXTRACTION_RENAMEAT2_INCAPABLE")
    assert fallback_calls == []
    assert not (directory / extraction.GATE_PAGE_NAME).exists()
    assert not (directory / extraction.GATE_PAGE_TMP_NAME).exists()


def test_controller_reauthenticates_before_any_page_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory, _, _, _ = _install_controller_harness(tmp_path, monkeypatch)
    events: list[tuple[str, bool]] = []
    real_reauthenticate = extraction._reauthenticate_bound_directory

    def observed_reauthenticate(*args: object, **kwargs: object) -> None:
        events.append(("reauthenticate", (directory / extraction.GATE_PAGE_NAME).exists()))
        real_reauthenticate(*args, **kwargs)

    def observed_rename(directory_fd: int) -> None:
        events.append(("renameat2", (directory / extraction.GATE_PAGE_NAME).exists()))
        os.rename(
            directory / extraction.GATE_PAGE_TMP_NAME,
            directory / extraction.GATE_PAGE_NAME,
        )

    monkeypatch.setattr(extraction, "_reauthenticate_bound_directory", observed_reauthenticate)
    monkeypatch.setattr(extraction, "_rename_noreplace", observed_rename)
    result = extraction.diagnostic_extract_launch_gate_page_v1(directory)

    assert not result.authority
    assert events == [
        ("reauthenticate", False),
        ("renameat2", False),
        ("reauthenticate", True),
    ]
