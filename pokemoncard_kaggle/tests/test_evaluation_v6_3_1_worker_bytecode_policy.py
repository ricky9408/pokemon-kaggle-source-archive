"""Independent exact-runtime tests for the v631302 worker bytecode policy."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/verify_v631302_worker_bytecode_policy.py"
WORKER = ROOT / "worker/v631302_diagnostic_worker_v1.py"
IMAGE = "sha256:38634214ff91fc0007016cdf04d9f05d9289880fe8d30c4d66b0c284095460dd"
INTERPRETER_SHA256 = "6d972cf21be56fe3c947ab6ba257ff8d08c342dd2714442986791bd9a6dfabfe"
BASE_OPCODE_MAP_ROOT = "3b1cc4c4171c908b2880c20838f4eebf80de54fbe10b46e7d5c74f6e23d0fb77"
INLINE_CACHE_WIDTHS_ROOT = "6216aa659e01666076e2a4d62983aa5993062a502d57cf5bb8303005f081ae32"
WORKER_OPCODE_POLICY_ROOT = "57265e0fe9fcb34f51324a68d9605319d720b23789a043eaf4667965fb430d4d"
REFERENCE_EXTRACTOR_SHA256 = "a6535147b4a7e1ed027d0a78e75ea07afdae905995d870e4b09d4956e04f373e"
RETIRED_AMENDMENT7_INPUT_MANIFEST_ROOT = (
    "fb1c598f6fa3257d647d3cb928f62ffb947e8f66f8e2436814ccff010e084579"
)
RETIRED_AMENDMENT7_BUNDLE_INVENTORY_ROOT = (
    "6cb243eb94f4bc71641e989ef2f3ba6952a20244495734f034b30bd2c849dd4b"
)
RETIRED_AMENDMENT8_INPUT_MANIFEST_ROOT = (
    "4377965d2b09fdfd40e9a28f349a9341d5f14a15bee45e935c61535862c09a3f"
)
RETIRED_AMENDMENT8_BUNDLE_INVENTORY_ROOT = (
    "b178edd6cd89dfe3cbe278b9f5ee9398a9d53ddbb91def23ce55c9c80e608b99"
)
REFERENCE_INPUT_MANIFEST_ROOT = "baebe25420aa820045ee7deb69b780424b086e301f7a63a1ebc13d593e6975e4"
RECURSIVE_BUNDLE_INVENTORY_ROOT = "9b221516bc11142705ac563d8ac548dd4debd826cc23bdfe25f5e58992a75f49"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_exact_runtime() -> bool:
    executable = Path("/proc/self/exe")
    return executable.is_file() and _sha256(executable) == INTERPRETER_SHA256


def _run_proof() -> subprocess.CompletedProcess[str]:
    if _is_exact_runtime():
        return subprocess.run(
            [sys.executable, str(SCRIPT)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    if shutil.which("docker") is None:
        pytest.skip("exact Linux/amd64 image is unavailable")
    inspect = subprocess.run(
        ["docker", "image", "inspect", IMAGE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if inspect.returncode:
        pytest.skip("exact Linux/amd64 image is unavailable")
    return subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "-v",
            f"{ROOT}:/repo:ro",
            "-w",
            "/repo",
            IMAGE,
            "/usr/bin/python3.11",
            "tools/verify_v631302_worker_bytecode_policy.py",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def test_independent_policy_proof_reproduces_frozen_roots() -> None:
    result = _run_proof()
    assert result.returncode == 0, result.stderr
    proof = json.loads(result.stdout)
    assert proof["schema"] == "V631302_WORKER_BYTECODE_POLICY_PROOF_V1"
    assert proof["proof_result"] == 1
    assert proof["base_opcode_map_root"] == BASE_OPCODE_MAP_ROOT
    assert proof["inline_cache_widths_root"] == INLINE_CACHE_WIDTHS_ROOT
    assert proof["worker_opcode_policy_root"] == WORKER_OPCODE_POLICY_ROOT
    assert proof["reference_extractor"]["sha256"] == REFERENCE_EXTRACTOR_SHA256
    assert proof["reference_input_manifest_root"] == REFERENCE_INPUT_MANIFEST_ROOT
    assert (
        proof["recursive_bundle_bytecode_inventory_root"]
        == RECURSIVE_BUNDLE_INVENTORY_ROOT
    )
    assert proof["worker"]["sha256"] == _sha256(WORKER)
    assert proof["reference_input_manifest_root"] != RETIRED_AMENDMENT7_INPUT_MANIFEST_ROOT
    assert proof["reference_input_manifest_root"] != RETIRED_AMENDMENT8_INPUT_MANIFEST_ROOT
    assert (
        proof["recursive_bundle_bytecode_inventory_root"]
        != RETIRED_AMENDMENT7_BUNDLE_INVENTORY_ROOT
    )
    assert (
        proof["recursive_bundle_bytecode_inventory_root"]
        != RETIRED_AMENDMENT8_BUNDLE_INVENTORY_ROOT
    )
    assert len(proof["permitted_executable_opcodes"]) > 0
    assert len(proof["prohibited_executable_opcodes"]) > 0
    assert proof["name_operand_rules"] == [
        [90, 0],
        [91, 0],
        [95, 0],
        [96, 0],
        [97, 0],
        [98, 0],
        [101, 0],
        [106, 0],
        [108, 0],
        [109, 0],
        [116, 1],
        [160, 0],
    ]
    assert set(proof["observed_project_opcodes"]) <= set(
        proof["permitted_executable_opcodes"]
    )


@pytest.mark.skipif(_is_exact_runtime(), reason="negative test requires a non-pinned host")
def test_reference_proof_fails_closed_outside_pinned_runtime() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode != 0
    assert result.stdout == ""
    assert "pinned CPython 3.11.2 identity mismatch" in result.stderr
