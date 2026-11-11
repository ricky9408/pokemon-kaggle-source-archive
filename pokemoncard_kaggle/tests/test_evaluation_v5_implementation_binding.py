from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import json
import os

import pytest

from evaluation_v5.canonical import canonical_json_bytes
from evaluation_v5.implementation_binding import (
    ImplementationBindingError,
    MANIFEST_SCHEMA,
    build_manifest,
    manifest_sha256,
    runtime_versions,
    validate_manifest,
    verify_manifest,
    write_manifest_once,
)


ARCHITECTURE_SHA256 = "a" * 64


def _manifest(tmp_path: Path) -> tuple[dict, Path, list[str]]:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "alpha.py").write_bytes(b"alpha\n")
    (tmp_path / "src" / "beta.py").write_bytes(b"beta\n")
    paths = ["src/alpha.py", "src/beta.py"]
    manifest = build_manifest(
        tmp_path,
        ARCHITECTURE_SHA256,
        paths,
        created_at_utc="2026-07-14T01:02:03.000004Z",
    )
    return manifest, tmp_path, paths


def test_stable_roundtrip_and_self_hash(tmp_path: Path) -> None:
    manifest, root, _ = _manifest(tmp_path)
    assert validate_manifest(manifest) == manifest
    assert manifest["schema"] == MANIFEST_SCHEMA
    assert manifest["authority"] is False
    assert manifest["manifest_sha256"] == manifest_sha256(manifest)
    assert verify_manifest(root, manifest) == manifest

    output = tmp_path / "manifest.json"
    write_manifest_once(output, manifest)
    assert output.read_bytes() == canonical_json_bytes(manifest)
    assert json.loads(output.read_text()) == manifest


def test_authoritative_verification_requires_the_exact_file_set(tmp_path: Path) -> None:
    manifest, root, paths = _manifest(tmp_path)
    assert verify_manifest(root, manifest, required_paths=paths) == manifest
    with pytest.raises(ImplementationBindingError, match="exact required file set"):
        verify_manifest(root, manifest, required_paths=[paths[0]])
    with pytest.raises(ImplementationBindingError, match="exact required file set"):
        verify_manifest(root, manifest, required_paths=list(reversed(paths)))


def test_byte_mutation_is_rejected(tmp_path: Path) -> None:
    manifest, root, _ = _manifest(tmp_path)
    target = root / "src" / "alpha.py"
    target.write_bytes(b"mutated\n")
    with pytest.raises(ImplementationBindingError, match="digest mismatch"):
        verify_manifest(root, manifest)


@pytest.mark.parametrize("path", ["/tmp/x.py", "../x.py", "src/../x.py", "src\\x.py", "src/\x00x.py", "./src/x.py"])
def test_unsafe_paths_are_rejected(tmp_path: Path, path: str) -> None:
    manifest, _, _ = _manifest(tmp_path)
    changed = deepcopy(manifest)
    changed["files"][0]["path"] = path
    with pytest.raises(ImplementationBindingError):
        validate_manifest(changed)


def test_duplicate_paths_are_rejected(tmp_path: Path) -> None:
    manifest, _, _ = _manifest(tmp_path)
    changed = deepcopy(manifest)
    changed["files"][1] = deepcopy(changed["files"][0])
    with pytest.raises(ImplementationBindingError, match="duplicate"):
        validate_manifest(changed)


def test_symlink_and_nonregular_files_are_rejected(tmp_path: Path) -> None:
    manifest, root, _ = _manifest(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_bytes(b"outside\n")
    target = root / "src" / "alpha.py"
    target.unlink()
    target.symlink_to(outside)
    with pytest.raises(ImplementationBindingError):
        verify_manifest(root, manifest)

    target.unlink()
    target.mkdir()
    with pytest.raises(ImplementationBindingError):
        verify_manifest(root, manifest)


def test_runtime_mismatch_is_rejected(tmp_path: Path) -> None:
    manifest, root, _ = _manifest(tmp_path)
    changed = deepcopy(manifest)
    changed["runtime"]["python"] = "0.0.0-test"
    changed["manifest_sha256"] = manifest_sha256(changed)
    with pytest.raises(ImplementationBindingError, match="runtime version mismatch"):
        verify_manifest(root, changed)


def test_extra_fields_and_authority_are_rejected(tmp_path: Path) -> None:
    manifest, _, _ = _manifest(tmp_path)
    extra = deepcopy(manifest)
    extra["extra"] = True
    with pytest.raises(ImplementationBindingError):
        validate_manifest(extra)
    authority = deepcopy(manifest)
    authority["authority"] = {"submission": False}
    with pytest.raises(ImplementationBindingError):
        validate_manifest(authority)


@pytest.mark.parametrize("mutation", ["missing", "wrong"])
def test_missing_or_wrong_schema_is_rejected(tmp_path: Path, mutation: str) -> None:
    manifest, _, _ = _manifest(tmp_path)
    changed = deepcopy(manifest)
    if mutation == "missing":
        changed.pop("schema")
    else:
        changed["schema"] = "evaluation_v5_implementation_binding_v999"
    with pytest.raises(ImplementationBindingError):
        validate_manifest(changed)


def test_create_once_refuses_overwrite_and_symlink(tmp_path: Path) -> None:
    manifest, _, _ = _manifest(tmp_path)
    output = tmp_path / "manifest.json"
    write_manifest_once(output, manifest)
    original = output.read_bytes()
    with pytest.raises(ImplementationBindingError):
        write_manifest_once(output, manifest)
    assert output.read_bytes() == original

    linked = tmp_path / "linked.json"
    linked.symlink_to(output)
    with pytest.raises(ImplementationBindingError):
        write_manifest_once(linked, manifest)


def test_builder_preserves_explicit_order_and_runtime_records(tmp_path: Path) -> None:
    manifest, root, paths = _manifest(tmp_path)
    assert [item["path"] for item in manifest["files"]] == paths
    assert set(manifest["runtime"]) == {
        "cryptography",
        "cryptography_distribution_sha256",
        "joblib",
        "joblib_distribution_sha256",
        "numpy",
        "numpy_distribution_sha256",
        "python",
        "python_executable_sha256",
        "python_stdlib_sha256",
        "scipy",
        "scipy_distribution_sha256",
        "sklearn",
        "sklearn_distribution_sha256",
        "threadpoolctl",
        "threadpoolctl_distribution_sha256",
    }
    assert manifest["runtime"] == runtime_versions()
    assert all(value is False for key, value in manifest.items() if key == "authority")


def test_descriptor_verification_rejects_parent_symlink(tmp_path: Path) -> None:
    manifest, root, _ = _manifest(tmp_path)
    real = root / "src"
    moved = root / "real-src"
    real.rename(moved)
    real.symlink_to(moved, target_is_directory=True)
    with pytest.raises(ImplementationBindingError):
        verify_manifest(root, manifest)


def test_no_outcome_or_authority_surface() -> None:
    import evaluation_v5.implementation_binding as module

    assert not hasattr(module, "fit")
    assert not hasattr(module, "outcome")
    assert module.AUTHORITY is False
