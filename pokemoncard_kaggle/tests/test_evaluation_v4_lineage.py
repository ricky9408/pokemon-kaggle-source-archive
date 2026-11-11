from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import tarfile

import pytest

from evaluation_v4.lineage import (
    MAX_UNCOMPRESSED_BYTES,
    REGISTRY_SCHEMA,
    UNDECLARED_PARENT_LIMITATION,
    build_registry,
    canonical_json_bytes,
    inspect_archive,
    lineage_id_for_archive,
    validate_registry,
    write_registry_once,
)
from evaluation_v4.protocol import validate_lineage_records


def _tar_bytes(entries: list[tuple[str, bytes]], *, mtime: int = 0) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for name, data in entries:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mtime = mtime
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


def _write_valid(path: Path, *, agent: bytes = b"def act(state): return []\n", mtime: int = 0) -> Path:
    raw = _tar_bytes(
        [
            ("main.py", agent),
            ("deck.csv", b"1,4\n2,4\n"),
            ("policy.py", b"# policy\n"),
        ],
        mtime=mtime,
    )
    path.write_bytes(raw)
    return path


def _input(path: Path, *, parents: list[str] | None = None, family: str = "family-a") -> dict[str, object]:
    return {
        "archive_path": path,
        "family_id": family,
        "parent_archive_sha256": list(parents or []),
        "first_seen_utc": "2026-07-11T01:02:03.000000Z",
    }


def test_identity_uses_exact_bytes_and_canonical_policy_framing(tmp_path: Path) -> None:
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    entries = [
        ("policy.py", b"# policy\n"),
        ("deck.csv", b"1,4\n2,4\n"),
        ("main.py", b"def act(state): return []\n"),
        ("._Finder", b"ignored metadata"),
    ]
    first.write_bytes(_tar_bytes(entries, mtime=1))
    second.write_bytes(_tar_bytes(list(reversed(entries)), mtime=2))

    identity = inspect_archive(first)
    other = inspect_archive(second)
    assert identity["archive_sha256"] == hashlib.sha256(first.read_bytes()).hexdigest()
    assert identity["deck_sha256"] == hashlib.sha256(b"1,4\n2,4\n").hexdigest()
    assert identity["policy_content_sha256"] == other["policy_content_sha256"]
    assert identity["archive_sha256"] != other["archive_sha256"]

    name = b"main.py"
    policy = hashlib.sha256()
    policy.update(len(name).to_bytes(4, "big"))
    policy.update(name)
    agent = b"def act(state): return []\n"
    policy.update(len(agent).to_bytes(8, "big"))
    policy.update(agent)
    name = b"policy.py"
    policy.update(len(name).to_bytes(4, "big"))
    policy.update(name)
    body = b"# policy\n"
    policy.update(len(body).to_bytes(8, "big"))
    policy.update(body)
    assert identity["policy_content_sha256"] == policy.hexdigest()


def test_registry_is_input_order_invariant_and_protocol_compatible(tmp_path: Path) -> None:
    root = _write_valid(tmp_path / "root.tar.gz")
    child = _write_valid(tmp_path / "child.tar.gz", agent=b"def act(state): return [1]\n")
    root_hash = inspect_archive(root)["archive_sha256"]
    inputs = [_input(root), _input(child, parents=[root_hash])]

    forward = build_registry(inputs)
    reverse = build_registry(list(reversed(inputs)))
    assert forward == reverse
    assert forward["schema"] == REGISTRY_SCHEMA
    assert validate_lineage_records(forward["records"]) == forward["records"]
    assert all(record["lineage_id"] == lineage_id_for_archive(record["archive_sha256"]) for record in forward["records"])
    assert "Undeclared parents" in UNDECLARED_PARENT_LIMITATION


def test_dag_rejects_missing_parent_and_cycles(tmp_path: Path) -> None:
    first = _write_valid(tmp_path / "first.tar.gz")
    second = _write_valid(tmp_path / "second.tar.gz", agent=b"def act(state): return [1]\n")
    first_hash = inspect_archive(first)["archive_sha256"]
    second_hash = inspect_archive(second)["archive_sha256"]

    with pytest.raises(ValueError, match="missing parent archive"):
        build_registry([_input(first, parents=["a" * 64])])
    with pytest.raises(ValueError, match="cycle"):
        build_registry([_input(first, parents=[second_hash]), _input(second, parents=[first_hash])])


def test_duplicate_archive_bytes_and_cross_ancestry_policy_are_rejected(tmp_path: Path) -> None:
    archive = _write_valid(tmp_path / "one.tar.gz")
    with pytest.raises(ValueError, match="duplicate archive bytes"):
        build_registry([_input(archive), _input(archive)])

    first = _write_valid(tmp_path / "first.tar.gz", mtime=1)
    second = _write_valid(tmp_path / "second.tar.gz", mtime=2)
    assert inspect_archive(first)["policy_content_sha256"] == inspect_archive(second)["policy_content_sha256"]
    with pytest.raises(ValueError, match="multiple ancestry components"):
        build_registry([_input(first), _input(second)])


def test_archive_mutation_changes_derived_identity(tmp_path: Path) -> None:
    archive = _write_valid(tmp_path / "candidate.tar.gz")
    before = inspect_archive(archive)
    archive.write_bytes(archive.read_bytes() + b"mutation")
    mutated = inspect_archive(archive)
    assert mutated["archive_sha256"] != before["archive_sha256"]
    # A valid replacement is still derived afresh rather than compared with a
    # caller-supplied stale hash.
    _write_valid(archive, agent=b"def act(state): return [2]\n")
    after = inspect_archive(archive)
    assert after["archive_sha256"] != before["archive_sha256"]
    assert after["policy_content_sha256"] != before["policy_content_sha256"]


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("/absolute", "absolute archive member path"),
        ("../traversal", "traversal archive member path"),
        ("pkg/../traversal", "traversal archive member path"),
        ("cache/x.pyc", "pyc"),
        ("pkg/__pycache__/x", "__pycache__"),
    ],
)
def test_archive_rejects_unsafe_paths_and_bytecode(tmp_path: Path, name: str, message: str) -> None:
    archive = tmp_path / "unsafe.tar.gz"
    archive.write_bytes(_tar_bytes([("main.py", b"a"), ("deck.csv", b"d"), (name, b"x")]))
    with pytest.raises(ValueError, match=message):
        inspect_archive(archive)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "device"])
def test_archive_rejects_non_regular_members(tmp_path: Path, kind: str) -> None:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for name, data in (("main.py", b"a"), ("deck.csv", b"d")):
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        member = tarfile.TarInfo("bad")
        if kind == "symlink":
            member.type = tarfile.SYMTYPE
            member.linkname = "main.py"
        elif kind == "hardlink":
            member.type = tarfile.LNKTYPE
            member.linkname = "main.py"
        elif kind == "device":
            member.type = tarfile.CHRTYPE
            member.devmajor = 1
            member.devminor = 3
        else:
            member.type = tarfile.DIRTYPE
        archive.addfile(member)
    path = tmp_path / f"{kind}.tar.gz"
    path.write_bytes(output.getvalue())
    with pytest.raises(ValueError, match="not a regular file"):
        inspect_archive(path)


def test_archive_rejects_duplicate_and_multiple_required_members(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.tar.gz"
    duplicate.write_bytes(_tar_bytes([("main.py", b"a"), ("./main.py", b"b"), ("deck.csv", b"d")]))
    with pytest.raises(ValueError, match="duplicate archive member path"):
        inspect_archive(duplicate)

    multiple = tmp_path / "multiple.tar.gz"
    multiple.write_bytes(_tar_bytes([("main.py", b"a"), ("pkg/main.py", b"b"), ("deck.csv", b"d")]))
    with pytest.raises(ValueError, match="exactly one main.py"):
        inspect_archive(multiple)

    missing = tmp_path / "missing.tar.gz"
    missing.write_bytes(_tar_bytes([("main.py", b"a"), ("policy.py", b"p")]))
    with pytest.raises(ValueError, match="exactly one deck.csv"):
        inspect_archive(missing)


def test_archive_size_bound_and_input_schema_reject_self_reported_hashes(tmp_path: Path) -> None:
    archive = tmp_path / "large.tar.gz"
    archive.write_bytes(_tar_bytes([("main.py", b"a"), ("deck.csv", b"d"), ("large", b"x" * 8)]))
    with pytest.raises(ValueError, match="maximum uncompressed size"):
        inspect_archive(archive, max_uncompressed_bytes=7)
    assert MAX_UNCOMPRESSED_BYTES > 0

    bad_input = _input(archive)
    bad_input["archive_sha256"] = "a" * 64
    with pytest.raises(ValueError, match="fields must exactly"):
        build_registry([bad_input])


def test_write_registry_once_is_canonical_and_append_only(tmp_path: Path) -> None:
    archive = _write_valid(tmp_path / "candidate.tar.gz")
    registry = build_registry([_input(archive)])
    output = tmp_path / "registry.json"
    assert write_registry_once(output, registry) == output
    assert output.read_bytes() == canonical_json_bytes(registry) + b"\n"
    assert json.loads(output.read_text(encoding="ascii")) == validate_registry(registry)
    with pytest.raises(FileExistsError):
        write_registry_once(output, registry)
