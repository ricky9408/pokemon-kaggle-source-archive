from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from evaluation_v4_2.runtime_binding import (
    RuntimeBindingError,
    build_runtime_binding,
    python_tree_sha256,
    validate_runtime_binding,
    validate_runtime_binding_file,
)
from evaluation_v4_2.simulation_design import canonical_sha256


def _trees(tmp_path: Path) -> dict[str, Path]:
    values: dict[str, Path] = {}
    for name in ("evaluation_v2", "evaluation_v4_2"):
        path = tmp_path / name
        path.mkdir()
        (path / "module.py").write_text(f"NAME = {name!r}\n", encoding="ascii")
        values[name] = path
    return values


def test_runtime_binding_round_trips_and_binds_source_bytes(tmp_path: Path) -> None:
    trees = _trees(tmp_path)
    receipt = build_runtime_binding(trees)
    assert validate_runtime_binding(receipt) == receipt

    path = tmp_path / "runtime.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    assert validate_runtime_binding_file(path) == receipt

    (trees["evaluation_v2"] / "module.py").write_text("NAME = 'changed'\n", encoding="ascii")
    with pytest.raises(RuntimeBindingError, match="current runtime bytes"):
        validate_runtime_binding(receipt)


def test_runtime_binding_rejects_rehashed_environment_tamper(tmp_path: Path) -> None:
    receipt = build_runtime_binding(_trees(tmp_path))
    tampered = copy.deepcopy(receipt)
    tampered["python_version"] = "0.0.0"
    content = {key: value for key, value in tampered.items() if key != "content_sha256"}
    tampered["content_sha256"] = canonical_sha256(content)
    with pytest.raises(RuntimeBindingError, match="current runtime bytes"):
        validate_runtime_binding(tampered)


def test_runtime_binding_requires_both_evaluator_source_trees(tmp_path: Path) -> None:
    trees = _trees(tmp_path)
    with pytest.raises(RuntimeBindingError, match="source trees must exactly"):
        build_runtime_binding({"evaluation_v2": trees["evaluation_v2"]})


def test_python_tree_digest_is_path_and_content_sensitive(tmp_path: Path) -> None:
    trees = _trees(tmp_path)
    before = python_tree_sha256(trees["evaluation_v2"])
    (trees["evaluation_v2"] / "other.py").write_text("VALUE = 1\n", encoding="ascii")
    assert python_tree_sha256(trees["evaluation_v2"]) != before
