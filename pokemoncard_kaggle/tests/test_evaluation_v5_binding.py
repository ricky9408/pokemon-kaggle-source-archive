from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path

import pytest

from evaluation_v5.binding import BindingVerificationError, validate_binding, verify_binding


ROOT = Path(__file__).parents[1]
BINDING = json.loads((ROOT / "strategy/evaluation_v5_architecture_binding_20260713.json").read_text())


def test_frozen_binding_verifies_current_document_bytes() -> None:
    checked = verify_binding(ROOT, BINDING)
    assert checked == BINDING


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.pop("protocol_id"),
        lambda value: value.update({"protocol_id": "OTHER"}),
        lambda value: value.update({"authority": {**value["authority"], "submission": True}}),
        lambda value: value["documents"].append({"path": "extra.md", "sha256": "0" * 64}),
        lambda value: value["documents"].pop(),
        lambda value: value["documents"].__setitem__(0, {**value["documents"][0], "sha256": "0" * 64}),
    ],
)
def test_binding_schema_protocol_authority_and_document_set_are_exact(mutate) -> None:
    value = deepcopy(BINDING)
    mutate(value)
    with pytest.raises(BindingVerificationError):
        verify_binding(ROOT, value)


@pytest.mark.parametrize("path", ["../escape.md", "/tmp/escape.md", "strategy/../escape.md", "strategy\\escape.md"])
def test_binding_rejects_unsafe_paths(path: str) -> None:
    value = deepcopy(BINDING)
    value["documents"][0]["path"] = path
    with pytest.raises(BindingVerificationError):
        validate_binding(value)


def test_binding_rejects_symlink_escape(tmp_path: Path) -> None:
    value = deepcopy(BINDING)
    for document in value["documents"]:
        destination = tmp_path / document["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / document["path"]).read_bytes())
    outside = tmp_path / "outside.md"
    outside.write_bytes(b"outside")
    target = tmp_path / value["documents"][0]["path"]
    target.unlink()
    target.symlink_to(outside)
    with pytest.raises(BindingVerificationError):
        verify_binding(tmp_path, value)


def test_binding_rejects_document_mutation(tmp_path: Path) -> None:
    value = deepcopy(BINDING)
    for document in value["documents"]:
        destination = tmp_path / document["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / document["path"]).read_bytes())
    mutated = tmp_path / value["documents"][0]["path"]
    mutated.write_bytes(mutated.read_bytes() + b"\nmutation")
    with pytest.raises(BindingVerificationError):
        verify_binding(tmp_path, value)


def test_binding_does_not_accept_a_repo_root_symlinked_document(tmp_path: Path) -> None:
    value = deepcopy(BINDING)
    for document in value["documents"]:
        destination = tmp_path / document["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / document["path"]).read_bytes())
    link = tmp_path / "strategy" / "evaluation_v5_scenario_contract_20260713.md"
    link.unlink()
    link.symlink_to(os.devnull)
    with pytest.raises(BindingVerificationError):
        verify_binding(tmp_path, value)
