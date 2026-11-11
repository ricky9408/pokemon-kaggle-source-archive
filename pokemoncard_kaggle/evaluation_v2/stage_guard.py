"""Hash-bound, fail-closed evidence loading for outcome-transfer stages."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import platform
from typing import Any, Iterable, Mapping


PREREG_SCHEMA = "branch_bridge_preregistration_v2"
FORBIDDEN_EVIDENCE_KEYS = frozenset(
    {
        "outcome",
        "outcome_label",
        "reward",
        "rewards",
        "target_reward",
        "teacher_reward",
        "terminal_reward",
        "winner",
        "winner_team",
        "public_score",
        "score",
        "rank",
        "logs",
        "result",
    }
)


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def load_preregistration(path: str | Path, *, root: str | Path) -> dict[str, Any]:
    preregistration_path = Path(path)
    value = json.loads(preregistration_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema") != PREREG_SCHEMA:
        raise ValueError("unsupported branch-bridge preregistration")
    if value.get("experiment_id") != "branch_bridge_v2":
        raise ValueError("unexpected branch-bridge experiment")
    if value.get("status") != "frozen_before_stage_a_metrics":
        raise ValueError("preregistration is not frozen before Stage A")
    verify_frozen_artifacts(value, root=root)
    return value


def _artifact_records(value: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        if isinstance(value.get("path"), str) and isinstance(value.get("sha256"), str):
            yield value
        if isinstance(value.get("library_path"), str) and isinstance(value.get("library_sha256"), str):
            yield {"path": value["library_path"], "sha256": value["library_sha256"]}
        for item in value.values():
            yield from _artifact_records(item)
    elif isinstance(value, list):
        for item in value:
            yield from _artifact_records(item)


def verify_frozen_artifacts(preregistration: Mapping[str, Any], *, root: str | Path) -> None:
    workspace = Path(root).resolve()
    records = list(_artifact_records(preregistration.get("data")))
    records.extend(_artifact_records(preregistration.get("frozen_code")))
    if not records:
        raise ValueError("preregistration binds no frozen artifacts")
    for record in records:
        path = (workspace / str(record["path"])).resolve()
        if not path.is_relative_to(workspace):
            raise ValueError("frozen artifact escapes workspace")
        if not path.is_file():
            raise ValueError(f"missing frozen artifact: {record['path']}")
        actual = sha256_file(path)
        if actual != record["sha256"]:
            raise ValueError(f"frozen artifact hash mismatch: {record['path']}")


def denylisted_hashes(preregistration: Mapping[str, Any]) -> frozenset[str]:
    values = {
        str(record["sha256"])
        for record in preregistration.get("forbidden_artifacts") or ()
        if isinstance(record, Mapping) and isinstance(record.get("sha256"), str)
    }
    if not values:
        raise ValueError("preregistration has no technical denylist")
    return frozenset(values)


def reject_denylisted_artifact(path: str | Path, preregistration: Mapping[str, Any]) -> None:
    actual = sha256_file(path)
    if actual in denylisted_hashes(preregistration):
        raise ValueError(f"denylisted artifact sha256: {actual}")


def forbidden_paths(value: Any, *, path: tuple[str, ...] = ()) -> tuple[str, ...]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            child = (*path, str(key))
            if str(key) in FORBIDDEN_EVIDENCE_KEYS:
                found.append(".".join(child))
            found.extend(forbidden_paths(item, path=child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(forbidden_paths(item, path=(*path, str(index))))
    return tuple(found)


def require_outcome_blind(value: Any) -> None:
    found = forbidden_paths(value)
    if found:
        raise ValueError(f"outcome/future fields are forbidden in this stage: {found[0]}")


def stage_execution_manifest(
    *,
    stage: str,
    preregistration_path: str | Path,
    code_paths: Iterable[str | Path],
    lock_paths: Iterable[str | Path],
    dependency_versions: Mapping[str, str],
) -> dict[str, Any]:
    if stage not in {"stage_a", "stage_b", "stage_c"}:
        raise ValueError("unsupported outcome-transfer stage")
    records = []
    for path in sorted((Path(path) for path in code_paths), key=lambda value: str(value)):
        if not path.is_file():
            raise ValueError(f"missing stage code artifact: {path}")
        records.append({"logical_name": path.name, "sha256": sha256_file(path)})
    if not records:
        raise ValueError("stage execution manifest requires code artifacts")
    locks = []
    for path in sorted((Path(path) for path in lock_paths), key=lambda value: str(value)):
        if not path.is_file():
            raise ValueError(f"missing dependency lock artifact: {path}")
        locks.append({"logical_name": path.name, "sha256": sha256_file(path)})
    if not locks:
        raise ValueError("stage execution manifest requires a dependency lock")
    payload = {
        "schema": "branch_bridge_stage_execution_manifest_v2",
        "experiment_id": "branch_bridge_v2",
        "stage": stage,
        "preregistration_sha256": sha256_file(preregistration_path),
        "code": records,
        "dependency_locks": locks,
        "dependencies": {str(key): str(value) for key, value in sorted(dependency_versions.items())},
        "python": platform.python_version(),
    }
    payload["content_sha256"] = hashlib.sha256(canonical_json(payload).encode("ascii")).hexdigest()
    return payload


def verify_execution_manifest(
    manifest: Mapping[str, Any],
    *,
    stage: str,
    preregistration_path: str | Path,
    code_paths: Iterable[str | Path],
    lock_paths: Iterable[str | Path],
    dependency_versions: Mapping[str, str],
) -> None:
    expected = stage_execution_manifest(
        stage=stage,
        preregistration_path=preregistration_path,
        code_paths=code_paths,
        lock_paths=lock_paths,
        dependency_versions=dependency_versions,
    )
    if canonical_json(manifest) != canonical_json(expected):
        raise ValueError("stage execution manifest does not match current bytes")


__all__ = [
    "canonical_json",
    "denylisted_hashes",
    "forbidden_paths",
    "load_preregistration",
    "reject_denylisted_artifact",
    "require_outcome_blind",
    "sha256_file",
    "stage_execution_manifest",
    "verify_execution_manifest",
    "verify_frozen_artifacts",
]
