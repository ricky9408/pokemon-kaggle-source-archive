"""Fail-closed composition of outcome-transfer promotion artifacts."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any


@dataclass(frozen=True)
class PromotionCheck:
    name: str
    passed: bool
    detail: str


def _load(path: Path, schema: str) -> dict[str, Any]:
    payload = json.loads(path.read_text())
    if payload.get("schema") != schema:
        raise ValueError(f"{path} has schema {payload.get('schema')!r}, expected {schema!r}")
    return payload


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compose_promotion_verdict(
    *,
    archive_path: Path,
    transfer_path: Path,
    candidate_path: Path,
    safety_path: Path,
    prospective_shadow_path: Path | None = None,
    holdout_path: Path | None = None,
) -> dict[str, Any]:
    transfer = _load(transfer_path, "public_transfer_validation_v1")
    candidate = _load(candidate_path, "candidate_matched_outcome_v1")
    safety = _load(safety_path, "candidate_safety_burnin_v1")
    shadow = (
        _load(prospective_shadow_path, "prospective_shadow_validation_v1")
        if prospective_shadow_path
        else None
    )
    holdout = _load(holdout_path, "sealed_holdout_verdict_v1") if holdout_path else None
    archive_hash = _sha256(archive_path)
    identity = candidate.get("candidate_identity") or {}
    label = str(candidate.get("candidate_label") or "")
    checks = [
        PromotionCheck(
            "transfer_certified",
            bool(transfer.get("transfer_certified")),
            f"panel={transfer.get('panel_id')}",
        ),
        PromotionCheck("candidate_outcomes", bool(candidate.get("passed")), label),
        PromotionCheck("safety_burnin", bool(safety.get("passed")), str(safety_path)),
        PromotionCheck(
            "archive_identity_candidate",
            identity.get("archive_sha256") == archive_hash,
            f"expected={identity.get('archive_sha256')} actual={archive_hash}",
        ),
        PromotionCheck(
            "archive_identity_safety",
            safety.get("archive_sha256") == archive_hash,
            f"expected={safety.get('archive_sha256')} actual={archive_hash}",
        ),
        PromotionCheck(
            "naming",
            "final" not in archive_path.name.lower()
            and "final" not in label.lower()
            and "codex" in label.lower()
            and re.search(r"v\d+", label.lower()) is not None,
            f"archive={archive_path.name} label={label}",
        ),
    ]
    checks.append(
        PromotionCheck(
            "prospective_shadow",
            shadow is not None and bool(shadow.get("certified")),
            str(prospective_shadow_path) if prospective_shadow_path else "missing",
        )
    )
    preholdout_open = all(check.passed for check in checks)
    checks.append(
        PromotionCheck(
            "sealed_holdout",
            holdout is not None
            and bool(holdout.get("passed"))
            and holdout.get("archive_sha256") == archive_hash
            and int(holdout.get("episodes", 0)) >= 50,
            str(holdout_path) if holdout_path else "not opened",
        )
    )
    submit_open = all(check.passed for check in checks)
    return {
        "schema": "outcome_transfer_promotion_verdict_v1",
        "archive": str(archive_path),
        "archive_sha256": archive_hash,
        "candidate_label": label,
        "checks": [asdict(check) for check in checks],
        "preholdout_open": preholdout_open,
        "submit_open": submit_open,
        "decision": "SUBMIT_AUTHORIZED" if submit_open else "CLOSED",
    }


__all__ = ["PromotionCheck", "compose_promotion_verdict"]
