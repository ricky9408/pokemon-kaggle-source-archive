#!/usr/bin/env python3
"""Report the read-only, fail-closed state of evaluation v5.

This command is deliberately a status reporter, not a gate runner.  It only
reads explicitly named v5 artifacts and calls the authority-free v5 validators.
It never opens a sealed holdout, runs a candidate evaluation, or emits an
authorization decision.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v5.binding import binding_sha256, verify_binding
from evaluation_v5.canonical import canonical_sha256
from evaluation_v5.cohort import validate_registry
from evaluation_v5.engine_capabilities import (
    audit_engine_capabilities,
    validate_engine_capability_manifest,
)
from evaluation_v5.engine_evidence import audit_engine_evidence
from evaluation_v5.evidence_bound_gate import AUTHORITATIVE_IMPLEMENTATION_PATHS
from evaluation_v5.implementation_binding import verify_manifest
from evaluation_v5 import trust_roots


SCHEMA = "evaluation_v5_status_v1"
PROTOCOL_ID = "MCI_TRANSFER_V1"

DEFAULT_ARTIFACTS = {
    "architecture_binding": "strategy/evaluation_v5_architecture_binding_20260713.json",
    "engine_capability_manifest": "strategy/evaluation_v5_current_engine_capability_manifest_20260713.json",
    "implementation_binding": "strategy/evaluation_v5_implementation_binding.json",
    "signed_engine_evidence": "strategy/evaluation_v5_engine_evidence_manifest.json",
    "engine_evidence_public_key": "strategy/evaluation_v5_engine_evidence_public_key.hex",
    "signed_host_evidence": "strategy/evaluation_v5_host_evidence_manifest.json",
    "signed_provenance_evidence": "strategy/evaluation_v5_provenance_evidence_manifest.json",
    "signed_safety_evidence": "strategy/evaluation_v5_safety_evidence_manifest.json",
    "campaign_anchor": "strategy/evaluation_v5_campaign_anchor.json",
    "rfc3161_anchors": "strategy/evaluation_v5_rfc3161_anchors.json",
    "external_cohort_registry": "strategy/evaluation_v5_external_confirmatory_registry.json",
    "candidate_production_gate": "strategy/evaluation_v5_candidate_production_gate.json",
}

_DISCOVERY_PATTERNS = {
    "implementation_binding": "strategy/evaluation_v5_implementation_binding_*.json",
    "signed_engine_evidence": "strategy/evaluation_v5_engine_evidence_manifest_*.json",
    "engine_evidence_public_key": "strategy/evaluation_v5_engine_evidence_public_key_*.hex",
    "signed_host_evidence": "strategy/evaluation_v5_host_evidence_manifest_*.json",
    "signed_provenance_evidence": "strategy/evaluation_v5_provenance_evidence_manifest_*.json",
    "signed_safety_evidence": "strategy/evaluation_v5_safety_evidence_manifest_*.json",
    "campaign_anchor": "strategy/evaluation_v5_campaign_anchor_*.json",
    "rfc3161_anchors": "strategy/evaluation_v5_rfc3161_anchors_*.json",
    "external_cohort_registry": "strategy/evaluation_v5_external_confirmatory_registry_*.json",
    "candidate_production_gate": "strategy/evaluation_v5_candidate_production_gate_*.json",
}

REASON_ARCHITECTURE_BINDING_MISSING = "architecture_binding_missing"
REASON_ARCHITECTURE_BINDING_INVALID = "architecture_binding_invalid"
REASON_ENGINE_MANIFEST_MISSING = "engine_capability_manifest_missing"
REASON_ENGINE_MANIFEST_INVALID = "engine_capability_manifest_invalid"
REASON_ENGINE_CAPABILITY_GAP = "engine_capability_gap"
REASON_IMPLEMENTATION_BINDING_MISSING = "implementation_binding_missing"
REASON_IMPLEMENTATION_BINDING_INVALID = "implementation_binding_invalid"
REASON_EXTERNAL_TRUST_ROOTS_UNCONFIGURED = "external_trust_roots_unconfigured"
REASON_CAMPAIGN_ANCHOR_MISSING = "campaign_preregistration_anchor_missing"
REASON_SIGNED_HOST_EVIDENCE_MISSING = "signed_host_evidence_missing"
REASON_SIGNED_PROVENANCE_EVIDENCE_MISSING = "signed_provenance_evidence_missing"
REASON_SIGNED_SAFETY_EVIDENCE_MISSING = "signed_safety_evidence_missing"
REASON_SIGNED_ENGINE_EVIDENCE_MISSING = "signed_engine_evidence_missing"
REASON_SIGNED_ENGINE_EVIDENCE_INVALID = "signed_engine_evidence_invalid"
REASON_RFC3161_ANCHORS_MISSING = "rfc3161_anchors_missing"
REASON_RFC3161_ANCHORS_INVALID = "rfc3161_anchors_invalid"
REASON_EXTERNAL_COHORT_MISSING = "external_confirmatory_cohort_missing"
REASON_EXTERNAL_COHORT_INVALID = "external_confirmatory_cohort_invalid"
REASON_EXTERNAL_COHORT_INCOMPLETE = "external_confirmatory_cohort_incomplete"
REASON_CANDIDATE_PRODUCTION_GATE_MISSING = "candidate_production_gate_missing"

_FORBIDDEN_PATH_PARTS = frozenset({"sealed", "holdout", "sealed_holdout"})


def _closed_check(reason: str, *, detail: str | None = None, path: Path | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "CLOSED", "reason": reason}
    if detail:
        result["detail"] = detail
    if path is not None:
        result["path"] = str(path)
    return result


def _present_check(path: Path, **values: Any) -> dict[str, Any]:
    return {"status": "PASS", "path": str(path), **values}


def _relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def _is_forbidden_path(path: Path, root: Path) -> bool:
    try:
        relative = path.resolve().relative_to(root.resolve())
    except (OSError, RuntimeError, ValueError):
        relative = path
    return any(part.lower() in _FORBIDDEN_PATH_PARTS for part in relative.parts)


def _safe_candidate(root: Path, path: Path) -> Path | None:
    """Return one regular, in-repository artifact path, never a holdout path."""

    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve())
    except (OSError, RuntimeError, ValueError):
        return None
    if _is_forbidden_path(resolved, root) or not resolved.is_file() or resolved.is_symlink():
        return None
    return resolved


def _artifact_path(root: Path, name: str) -> Path | None:
    exact = _safe_candidate(root, root / DEFAULT_ARTIFACTS[name])
    if exact is not None:
        return exact
    pattern = _DISCOVERY_PATTERNS.get(name)
    if pattern is None:
        return None
    candidates = [
        candidate
        for candidate in sorted(root.glob(pattern))
        if _safe_candidate(root, candidate) is not None
    ]
    if len(candidates) != 1:
        return None
    return candidates[0].resolve()


def _load_json(path: Path) -> object:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_json_object(path: Path) -> Mapping[str, Any]:
    value = _load_json(path)
    if not isinstance(value, Mapping):
        raise ValueError("artifact must be a JSON object")
    return value


def _path_values_are_allowed(value: object, *, key: str = "") -> bool:
    """Reject receipt paths that could point at a sealed or holdout artifact."""

    if isinstance(value, Mapping):
        return all(_path_values_are_allowed(item, key=str(field)) for field, item in value.items())
    if isinstance(value, list):
        return all(_path_values_are_allowed(item, key=key) for item in value)
    if key.endswith("path") or key in {"ca_file", "ca_file_path"}:
        if isinstance(value, str):
            return not any(part.lower() in _FORBIDDEN_PATH_PARTS for part in Path(value).parts)
    return True


def _check_architecture(root: Path) -> tuple[dict[str, Any], dict[str, Any] | None, str | None]:
    path = _artifact_path(root, "architecture_binding")
    if path is None:
        return _closed_check(REASON_ARCHITECTURE_BINDING_MISSING), None, None
    try:
        checked = verify_binding(root, _load_json_object(path))
    except Exception as exc:
        return _closed_check(REASON_ARCHITECTURE_BINDING_INVALID, detail=str(exc), path=path), None, None
    return (
        _present_check(path, gate_state=checked["gate_state"]),
        checked,
        binding_sha256(checked),
    )


def _check_engine(root: Path) -> tuple[dict[str, Any], object | None, dict[str, Any] | None]:
    path = _artifact_path(root, "engine_capability_manifest")
    if path is None:
        return _closed_check(REASON_ENGINE_MANIFEST_MISSING), None, None
    try:
        manifest = validate_engine_capability_manifest(_load_json_object(path))
        audit = audit_engine_capabilities(manifest)
    except Exception as exc:
        return _closed_check(REASON_ENGINE_MANIFEST_INVALID, detail=str(exc), path=path), None, None
    if audit["decision"] != "LOCAL_FEATURE_EXTRACTION_FEASIBLE":
        return (
            _closed_check(
                REASON_ENGINE_CAPABILITY_GAP,
                detail=audit["decision"],
                path=path,
            )
            | {
                "missing_features": audit["missing_features"],
                "missing_capabilities": audit["missing_capabilities"],
                "manifest_sha256": manifest.manifest_sha256,
            },
            manifest,
            audit,
        )
    return _present_check(path, manifest_sha256=manifest.manifest_sha256), manifest, audit


def _check_implementation(
    root: Path,
    architecture: Mapping[str, Any] | None,
    architecture_sha256: str | None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    path = _artifact_path(root, "implementation_binding")
    if path is None:
        return _closed_check(REASON_IMPLEMENTATION_BINDING_MISSING), None
    if architecture is None or architecture_sha256 is None:
        return _closed_check(REASON_IMPLEMENTATION_BINDING_INVALID, detail="architecture binding is not verified", path=path), None
    try:
        checked = verify_manifest(
            root,
            _load_json_object(path),
            required_paths=AUTHORITATIVE_IMPLEMENTATION_PATHS,
        )
        if checked["architecture_binding_sha256"] != architecture_sha256:
            raise ValueError("implementation binding does not match verified architecture")
    except Exception as exc:
        return _closed_check(REASON_IMPLEMENTATION_BINDING_INVALID, detail=str(exc), path=path), None
    return _present_check(path, manifest_sha256=checked["manifest_sha256"]), checked


def _check_external_trust_roots() -> dict[str, Any]:
    configured = {
        "ancestry_auditor_key": trust_roots.PINNED_ANCESTRY_AUDITOR_PUBLIC_KEY_SHA256,
        "engine_evidence_key": trust_roots.PINNED_ENGINE_EVIDENCE_PUBLIC_KEY_SHA256,
        "host_evidence_key": trust_roots.PINNED_HOST_EVIDENCE_PUBLIC_KEY_SHA256,
        "safety_evidence_key": trust_roots.PINNED_SAFETY_EVIDENCE_PUBLIC_KEY_SHA256,
        "provenance_evidence_key": trust_roots.PINNED_PROVENANCE_EVIDENCE_PUBLIC_KEY_SHA256,
        "custody_ca": trust_roots.PINNED_CUSTODY_CA_FILE_SHA256,
        "custody_tsa_policy": trust_roots.PINNED_CUSTODY_TSA_POLICY_OID,
        "openssl_executable": trust_roots.PINNED_OPENSSL_EXECUTABLE_SHA256,
    }
    missing = sorted(name for name, value in configured.items() if value is None)
    if missing:
        return _closed_check(
            REASON_EXTERNAL_TRUST_ROOTS_UNCONFIGURED,
            detail="missing independent pins: " + ", ".join(missing),
        ) | {"missing": missing}
    return {"status": "PASS", "configured": sorted(configured)}


def _check_required_artifact(root: Path, name: str, reason: str) -> dict[str, Any]:
    path = _artifact_path(root, name)
    if path is None:
        return _closed_check(reason)
    return _closed_check(
        reason,
        detail="artifact exists but is only authoritative after composed verification",
        path=path,
    )


def _read_public_key(path: Path) -> bytes:
    raw = path.read_bytes()
    text = raw.decode("ascii").strip()
    if len(text) != 64:
        raise ValueError("engine evidence public key must be 32-byte hex")
    return bytes.fromhex(text)


def _check_engine_evidence(
    root: Path,
    engine_manifest: object | None,
) -> dict[str, Any]:
    evidence_path = _artifact_path(root, "signed_engine_evidence")
    key_path = _artifact_path(root, "engine_evidence_public_key")
    if evidence_path is None or key_path is None:
        missing = REASON_SIGNED_ENGINE_EVIDENCE_MISSING
        detail = "signed manifest" if evidence_path is None else "pinned public key"
        return _closed_check(missing, detail=f"missing {detail}")
    try:
        evidence = _load_json_object(evidence_path)
        if not _path_values_are_allowed(evidence):
            raise ValueError("engine evidence references a sealed or holdout path")
        if engine_manifest is None:
            raise ValueError("engine capability manifest is not verified")
        audit = audit_engine_evidence(
            engine_manifest,
            evidence,
            root,
            pinned_public_key=_read_public_key(key_path),
        )
    except Exception as exc:
        return _closed_check(REASON_SIGNED_ENGINE_EVIDENCE_INVALID, detail=str(exc), path=evidence_path)
    if audit.get("evidence_complete") is not True:
        return _closed_check(
            REASON_SIGNED_ENGINE_EVIDENCE_INVALID,
            detail=str(audit.get("failure_reason") or audit.get("decision")),
            path=evidence_path,
        )
    return _present_check(
        evidence_path,
        signed_manifest_sha256=audit.get("signed_manifest_sha256"),
        signer_public_key_fingerprint_sha256=audit.get("signer_public_key_fingerprint_sha256"),
    )


def _check_rfc3161_anchors(root: Path) -> dict[str, Any]:
    path = _artifact_path(root, "rfc3161_anchors")
    if path is None:
        return _closed_check(REASON_RFC3161_ANCHORS_MISSING)
    try:
        value = _load_json_object(path)
        anchors = value.get("anchors")
        if not isinstance(anchors, list) or not anchors:
            raise ValueError("anchor artifact must contain a non-empty anchors list")
        if not _path_values_are_allowed(value):
            raise ValueError("anchor artifact references a sealed or holdout path")
        # Raw token verification requires the campaign, registry, ancestry, and
        # first-hosted-game bindings.  A mere JSON receipt is never accepted.
        raise ValueError("raw RFC3161 token verification context is unavailable")
    except Exception as exc:
        return _closed_check(REASON_RFC3161_ANCHORS_INVALID, detail=str(exc), path=path)


def _check_external_cohort(root: Path) -> dict[str, Any]:
    path = _artifact_path(root, "external_cohort_registry")
    if path is None:
        return _closed_check(REASON_EXTERNAL_COHORT_MISSING)
    try:
        registry = validate_registry(_load_json_object(path))
    except Exception as exc:
        return _closed_check(REASON_EXTERNAL_COHORT_INVALID, detail=str(exc), path=path)
    count = len(registry["records"])
    if count == 0:
        return _closed_check(REASON_EXTERNAL_COHORT_INCOMPLETE, detail="zero registered archives", path=path) | {"archive_count": 0}
    return _closed_check(
        REASON_EXTERNAL_COHORT_INCOMPLETE,
        detail=f"{count} registered archives; confirmatory cohort readiness is not established by the registry alone",
        path=path,
    ) | {"archive_count": count}


def _check_candidate_production_gate(root: Path) -> dict[str, Any]:
    path = _artifact_path(root, "candidate_production_gate")
    if path is None:
        return _closed_check(REASON_CANDIDATE_PRODUCTION_GATE_MISSING)
    return _closed_check(
        REASON_CANDIDATE_PRODUCTION_GATE_MISSING,
        detail="evaluation_v5 has no authority-granting candidate production gate API",
        path=path,
    )


def build_status(repo_root: str | Path = ROOT) -> dict[str, Any]:
    """Build a deterministic read-only status report for the repository."""

    root = Path(repo_root).resolve()
    checks: dict[str, dict[str, Any]] = {}
    reasons: list[str] = []

    architecture_check, architecture, architecture_sha256 = _check_architecture(root)
    checks["architecture_binding"] = architecture_check
    engine_check, engine_manifest, engine_audit = _check_engine(root)
    checks["engine_capability_manifest"] = engine_check
    implementation_check, implementation = _check_implementation(root, architecture, architecture_sha256)
    checks["implementation_binding"] = implementation_check
    checks["external_trust_roots"] = _check_external_trust_roots()
    checks["campaign_preregistration_anchor"] = _check_required_artifact(
        root, "campaign_anchor", REASON_CAMPAIGN_ANCHOR_MISSING
    )
    checks["signed_engine_evidence"] = _check_engine_evidence(root, engine_manifest)
    checks["signed_host_evidence"] = _check_required_artifact(
        root, "signed_host_evidence", REASON_SIGNED_HOST_EVIDENCE_MISSING
    )
    checks["signed_provenance_evidence"] = _check_required_artifact(
        root, "signed_provenance_evidence", REASON_SIGNED_PROVENANCE_EVIDENCE_MISSING
    )
    checks["signed_safety_evidence"] = _check_required_artifact(
        root, "signed_safety_evidence", REASON_SIGNED_SAFETY_EVIDENCE_MISSING
    )
    checks["rfc3161_custody_anchors"] = _check_rfc3161_anchors(root)
    checks["external_confirmatory_cohort"] = _check_external_cohort(root)
    checks["candidate_production_gate"] = _check_candidate_production_gate(root)

    for check in checks.values():
        reason = check.get("reason")
        if isinstance(reason, str) and reason not in reasons:
            reasons.append(reason)

    integrity_reasons = {
        REASON_ARCHITECTURE_BINDING_INVALID,
        REASON_ENGINE_MANIFEST_INVALID,
        REASON_IMPLEMENTATION_BINDING_INVALID,
        REASON_SIGNED_ENGINE_EVIDENCE_INVALID,
        REASON_RFC3161_ANCHORS_INVALID,
        REASON_EXTERNAL_COHORT_INVALID,
    }
    decision = "NO_SUBMIT_INTEGRITY" if integrity_reasons.intersection(reasons) else "NO_SUBMIT_IDENTIFIABILITY"
    content: dict[str, Any] = {
        "authority": {
            "candidate_development": False,
            "sealed_holdout_access": False,
            "submission": False,
        },
        "checks": checks,
        "closed_reasons": reasons,
        "decision": decision,
        "inspected_sealed_holdout": False,
        "protocol_id": PROTOCOL_ID,
        "read_only": True,
        "schema": SCHEMA,
        "sealed_holdout_access": False,
        "submission_authorized": False,
    }
    return {**content, "status_sha256": canonical_sha256(content)}


def _render_text(report: Mapping[str, Any]) -> str:
    lines = [
        f"decision={report['decision']}",
        "submission_authorized=false",
        "sealed_holdout_access=false",
        "inspected_sealed_holdout=false",
        "closed_reasons=" + ",".join(report["closed_reasons"]),
    ]
    for name, check in report["checks"].items():
        state = check["status"]
        reason = f" ({check['reason']})" if "reason" in check else ""
        lines.append(f"{state} {name}{reason}")
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--json", action="store_true", help="emit the complete machine-readable report")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = build_status(args.repo_root)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(_render_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
