from __future__ import annotations

import hashlib

import pytest

import evaluation_v5.trust_roots as roots
from evaluation_v5.canonical import canonical_sha256


def _configure(monkeypatch):
    ancestry = b"a" * 32
    engine = b"e" * 32
    host = b"h" * 32
    safety = b"s" * 32
    provenance = b"p" * 32
    values = {
        "PINNED_ANCESTRY_AUDITOR_PUBLIC_KEY_SHA256": hashlib.sha256(ancestry).hexdigest(),
        "PINNED_ENGINE_EVIDENCE_PUBLIC_KEY_SHA256": hashlib.sha256(engine).hexdigest(),
        "PINNED_HOST_EVIDENCE_PUBLIC_KEY_SHA256": hashlib.sha256(host).hexdigest(),
        "PINNED_SAFETY_EVIDENCE_PUBLIC_KEY_SHA256": hashlib.sha256(safety).hexdigest(),
        "PINNED_PROVENANCE_EVIDENCE_PUBLIC_KEY_SHA256": hashlib.sha256(provenance).hexdigest(),
        "PINNED_CUSTODY_CA_FILE_SHA256": "c" * 64,
        "PINNED_CUSTODY_TSA_POLICY_OID": "1.2.3.4",
        "PINNED_OPENSSL_EXECUTABLE_SHA256": "d" * 64,
    }
    for name, value in values.items():
        monkeypatch.setattr(roots, name, value)
    campaign = {
        "ancestry_auditor_public_key_sha256": values[
            "PINNED_ANCESTRY_AUDITOR_PUBLIC_KEY_SHA256"
        ],
        "engine_evidence_signer_public_key_sha256": values[
            "PINNED_ENGINE_EVIDENCE_PUBLIC_KEY_SHA256"
        ],
        "host_evidence_signer_public_key_sha256": values[
            "PINNED_HOST_EVIDENCE_PUBLIC_KEY_SHA256"
        ],
        "safety_evidence_signer_public_key_sha256": values[
            "PINNED_SAFETY_EVIDENCE_PUBLIC_KEY_SHA256"
        ],
        "provenance_evidence_signer_public_key_sha256": values[
            "PINNED_PROVENANCE_EVIDENCE_PUBLIC_KEY_SHA256"
        ],
        "custody_ca_file_sha256": "c" * 64,
        "custody_tsa_policy_oid": "1.2.3.4",
    }
    campaign["trust_roots_snapshot_sha256"] = canonical_sha256(
        {
            "schema": "evaluation_v5_external_trust_roots_v1",
            "ancestry_auditor_public_key_sha256": campaign[
                "ancestry_auditor_public_key_sha256"
            ],
            "engine_evidence_signer_public_key_sha256": campaign[
                "engine_evidence_signer_public_key_sha256"
            ],
            "host_evidence_signer_public_key_sha256": campaign[
                "host_evidence_signer_public_key_sha256"
            ],
            "safety_evidence_signer_public_key_sha256": campaign[
                "safety_evidence_signer_public_key_sha256"
            ],
            "provenance_evidence_signer_public_key_sha256": campaign[
                "provenance_evidence_signer_public_key_sha256"
            ],
            "custody_ca_file_sha256": campaign["custody_ca_file_sha256"],
            "custody_tsa_policy_oid": campaign["custody_tsa_policy_oid"],
            "openssl_executable_sha256": "d" * 64,
        }
    )
    return ancestry, engine, host, safety, provenance, campaign


def test_unconfigured_roots_fail_closed() -> None:
    with pytest.raises(roots.TrustRootError, match="not independently configured"):
        roots.validate_campaign_trust_roots(
            {},
            ancestry_public_key_hex=(b"a" * 32).hex(),
            engine_evidence_public_key=b"e" * 32,
            host_evidence_public_key=b"h" * 32,
            safety_evidence_public_key=b"s" * 32,
            provenance_evidence_public_key=b"p" * 32,
        )


def test_exact_independent_roots_pass(monkeypatch) -> None:
    ancestry, engine, host, safety, provenance, campaign = _configure(monkeypatch)
    result = roots.validate_campaign_trust_roots(
        campaign,
        ancestry_public_key_hex=ancestry.hex(),
        engine_evidence_public_key=engine,
        host_evidence_public_key=host,
        safety_evidence_public_key=safety,
        provenance_evidence_public_key=provenance,
    )
    assert result["custody_ca_file_sha256"] == "c" * 64
    assert result["openssl_executable_sha256"] == "d" * 64


def test_caller_selected_key_or_campaign_fails(monkeypatch) -> None:
    ancestry, engine, host, safety, provenance, campaign = _configure(monkeypatch)
    with pytest.raises(roots.TrustRootError):
        roots.validate_campaign_trust_roots(
            campaign,
            ancestry_public_key_hex=ancestry.hex(),
            engine_evidence_public_key=b"x" * 32,
            host_evidence_public_key=host,
            safety_evidence_public_key=safety,
            provenance_evidence_public_key=provenance,
        )
    with pytest.raises(roots.TrustRootError):
        roots.validate_campaign_trust_roots(
            {**campaign, "custody_ca_file_sha256": "0" * 64},
            ancestry_public_key_hex=ancestry.hex(),
            engine_evidence_public_key=engine,
            host_evidence_public_key=host,
            safety_evidence_public_key=safety,
            provenance_evidence_public_key=provenance,
        )
