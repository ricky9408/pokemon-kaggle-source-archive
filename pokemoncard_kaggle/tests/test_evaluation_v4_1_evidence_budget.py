from __future__ import annotations

import json
from pathlib import Path

import pytest

from evaluation_v4_1.evidence_budget import (
    EvidenceBudgetError,
    append_allocation,
    append_close,
    create_genesis,
    load_ledger,
)


def test_program_budget_does_not_reset_for_new_protocol_sha(tmp_path: Path) -> None:
    path = tmp_path / "budget.jsonl"
    create_genesis(path, program_id="pokemon-selector", created_at_utc="2026-07-11T08:00:00.000000Z")
    first = append_allocation(
        path,
        protocol_context_sha256="a" * 64,
        alpha_amount=0.04,
        created_at_utc="2026-07-11T08:01:00.000000Z",
    )
    assert first["remaining_alpha"] == pytest.approx(0.01)
    with pytest.raises(EvidenceBudgetError, match="budget is exceeded"):
        append_allocation(
            path,
            protocol_context_sha256="b" * 64,
            alpha_amount=0.02,
            created_at_utc="2026-07-11T08:02:00.000000Z",
        )
    assert load_ledger(path)["open_protocols"] == ["a" * 64]


def test_allocation_and_close_are_single_use(tmp_path: Path) -> None:
    path = tmp_path / "budget.jsonl"
    create_genesis(path, program_id="pokemon-selector", created_at_utc="2026-07-11T08:00:00.000000Z")
    append_allocation(
        path,
        protocol_context_sha256="a" * 64,
        alpha_amount=0.04,
        created_at_utc="2026-07-11T08:01:00.000000Z",
    )
    with pytest.raises(EvidenceBudgetError, match="duplicated"):
        append_allocation(
            path,
            protocol_context_sha256="a" * 64,
            alpha_amount=0.001,
            created_at_utc="2026-07-11T08:02:00.000000Z",
        )
    closed = append_close(
        path,
        protocol_context_sha256="a" * 64,
        disposition="FAILED",
        created_at_utc="2026-07-11T08:03:00.000000Z",
    )
    assert closed["closed_protocols"] == {"a" * 64: "FAILED"}
    with pytest.raises(EvidenceBudgetError, match="open allocation"):
        append_close(
            path,
            protocol_context_sha256="a" * 64,
            disposition="PASSED",
            created_at_utc="2026-07-11T08:04:00.000000Z",
        )


def test_hash_chain_and_backdating_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "budget.jsonl"
    create_genesis(path, program_id="pokemon-selector", created_at_utc="2026-07-11T08:00:00.000000Z")
    append_allocation(
        path,
        protocol_context_sha256="a" * 64,
        alpha_amount=0.04,
        created_at_utc="2026-07-11T08:01:00.000000Z",
    )
    lines = path.read_text().splitlines()
    event = json.loads(lines[1])
    event["alpha_amount"] = 0.001
    lines[1] = json.dumps(event, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(EvidenceBudgetError, match="hash mismatch"):
        load_ledger(path)

    second = tmp_path / "backdated.jsonl"
    create_genesis(second, program_id="pokemon-selector", created_at_utc="2026-07-11T08:00:00.000000Z")
    with pytest.raises(EvidenceBudgetError, match="timestamps move backward"):
        append_allocation(
            second,
            protocol_context_sha256="a" * 64,
            alpha_amount=0.04,
            created_at_utc="2026-07-11T07:59:00.000000Z",
        )


def test_genesis_is_create_once(tmp_path: Path) -> None:
    path = tmp_path / "budget.jsonl"
    create_genesis(path, program_id="pokemon-selector", created_at_utc="2026-07-11T08:00:00.000000Z")
    with pytest.raises(FileExistsError):
        create_genesis(path, program_id="pokemon-selector", created_at_utc="2026-07-11T08:00:00.000000Z")
