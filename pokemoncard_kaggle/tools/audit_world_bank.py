#!/usr/bin/env python3
"""Audit deterministic public-belief world generation on frozen development roots."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from evaluation_v2.cohort import load_manifest, read_deck, verify_manifest  # noqa: E402
from evaluation_v2.replay_eval import _state_key  # noqa: E402
from evaluation_v2.world_bank import build_world_bank  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--role", choices=("development", "holdout"), default="development")
    parser.add_argument("--deck", type=Path, required=True)
    parser.add_argument("--meta-snapshot", type=Path, required=True)
    parser.add_argument("--max-roots", type=int, default=105)
    parser.add_argument("--worlds", type=int, default=96)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    errors = verify_manifest(manifest, REPO)
    if errors:
        raise SystemExit("frozen cohort verification failed: " + "; ".join(errors))
    own_deck = read_deck(args.deck)
    meta_payload = json.loads(args.meta_snapshot.read_text())
    entries = meta_payload.get("entries") or []
    roots = []
    for episode in manifest.episodes:
        if episode.role != args.role:
            continue
        replay = json.loads(manifest.resolve_replay(REPO, episode).read_text())
        seen: set[str] = set()
        for step_index, step in enumerate(replay["steps"]):
            observation = step[episode.target_slot].get("observation") or {}
            select = observation.get("select") or {}
            if select.get("context") != 0 or len(select.get("option") or []) <= 1:
                continue
            key = _state_key(observation)
            if key in seen:
                continue
            seen.add(key)
            identity = hashlib.sha256(f"{episode.episode_id}:{step_index}:{key}".encode()).hexdigest()
            roots.append((identity, episode.episode_id, step_index, observation))
    selected = sorted(roots, key=lambda item: item[0])[: args.max_roots]

    built = 0
    total_worlds = 0
    invariant_failures = 0
    error_counts: Counter[str] = Counter()
    bank_hashes = []
    for _, episode_id, step_index, observation in selected:
        try:
            bank = build_world_bank(observation, own_deck, entries, world_count=args.worlds)
            noisy = copy.deepcopy(observation)
            noisy["logs"] = [{"ignored": "changed"}]
            noisy["remainingOverageTime"] = -999.0
            noisy["search_begin_input"] = "changed"
            noisy["private_note"] = {"episode": episode_id, "step": step_index}
            repeated = build_world_bank(noisy, own_deck, entries, world_count=args.worlds)
            if bank != repeated:
                invariant_failures += 1
                continue
            built += 1
            total_worlds += len(bank.worlds)
            bank_hashes.append(bank.stable_hash)
        except Exception as exc:
            error_counts[f"{type(exc).__name__}: {str(exc)}"] += 1

    payload = {
        "schema_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "manifest": str(args.manifest),
        "cohort_id": manifest.cohort_id,
        "role": args.role,
        "meta_snapshot": str(args.meta_snapshot),
        "requested_roots": len(selected),
        "resolved_roots": built,
        "coverage": built / len(selected) if selected else 0.0,
        "worlds_per_root": args.worlds,
        "total_worlds": total_worlds,
        "private_metadata_invariance_failures": invariant_failures,
        "error_counts": dict(error_counts),
        "audit_sha256": hashlib.sha256("".join(sorted(bank_hashes)).encode()).hexdigest(),
        "passed": bool(selected) and built == len(selected) and invariant_failures == 0 and total_worlds >= 10000,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(json.dumps(payload, sort_keys=True))
    return 0 if payload["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
