#!/usr/bin/env python3
"""Build one exact archive and produce one auditable qualification verdict."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from evaluation_v2.arena import summarize_arena  # noqa: E402
from evaluation_v2.calibration import PredictionRecord, register_prediction  # noqa: E402
from evaluation_v2.cohort import deck_sha256, load_manifest, read_deck, verify_manifest  # noqa: E402
from evaluation_v2.gateway import decide  # noqa: E402
from evaluation_v2.meta import evaluate_deck_meta  # noqa: E402
from evaluation_v2.package import (  # noqa: E402
    build_archive,
    inspect_archive,
    materialize_archive,
    sha256_file,
    source_fingerprints,
)
from evaluation_v2.replay_eval import (  # noqa: E402
    _load_agent,
    _state_key,
    _valid_action,
    compare_manifest,
    summarize,
)
from evaluation_v2.statistics import EpisodeRecord, episode_cluster_bootstrap  # noqa: E402


def pipeline_sha256() -> str:
    digest = hashlib.sha256()
    paths = sorted((REPO / "evaluation_v2").glob("*.py")) + [Path(__file__).resolve()]
    for path in paths:
        digest.update(str(path.relative_to(REPO)).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def worker_replay(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest)
    rows = compare_manifest(
        manifest=manifest,
        repo_root=REPO,
        candidate_dir=args.candidate_dir,
        baseline_dir=args.baseline_dir,
        role=args.role,
    )
    summary = summarize(rows)
    bootstrap = episode_cluster_bootstrap(
        [
            EpisodeRecord(row.candidate_main_correct, row.baseline_main_correct, row.main_compared)
            for row in rows
            if row.main_compared > 0
        ],
        seed=args.seed,
    )
    print(json.dumps({"summary": summary, "bootstrap": asdict(bootstrap)}, sort_keys=True))
    return 0


def worker_determinism(args: argparse.Namespace) -> int:
    manifest = load_manifest(args.manifest)
    errors = verify_manifest(manifest, REPO)
    if errors:
        raise ValueError("frozen cohort verification failed: " + "; ".join(errors))
    agent = _load_agent(args.candidate_dir, "determinism")
    decisions: list[tuple[str, int, dict[str, object], int, int]] = []
    for episode in manifest.episodes:
        if episode.role != "development":
            continue
        replay = json.loads(manifest.resolve_replay(REPO, episode).read_text())
        seen: set[str] = set()
        for step_index, step in enumerate(replay["steps"]):
            observation = (step[episode.target_slot].get("observation") or {})
            select = observation.get("select")
            if not select or not select.get("option"):
                continue
            key = _state_key(observation)
            if key in seen:
                continue
            seen.add(key)
            if len(select.get("option") or []) == 60:
                continue
            identity = hashlib.sha256(f"{episode.episode_id}:{step_index}:{key}".encode()).hexdigest()
            decisions.append(
                (
                    identity,
                    episode.episode_id,
                    observation,
                    int(select.get("minCount", 0)),
                    int(select.get("maxCount", len(select.get("option") or []))),
                )
            )
    selected = sorted(decisions, key=lambda item: item[0])[: args.max_decisions]
    transcript = []
    invalid = 0
    for identity, episode_id, observation, minimum, maximum in selected:
        action = agent(observation)
        option_count = len((observation.get("select") or {}).get("option") or [])
        valid = _valid_action(action, option_count, minimum, maximum)
        invalid += int(not valid)
        transcript.append({"id": identity, "episode_id": episode_id, "action": action, "valid": valid})
    encoded = json.dumps(transcript, sort_keys=True, separators=(",", ":")).encode()
    print(
        json.dumps(
            {
                "decisions": len(transcript),
                "invalid": invalid,
                "transcript_sha256": hashlib.sha256(encoded).hexdigest(),
            },
            sort_keys=True,
        )
    )
    return 0


def _docker(command: list[str], *, capture: bool = True) -> subprocess.CompletedProcess[str]:
    docker = [
        "docker", "run", "--rm", "--platform", "linux/amd64",
        "-v", f"{REPO}:/work", "-w", "/work", "python:3.11-slim",
        *command,
    ]
    return subprocess.run(docker, check=False, text=True, capture_output=capture)


def _run_replay_worker(args: argparse.Namespace, materialized: Path) -> dict[str, object]:
    command = [
        "python", "tools/qualify_candidate.py", "worker-replay",
        "--candidate-dir", str(materialized.resolve().relative_to(REPO)),
        "--baseline-dir", str(args.baseline_dir),
        "--manifest", str(args.manifest),
        "--role", "holdout",
        "--seed", str(args.seed),
    ]
    result = _docker(command)
    if result.returncode:
        raise RuntimeError(f"holdout worker failed:\n{result.stdout}\n{result.stderr}")
    return json.loads(result.stdout)


def _run_determinism_workers(args: argparse.Namespace, materialized: Path) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for _ in range(args.determinism_runs):
        command = [
            "python",
            "tools/qualify_candidate.py",
            "worker-determinism",
            "--candidate-dir",
            str(materialized.resolve().relative_to(REPO)),
            "--manifest",
            str(args.manifest),
            "--max-decisions",
            str(args.determinism_decisions),
        ]
        result = _docker(command)
        if result.returncode:
            raise RuntimeError(f"determinism worker failed:\n{result.stdout}\n{result.stderr}")
        results.append(json.loads(result.stdout))
    return results


def _run_safety(materialized: Path, report: Path) -> bool:
    command = [
        "python", "tools/audit_dudunsparce_safety.py",
        "--agent", str(materialized.resolve().relative_to(REPO)),
        "--output", str(report.resolve().relative_to(REPO)),
    ]
    result = _docker(command)
    return result.returncode == 0


def _render_report(payload: dict[str, object]) -> str:
    verdict = payload["verdict"]
    lines = [
        "# Candidate Qualification v2",
        "",
        f"Generated: {payload['generated_at_utc']}",
        "",
        f"- Candidate: `{payload['candidate']['label']}`",
        f"- Archive: `{payload['candidate']['archive']}`",
        f"- Archive SHA-256: `{payload['candidate']['archive_sha256']}`",
        f"- Cohort: `{payload['cohort_id']}`",
        f"- Gate: **{'OPEN' if verdict['open'] else 'CLOSED'}** (`{verdict['mode']}`)",
        "",
        "## Checks",
        "",
        "| Check | Pass | Actual | Requirement | Trust |",
        "| --- | --- | ---: | --- | --- |",
    ]
    for check in verdict["checks"]:
        lines.append(
            f"| `{check['name']}` | {'yes' if check['passed'] else 'no'} | {check['actual']} | "
            f"{check['requirement']} | {check['trust']} |"
        )
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in verdict["limitations"])
    return "\n".join(lines) + "\n"


def _write_preholdout_failure(
    args: argparse.Namespace,
    *,
    archive_hash: str,
    candidate_fingerprints: dict[str, str],
    manifest_id: str,
    hard_checks: dict[str, bool],
    determinism: list[dict[str, object]],
) -> int:
    failed = sorted(name for name, passed in hard_checks.items() if not passed)
    payload = {
        "schema_version": 2,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "pipeline_sha256": pipeline_sha256(),
        "stage": "preholdout_closed",
        "candidate": {
            "label": args.label,
            "archive": str(args.archive),
            "archive_sha256": archive_hash,
            **candidate_fingerprints,
        },
        "cohort_id": manifest_id,
        "hard_checks": hard_checks,
        "determinism": determinism,
        "failed_checks": failed,
        "holdout_opened": False,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "verdict.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    report = [
        "# Candidate Qualification v2",
        "",
        "- Gate: **CLOSED BEFORE HOLDOUT**",
        f"- Candidate: `{args.label}`",
        f"- Archive SHA-256: `{archive_hash}`",
        f"- Cohort: `{manifest_id}`",
        "- Holdout opened: **no**",
        "",
        "## Failed Checks",
        "",
    ]
    report.extend(f"- `{name}`" for name in failed)
    (args.output_dir / "report.md").write_text("\n".join(report) + "\n")
    print((args.output_dir / "report.md").read_text())
    return 2


def full(args: argparse.Namespace) -> int:
    args.output_dir.mkdir(parents=True, exist_ok=True)
    archive_hash = build_archive(args.candidate_dir, args.archive)
    materialized = (args.output_dir / "materialized" / f"{args.label}_{archive_hash[:16]}").resolve()
    if materialized.exists():
        raise ValueError(f"refusing to reuse materialized directory: {materialized}")
    materialize_archive(args.archive, materialized)
    manifest = load_manifest(args.manifest)
    manifest_errors = verify_manifest(manifest, REPO)
    deck = read_deck(materialized / "deck.csv")
    candidate_fingerprints = source_fingerprints(materialized)
    baseline_fingerprints = source_fingerprints(args.baseline_dir)
    hard_checks = {
        "archive_clean": not inspect_archive(args.archive),
        "archive_exact_source": candidate_fingerprints == source_fingerprints(args.candidate_dir),
        "deck_has_60_cards": len(deck) == 60,
        "deck_matches_frozen_cohort": deck_sha256(deck) == manifest.target_deck_sha256,
        "cohort_immutable": not manifest_errors,
        "engine_matches_baseline": (
            candidate_fingerprints["engine_api_sha256"] == baseline_fingerprints["engine_api_sha256"]
            and candidate_fingerprints["engine_native_sha256"] == baseline_fingerprints["engine_native_sha256"]
        ),
    }
    safety_report = args.output_dir / "dudunsparce_safety.md"
    hard_checks["linux_dudunsparce_safety"] = _run_safety(materialized, safety_report)
    determinism = _run_determinism_workers(args, materialized)
    hard_checks["determinism_run_count"] = len(determinism) >= 3
    hard_checks["cross_process_policy_determinism"] = len(
        {str(result["transcript_sha256"]) for result in determinism}
    ) == 1
    hard_checks["determinism_sample_count"] = all(
        int(result["decisions"]) >= args.determinism_decisions for result in determinism
    )
    hard_checks["determinism_zero_illegal"] = all(int(result["invalid"]) == 0 for result in determinism)
    if not all(hard_checks.values()):
        return _write_preholdout_failure(
            args,
            archive_hash=archive_hash,
            candidate_fingerprints=candidate_fingerprints,
            manifest_id=manifest.cohort_id,
            hard_checks=hard_checks,
            determinism=determinism,
        )
    replay_payload = _run_replay_worker(args, materialized)
    replay_summary = replay_payload["summary"]
    hard_checks["candidate_replay_legality"] = replay_summary["candidate_illegal"] == 0
    hard_checks["baseline_replay_legality"] = replay_summary["baseline_illegal"] == 0
    meta = evaluate_deck_meta(
        deck_cards=list(deck),
        download_summary=args.download_summary,
        leaderboard=args.leaderboard,
    )
    arena = summarize_arena(args.arena_csv, candidate=args.arena_candidate_label, baseline=args.arena_baseline_label, seed=args.seed)
    from evaluation_v2.statistics import BootstrapSummary
    bootstrap = BootstrapSummary(**replay_payload["bootstrap"])
    verdict = decide(hard_checks=hard_checks, replay=replay_summary, bootstrap=bootstrap, meta=meta, arena=arena)
    generated_at = datetime.now(timezone.utc).isoformat()
    prediction = None
    if verdict.open:
        prediction = register_prediction(
            args.prediction_ledger,
            PredictionRecord(
                created_at_utc=generated_at,
                candidate_label=args.label,
                archive_sha256=archive_hash,
                pipeline_sha256=pipeline_sha256(),
                deck_family=args.deck_family,
                meta_snapshot_id=args.meta_snapshot_id,
                baseline_label=args.baseline_label,
                metrics={
                    "candidate_main_agreement": float(replay_summary["candidate_main_agreement"]),
                    "bootstrap_q10": float(bootstrap.q10),
                    "arena_robust_q10": float(arena.robust.q10),
                    "meta_margin_over_rank10": float(meta.margin_over_rank10),
                },
                horizon_hours=args.prediction_horizon_hours,
            ),
        )
    payload = {
        "schema_version": 2,
        "generated_at_utc": generated_at,
        "pipeline_sha256": pipeline_sha256(),
        "candidate": {
            "label": args.label,
            "archive": str(args.archive),
            "archive_sha256": archive_hash,
            **candidate_fingerprints,
        },
        "baseline": {"path": str(args.baseline_dir), **baseline_fingerprints},
        "cohort_id": manifest.cohort_id,
        "determinism": determinism,
        "holdout": replay_payload,
        "meta": meta.to_dict(),
        "arena": arena.to_dict(),
        "prospective_prediction": asdict(prediction) if prediction is not None else None,
        "verdict": verdict.to_dict(),
    }
    json_path = args.output_dir / "verdict.json"
    report_path = args.output_dir / "report.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    report_path.write_text(_render_report(payload))
    print(report_path.read_text())
    return 0 if verdict.open else 2


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    subparsers = root.add_subparsers(dest="command", required=True)
    worker = subparsers.add_parser("worker-replay")
    worker.add_argument("--candidate-dir", type=Path, required=True)
    worker.add_argument("--baseline-dir", type=Path, required=True)
    worker.add_argument("--manifest", type=Path, required=True)
    worker.add_argument("--role", choices=("development", "holdout"), required=True)
    worker.add_argument("--seed", type=int, default=20260710)
    worker.set_defaults(func=worker_replay)

    determinism_worker = subparsers.add_parser("worker-determinism")
    determinism_worker.add_argument("--candidate-dir", type=Path, required=True)
    determinism_worker.add_argument("--manifest", type=Path, required=True)
    determinism_worker.add_argument("--max-decisions", type=int, default=40)
    determinism_worker.set_defaults(func=worker_determinism)

    qualify = subparsers.add_parser("full")
    qualify.add_argument("--label", required=True)
    qualify.add_argument("--candidate-dir", type=Path, required=True)
    qualify.add_argument("--baseline-dir", type=Path, required=True)
    qualify.add_argument("--archive", type=Path, required=True)
    qualify.add_argument("--manifest", type=Path, required=True)
    qualify.add_argument("--download-summary", type=Path, required=True)
    qualify.add_argument("--leaderboard", type=Path, required=True)
    qualify.add_argument("--arena-csv", type=Path, required=True)
    qualify.add_argument("--arena-candidate-label", default="codex_v161")
    qualify.add_argument("--arena-baseline-label", default="codex_v160")
    qualify.add_argument("--output-dir", type=Path, required=True)
    qualify.add_argument("--seed", type=int, default=20260710)
    qualify.add_argument("--determinism-runs", type=int, default=3)
    qualify.add_argument("--determinism-decisions", type=int, default=40)
    qualify.add_argument("--deck-family", required=True)
    qualify.add_argument("--meta-snapshot-id", required=True)
    qualify.add_argument("--baseline-label", required=True)
    qualify.add_argument(
        "--prediction-ledger",
        type=Path,
        default=REPO / "outcomes" / "prospective_predictions.jsonl",
    )
    qualify.add_argument("--prediction-horizon-hours", type=float, default=24.0)
    qualify.set_defaults(func=full)
    return root


def main() -> int:
    args = parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
