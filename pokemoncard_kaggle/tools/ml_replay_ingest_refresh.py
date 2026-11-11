#!/usr/bin/env python3
"""Refresh the public-replay ML corpus for the current top leaderboard window.

This is the one-command wrapper for the research-only ML/RL intake loop:

1. audit whether the existing scout covers the current top window;
2. rescout public episodes if the audit says the pool is stale;
3. rebuild replay manifest + decision JSONL;
4. run the ML replay coverage report;
5. optionally train/evaluate the lightweight action-ranker baseline.

It never submits to Kaggle. The generated artifacts are freshness and training
data gates for behavior cloning, conservative offline RL, and PSRO-style
analysis.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%MZ")


def leaderboard_timestamp(path: Path) -> float:
    match = re.search(r"publicleaderboard-(\d{4}-\d{2}-\d{2}T[\d:-]+)", path.name)
    if not match:
        return path.stat().st_mtime
    stamp = match.group(1)
    date_part, time_part = stamp.split("T", 1)
    time_part = time_part.replace("-", ":")
    try:
        return datetime.fromisoformat(f"{date_part}T{time_part}+00:00").timestamp()
    except ValueError:
        return path.stat().st_mtime


def latest_leaderboard(root: Path = Path("leaderboard/current")) -> Path:
    files = list(root.glob("*publicleaderboard*.csv"))
    if not files:
        raise FileNotFoundError(f"No leaderboard CSVs found under {root}")
    return max(files, key=leaderboard_timestamp)


def latest_scout(root: Path = Path("scouting")) -> Path:
    candidates = [path for path in root.glob("live_top_*") if (path / "download_summary.csv").exists()]
    if not candidates:
        raise FileNotFoundError(f"No live_top_* scout directories with download_summary.csv under {root}")
    return max(candidates, key=lambda path: (path / "download_summary.csv").stat().st_mtime)


@dataclass
class Step:
    name: str
    command: list[str]
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    skipped: bool = False


def run_step(step: Step, dry_run: bool) -> Step:
    if dry_run:
        step.skipped = True
        return step
    result = subprocess.run(step.command, check=False, text=True, capture_output=True)
    step.returncode = result.returncode
    step.stdout = result.stdout
    step.stderr = result.stderr
    if result.returncode != 0:
        raise RuntimeError(
            f"{step.name} failed with exit code {result.returncode}\n"
            f"command: {' '.join(step.command)}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return step


def py_cmd() -> list[str]:
    return ["uv", "run", "python"] if shutil.which("uv") else [sys.executable]


def parse_audit_action(path: Path) -> str:
    if not path.exists():
        return "unknown"
    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"Recommended action:\s+\*\*([^*]+)\*\*", text)
    return match.group(1).strip().lower() if match else "unknown"


def replay_glob(scout_dir: Path) -> str:
    return str(scout_dir / "**" / "episode-*-replay.json")


def shell_expanded_replays(scout_dir: Path) -> list[str]:
    return [str(path) for path in sorted(scout_dir.glob("**/episode-*-replay.json"))]


def render_report(
    args: argparse.Namespace,
    stamp: str,
    leaderboard: Path,
    initial_scout: Path,
    working_scout: Path,
    audit_action: str,
    steps: list[Step],
    manifest: Path,
    decisions: Path,
    coverage: Path,
    ranker_report: Path | None,
    ranker_eval: Path | None,
) -> str:
    lines: list[str] = []
    lines.append("# ML Replay Ingest Refresh")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    lines.append("## Research Agent Metadata")
    lines.append("")
    lines.append("- Research agent: Codex coding agent in the local workspace")
    lines.append("- Model family exposed to this thread: GPT-5")
    lines.append(f"- Host: {socket.gethostname()}")
    lines.append(f"- Workspace: `{Path.cwd()}`")
    lines.append(f"- Command cwd metadata: pid={os.getpid()} user={os.environ.get('USER', '')}")
    lines.append("- Live submission action: none; this tool only reads Kaggle public data and writes local research artifacts.")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    lines.append(f"- Leaderboard: `{leaderboard}`")
    lines.append(f"- Initial scout: `{initial_scout}`")
    lines.append(f"- Working scout: `{working_scout}`")
    lines.append(f"- Audit action: `{audit_action}`")
    lines.append(f"- Dry run: `{args.dry_run}`")
    lines.append("")
    lines.append("## Outputs")
    lines.append("")
    lines.append(f"- Manifest: `{manifest}`")
    lines.append(f"- Decisions: `{decisions}`")
    lines.append(f"- Coverage: `{coverage}`")
    if ranker_report:
        lines.append(f"- Action-ranker report: `{ranker_report}`")
    if ranker_eval:
        lines.append(f"- MAIN action-ranker evaluation: `{ranker_eval}`")
    lines.append("")
    lines.append("## Steps")
    lines.append("")
    lines.append("| Step | Status | Command |")
    lines.append("| --- | --- | --- |")
    for step in steps:
        if step.skipped:
            status = "dry-run"
        elif step.returncode == 0:
            status = "ok"
        elif step.returncode is None:
            status = "planned"
        else:
            status = f"failed:{step.returncode}"
        command = " ".join(step.command)
        lines.append(f"| {step.name} | `{status}` | `{command}` |")
    lines.append("")
    lines.append("## Policy")
    lines.append("")
    lines.append("- Use the generated coverage report as the freshness gate before training behavior-cloning or offline-RL probes.")
    lines.append("- If audit action is `rescout`, downstream reports from the old scout are stale for submit-facing decisions.")
    lines.append("- Full-game local win rate remains fenced by replay-fidelity findings; this refresh does not create a submit-safe pair.")
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--leaderboard", type=Path)
    parser.add_argument("--scout-dir", type=Path)
    parser.add_argument("--stamp", default="")
    parser.add_argument("--team-limit", type=int, default=12)
    parser.add_argument("--critical-team-limit", type=int, default=10)
    parser.add_argument("--submissions-per-team", type=int, default=2)
    parser.add_argument("--episodes-per-submission", type=int, default=4)
    parser.add_argument("--force-rescout", action="store_true")
    parser.add_argument("--reuse-even-if-stale", action="store_true")
    parser.add_argument("--train-baseline", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--strategy-dir", type=Path, default=Path("strategy"))
    parser.add_argument("--scouting-root", type=Path, default=Path("scouting"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    stamp = args.stamp or utc_stamp()
    leaderboard = args.leaderboard or latest_leaderboard()
    initial_scout = args.scout_dir or latest_scout(args.scouting_root)
    strategy_dir = args.strategy_dir
    strategy_dir.mkdir(parents=True, exist_ok=True)

    audit_out = strategy_dir / f"live_window_audit_{stamp}_ml_ingest.md"
    manifest = strategy_dir / f"ml_replay_manifest_{stamp}_ml_ingest.csv"
    decisions = strategy_dir / f"ml_decisions_{stamp}_ml_ingest.jsonl"
    coverage = strategy_dir / f"ml_replay_coverage_{stamp}_ml_ingest.md"
    coverage_csv = strategy_dir / f"ml_replay_coverage_{stamp}_ml_ingest.csv"
    model = strategy_dir / f"action_ranker_model_{stamp}_ml_ingest.json"
    ranker_report = strategy_dir / f"action_ranker_report_{stamp}_ml_ingest.md"
    ranker_eval = strategy_dir / f"action_ranker_eval_{stamp}_ml_ingest.md"
    report_out = strategy_dir / f"ml_replay_ingest_refresh_{stamp}.md"

    steps: list[Step] = []
    audit_step = Step(
        "audit scout freshness",
        py_cmd()
        + [
            "tools/live_window_audit.py",
            "--leaderboard",
            str(leaderboard),
            "--scout-dir",
            str(initial_scout),
            "--team-limit",
            str(args.team_limit),
            "--critical-team-limit",
            str(args.critical_team_limit),
            "--output",
            str(audit_out),
        ],
    )
    steps.append(run_step(audit_step, args.dry_run))
    audit_action = parse_audit_action(audit_out) if not args.dry_run else "dry-run"

    should_rescout = args.force_rescout or audit_action == "rescout"
    if args.reuse_even_if_stale:
        should_rescout = False
    working_scout = args.scouting_root / f"live_top_{stamp}_ml_ingest" if should_rescout else initial_scout

    if should_rescout:
        scout_step = Step(
            "rescout top public episodes",
            py_cmd()
            + [
                "tools/scout_top_replays.py",
                "--leaderboard",
                str(leaderboard),
                "--output-dir",
                str(working_scout),
                "--team-limit",
                str(args.team_limit),
                "--submissions-per-team",
                str(args.submissions_per_team),
                "--episodes-per-submission",
                str(args.episodes_per_submission),
            ],
        )
        steps.append(run_step(scout_step, args.dry_run))

    replays = shell_expanded_replays(working_scout)
    if not args.dry_run and not replays:
        raise FileNotFoundError(f"No replay files found under {working_scout}")
    build_step = Step(
        "build replay ML dataset",
        py_cmd()
        + [
            "tools/build_ml_replay_dataset.py",
            *(replays if replays else [replay_glob(working_scout)]),
            "--manifest-out",
            str(manifest),
            "--decisions-out",
            str(decisions),
        ],
    )
    steps.append(run_step(build_step, args.dry_run))

    coverage_step = Step(
        "report replay ML coverage",
        py_cmd()
        + [
            "tools/ml_replay_coverage_report.py",
            "--leaderboard",
            str(leaderboard),
            "--scout-summary",
            str(working_scout / "download_summary.csv"),
            "--manifest",
            str(manifest),
            "--decisions",
            str(decisions),
            "--report-out",
            str(coverage),
            "--csv-out",
            str(coverage_csv),
            "--team-limit",
            str(args.team_limit),
            "--critical-team-limit",
            str(args.critical_team_limit),
        ],
    )
    steps.append(run_step(coverage_step, args.dry_run))

    baseline_report: Path | None = None
    baseline_eval: Path | None = None
    if args.train_baseline:
        train_step = Step(
            "train action-ranker baseline",
            py_cmd()
            + [
                "tools/train_action_ranker.py",
                str(decisions),
                "--model-out",
                str(model),
                "--report-out",
                str(ranker_report),
                "--epochs",
                "4",
                "--holdout-mod",
                "5",
                "--holdout-bucket",
                "0",
            ],
        )
        steps.append(run_step(train_step, args.dry_run))
        eval_step = Step(
            "evaluate MAIN action ranker",
            py_cmd()
            + [
                "tools/evaluate_action_ranker.py",
                str(decisions),
                "--model",
                str(model),
                "--report-out",
                str(ranker_eval),
                "--context",
                "MAIN",
                "--min-group-n",
                "20",
                "--limit",
                "20",
            ],
        )
        steps.append(run_step(eval_step, args.dry_run))
        baseline_report = ranker_report
        baseline_eval = ranker_eval

    report = render_report(
        args,
        stamp,
        leaderboard,
        initial_scout,
        working_scout,
        audit_action,
        steps,
        manifest,
        decisions,
        coverage,
        baseline_report,
        baseline_eval,
    )
    if not args.dry_run:
        report_out.write_text(report, encoding="utf-8")
    else:
        print(report)

    print(
        f"audit_action={audit_action} working_scout={working_scout} "
        f"manifest={manifest} decisions={decisions} coverage={coverage} report={report_out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
