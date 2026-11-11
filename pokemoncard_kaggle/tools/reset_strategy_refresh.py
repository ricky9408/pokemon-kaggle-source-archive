#!/usr/bin/env python3
"""Run the reset-window strategy refresh pipeline.

This is the one-command wrapper for the 00:01 UTC workflow:

1. Audit whether the current scout still covers the leaderboard.
2. Reuse, reweight, or rescout the public replay pool.
3. Regenerate type pressure, broad/focus gauntlets, calibration, pair
   selection, decision packet, playbook, and pressure-router reports.

Use ``--dry-run`` before the quota reset to verify the exact commands without
spending Kaggle/API or simulation time.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import os
import re
import shlex
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path


DEFAULT_CANDIDATES = [
    "agents/v75_hiroingk_hammer_v57policy",
    "agents/v90_hiroingk_hammer_setup_restraint",
    "agents/v77_tubotu_plain_alakazam_v75policy",
    "agents/v61_kadoraba_nighttime_hammer",
    "agents/v82_hiroingk_hammer_dunsparce_fix",
    "agents/v72_hiroingk_hammer",
    "agents/v8_dynamic_backup",
    "agents/v36_patient_second",
    "agents/v20_hammer_target",
]

ALIAS_OVERRIDES = {
    "pure-crustle-v2": "v8",
    "submission-crustle.tar.gz": "v8",
    "submission-crustle-backup-v4.tar.gz": "v8",
    "crustle-backup-v4": "v8",
    "kenn-ethan-patient-second-v36": "v36",
    "submission-kenn-ethan-patient-second-v36.tar.gz": "v36",
    "crustle-strayuru-hammer-target-v20": "v20",
    "submission-crustle-strayuru-hammer-target-v20.tar.gz": "v20",
}

FOCUS_ARCHETYPES = [
    "alakazam-hammer",
    "alakazam-battle-cage",
    "alakazam-nighttime-hammer",
    "alakazam",
]


@dataclass
class StepResult:
    name: str
    command: list[str]
    output: Path | None = None
    skipped: bool = False


def now_stamp() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")


def latest_by_mtime(pattern: str) -> Path:
    files = [path for path in Path(".").glob(pattern)]
    if not files:
        raise FileNotFoundError(f"No files match {pattern}")
    return max(files, key=lambda path: path.stat().st_mtime)


def leaderboard_timestamp(path: Path) -> dt.datetime:
    match = re.search(r"publicleaderboard-(\d{4}-\d{2}-\d{2}T[\d:-]+)\.csv$", path.name)
    if match:
        date_part, time_part = match.group(1).split("T", 1)
        time_part = time_part.replace("-", ":")
        return dt.datetime.fromisoformat(f"{date_part}T{time_part}").replace(tzinfo=dt.UTC)
    return dt.datetime.fromtimestamp(path.stat().st_mtime, dt.UTC)


def latest_leaderboard() -> Path:
    files = [path for path in Path("leaderboard/current").glob("*publicleaderboard*.csv")]
    if not files:
        raise FileNotFoundError("No files match leaderboard/current/*publicleaderboard*.csv")
    return max(files, key=leaderboard_timestamp)



def latest_scout() -> Path:
    candidates = [path for path in Path("scouting").glob("live_top_*") if (path / "download_summary.csv").exists()]
    if not candidates:
        raise FileNotFoundError("No scouting/live_top_* directories with download_summary.csv found")
    return max(candidates, key=lambda path: path.stat().st_mtime)


def latest_candidate_csv() -> Path:
    return latest_by_mtime("strategy/reset_candidates_*.csv")


def shell_join(command: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def display_command(command: list[str]) -> str:
    replay_count = sum(1 for part in command if "episode-" in part and part.endswith("-replay.json"))
    compact: list[str] = []
    inserted_replay_marker = False
    for part in command:
        if "**/episode-*-replay.json" in part:
            compact.append("<replay-json glob>")
            continue
        is_replay = "episode-" in part and part.endswith("-replay.json")
        if is_replay:
            if not inserted_replay_marker:
                compact.append(f"<{replay_count} replay-json files>")
                inserted_replay_marker = True
            continue
        compact.append(part)
    text = shell_join(compact)
    if len(text) > 700:
        return text[:650] + " ... <truncated>"
    return text


def run_command(command: list[str], output: Path | None, dry_run: bool, cwd: Path) -> str:
    if dry_run:
        return ""
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(command, cwd=cwd, check=True, text=True, capture_output=True)
    text = result.stdout
    if result.stderr:
        text += ("\n" if text else "") + result.stderr
    if output:
        output.write_text(text, encoding="utf-8")
    return text


def parse_audit_action(text: str, fallback: str = "reuse-existing") -> str:
    match = re.search(r"Recommended action:\s+\*\*([^*]+)\*\*", text)
    return match.group(1).strip() if match else fallback


def replay_files(scout_dir: Path, compact: bool = False) -> list[str]:
    if compact:
        return [f"{scout_dir}/**/episode-*-replay.json"]
    files = sorted(scout_dir.glob("**/episode-*-replay.json"))
    if not files:
        raise FileNotFoundError(f"No replay JSON files under {scout_dir}")
    return [str(path) for path in files]


def docker_prefix(image: str, cwd: Path) -> list[str]:
    return [
        "docker",
        "run",
        "-i",
        "--rm",
        "--platform",
        "linux/amd64",
        "-v",
        f"{cwd}:/work",
        "-w",
        "/work",
        image,
        "python",
    ]


def read_cutoff(leaderboard: Path) -> float:
    with leaderboard.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            if row.get("Rank") == "10":
                return float(row["Score"])
    raise ValueError(f"Could not find rank 10 in {leaderboard}")


def candidate_alias(text: str) -> str:
    lowered = text.lower()
    for needle, alias in ALIAS_OVERRIDES.items():
        if needle in lowered:
            return alias
    match = re.search(r"\bv(\d+)\b|v(\d+)_|-(v\d+)\b", lowered)
    if match:
        for group in match.groups():
            if group:
                return group if group.startswith("v") else f"v{group}"
    return Path(text).stem


def parse_weighted_rates(gauntlet: Path) -> dict[str, str]:
    rates: dict[str, str] = {}
    current: str | None = None
    with gauntlet.open() as handle:
        for raw in handle:
            line = raw.strip()
            if line.startswith("Candidate "):
                current = candidate_alias(line)
            elif current and line.startswith("weighted_win_rate,"):
                rates[current] = line.split(",", 1)[1]
                current = None
    return rates


def update_candidate_evidence(base: Path, broad: Path, output: Path) -> None:
    rates = parse_weighted_rates(broad)
    with base.open(newline="") as handle:
        rows = list(csv.DictReader(handle))
        fieldnames = list(rows[0].keys()) if rows else []
    for row in rows:
        alias = candidate_alias(f"{row.get('candidate', '')} {row.get('path', '')}")
        if alias in rates:
            row["replay_win_rate"] = rates[alias]
            note = row.get("notes", "")
            marker = f"reset-pipeline broad={rates[alias]}"
            row["notes"] = note if marker in note else f"{note} {marker}".strip()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def parse_pair_from_packet(path: Path) -> tuple[str, str] | None:
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"Strategic latest-two pair:\s+`([^`]+)`\s+then\s+`([^`]+)`", text)
    if match:
        return candidate_alias(match.group(1)), candidate_alias(match.group(2))
    return None


def parse_pair_from_calibration(path: Path) -> tuple[str, str] | None:
    if not path.exists():
        return None
    first: str | None = None
    second: str | None = None
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if raw.startswith("recommended_pair_first="):
            first = candidate_alias(raw.split("=", 1)[1])
        elif raw.startswith("recommended_pair_second="):
            second = candidate_alias(raw.split("=", 1)[1])
    if first and second:
        return first, second
    return None


def render_manifest(
    args: argparse.Namespace,
    stamp: str,
    leaderboard: Path,
    initial_scout: Path,
    working_scout: Path,
    action: str,
    steps: list[StepResult],
) -> str:
    lines: list[str] = []
    lines.append("# Reset Strategy Refresh Manifest")
    lines.append("")
    lines.append(f"Generated: {dt.datetime.now(dt.UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    lines.append("## Research Agent Metadata")
    lines.append("")
    lines.append("- Research agent: Codex coding agent in the local workspace")
    lines.append("- Model family exposed to this thread: GPT-5")
    lines.append(f"- Host: {socket.gethostname()}")
    lines.append(f"- Workspace: `{Path.cwd()}`")
    lines.append(f"- Process metadata: pid={os.getpid()} user={os.environ.get('USER', 'unknown')}")
    lines.append("- Strategic premise: reset submissions should be chosen from current pressure lanes, not from a single strongest-deck myth.")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    lines.append(f"- Stamp: `{stamp}`")
    lines.append(f"- Leaderboard: `{leaderboard}`")
    lines.append(f"- Initial scout: `{initial_scout}`")
    lines.append(f"- Working scout: `{working_scout}`")
    lines.append(f"- Audit action: `{action}`")
    lines.append(f"- Candidate evidence: `{args.candidates}`")
    lines.append(f"- Dry run: `{args.dry_run}`")
    lines.append("")
    lines.append("## Steps")
    lines.append("")
    lines.append("| Step | Status | Output | Command |")
    lines.append("| --- | --- | --- | --- |")
    for step in steps:
        status = "skipped" if step.skipped else ("planned" if args.dry_run else "ran")
        output = f"`{step.output}`" if step.output else "-"
        lines.append(f"| {step.name} | {status} | {output} | `{display_command(step.command)}` |")
    lines.append("")
    lines.append("## Submit Gate")
    lines.append("")
    lines.append("- This tool does not submit. Use the generated decision packet and only submit after the UTC quota reset is verified.")
    lines.append("- Submit the first and second archives recommended by the current packet, preserving the packet order.")
    lines.append("- If fresh evidence changes the route, follow the current packet and pressure-router report, not stale notes from earlier manifests.")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--leaderboard", type=Path, default=None)
    parser.add_argument("--scout-dir", type=Path, default=None)
    parser.add_argument("--candidates", type=Path, default=None)
    parser.add_argument("--stamp", default=None)
    parser.add_argument("--action", choices=["auto", "reuse-existing", "reweight-existing", "rescout"], default="auto")
    parser.add_argument("--team-limit", type=int, default=12)
    parser.add_argument("--critical-team-limit", type=int, default=10)
    parser.add_argument("--episodes-per-submission", type=int, default=8)
    parser.add_argument("--submissions-per-team", type=int, default=2)
    parser.add_argument("--broad-games", type=int, default=12)
    parser.add_argument("--focus-games", type=int, default=16)
    parser.add_argument("--max-opponents", type=int, default=12)
    parser.add_argument("--docker-image", default="python:3.11-slim")
    parser.add_argument("--candidate-agent", action="append", default=[])
    parser.add_argument(
        "--composite-source",
        action="append",
        default=[],
        type=Path,
        help="Additional cached scout directories to union before a fresh rescout when only edge teams are missing.",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip-gauntlets", action="store_true")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    cwd = Path.cwd()
    stamp = args.stamp or now_stamp()
    leaderboard = args.leaderboard or latest_leaderboard()
    scout_dir = args.scout_dir or latest_scout()
    args.candidates = args.candidates or latest_candidate_csv()
    candidate_agents = args.candidate_agent or DEFAULT_CANDIDATES
    steps: list[StepResult] = []

    audit_output = Path(f"strategy/live_window_audit_{stamp}.md")
    audit_cmd = [
        "uv",
        "run",
        "python",
        "tools/live_window_audit.py",
        "--leaderboard",
        str(leaderboard),
        "--scout-dir",
        str(scout_dir),
        "--team-limit",
        str(args.team_limit),
        "--critical-team-limit",
        str(args.critical_team_limit),
        "--output",
        str(audit_output),
    ]
    # Even in dry-run mode, the audit is cheap and local; running it makes the
    # planned downstream route match the current leaderboard instead of a guess.
    audit_text = run_command(audit_cmd, None, False, cwd)
    steps.append(StepResult("audit", audit_cmd, audit_output))
    action = args.action if args.action != "auto" else parse_audit_action(audit_text)

    working_scout = scout_dir
    if action == "rescout" and args.composite_source and not args.dry_run:
        composite_sources: list[Path] = []
        seen_sources: set[Path] = set()
        for source in [scout_dir, *args.composite_source]:
            resolved = source.resolve()
            if resolved in seen_sources:
                continue
            seen_sources.add(resolved)
            composite_sources.append(source)

        composite_scout = Path(f"scouting/live_top_composite_{stamp}")
        composite_cmd = [
            "uv",
            "run",
            "python",
            "tools/composite_scout.py",
            "--leaderboard",
            str(leaderboard),
            "--output",
            str(composite_scout),
            "--team-limit",
            str(args.team_limit),
            "--mode",
            "hardlink",
        ]
        for source in composite_sources:
            composite_cmd.extend(["--source", str(source)])
        try:
            run_command(composite_cmd, None, False, cwd)
            steps.append(StepResult("composite scout", composite_cmd, composite_scout / "composite_manifest.md"))

            composite_audit_output = Path(f"strategy/live_window_audit_{stamp}_composite.md")
            composite_audit_cmd = [
                "uv",
                "run",
                "python",
                "tools/live_window_audit.py",
                "--leaderboard",
                str(leaderboard),
                "--scout-dir",
                str(composite_scout),
                "--team-limit",
                str(args.team_limit),
                "--critical-team-limit",
                str(args.critical_team_limit),
                "--output",
                str(composite_audit_output),
            ]
            composite_audit_text = run_command(composite_audit_cmd, None, False, cwd)
            steps.append(StepResult("audit composite scout", composite_audit_cmd, composite_audit_output))
            composite_action = parse_audit_action(composite_audit_text, fallback="rescout")
            if composite_action != "rescout":
                working_scout = composite_scout
                action = composite_action
        except (subprocess.CalledProcessError, FileExistsError, FileNotFoundError, ValueError) as error:
            steps.append(
                StepResult(
                    "composite scout",
                    [*composite_cmd, f"<failed: {error}>"],
                    composite_scout / "composite_manifest.md",
                    skipped=True,
                )
            )

    if action == "reweight-existing":
        source_scout = working_scout
        working_scout = Path(f"scouting/{source_scout.name}_reweighted_{stamp}")
        cmd = [
            "uv",
            "run",
            "python",
            "tools/reweight_scout.py",
            "--source",
            str(source_scout),
            "--leaderboard",
            str(leaderboard),
            "--output",
            str(working_scout),
            "--mode",
            "hardlink",
        ]
        run_command(cmd, None, args.dry_run, cwd)
        steps.append(StepResult("reweight scout", cmd, working_scout / "reweight_manifest.md"))
    elif action == "rescout":
        working_scout = Path(f"scouting/live_top_{stamp}")
        cmd = [
            "uv",
            "run",
            "python",
            "tools/scout_top_replays.py",
            "--leaderboard",
            str(leaderboard),
            "--output-dir",
            str(working_scout),
            "--team-limit",
            str(args.team_limit),
            "--episodes-per-submission",
            str(args.episodes_per_submission),
            "--submissions-per-team",
            str(args.submissions_per_team),
        ]
        run_command(cmd, Path(f"strategy/scout_top_{stamp}.log"), args.dry_run, cwd)
        steps.append(StepResult("rescout top window", cmd, working_scout / "download_summary.csv"))

    files = replay_files(working_scout, compact=args.dry_run)
    analyze_output = Path(f"strategy/analyze_replays_{stamp}.txt")
    analyze_cmd = ["uv", "run", "python", "tools/analyze_replays.py", *files, "--top", "24"]
    run_command(analyze_cmd, analyze_output, args.dry_run, cwd)
    steps.append(StepResult("analyze replays", analyze_cmd, analyze_output))

    type_output = Path(f"strategy/type_pressure_{stamp}.md")
    type_cmd = [
        "uv",
        "run",
        "python",
        "tools/type_pressure_report.py",
        *files,
        "--winners-only",
        "--rank-weighting",
        "--agent",
        "agents/v75_hiroingk_hammer_v57policy",
        "--output",
        str(type_output),
    ]
    run_command(type_cmd, None, args.dry_run, cwd)
    steps.append(StepResult("type pressure", type_cmd, type_output))

    broad_output = Path(f"strategy/replay_pool_{stamp}_broad_shortlist.txt")
    focus_output = Path(f"strategy/replay_pool_{stamp}_alakazam_focus.txt")
    if args.skip_gauntlets:
        steps.append(StepResult("broad gauntlet", [], broad_output, skipped=True))
        steps.append(StepResult("focus gauntlet", [], focus_output, skipped=True))
    else:
        broad_cmd = [
            *docker_prefix(args.docker_image, cwd),
            "tools/replay_pool_gauntlet.py",
            *files,
        ]
        for candidate in candidate_agents:
            broad_cmd.extend(["--candidate", candidate])
        broad_cmd.extend(
            [
                "--games",
                str(args.broad_games),
                "--winners-only",
                "--rank-weighting",
                "--max-opponents",
                str(args.max_opponents),
                "--quiet",
            ]
        )
        run_command(broad_cmd, broad_output, args.dry_run, cwd)
        steps.append(StepResult("broad gauntlet", broad_cmd, broad_output))

        focus_cmd = [
            *docker_prefix(args.docker_image, cwd),
            "tools/replay_pool_gauntlet.py",
            *files,
        ]
        for candidate in candidate_agents:
            focus_cmd.extend(["--candidate", candidate])
        focus_cmd.extend(["--games", str(args.focus_games), "--winners-only", "--rank-weighting"])
        for archetype in FOCUS_ARCHETYPES:
            focus_cmd.extend(["--only-archetype", archetype])
        focus_cmd.append("--quiet")
        run_command(focus_cmd, focus_output, args.dry_run, cwd)
        steps.append(StepResult("focus gauntlet", focus_cmd, focus_output))

    card_strategy_output = Path(f"strategy/card_pool_strategy_{stamp}.md")
    card_strategy_cmd = [
        "uv",
        "run",
        "python",
        "tools/strategy_research.py",
        *files,
        "--cards",
        "data/EN_Card_Data.csv",
        "--top-groups",
        "14",
        "--winners-only",
        "--rank-weighting",
    ]
    for candidate in candidate_agents:
        card_strategy_cmd.extend(["--agent", candidate])
    if not args.skip_gauntlets:
        card_strategy_cmd.extend(["--broad-gauntlet", str(broad_output), "--focus-gauntlet", str(focus_output)])
    card_strategy_cmd.extend(["--output", str(card_strategy_output)])
    run_command(card_strategy_cmd, None, args.dry_run, cwd)
    steps.append(StepResult("card-pool strategy", card_strategy_cmd, card_strategy_output))

    evidence_output = Path(f"strategy/reset_candidates_{stamp}.csv")
    if not args.dry_run and not args.skip_gauntlets:
        update_candidate_evidence(args.candidates, broad_output, evidence_output)
    steps.append(StepResult("candidate evidence refresh", ["internal", "update_candidate_evidence"], evidence_output, skipped=args.dry_run or args.skip_gauntlets))

    matrix_output = Path(f"strategy/strategy_matrix_{stamp}.md")
    matrix_cmd = [
        "uv",
        "run",
        "python",
        "tools/strategy_matrix.py",
        *files,
        "--gauntlet-output",
        str(broad_output),
        "--winners-only",
        "--rank-weighting",
        "--only-with-results",
        "--output",
        str(matrix_output),
    ]
    run_command(matrix_cmd, None, args.dry_run or args.skip_gauntlets, cwd)
    steps.append(StepResult("strategy matrix", matrix_cmd, matrix_output, skipped=args.skip_gauntlets))

    drift_output = Path(f"strategy/strategy_drift_{stamp}.md")
    recent_gauntlets = sorted(Path("strategy").glob("replay_pool_*confirm.txt"), key=lambda path: path.stat().st_mtime)[-3:]
    drift_cmd = [
        "uv",
        "run",
        "python",
        "tools/strategy_drift_dashboard.py",
        *[str(path) for path in recent_gauntlets],
        str(broad_output),
        "--candidate-evidence",
        str(evidence_output if evidence_output.exists() else args.candidates),
        "--output",
        str(drift_output),
    ]
    run_command(drift_cmd, None, args.dry_run or args.skip_gauntlets, cwd)
    steps.append(StepResult("strategy drift", drift_cmd, drift_output, skipped=args.skip_gauntlets))

    calibration_output = Path(f"strategy/calibrated_rank_{stamp}.txt")
    calibration_cmd = [
        "uv",
        "run",
        "python",
        "tools/calibrated_candidate_rank.py",
        "--candidates",
        str(evidence_output if evidence_output.exists() else args.candidates),
        "--top10-target",
        f"{read_cutoff(leaderboard):.1f}",
    ]
    run_command(calibration_cmd, calibration_output, args.dry_run or args.skip_gauntlets, cwd)
    steps.append(StepResult("calibration", calibration_cmd, calibration_output, skipped=args.skip_gauntlets))

    pair_output = Path(f"strategy/pair_strategy_selector_{stamp}.md")
    pair_cmd = [
        "uv",
        "run",
        "python",
        "tools/pair_strategy_selector.py",
        "--broad",
        str(broad_output),
        "--focus",
        str(focus_output),
        "--drift",
        str(drift_output),
        "--candidates",
        str(evidence_output if evidence_output.exists() else args.candidates),
        "--output",
        str(pair_output),
    ]
    run_command(pair_cmd, None, args.dry_run or args.skip_gauntlets, cwd)
    steps.append(StepResult("pair selector", pair_cmd, pair_output, skipped=args.skip_gauntlets))

    packet_output = Path(f"strategy/strategy_decision_packet_{stamp}.md")
    packet_cmd = [
        "uv",
        "run",
        "python",
        "tools/strategy_decision_packet.py",
        "--leaderboard",
        str(leaderboard),
        "--candidates",
        str(evidence_output if evidence_output.exists() else args.candidates),
        "--calibration",
        str(calibration_output),
        "--gauntlet-output",
        str(broad_output),
        "--focus-output",
        str(focus_output),
        "--type-report",
        str(type_output),
        "--quota-note",
        "Refresh run only; verify UTC quota before submitting.",
        "--output",
        str(packet_output),
    ]
    run_command(packet_cmd, None, args.dry_run or args.skip_gauntlets, cwd)
    steps.append(StepResult("decision packet", packet_cmd, packet_output, skipped=args.skip_gauntlets))

    blindspot_output = Path(f"strategy/strategy_blindspot_backlog_{stamp}.md")
    packet_pair = None if args.dry_run or args.skip_gauntlets else parse_pair_from_packet(packet_output)
    calibration_pair = None if args.dry_run or args.skip_gauntlets else parse_pair_from_calibration(calibration_output)
    blindspot_pair = packet_pair or calibration_pair
    blindspot_cmd: list[str] = []
    if blindspot_pair:
        blindspot_cmd = [
            "uv",
            "run",
            "python",
            "tools/strategy_blindspot_backlog.py",
            "--window",
            f"broad:{broad_output}",
            "--window",
            f"control:{focus_output}",
            "--pair",
            blindspot_pair[0],
            "--pair",
            blindspot_pair[1],
            "--candidates",
            str(evidence_output if evidence_output.exists() else args.candidates),
            "--output",
            str(blindspot_output),
        ]
        run_command(blindspot_cmd, None, False, cwd)
    steps.append(
        StepResult(
            "blindspot backlog",
            blindspot_cmd or ["internal", "await_decision_pair"],
            blindspot_output,
            skipped=args.skip_gauntlets or args.dry_run or blindspot_pair is None,
        )
    )

    router_output = Path(f"strategy/strategy_pressure_router_{stamp}.md")
    router_cmd = [
        "uv",
        "run",
        "python",
        "tools/strategy_pressure_router.py",
        "--leaderboard",
        str(leaderboard),
        "--type-report",
        str(type_output),
        "--broad",
        str(broad_output),
        "--focus",
        str(focus_output),
        "--candidates",
        str(evidence_output if evidence_output.exists() else args.candidates),
        "--output",
        str(router_output),
    ]
    run_command(router_cmd, None, args.dry_run or args.skip_gauntlets, cwd)
    steps.append(StepResult("pressure router", router_cmd, router_output, skipped=args.skip_gauntlets))

    playbook_output = Path(f"strategy/current_strategy_playbook_{stamp}.md")
    playbook_cmd = [
        "uv",
        "run",
        "python",
        "tools/strategy_playbook.py",
        "--leaderboard",
        str(leaderboard),
        "--candidates",
        str(evidence_output if evidence_output.exists() else args.candidates),
        "--calibration",
        str(calibration_output),
        "--top-weight-confirmation",
        str(broad_output),
        "--output",
        str(playbook_output),
    ]
    run_command(playbook_cmd, None, args.dry_run or args.skip_gauntlets, cwd)
    steps.append(StepResult("playbook", playbook_cmd, playbook_output, skipped=args.skip_gauntlets))

    doctrine_output = Path(f"strategy/strategy_doctrine_{stamp}.md")
    doctrine_cmd = [
        "uv",
        "run",
        "python",
        "tools/strategy_doctrine.py",
        "--leaderboard",
        str(leaderboard),
        "--type-report",
        str(type_output),
        "--broad",
        str(broad_output),
        "--focus",
        str(focus_output),
        "--candidates",
        str(evidence_output if evidence_output.exists() else args.candidates),
        "--blindspot",
        str(blindspot_output),
        "--output",
        str(doctrine_output),
    ]
    run_command(doctrine_cmd, None, args.dry_run or args.skip_gauntlets, cwd)
    steps.append(StepResult("strategy doctrine", doctrine_cmd, doctrine_output, skipped=args.skip_gauntlets))

    manifest = render_manifest(args, stamp, leaderboard, scout_dir, working_scout, action, steps)
    output = args.output or Path(f"strategy/reset_strategy_refresh_{stamp}.md")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(manifest, encoding="utf-8")
    print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
