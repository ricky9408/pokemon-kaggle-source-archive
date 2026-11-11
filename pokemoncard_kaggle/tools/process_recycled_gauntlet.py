#!/usr/bin/env python3
"""Run replay-pool gauntlets in short-lived subprocess chunks.

The native simulator can accumulate memory/state in long runs. This wrapper
keeps the host process free of `libcg` imports, builds the opponent pool once,
then runs `tools/replay_pool_gauntlet.py` in fresh subprocesses over small
opponent chunks. The resulting chunk files can be merged directly by
`tools/psro_payoff_report.py` with multiple `--gauntlet` arguments.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import socket
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import replay_pool_gauntlet as pool_tool


@dataclass(frozen=True)
class ChunkRun:
    index: int
    keys: list[str]
    candidates: list[Path]
    output: Path
    stderr: Path
    command: list[str]
    returncode: int | None


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def safe_label(text: str) -> str:
    allowed = [ch if ch.isalnum() else "_" for ch in text]
    return "_".join("".join(allowed).split("_"))[:80] or "chunk"


def rel_for_container(path: Path, workspace: Path) -> str:
    try:
        return str(path.resolve().relative_to(workspace.resolve()))
    except ValueError:
        return str(path)


def select_pool(args: argparse.Namespace) -> list[pool_tool.DeckRecord]:
    records, skipped = pool_tool.load_pool(
        args.replays,
        args.winners_only,
        not args.no_dedupe,
        args.rank_weighting,
    )
    if args.only_archetype:
        wanted = {name.replace("-", "_") for name in args.only_archetype}
        records = [record for record in records if record.archetype in wanted]
    if args.only_key:
        wanted_keys = {key.replace("_", "-") for key in args.only_key}
        records = [record for record in records if pool_tool.normalized_key(record) in wanted_keys]
    if args.max_opponents > 0:
        records = records[: args.max_opponents]
    if skipped:
        print("skipped=" + ",".join(f"{name}:{count}" for name, count in skipped.most_common()))
    return records


def chunked(values: list[str], size: int) -> list[list[str]]:
    return [values[index : index + size] for index in range(0, len(values), size)]


def base_command(args: argparse.Namespace) -> list[str]:
    workspace = args.workspace.resolve()
    if args.docker:
        return [
            "docker",
            "run",
            "-i",
            "--rm",
            "--platform",
            args.docker_platform,
            "-v",
            f"{workspace}:/work",
            "-w",
            "/work",
            args.docker_image,
            args.python,
            "tools/replay_pool_gauntlet.py",
        ]
    return [args.python, "tools/replay_pool_gauntlet.py"]


def replay_args(args: argparse.Namespace) -> list[str]:
    workspace = args.workspace.resolve()
    if args.docker:
        return [rel_for_container(path, workspace) for path in args.replays]
    return [str(path) for path in args.replays]


def candidate_args(candidates: list[Path], args: argparse.Namespace) -> list[str]:
    workspace = args.workspace.resolve()
    result: list[str] = []
    for candidate in candidates:
        result.append("--candidate")
        result.append(rel_for_container(candidate, workspace) if args.docker else str(candidate))
    return result


def make_command(args: argparse.Namespace, keys: list[str], candidates: list[Path]) -> list[str]:
    command = base_command(args)
    command.extend(replay_args(args))
    command.extend(candidate_args(candidates, args))
    command.extend(["--games", str(args.games), "--max-steps", str(args.max_steps)])
    if args.quiet:
        command.append("--quiet")
    if args.winners_only:
        command.append("--winners-only")
    if args.rank_weighting:
        command.append("--rank-weighting")
    if args.no_dedupe:
        command.append("--no-dedupe")
    for key in keys:
        command.extend(["--only-key", key])
    return command


def run_chunk(
    args: argparse.Namespace,
    output_dir: Path,
    index: int,
    keys: list[str],
    candidates: list[Path],
) -> ChunkRun:
    label = safe_label("_".join(keys))
    candidate_label = "all" if len(candidates) != 1 else safe_label(candidates[0].name)
    output = output_dir / f"chunk_{index:03d}_{candidate_label}_{label}.txt"
    stderr = output.with_suffix(".stderr.txt")
    command = make_command(args, keys, candidates)
    if args.dry_run:
        return ChunkRun(index, keys, candidates, output, stderr, command, None)
    with output.open("w", encoding="utf-8") as stdout_file, stderr.open("w", encoding="utf-8") as stderr_file:
        completed = subprocess.run(command, cwd=args.workspace, stdout=stdout_file, stderr=stderr_file, check=False)
    return ChunkRun(index, keys, candidates, output, stderr, command, completed.returncode)


def render_manifest(args: argparse.Namespace, records: list[pool_tool.DeckRecord], runs: list[ChunkRun]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = [
        "# Process-Recycled Replay Gauntlet Manifest",
        "",
        f"Generated: {now}",
        "",
        "## Research Agent Metadata",
        "",
        "- Research agent: Codex coding agent in the local workspace",
        "- Model family exposed to this thread: GPT-5",
        f"- Host: {socket.gethostname()}",
        f"- Workspace: `{args.workspace.resolve()}`",
        f"- Process metadata: pid={os.getpid()} user={os.environ.get('USER', 'unknown')}",
        "- Strategic premise: recycle simulator processes so ML/RL experiments can scale without trusting one long-lived native-engine process.",
        "",
        "## Configuration",
        "",
        f"- Docker: `{args.docker}`",
        f"- Games per seat: {args.games}",
        f"- Max steps: {args.max_steps}",
        f"- Winners only: `{args.winners_only}`",
        f"- Rank weighting: `{args.rank_weighting}`",
        f"- Opponent chunk size: {args.chunk_size}",
        f"- Candidate per process: `{args.candidate_per_process}`",
        f"- Opponents selected: {len(records)}",
        f"- Runs planned: {len(runs)}",
        "",
        "## Opponent Chunks",
        "",
        "| Run | Keys | Candidates | Return | Output | Stderr |",
        "| ---: | --- | --- | ---: | --- | --- |",
    ]
    for run in runs:
        candidates = ", ".join(f"`{candidate}`" for candidate in run.candidates)
        key_text = ", ".join(f"`{key}`" for key in run.keys)
        return_text = "-" if run.returncode is None else str(run.returncode)
        lines.append(
            f"| {run.index} | {key_text} | {candidates} | {return_text} | `{run.output}` | `{run.stderr}` |"
        )
    lines.extend(["", "## Opponent Pool", "", "| Rank | Key | Weight | Seen | Wins | Teams |", "| ---: | --- | ---: | ---: | ---: | --- |"])
    for rank, record in enumerate(records, 1):
        lines.append(
            f"| {rank} | `{pool_tool.normalized_key(record)}` | {record.weight:.2f} | "
            f"{record.seen} | {record.wins} | {'; '.join(record.teams) or '-'} |"
        )
    gauntlet_args = " ".join(f"--gauntlet {shlex.quote(str(run.output))}" for run in runs)
    lines.extend(
        [
            "",
            "## Follow-Up",
            "",
            "Merge successful chunks with:",
            "",
            "```bash",
            f"uv run python tools/psro_payoff_report.py {gauntlet_args} --candidates strategy/reset_candidates_20260620T0112_public_failure_overlay.csv --output strategy/psro_payoff_{timestamp()}_process_recycled.md",
            "```",
            "",
            "A return code of 1 can still contain useful results from `replay_pool_gauntlet.py`; inspect stderr and unfinished counts before discarding it.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("replays", nargs="+", type=Path)
    parser.add_argument("--candidate", action="append", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--games", type=int, default=4)
    parser.add_argument("--max-steps", type=int, default=1000)
    parser.add_argument("--max-opponents", type=int, default=0)
    parser.add_argument("--chunk-size", type=int, default=2)
    parser.add_argument("--only-archetype", action="append", default=[])
    parser.add_argument("--only-key", action="append", default=[])
    parser.add_argument("--winners-only", action="store_true")
    parser.add_argument("--rank-weighting", action="store_true")
    parser.add_argument("--no-dedupe", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--docker", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--docker-image", default="python:3.11-slim")
    parser.add_argument("--docker-platform", default="linux/amd64")
    parser.add_argument("--python", default="python")
    parser.add_argument("--candidate-per-process", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--fail-fast", action="store_true")
    args = parser.parse_args()

    if args.chunk_size <= 0:
        raise ValueError("--chunk-size must be positive")
    output_dir = args.output_dir or Path("strategy") / f"process_recycled_gauntlet_{timestamp()}"
    output_dir.mkdir(parents=True, exist_ok=True)

    records = select_pool(args)
    keys = [pool_tool.normalized_key(record) for record in records]
    if not keys:
        raise ValueError("No opponents selected from replay pool")

    runs: list[ChunkRun] = []
    run_index = 1
    for key_chunk in chunked(keys, args.chunk_size):
        candidate_groups = [[candidate] for candidate in args.candidate] if args.candidate_per_process else [args.candidate]
        for candidates in candidate_groups:
            run = run_chunk(args, output_dir, run_index, key_chunk, candidates)
            runs.append(run)
            print(f"run={run.index} return={run.returncode} output={run.output}")
            if args.fail_fast and run.returncode not in (None, 0):
                manifest = render_manifest(args, records, runs)
                (output_dir / "manifest.md").write_text(manifest, encoding="utf-8")
                print(manifest)
                return run.returncode or 1
            run_index += 1

    manifest = render_manifest(args, records, runs)
    (output_dir / "manifest.md").write_text(manifest, encoding="utf-8")
    print(manifest)
    return 0 if all(run.returncode in (None, 0) for run in runs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
