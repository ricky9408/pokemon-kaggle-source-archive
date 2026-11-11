#!/usr/bin/env python3
"""Run the frozen pre-cutoff engine-oracle parity experiment in Docker.

The report is create-once JSON.  It is intentionally incapable of emitting a
hosted-public oracle claim: matching local references yield only
``REFERENCE_PARITY_ONLY``.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import platform
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v3.engine_oracle import (  # noqa: E402
    ProbeFailure,
    run_reference_probe,
    unsupported_receipt,
    write_create_once_json,
)


DEFAULT_REPLAY = Path("scouting/live_top_20260710T1135_top20_e16/06_nasuo445_16371722/submission_54337127/episode-85178405-replay.json")
DEFAULT_ROOTS = Path("evaluation_artifacts/branch_bridge_v2/native_roots.jsonl")
DEFAULT_ROOT_ID = "0085bbecc265fe58d11b531b191089cc153eca03231265ccdc7d707dbc9adebe"
DEFAULT_SAMPLE = Path("references/kaggle_sample_engine_20260701/cg/libcg.so")
DEFAULT_GITHUB = Path("references/kaggle-environments-source/kaggle_environments/envs/cabt/cg/libcg.so")
DEFAULT_SOURCE = Path("references/ptcg_engine_20260701")
DEFAULT_ZIG = Path("evaluation_artifacts/native_engine/ziglinux/ziglang/zig")


def _workspace_path(path: Path) -> Path:
    return path if path.is_absolute() else (ROOT / path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--replay", type=Path, default=DEFAULT_REPLAY)
    parser.add_argument("--native-roots", type=Path, default=DEFAULT_ROOTS)
    parser.add_argument("--sample-library", type=Path, default=DEFAULT_SAMPLE)
    parser.add_argument("--github-library", type=Path, default=DEFAULT_GITHUB)
    parser.add_argument("--source-dir", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--zig", type=Path, default=DEFAULT_ZIG)
    parser.add_argument("--root-id", default=DEFAULT_ROOT_ID)
    parser.add_argument("--docker-image", default="python:3.11-slim")
    parser.add_argument("--docker-image-id", help=argparse.SUPPRESS)
    parser.add_argument("--inside-docker", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args()


def _docker_command(args: argparse.Namespace) -> list[str]:
    output = _workspace_path(args.output).resolve()
    try:
        output.relative_to(ROOT)
    except ValueError as exc:
        raise ProbeFailure("output must be inside the workspace for Docker execution") from exc
    try:
        image_id = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", args.docker_image],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ProbeFailure(f"Docker image identity unavailable: {type(exc).__name__}") from exc
    if not image_id:
        raise ProbeFailure("Docker image identity unavailable")
    command = [
        "docker", "run", "--rm", "--platform", "linux/amd64",
        "-v", f"{ROOT}:/work", "-w", "/work", args.docker_image,
        "python", "tools/run_engine_oracle_probe.py", "--inside-docker",
        "--output", "/work/" + output.relative_to(ROOT).as_posix(),
        "--docker-image", args.docker_image,
        "--docker-image-id", image_id,
        "--replay", "/work/" + _workspace_path(args.replay).resolve().relative_to(ROOT).as_posix(),
        "--native-roots", "/work/" + _workspace_path(args.native_roots).resolve().relative_to(ROOT).as_posix(),
        "--sample-library", "/work/" + _workspace_path(args.sample_library).resolve().relative_to(ROOT).as_posix(),
        "--source-dir", "/work/" + _workspace_path(args.source_dir).resolve().relative_to(ROOT).as_posix(),
        "--zig", "/work/" + _workspace_path(args.zig).resolve().relative_to(ROOT).as_posix(),
    ]
    github = _workspace_path(args.github_library).resolve()
    if github.is_file():
        command.extend(["--github-library", "/work/" + github.relative_to(ROOT).as_posix()])
    if args.root_id:
        command.extend(["--root-id", args.root_id])
    return command


def _write_failure_receipt(args: argparse.Namespace, *, stage: str, exc: BaseException, docker_identity: dict | None = None) -> None:
    """Persist expected failures as evidence, unless a prior receipt exists."""

    output = _workspace_path(args.output)
    receipt = unsupported_receipt(
        reason=f"{type(exc).__name__}: {exc}",
        stage=stage,
        replay_path=_workspace_path(args.replay),
        native_roots_path=_workspace_path(args.native_roots),
        sample_library=_workspace_path(args.sample_library),
        github_library=_workspace_path(args.github_library) if args.github_library else None,
        source_dir=_workspace_path(args.source_dir),
        zig=_workspace_path(args.zig),
        docker_identity=docker_identity,
    )
    write_create_once_json(output, receipt)


def main() -> int:
    args = parse_args()
    output = _workspace_path(args.output)
    if output.exists():
        print(f"refusing to overwrite existing report: {output}", file=sys.stderr)
        return 2
    if not args.inside_docker:
        try:
            completed = subprocess.run(_docker_command(args), check=False)
        except (ProbeFailure, OSError, ValueError, subprocess.SubprocessError) as exc:
            _write_failure_receipt(args, stage="docker_preflight", exc=exc)
            print(f"UNSUPPORTED: {output}", file=sys.stderr)
            return 1
        if completed.returncode and not output.exists():
            failure = ProbeFailure(f"Docker probe exited {completed.returncode} without a receipt")
            _write_failure_receipt(args, stage="docker_execution", exc=failure)
        return completed.returncode
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        failure = ProbeFailure("native probe requires Linux/amd64 Docker")
        _write_failure_receipt(args, stage="native_platform_preflight", exc=failure)
        print(f"UNSUPPORTED: {args.output}", file=sys.stderr)
        return 1
    try:
        if not args.docker_image_id:
            raise ProbeFailure("missing Docker image identity")
        report = run_reference_probe(
            replay_path=Path(args.replay),
            native_roots_path=Path(args.native_roots),
            sample_library=Path(args.sample_library),
            github_library=Path(args.github_library) if args.github_library else None,
            source_dir=Path(args.source_dir),
            zig=Path(args.zig),
            root_id=args.root_id,
            docker_identity={"image": args.docker_image, "image_id": args.docker_image_id, "platform": "linux/amd64"},
        )
        write_create_once_json(Path(args.output), report)
    except (OSError, ValueError, ProbeFailure, subprocess.SubprocessError) as exc:
        _write_failure_receipt(args, stage="native_preflight_or_execution", exc=exc)
        print(f"UNSUPPORTED: {args.output}", file=sys.stderr)
        return 1
    print(f"{report['verdict']}: {args.output}; omniscient_visualize_index={report['native_root']['omniscient_visualize_index']}")
    return 0 if report["verdict"] == "REFERENCE_PARITY_ONLY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
