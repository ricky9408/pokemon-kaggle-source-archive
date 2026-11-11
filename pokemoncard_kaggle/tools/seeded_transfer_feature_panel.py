#!/usr/bin/env python3
"""Extract matched-seed local features for exact public-agent lineages."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import subprocess
import tempfile
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v2.public_transfer import (  # noqa: E402
    archive_policy_identity,
    load_sources,
    materialize_historical_archive,
)
from evaluation_v2.seeded_arena import (  # noqa: E402
    load_entry_isolated,
    load_seeded_game,
    run_seeded_game,
    summarize_matched_deltas,
)


def parse_control(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("control must be LABEL=AGENT_DIR")
    label, path = value.split("=", 1)
    return label, Path(path)


def _row_key(row: dict[str, Any]) -> tuple[str, str, int, int]:
    return (
        str(row["anchor"]),
        str(row["control"]),
        int(row["seed"]),
        int(row["anchor_left"]),
    )


def _run_matchup(task: dict[str, Any]) -> list[dict[str, Any]]:
    anchor_label = str(task["anchor_label"])
    control_label = str(task["control_label"])
    anchor = load_entry_isolated(anchor_label, Path(task["anchor_dir"]))
    control = load_entry_isolated(control_label, Path(task["control_dir"]))
    game = load_seeded_game(Path(task["engine_dir"]))
    rows: list[dict[str, Any]] = []
    for seed in task["seeds"]:
        for anchor_left in task.get("anchor_lefts", (1, 0)):
            left, right = (anchor, control) if anchor_left else (control, anchor)
            row = run_seeded_game(
                game,
                left,
                right,
                seed=int(seed),
                max_steps=int(task["max_steps"]),
            )
            row.update(
                {
                    "anchor": anchor_label,
                    "control": control_label,
                    "anchor_left": anchor_left,
                }
            )
            rows.append(row)
    return rows


def _failed_matchup_rows(task: dict[str, Any], error: str) -> list[dict[str, Any]]:
    return [
        {
            "seed": int(seed),
            "left": task["anchor_label"] if anchor_left else task["control_label"],
            "right": task["control_label"] if anchor_left else task["anchor_label"],
            "winner": None,
            "steps": 0,
            "error": error,
            "max_action_seconds": 0.0,
            "transcript_sha256": None,
            "anchor": task["anchor_label"],
            "control": task["control_label"],
            "anchor_left": anchor_left,
        }
        for seed in task["seeds"]
        for anchor_left in task.get("anchor_lefts", (1, 0))
    ]


def _run_matchup_subprocess(task: dict[str, Any]) -> list[dict[str, Any]]:
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "worker-matchup",
        "--anchor-label",
        str(task["anchor_label"]),
        "--anchor-dir",
        str(task["anchor_dir"]),
        "--control-label",
        str(task["control_label"]),
        "--control-dir",
        str(task["control_dir"]),
        "--engine-dir",
        str(task["engine_dir"]),
        "--max-steps",
        str(task["max_steps"]),
    ]
    for seed in task["seeds"]:
        command.extend(("--seed", str(seed)))
    for anchor_left in task.get("anchor_lefts", ()):
        command.extend(("--anchor-left", str(anchor_left)))
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=float(task["matchup_timeout_seconds"]),
        )
    except subprocess.TimeoutExpired:
        return _failed_matchup_rows(task, "worker_timeout")
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "worker failed").strip()[-1000:]
        return _failed_matchup_rows(task, f"worker_exit_{result.returncode}: {detail}")
    try:
        payload = json.loads(result.stdout)
        return list(payload["rows"])
    except (KeyError, TypeError, ValueError) as exc:
        return _failed_matchup_rows(task, f"worker_protocol_error: {exc}")


def worker_matchup_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="isolated seeded matchup worker")
    parser.add_argument("--anchor-label", required=True)
    parser.add_argument("--anchor-dir", type=Path, required=True)
    parser.add_argument("--control-label", required=True)
    parser.add_argument("--control-dir", type=Path, required=True)
    parser.add_argument("--engine-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, action="append", required=True)
    parser.add_argument("--anchor-left", type=int, choices=(0, 1), action="append")
    parser.add_argument("--max-steps", type=int, required=True)
    args = parser.parse_args(argv)
    rows = _run_matchup(
        {
            "anchor_label": args.anchor_label,
            "anchor_dir": str(args.anchor_dir),
            "control_label": args.control_label,
            "control_dir": str(args.control_dir),
            "engine_dir": str(args.engine_dir),
            "seeds": args.seed,
            "anchor_lefts": args.anchor_left or (1, 0),
            "max_steps": args.max_steps,
        }
    )
    print(json.dumps({"rows": rows}, sort_keys=True))
    return 0


def _result(
    *,
    args: argparse.Namespace,
    rows: list[dict[str, Any]],
    complete: bool,
) -> dict[str, Any]:
    ordered = sorted(rows, key=_row_key)
    return {
        "schema": "seeded_transfer_feature_panel_v1",
        "engine_manifest": json.loads((args.engine_dir / "build_manifest.json").read_text()),
        "baseline_label": args.baseline_label,
        "seeds": args.seed,
        "controls": [label for label, _ in args.control],
        "source_identities": getattr(args, "source_identities", {}),
        "rows": ordered,
        "features": summarize_matched_deltas(ordered, baseline_label=args.baseline_label),
        "errors": sum(bool(row["error"]) for row in ordered),
        "complete": complete,
    }


def _write_checkpoint(args: argparse.Namespace, rows: list[dict[str, Any]], *, complete: bool) -> None:
    result = _result(args=args, rows=rows, complete=complete)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    temporary.replace(args.output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--engine-dir", type=Path, required=True)
    parser.add_argument("--baseline-label", required=True)
    parser.add_argument("--label", action="append", help="optional source label subset")
    parser.add_argument("--control", type=parse_control, action="append", required=True)
    parser.add_argument("--seed", type=int, action="append", required=True)
    parser.add_argument("--max-steps", type=int, default=600)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--retry-errors", action="store_true")
    parser.add_argument("--matchup-timeout-seconds", type=float, default=900.0)
    parser.add_argument("--task-granularity", choices=("game", "matchup"), default="game")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    sources = load_sources(args.sources)
    if args.label:
        requested = set(args.label)
        sources = tuple(source for source in sources if source.label in requested)
        missing = requested - {source.label for source in sources}
        if missing:
            raise SystemExit("unknown source labels: " + ", ".join(sorted(missing)))
    labels = {source.label for source in sources}
    args.source_identities = {
        source.label: archive_policy_identity(ROOT / source.archive_path).__dict__
        for source in sources
    }
    all_labels = {source.label for source in load_sources(args.sources)}
    if args.baseline_label not in all_labels:
        raise SystemExit("baseline label is not in source config")
    if args.workers <= 0:
        raise SystemExit("--workers must be positive")
    existing_rows: list[dict[str, Any]] = []
    if args.resume and args.output.exists():
        existing = json.loads(args.output.read_text())
        if existing.get("schema") != "seeded_transfer_feature_panel_v1":
            raise SystemExit("cannot resume an incompatible output schema")
        if existing.get("baseline_label") != args.baseline_label:
            raise SystemExit("cannot resume with a different baseline")
        if list(existing.get("seeds") or []) != list(args.seed):
            raise SystemExit("cannot resume with different seeds")
        if list(existing.get("controls") or []) != [label for label, _ in args.control]:
            raise SystemExit("cannot resume with different controls")
        prior_identities = existing.get("source_identities")
        if prior_identities and prior_identities != args.source_identities:
            raise SystemExit("cannot resume with different source archives")
        current_engine = json.loads((args.engine_dir / "build_manifest.json").read_text())
        prior_engine = existing.get("engine_manifest") or {}
        if (
            prior_engine.get("libcg_sha256") != current_engine.get("libcg_sha256")
            or (prior_engine.get("patch") or {}).get("patch_version")
            != (current_engine.get("patch") or {}).get("patch_version")
        ):
            raise SystemExit("cannot resume with a different evaluator engine")
        existing_rows = list(existing.get("rows") or [])
    completed = {
        _row_key(row)
        for row in existing_rows
        if not args.retry_errors or not row.get("error")
    }
    with tempfile.TemporaryDirectory(prefix="ptcg-seeded-agents-") as temporary:
        root = Path(temporary)
        agent_dirs: dict[str, Path] = {}
        for source in sources:
            destination = root / source.label
            materialize_historical_archive(ROOT / source.archive_path, destination)
            agent_dirs[source.label] = destination
        control_dirs = {label: (ROOT / path).resolve() for label, path in args.control}
        tasks: list[dict[str, Any]] = []
        for anchor_label, anchor_dir in agent_dirs.items():
            for control_label, control_dir in control_dirs.items():
                expected = {
                    (anchor_label, control_label, int(seed), anchor_left)
                    for seed in args.seed
                    for anchor_left in (1, 0)
                }
                if expected <= completed:
                    continue
                base_task = {
                    "anchor_label": anchor_label,
                    "anchor_dir": str(anchor_dir),
                    "control_label": control_label,
                    "control_dir": str(control_dir),
                    "engine_dir": str(args.engine_dir.resolve()),
                    "seeds": list(args.seed),
                    "max_steps": args.max_steps,
                    "matchup_timeout_seconds": args.matchup_timeout_seconds,
                }
                if args.task_granularity == "game":
                    for _, _, seed, anchor_left in sorted(expected - completed):
                        tasks.append(
                            {
                                **base_task,
                                "seeds": [seed],
                                "anchor_lefts": [anchor_left],
                            }
                        )
                else:
                    tasks.append(base_task)
        rows = list(existing_rows)
        _write_checkpoint(args, rows, complete=not tasks)
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(_run_matchup_subprocess, task): task for task in tasks}
            for future in as_completed(futures):
                task = futures[future]
                matchup_rows = future.result()
                rows = [row for row in rows if _row_key(row) not in {_row_key(value) for value in matchup_rows}]
                rows.extend(matchup_rows)
                for row in matchup_rows:
                    print(
                        f"{row['anchor']} vs {row['control']} seed={row['seed']} "
                        f"left={row['anchor_left']} winner={row['winner']} error={row['error']}",
                        flush=True,
                    )
                _write_checkpoint(args, rows, complete=False)
    result = _result(args=args, rows=rows, complete=True)
    _write_checkpoint(args, rows, complete=True)
    print(json.dumps({key: value for key, value in result.items() if key not in {"rows", "engine_manifest"}}, indent=2))
    return 0 if result["errors"] == 0 else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "worker-matchup":
        raise SystemExit(worker_matchup_main(sys.argv[2:]))
    raise SystemExit(main())
