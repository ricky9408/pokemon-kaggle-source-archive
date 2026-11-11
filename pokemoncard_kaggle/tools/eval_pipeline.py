#!/usr/bin/env python3
"""
eval_pipeline.py — Pipeline for creating a new Grok agent version and evaluating it properly.

Continuous improvement requires continuous, multi-layer local evaluation because
Kaggle public matchmaking is noisy, low-sample, and meta-stratified.

This tool:
- Enforces the rule: new versions are always created first (with 'grok' in the name).
- Scaffolds a fresh agent directory from a base (copy + header update).
- Runs the recommended layered evaluation from the design:
  1. Basic guards + compilation + card audit + safety audits.
  2. Public decision fidelity (action agreement on real public replays).
  3. Targeted / anchored local simulation (via existing harness + direct pair evals).
  4. Pair coverage (candidate + anchor vs key opponents).
  5. Robustness + stats.
- Produces a rich scorecard + artifacts that feed the heartbeat, candidate_critic, and pre_submit_gate.
- Auto-suggests Docker for simulation steps on non-Linux (libcg.so is Linux/amd64 only).

Usage examples:
  # Create new version (ALWAYS do this before editing/fixing policy)
  uv run python tools/eval_pipeline.py --create-grok --base agents/v119_grok_dunsparce_safety \
      --next-version 120 --tag "eval_pipeline_base"

  # Full local eval of a candidate (use recent scout)
  uv run python tools/eval_pipeline.py --evaluate agents/v120_grok_eval_pipeline_base \
      --anchor agents/v116_codex_solo_runaway_guard \
      --scout-dir scouting/live_top_20260624T1527_meta \
      --games-per-matchup 5 --output-prefix strategy/eval_v120_

The output report + JSON can be consumed by heartbeat_loop / critic for promotion decisions.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent

# --- Helpers -----------------------------------------------------------------

def now_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S")

def is_linux_amd64() -> bool:
    return platform.system().lower() == "linux" and platform.machine() in ("x86_64", "amd64")

def run_cmd(cmd: list[str], cwd: Path | None = None, check: bool = False, capture: bool = True) -> dict[str, Any]:
    """Run a command, return structured result."""
    try:
        res = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            check=check,
            text=True,
            capture_output=capture,
            timeout=300,
        )
        return {
            "ok": res.returncode == 0,
            "returncode": res.returncode,
            "stdout": (res.stdout or "")[-2000:],
            "stderr": (res.stderr or "")[-2000:],
            "cmd": " ".join(shlex.quote(c) for c in cmd),
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "cmd": " ".join(shlex.quote(c) for c in cmd)}

def docker_wrap(args: list[str], workspace: Path = REPO) -> list[str]:
    """Wrap tool args (scripts + flags) to run inside container. Args should be relative (e.g. agents/xxx, tools/foo.py)."""
    return [
        "docker", "run", "-i", "--rm",
        "--platform", "linux/amd64",
        "-v", f"{workspace}:/work",
        "-w", "/work",
        "python:3.11-slim",
        "python", "-u"
    ] + args

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

# --- Agent Creation (enforces the rule) ---------------------------------------

def create_grok_agent(base: Path, next_version: int, tag: str) -> Path:
    """Create a new grok-named agent version. MUST be done before any policy fix."""
    if not base.exists() or not (base / "main.py").exists() or not (base / "deck.csv").exists():
        raise ValueError(f"Base agent invalid: {base}")

    safe_tag = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in tag)
    new_name = f"v{next_version}_grok_{safe_tag}"
    new_dir = REPO / "agents" / new_name

    if new_dir.exists():
        raise FileExistsError(f"Target already exists: {new_dir}. Bump version or choose different tag.")

    shutil.copytree(base, new_dir)

    # Clean caches
    for cache in new_dir.rglob("__pycache__"):
        shutil.rmtree(cache, ignore_errors=True)

    # Update header in main.py to mark provenance + rule compliance
    main_py = new_dir / "main.py"
    original = main_py.read_text(encoding="utf-8", errors="replace")

    header = f"""# Grok v{next_version} agent (created via eval_pipeline)
#
# Base: {base.name}
# Created: {datetime.now(UTC).isoformat()}
# Rule followed: new version created BEFORE any fixes/edits.
# This directory is the authoritative source for submission-codex-grok-... or equivalent tar.
#
# Edit policy ONLY in this new version. Never modify older vXXX_ dirs directly.
"""
    # Prepend or replace the top comment block
    if original.startswith("#"):
        # Replace first comment block
        lines = original.splitlines()
        new_lines = []
        in_header = True
        for line in lines:
            if in_header and line.startswith("#"):
                continue
            if in_header and not line.strip().startswith("#"):
                in_header = False
            if not in_header:
                new_lines.append(line)
        body = "\n".join(new_lines)
    else:
        body = original

    main_py.write_text(header + "\n" + body, encoding="utf-8")

    # Write a small MANIFEST for the version
    manifest = new_dir / "PIPELINE_MANIFEST.json"
    manifest.write_text(json.dumps({
        "version": next_version,
        "name": new_name,
        "base": str(base),
        "created_utc": datetime.now(UTC).isoformat(),
        "created_by": "eval_pipeline.py",
        "rule": "new grok version created before any modification"
    }, indent=2), encoding="utf-8")

    print(f"Created new Grok agent version: {new_dir}")
    print("Next step: edit ONLY files inside this directory, then run --evaluate on it.")
    return new_dir

# --- Layered Evaluation -------------------------------------------------------

@dataclass
class EvalReport:
    agent: str
    timestamp: str
    layers: dict[str, Any] = field(default_factory=dict)
    overall: dict[str, Any] = field(default_factory=dict)
    artifacts: list[str] = field(default_factory=list)
    verdict: str = "UNKNOWN"

def run_guards(agent_dir: Path, use_docker: bool) -> dict[str, Any]:
    results = {}
    py = run_cmd([sys.executable, "-m", "py_compile", str(agent_dir / "main.py")])
    results["py_compile"] = py

    rel_agent = str(agent_dir.relative_to(REPO)) if use_docker else str(agent_dir)
    card_args = ["tools/audit_card_id_usage.py", "--agent", rel_agent]
    card_cmd = docker_wrap(card_args) if use_docker else [sys.executable] + card_args
    results["card_audit"] = run_cmd(card_cmd)

    dud_args = ["tools/audit_dudunsparce_safety.py", "--agent", rel_agent]
    dud_cmd = docker_wrap(dud_args) if use_docker else [sys.executable] + dud_args
    results["dudunsparce_safety"] = run_cmd(dud_cmd)

    results["ok"] = all(r.get("ok", False) for r in results.values() if isinstance(r, dict) and "ok" in r)
    return results

def run_public_action_fidelity(agent_dir: Path, scout_dir: Path | None, use_docker: bool) -> dict[str, Any]:
    if not scout_dir or not scout_dir.exists():
        return {"skipped": "no scout_dir with replays provided"}

    rel_agent = str(agent_dir.resolve().relative_to(REPO)) if use_docker else str(agent_dir)
    replays = sorted(scout_dir.rglob("episode-*-replay.json"))
    if not replays:
        return {"skipped": f"no replay JSON files under {scout_dir}"}
    replay_args = [
        str(path.resolve().relative_to(REPO)) if use_docker else str(path)
        for path in replays[:80]
    ]
    output_prefix = REPO / "strategy" / f"pipeline_public_action_{agent_dir.name}_{now_stamp()}"
    output_arg = str(output_prefix.with_suffix(".md").relative_to(REPO)) if use_docker else str(output_prefix.with_suffix(".md"))
    csv_arg = str(output_prefix.with_suffix(".csv").relative_to(REPO)) if use_docker else str(output_prefix.with_suffix(".csv"))
    args = [
        "tools/public_action_mismatch_gate.py",
        "--candidate", f"new={rel_agent}",
        "--context", "MAIN",
        "--gate-context", "MAIN",
        "--max-replays", "20",
        "--min-compared", "50",
        "--output", output_arg,
        "--csv-output", csv_arg,
    ] + replay_args
    cmd = docker_wrap(args) if use_docker else [sys.executable] + args

    res = run_cmd(cmd)
    res["note"] = "Public action agreement is one of the highest-signal low-variance layers."
    res["output"] = str(output_prefix.with_suffix(".md"))
    res["csv"] = str(output_prefix.with_suffix(".csv"))
    return res

def run_anchored_league(agent_dir: Path, anchor: Path, scout_dir: Path, games: int, use_docker: bool) -> dict[str, Any]:
    """Use the existing harness for a controlled anchored league."""
    if not scout_dir.exists():
        return {"skipped": "no scout"}

    output_prefix = REPO / "strategy" / f"pipeline_league_{agent_dir.name}_{now_stamp()}"
    rel_agent = str(agent_dir.resolve().relative_to(REPO)) if use_docker else str(agent_dir)
    try:
        rel_anchor = str(anchor.resolve().relative_to(REPO)) if use_docker else str(anchor)
    except Exception:
        rel_anchor = str(anchor)
    try:
        rel_scout = str(scout_dir.resolve().relative_to(REPO)) if use_docker else str(scout_dir)
    except Exception:
        rel_scout = str(scout_dir)

    args = [
        "tools/local_top_league.py",
        "--scout-dir", rel_scout,
        "--top-limit", "6",
        "--selection-mode", "diverse",
        "--games-per-seat", str(games),
        "--max-steps", "600",
        "--output-prefix", str(output_prefix.relative_to(REPO)) if use_docker else str(output_prefix),
        "--quiet",
        "--allow-partial-top",
        "--candidate", f"new={rel_agent}",
        "--candidate", f"anchor={rel_anchor}",
    ]
    if use_docker:
        args.insert(1, "--no-docker")
    cmd = docker_wrap(args) if use_docker else [sys.executable] + args

    res = run_cmd(cmd, capture=True)
    res["output_prefix"] = str(output_prefix)
    res["note"] = "League results should be audited with audit_local_league_public_gap.py against real public anchors."
    return res

def run_pair_coverage(agent_dir: Path, anchor: Path, scout_dir: Path, games: int, use_docker: bool) -> dict[str, Any]:
    """Direct pair evaluation using run_local_battle (more controllable)."""
    rel_agent = str(agent_dir.resolve().relative_to(REPO)) if use_docker else str(agent_dir)
    try:
        rel_anchor = str(anchor.resolve().relative_to(REPO)) if use_docker else str(anchor)
    except Exception:
        rel_anchor = str(anchor)
    args = [
        "tools/run_local_battle.py",
        "--agent0", rel_agent,
        "--agent1", rel_anchor,
        "--games", str(games),
        "--max-steps", "600",
        "--quiet",
    ]
    cmd = docker_wrap(args) if use_docker else [sys.executable] + args

    res = run_cmd(cmd)
    return {"forward": res, "note": "For full pair robustness, also run swapped + against counter archetypes from scout."}

def generate_report(agent: Path, results: EvalReport, out_prefix: Path) -> Path:
    report_path = out_prefix.with_suffix(".md")
    ensure_dir(report_path.parent)

    lines = [
        f"# Local Eval Pipeline Report — {agent.name}",
        f"Generated: {results.timestamp}",
        "",
        "## Layers",
    ]

    for layer, data in results.layers.items():
        lines.append(f"\n### {layer}")
        if isinstance(data, dict):
            for k, v in data.items():
                if k in ("stdout", "stderr") and isinstance(v, str):
                    lines.append(f"  {k}: (truncated)")
                    continue
                lines.append(f"  {k}: {v}")
        else:
            lines.append(str(data))

    lines.append("\n## Overall Verdict")
    lines.append(results.verdict)
    lines.append("\n## Next Steps")
    lines.append("- Feed report + league CSV into candidate_critic_harness / pre_submit_gate.")
    lines.append("- If promising on multiple layers and no public-action regression, consider promotion.")
    lines.append("- Remember: only create new vNNN_grok_* versions for changes.")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    results.artifacts.append(str(report_path))
    return report_path

def main() -> int:
    parser = argparse.ArgumentParser(description="Create Grok agent + run proper layered local evaluation.")
    parser.add_argument("--create-grok", action="store_true", help="Create a new vNNN_grok_* agent from base (MANDATORY before edits)")
    parser.add_argument("--base", type=Path, help="Base agent dir to copy (e.g. agents/v119_grok_... or v116)")
    parser.add_argument("--next-version", type=int, help="Next version number")
    parser.add_argument("--tag", default="pipeline", help="Short tag for the new agent dir")

    parser.add_argument("--evaluate", type=Path, help="Agent dir to evaluate")
    parser.add_argument("--anchor", type=Path, default=Path("agents/v116_codex_solo_runaway_guard"), help="Current stable anchor for pair tests")
    parser.add_argument("--scout-dir", type=Path, default=Path("scouting/live_top_20260624T1527_meta"), help="Scout with replays for fidelity + league")
    parser.add_argument("--games-per-matchup", type=int, default=3)
    parser.add_argument("--output-prefix", type=Path, default=Path("strategy/pipeline_eval"))
    parser.add_argument("--force-docker", action="store_true", help="Force docker even if native might work")

    args = parser.parse_args()

    use_docker = args.force_docker or not is_linux_amd64()

    if args.create_grok:
        if not args.base or not args.next_version:
            print("ERROR: --create-grok requires --base and --next-version")
            return 2
        new_dir = create_grok_agent(args.base, args.next_version, args.tag)
        print(f"\nNew version ready: {new_dir}")
        print("Run with --evaluate on the new dir next.")
        return 0

    if args.evaluate:
        agent = args.evaluate.resolve()
        if not (agent / "main.py").exists():
            print(f"ERROR: {agent} does not look like a valid agent dir")
            return 2

        report = EvalReport(agent=str(agent), timestamp=now_stamp())

        print(f"Running layered evaluation on {agent} (docker={use_docker})...")

        # Layer 0+1: Guards + basic
        report.layers["guards"] = run_guards(agent, use_docker)

        # Layer 2: Public decision fidelity
        report.layers["public_action_fidelity"] = run_public_action_fidelity(agent, args.scout_dir, use_docker)

        # Layer 3: Anchored league
        report.layers["anchored_league"] = run_anchored_league(
            agent, args.anchor, args.scout_dir, args.games_per_matchup, use_docker
        )

        # Layer 4: Pair coverage
        report.layers["pair_vs_anchor"] = run_pair_coverage(
            agent, args.anchor, args.scout_dir, args.games_per_matchup, use_docker
        )

        # Simple verdict logic. The submit-facing gate remains stricter, but
        # the pipeline verdict should not call a candidate promising when a
        # required evaluation layer failed mechanically.
        guards_ok = report.layers["guards"].get("ok", False)
        fidelity_ok = report.layers["public_action_fidelity"].get("ok", False)
        league_ok = report.layers["anchored_league"].get("ok", False)
        pair_ok = report.layers["pair_vs_anchor"].get("forward", {}).get("ok", False)
        verdict = "PROMISING" if guards_ok and fidelity_ok and league_ok and pair_ok else "NEEDS_WORK"
        report.verdict = verdict

        out_prefix = args.output_prefix / f"{agent.name}_{now_stamp()}"
        report_path = generate_report(agent, report, out_prefix)

        # Also write JSON for machine consumption (heartbeat, critic)
        json_path = out_prefix.with_suffix(".json")
        json_path.write_text(json.dumps(report.__dict__, indent=2, default=str), encoding="utf-8")
        report.artifacts.append(str(json_path))

        print(f"\nReport written to {report_path}")
        print(f"Verdict: {verdict}")
        print("Artifacts:", report.artifacts)
        print("\nRecommended: review the report, then feed league outputs + this to candidate_critic_harness.py and pre_submit_gate.py")
        return 0

    parser.print_help()
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
