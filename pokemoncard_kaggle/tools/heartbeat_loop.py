#!/usr/bin/env python3
"""Self-improving submission loop — the orchestrator the pipeline was missing.

The repo had 71 one-shot tools and NO driver. This is the driver. It is a single
one-shot, idempotent, crash-safe tick: run it on a ~1-hour schedule (cron /
launchd / scheduled-tasks) and each invocation advances the closed loop by one
tick. There is no internal `while`/`sleep`; the host scheduler owns the cadence.

What one tick does (the CLOSED LIGHT loop — cheap, safe, runs every hour):
  S0 SYNC         pull our Kaggle submission history -> canonical CSV (fail-closed)
  S1 OBSERVE      ledger ingest (one score tick per submission) + finalize any
                  submission watched >= 1h with >= 2 reads (median label, drift-aware)
  S2 UPDATE-PRIORS  derive_priors: ledger -> selector candidates CSV + anchor status
                  (THIS is the edge that closes the loop into selection)
  S3 GATE-METRIC  backtest_loocv: honest jackknife-lower-bound correlation of local
                  metrics vs ledger MEDIAN labels (firewall-aware)
  S4 GATE         read the LOOCV summary; OPEN only if a trusted metric exists
  S5 ADVISE       recommend one candidate from closed-loop ledger data by default;
                  if (gate OPEN and ARMED and quota ok and staged candidate protects
                  the live latest-2 window) print the exact submit command. Auto-execute ONLY
                  with --allow-auto-submit (default OFF: advisory).
  S6 CRITIC       validate candidates every tick. When the gate is CLOSED, run the
                  Docker league/public-gap critic by default so a heartbeat
                  produces either promotion evidence or a concrete improvement
                  target instead of only monitoring.

The HEAVY loop (replay re-ingest, model retrain, mining, gauntlet) is expensive and
needs the simulator, so it is OFF by default and only runs with --run-heavy and not
more often than --heavy-interval-hours. A heavy-stage failure never breaks the light
loop.

Safety rails (from adversarial review):
  * flock for the whole tick — no double-fire.
  * fail-closed quota: a failed/empty submissions pull => treat quota as exhausted.
  * >=1h watch + >=2 reads + drift verdict before any score becomes a label.
  * never auto-submit unless ARMED (state.json) AND the staged candidate protects
    the live latest-2 window by more than the noise band AND quota remains.
  * kill switch: an `outcomes/STOP` file aborts the tick.
"""

from __future__ import annotations

import argparse
import csv
import fcntl
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def now_utc() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat()


@dataclass
class TickLog:
    started: str
    steps: list[dict] = field(default_factory=list)
    advisory: dict = field(default_factory=dict)
    gate_open: bool = False
    errors: list[str] = field(default_factory=list)

    def step(self, name: str, ok: bool, detail: str) -> None:
        self.steps.append({"step": name, "ok": ok, "detail": detail})
        marker = "ok " if ok else "ERR"
        print(f"[{marker}] {name}: {detail}")


def run(cmd: list[str], log: TickLog, name: str, critical: bool) -> tuple[bool, str]:
    try:
        result = subprocess.run(cmd, cwd=REPO, check=True, text=True, capture_output=True)
        tail = (result.stdout or "").strip().splitlines()[-1:] or [""]
        log.step(name, True, tail[0][:200])
        return True, result.stdout
    except subprocess.CalledProcessError as exc:
        msg = (exc.stderr or exc.stdout or str(exc)).strip().splitlines()[-1:] or [str(exc)]
        log.step(name, False, msg[0][:200])
        log.errors.append(f"{name}: {msg[0][:200]}")
        if critical:
            raise
        return False, exc.stderr or ""


# --------------------------------------------------------------------------- #
# state.json
# --------------------------------------------------------------------------- #
def load_state(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError:
            pass
    return {"armed": False, "live_refs": [], "last_heavy_ts": None, "history": []}


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True))


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def count_today_submissions(submissions_csv: Path, today: str) -> int:
    if not submissions_csv.exists():
        return 99  # fail-closed: unknown => assume exhausted
    n = 0
    for row in csv.DictReader(submissions_csv.open(encoding="utf-8-sig")):
        if (row.get("date") or "")[:10] == today:
            n += 1
    return n


def gate_from_summary(summary_csv: Path, min_spearman: float) -> tuple[bool, str]:
    if not summary_csv.exists():
        return False, "no LOOCV summary"
    best = None
    for row in csv.DictReader(summary_csv.open(encoding="utf-8-sig")):
        if row.get("public_target") != "latest_public":
            continue
        try:
            sp = float(row.get("spearman", "nan"))
        except ValueError:
            sp = float("nan")
        trusted = row.get("trusted") == "1" and sp == sp and sp >= min_spearman
        cand = (trusted, sp, row.get("metric", ""))
        if best is None or cand > best:
            best = cand
    if best is None:
        return False, "no latest_public rows"
    trusted, sp, metric = best
    return trusted, f"best metric `{metric}` lb-spearman={sp:.3f} trusted={int(trusted)}"


def ledger_family_medians(db: Path) -> dict[str, dict]:
    import sqlite3
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    out: dict[str, dict] = {}
    try:
        rows = conn.execute(
            """SELECT s.alias, s.family, s.kaggle_filename AS archive,
                      o.realized_public_median AS med, o.verdict
               FROM outcomes o JOIN submissions s ON o.ref=s.ref
               WHERE o.verdict != 'drift'"""
        ).fetchall()
    except sqlite3.OperationalError:
        rows = []
    finally:
        conn.close()
    # [fix 3] median-of-finalized-medians per archive (was MAX, which let a
    # single lucky finalization drive the exploit pick and dominance test —
    # v129 has finalized medians 1098.9 AND 783.9).
    import statistics as _st
    grouped: dict[str, dict] = {}
    for r in rows:
        g = grouped.setdefault(r["archive"], {"alias": r["alias"], "family": r["family"],
                                              "archive": r["archive"], "meds": []})
        g["meds"].append(float(r["med"]))
    for a, g in grouped.items():
        out[a] = {"alias": g["alias"], "family": g["family"], "archive": a,
                  "median": float(_st.median(g["meds"]))}
    return out


def advise_pair(db: Path, fail_threshold: float) -> dict:
    """Single-candidate advice from closed-loop ledger data.

    The function name and `pair` output key are kept for compatibility with
    older reports, but current submit policy is one agent at a time unless the
    user explicitly requests a two-agent latest-2 sequence.
    """
    archives = list(ledger_family_medians(db).values())
    if not archives:
        return {"pair": None, "reason": "no finalized outcomes yet"}
    archives.sort(key=lambda a: -a["median"])
    exploit = archives[0]
    pair = [exploit]
    return {
        "pair": [{"alias": p["alias"], "archive": p["archive"],
                  "family": p["family"], "median": p["median"]} for p in pair],
        "reason": "best single finalized candidate; pair forcing disabled",
    }


def live_latest_two(submissions_csv: Path, db: Path) -> list[dict]:
    """The two most-recent submissions (the pair currently scored on the board),
    annotated with their best known median from the ledger."""
    if not submissions_csv.exists():
        return []
    rows = [r for r in csv.DictReader(submissions_csv.open(encoding="utf-8-sig"))
            if (r.get("fileName") or "").strip()]
    rows.sort(key=lambda r: r.get("date", ""), reverse=True)
    medians = ledger_family_medians(db)
    out = []
    for r in rows[:2]:
        fn = r["fileName"].strip()
        med = medians.get(fn, {}).get("median")
        if med is None:
            try:
                med = float(r.get("publicScore") or "nan")
            except ValueError:
                med = float("nan")
        out.append({"archive": fn, "median": med})
    return out


def regression_guard(advisory: dict, live: list[dict], noise_band: float) -> dict:
    """PTCG-Bench (arXiv 2605.29653) F1: self-evolving agents repeatedly FAILED to
    beat the non-evolving baseline. So never ship a candidate that does not protect
    the live latest-2 window by more than the noise band -- otherwise we evict a
    known-good slot for noise."""
    pair = advisory.get("pair") or []
    rec_best = max((p["median"] for p in pair if p["median"] == p["median"]), default=float("nan"))
    live_best = max((l["median"] for l in live if l["median"] == l["median"]), default=float("nan"))
    if rec_best != rec_best or live_best != live_best:
        dominates, note = False, "insufficient data to confirm dominance"
    else:
        dominates = rec_best > live_best + noise_band
        note = (f"rec_best {rec_best:.0f} {'>' if dominates else '<='} "
                f"live_best {live_best:.0f} + band {noise_band:.0f}")
    advisory["live_pair"] = [{"archive": l["archive"], "median": l["median"]} for l in live]
    advisory["dominates_live"] = dominates
    advisory["regression_risk"] = not dominates
    advisory["dominance_note"] = note
    return advisory


def run_candidate_critic(args: argparse.Namespace, log: TickLog, py: list[str], *, run_league: bool) -> None:
    command = py + [
        "tools/candidate_critic_harness.py",
        "--submissions",
        str(args.submissions_csv),
        "--output-prefix",
        str(args.critic_output_prefix),
        "--max-codex",
        str(args.critic_max_codex),
        "--max-claude",
        str(args.critic_max_claude),
        "--max-grok",
        str(args.critic_max_grok),
        "--top-limit",
        str(args.critic_top_limit),
        "--games-per-seat",
        str(args.critic_games_per_seat),
        "--max-steps",
        str(args.critic_max_steps),
        "--league-repeats",
        str(args.critic_league_repeats),
        "--league-timeout",
        str(args.critic_league_timeout),
        "--docker-image",
        args.critic_docker_image,
        "--docker-platform",
        args.critic_docker_platform,
    ]
    if args.critic_scout_dir:
        command += ["--scout-dir", str(args.critic_scout_dir)]
    for candidate in args.critic_candidate:
        command += ["--candidate", candidate]
    if run_league:
        command.append("--run-league")
    else:
        command.append("--no-run-league")
    if args.critic_no_docker:
        command.append("--no-docker")
    if args.critic_run_public_action_gate:
        command += [
            "--run-public-action-gate",
            "--public-action-baseline-label",
            args.critic_public_action_baseline_label,
            "--public-action-context",
            args.critic_public_action_context,
            "--public-action-scan-replays",
            str(args.critic_public_action_scan_replays),
            "--public-action-max-replays",
            str(args.critic_public_action_max_replays),
            "--public-action-min-compared",
            str(args.critic_public_action_min_compared),
            "--public-action-min-same-rate",
            str(args.critic_public_action_min_same_rate),
            "--public-action-max-regression",
            str(args.critic_public_action_max_regression),
            "--public-action-max-net-regressions",
            str(args.critic_public_action_max_net_regressions),
            "--public-action-max-net-weighted-regression",
            str(args.critic_public_action_max_net_weighted_regression),
            "--public-action-min-agent-deck-overlap",
            str(args.critic_public_action_min_agent_deck_overlap),
            "--public-action-timeout",
            str(args.critic_public_action_timeout),
        ]
        for label in args.critic_public_action_gate_label:
            command += ["--public-action-gate-label", label]

    ok, _ = run(command, log, "S6 CRITIC candidate-review", critical=False)
    report_path = args.critic_output_prefix.with_suffix(".md")
    verdict = "missing"
    if report_path.exists():
        text = report_path.read_text(encoding="utf-8", errors="replace")
        match = re.search(r"Critic verdict:\s+\*\*([^*]+)\*\*", text)
        if match:
            verdict = match.group(1).strip()
    log.advisory["critic_run_league"] = run_league
    log.advisory["critic_run_public_action_gate"] = args.critic_run_public_action_gate
    log.advisory["critic_report"] = str(report_path)
    log.advisory["critic_command_ok"] = ok
    log.advisory["critic_verdict"] = verdict
    log.advisory["critic_blocking"] = verdict in {"BLOCK", "RESEARCH_ONLY", "missing"}


def suffix_path(prefix: Path, suffix: str) -> Path:
    return prefix.parent / f"{prefix.name}{suffix}"


def run_critic_metric_diagnostic(args: argparse.Namespace, log: TickLog, py: list[str]) -> None:
    """Convert the critic league into a non-leaky LOOCV diagnostic panel.

    S3 runs before S6 by design, so this diagnostic is advisory for the current
    tick. The next gate can consume the emitted CSV through --metrics-csv if it
    proves useful.
    """
    league_csv = suffix_path(args.critic_output_prefix, "_league.csv")
    robustness_csv = suffix_path(args.critic_output_prefix, "_league_robustness.csv")
    if not league_csv.exists() and not robustness_csv.exists():
        log.step("S6 CRITIC-METRICS", True, "skipped (no critic league CSVs)")
        return

    maps_by_label: dict[str, str] = {}
    for candidate in args.critic_candidate:
        if "=" not in candidate:
            continue
        label, target = candidate.split("=", 1)
        archive = Path(target).name
        if archive.endswith(".tar.gz"):
            maps_by_label[label] = archive

    # Normal heartbeat usage passes LABEL=agents/foo directories. The critic
    # report CSV resolves those directories to versioned archive hints after
    # validation, so use that richer mapping before giving up.
    critic_csv = args.critic_output_prefix.with_suffix(".csv")
    if critic_csv.exists():
        try:
            for row in csv.DictReader(critic_csv.open(encoding="utf-8-sig", newline="")):
                label = (row.get("label") or "").strip()
                archive = Path((row.get("archive_hint") or "").strip()).name
                if label and archive.endswith(".tar.gz"):
                    maps_by_label.setdefault(label, archive)
        except OSError:
            pass

    maps = [f"{label}={archive}" for label, archive in sorted(maps_by_label.items())]
    if not maps:
        log.step("S6 CRITIC-METRICS", True, "skipped (no archive-backed critic candidates to map)")
        return

    panel_csv = suffix_path(args.critic_output_prefix, "_critic_metrics.csv")
    panel_report = suffix_path(args.critic_output_prefix, "_critic_metrics.md")
    command = py + [
        "tools/build_critic_metric_panel.py",
        "--output",
        str(panel_csv),
        "--report",
        str(panel_report),
    ]
    if league_csv.exists():
        command += ["--league-csv", str(league_csv)]
    if robustness_csv.exists():
        command += ["--robustness-csv", str(robustness_csv)]
    for mapping in maps:
        command += ["--map", mapping]
    ok, _ = run(command, log, "S6 CRITIC-METRICS panel", critical=False)
    if not ok:
        return

    summary_csv = suffix_path(args.critic_output_prefix, "_critic_metrics_loocv_summary.csv")
    loocv_report = suffix_path(args.critic_output_prefix, "_critic_metrics_loocv.md")
    ok, _ = run(
        py + [
            "tools/backtest_loocv.py",
            "--metrics-csv",
            str(panel_csv),
            "--ledger",
            str(args.db),
            "--summary-csv",
            str(summary_csv),
            "--report",
            str(loocv_report),
            "--min-trusted-spearman",
            str(args.min_spearman),
            "--min-trusted-n",
            str(args.min_trusted_n),
        ],
        log,
        "S6 CRITIC-METRICS loocv",
        critical=False,
    )
    log.advisory["critic_metric_panel"] = str(panel_csv)
    log.advisory["critic_metric_loocv_summary"] = str(summary_csv)
    log.advisory["critic_metric_loocv_report"] = str(loocv_report)
    log.advisory["critic_metric_loocv_ok"] = ok


# --------------------------------------------------------------------------- #
# the tick
# --------------------------------------------------------------------------- #
def tick(args: argparse.Namespace, log: TickLog) -> dict:
    state = load_state(args.state)
    now = now_utc()
    today = now.strftime("%Y-%m-%d")
    py = ["uv", "run", "python"]

    # S0 SYNC -------------------------------------------------------------- #
    ok, _ = run(py + ["tools/pull_submissions.py", "--competition", args.competition,
                      "--output", str(args.submissions_csv), "--stamped-dir", "strategy"],
                log, "S0 SYNC pull-submissions", critical=False)
    sync_stale = not ok
    if not ok and not args.submissions_csv.exists():
        log.errors.append("SYNC failed and no prior submissions CSV; aborting tick (fail-closed).")
        return finish(args, state, log, now)
    if sync_stale:
        log.step("S0 SYNC", True, "pull failed; stale CSV -> quota treated as EXHAUSTED (fail-closed)")

    # S1 OBSERVE ----------------------------------------------------------- #
    run(py + ["tools/outcome_ledger.py", "--db", str(args.db), "ingest-submissions",
              "--submissions", str(args.submissions_csv), "--tick-ts", iso(now)],
        log, "S1 OBSERVE ingest-ticks", critical=False)
    run(py + ["tools/outcome_ledger.py", "--db", str(args.db), "finalize",
              "--now", iso(now), "--min-watch-seconds", str(args.min_watch_seconds),
              "--min-ticks", str(args.min_ticks), "--drift-margin", str(args.drift_margin),
              "--refresh-finalized"],
        log, "S1 OBSERVE finalize", critical=False)

    # S2 UPDATE-PRIORS ----------------------------------------------------- #
    base = ["tools/derive_priors.py", "--db", str(args.db),
            "--candidates-out", str(args.candidates_csv),
            "--anchor-status-out", str(args.anchor_status_csv),
            "--noise-band", str(args.noise_band)]
    if args.base_candidates:
        base += ["--base-candidates", str(args.base_candidates)]
    run(py + base, log, "S2 UPDATE-PRIORS derive_priors", critical=False)

    # S3 GATE-METRIC ------------------------------------------------------- #
    metrics_csv = args.metrics_csv or args.candidates_csv
    loocv_cmd = py + ["tools/backtest_loocv.py", "--metrics-csv", str(metrics_csv),
                      "--ledger", str(args.db), "--summary-csv", str(args.loocv_summary),
                      "--min-trusted-spearman", str(args.min_spearman),
                      "--min-trusted-n", str(args.min_trusted_n)]
    for ex in state.get("firewall_excluded", []):
        loocv_cmd += ["--exclude-archive", ex]
    run(loocv_cmd, log, "S3 GATE-METRIC loocv", critical=False)

    # S4 GATE -------------------------------------------------------------- #
    gate_open, gate_detail = gate_from_summary(args.loocv_summary, args.min_spearman)
    log.gate_open = gate_open
    log.step("S4 GATE", True, f"{'OPEN' if gate_open else 'CLOSED'} — {gate_detail}")

    # S5 ADVISE / SUBMIT --------------------------------------------------- #
    advisory = advise_pair(args.db, args.fail_threshold)
    # PTCG-Bench F1 regression guard: must protect the live latest-2 baseline.
    live = live_latest_two(args.submissions_csv, args.db)
    advisory = regression_guard(advisory, live, args.noise_band)
    used_today = count_today_submissions(args.submissions_csv, today)
    quota_left = 0 if sync_stale else max(0, args.max_daily_submissions - used_today)
    armed = bool(state.get("armed", False))
    advisory.update({"quota_used_today": used_today, "quota_left": quota_left,
                     "armed": armed, "gate_open": gate_open})
    log.advisory = advisory

    dominates = advisory.get("dominates_live", False)
    can_auto = (args.allow_auto_submit and gate_open and armed and quota_left > 0
                and advisory.get("pair") and dominates)
    if advisory.get("pair"):
        pair_txt = " + ".join(f"{p['alias']}({p['family']},{p['median']:.0f})"
                              for p in advisory["pair"])
        guard = "DOMINATES live" if dominates else "REGRESSION RISK (does not beat live)"
        log.step("S5 ADVISE", True,
                 f"recommend: {pair_txt} | gate={'OPEN' if gate_open else 'CLOSED'} "
                 f"armed={armed} quota_left={quota_left} | {guard} [{advisory['dominance_note']}]")
        if can_auto:
            log.step("S5 SUBMIT", True, "AUTO-SUBMIT path enabled — but execution is a "
                     "Phase-4 capability; staying advisory this build.")
        else:
            reason = ("auto-submit disabled (default)" if not args.allow_auto_submit
                      else "not ARMED" if not armed
                      else "gate CLOSED" if not gate_open
                      else "no quota" if quota_left == 0
                      else "REGRESSION RISK — would not beat live baseline (PTCG-Bench F1)"
                      if not dominates else "no candidate")
            log.step("S5 SUBMIT", True, f"advisory only — {reason}")
    else:
        log.step("S5 ADVISE", True, "no finalized outcomes yet — nothing to recommend")

    # S6 CRITIC ------------------------------------------------------------ #
    # Lightweight by default: validates latest Codex/Claude/Grok candidates
    # in Linux Docker and writes a critic report. With --critic-run-league (or
    # --run-heavy) it also runs a Docker local league and public-gap audit.
    if args.run_critic:
        critic_league_due = (
            args.critic_run_league
            or args.run_heavy
            or (not gate_open and args.critic_league_on_closed_gate)
        )
        run_candidate_critic(args, log, py, run_league=critic_league_due)
        if critic_league_due:
            run_critic_metric_diagnostic(args, log, py)
    else:
        log.step("S6 CRITIC", True, "skipped (--no-run-critic)")

    # HEAVY (optional) ----------------------------------------------------- #
    if args.run_heavy:
        last = state.get("last_heavy_ts")
        due = True
        if last:
            try:
                hours = (now - datetime.fromisoformat(last)).total_seconds() / 3600
                due = hours >= args.heavy_interval_hours
            except ValueError:
                due = True
        if due:
            run_heavy(args, log, py)
            state["last_heavy_ts"] = iso(now)
        else:
            log.step("HEAVY", True, f"skipped (last run < {args.heavy_interval_hours}h ago)")

    return finish(args, state, log, now)


def run_heavy(args: argparse.Namespace, log: TickLog, py: list[str]) -> None:
    """Optional expensive stages. Each is best-effort; failures are logged, not fatal.
    These call the existing tools; wire/extend args here as the heavy loop matures."""
    # Replay re-ingest is the safest heavy stage (no submit, refreshes training data).
    run(py + ["tools/ml_replay_ingest_refresh.py"], log, "HEAVY ml-replay-ingest", critical=False)
    # NOTE: train/mine/gauntlet stages are intentionally left as documented hooks —
    # they need the simulator and careful per-tool args; add them here once a
    # model->agent compiler exists (the deferred candidate-generation frontier).


def finish(args: argparse.Namespace, state: dict, log: TickLog, now: datetime) -> dict:
    entry = {"ts": iso(now), "gate_open": log.gate_open,
             "advisory": log.advisory, "errors": log.errors,
             "steps": [s["step"] for s in log.steps if not s["ok"]]}
    # [fix 0] re-load the on-disk state and merge ONLY the keys this tick owns,
    # so an --arm/--disarm (or firewall edit) issued mid-tick survives.
    fresh = load_state(args.state)
    for key in ("armed", "firewall_excluded"):
        if key in fresh:
            state[key] = fresh[key]
    state.setdefault("history", []).append(entry)
    state["history"] = state["history"][-200:]  # cap
    state["last_tick_ts"] = iso(now)
    state["last_gate_open"] = log.gate_open
    save_state(args.state, state)

    # human-readable tick report
    report = [f"# Heartbeat tick {iso(now)}", "",
              f"- Gate: **{'OPEN' if log.gate_open else 'CLOSED'}**",
              f"- Armed: {state.get('armed', False)}",
              f"- Advisory: {json.dumps(log.advisory)}", "",
              "## Steps"]
    for s in log.steps:
        report.append(f"- [{'ok' if s['ok'] else 'ERR'}] {s['step']}: {s['detail']}")
    if log.errors:
        report += ["", "## Errors", *[f"- {e}" for e in log.errors]]
    args.tick_report.parent.mkdir(parents=True, exist_ok=True)
    args.tick_report.write_text("\n".join(report) + "\n", encoding="utf-8")
    return entry


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Self-improving submission heartbeat (one tick)")
    p.add_argument("--competition", default="pokemon-tcg-ai-battle")
    p.add_argument("--db", type=Path, default=Path("outcomes/ledger.sqlite"))
    p.add_argument("--state", type=Path, default=Path("outcomes/state.json"))
    p.add_argument("--lock", type=Path, default=Path("outcomes/heartbeat.lock"))
    p.add_argument("--stop-file", type=Path, default=Path("outcomes/STOP"))
    p.add_argument("--submissions-csv", type=Path, default=Path("outcomes/our_submissions.csv"))
    p.add_argument("--candidates-csv", type=Path, default=Path("outcomes/loop_candidates.csv"))
    p.add_argument("--anchor-status-csv", type=Path, default=Path("outcomes/loop_anchor_status.csv"))
    p.add_argument("--loocv-summary", type=Path, default=Path("outcomes/loocv_summary.csv"))
    p.add_argument("--tick-report", type=Path, default=Path("outcomes/last_tick.md"))
    p.add_argument("--metrics-csv", type=Path, default=None,
                   help="non-leaky local-metric CSV for the gate (e.g. gauntlet win-rates)")
    p.add_argument("--base-candidates", type=Path, default=None)
    p.add_argument("--min-watch-seconds", type=float, default=3600.0)
    p.add_argument("--min-ticks", type=int, default=4)
    p.add_argument("--drift-margin", type=float, default=100.0)
    p.add_argument("--noise-band", type=float, default=94.0)
    p.add_argument("--fail-threshold", type=float, default=800.0)
    p.add_argument("--min-spearman", type=float, default=0.55)
    p.add_argument("--min-trusted-n", type=int, default=8)
    p.add_argument("--max-daily-submissions", type=int, default=5)
    p.add_argument("--allow-auto-submit", action="store_true",
                   help="permit autonomous submission (still requires ARMED + gate OPEN + dominance)")
    p.add_argument("--run-heavy", action="store_true", help="also run expensive retrain stages")
    p.add_argument("--heavy-interval-hours", type=float, default=12.0)
    p.add_argument("--run-critic", action=argparse.BooleanOptionalAction, default=True,
                   help="run candidate_critic_harness as part of each tick")
    p.add_argument("--critic-run-league", action="store_true",
                   help="make the candidate critic run a Docker league plus public-gap audit")
    p.add_argument("--critic-league-on-closed-gate", action=argparse.BooleanOptionalAction, default=True,
                   help="when the gate is closed, run the Docker critic league/public-gap audit by default")
    p.add_argument("--critic-output-prefix", type=Path, default=Path("outcomes/candidate_critic_last"))
    p.add_argument("--critic-scout-dir", type=Path, default=None)
    p.add_argument("--critic-candidate", action="append", default=[],
                   help="candidate spec passed through as LABEL=AGENT_DIR; repeatable")
    p.add_argument("--critic-max-codex", type=int, default=3)
    p.add_argument("--critic-max-claude", type=int, default=1)
    p.add_argument("--critic-max-grok", type=int, default=1)
    p.add_argument("--critic-top-limit", type=int, default=4)
    p.add_argument("--critic-games-per-seat", type=int, default=1)
    p.add_argument("--critic-max-steps", type=int, default=800)
    p.add_argument("--critic-league-repeats", type=int, default=1,
                   help="repeat critic local league N times and block unstable winners")
    p.add_argument("--critic-league-timeout", type=int, default=1800)
    p.add_argument("--critic-no-docker", action="store_true")
    p.add_argument("--critic-docker-image", default="python:3.11-slim")
    p.add_argument("--critic-docker-platform", default="linux/amd64")
    p.add_argument("--critic-run-public-action-gate", action=argparse.BooleanOptionalAction, default=False,
                   help="ask candidate_critic_harness to run a public-action mismatch gate")
    p.add_argument("--critic-public-action-baseline-label", default="v100_anchor")
    p.add_argument("--critic-public-action-context", default="MAIN")
    p.add_argument("--critic-public-action-scan-replays", type=int, default=80)
    p.add_argument("--critic-public-action-max-replays", type=int, default=40)
    p.add_argument("--critic-public-action-min-compared", type=int, default=100)
    p.add_argument("--critic-public-action-min-same-rate", type=float, default=0.0)
    p.add_argument("--critic-public-action-max-regression", type=float, default=0.03)
    p.add_argument("--critic-public-action-max-net-regressions", type=int, default=0)
    p.add_argument("--critic-public-action-max-net-weighted-regression", type=float, default=0.0)
    p.add_argument("--critic-public-action-min-agent-deck-overlap", type=int, default=0)
    p.add_argument("--critic-public-action-timeout", type=int, default=900)
    p.add_argument("--critic-public-action-gate-label", action="append", default=[],
                   help="specific candidate_critic_harness public-action gate label; repeatable")
    p.add_argument("--arm", action="store_true", help="set armed=true in state and exit")
    p.add_argument("--disarm", action="store_true", help="set armed=false in state and exit")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # arm/disarm are quick state edits
    if args.arm or args.disarm:
        state = load_state(args.state)
        state["armed"] = bool(args.arm)
        save_state(args.state, state)
        print(f"armed = {state['armed']}")
        return 0

    if args.stop_file.exists():
        print(f"STOP file present ({args.stop_file}); aborting tick.")
        return 0

    args.lock.parent.mkdir(parents=True, exist_ok=True)
    lock_fh = args.lock.open("w")
    try:
        fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("Another heartbeat tick holds the lock; exiting.")
        return 0

    log = TickLog(started=iso(now_utc()))
    try:
        tick(args, log)
    finally:
        fcntl.flock(lock_fh, fcntl.LOCK_UN)
        lock_fh.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
