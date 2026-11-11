#!/usr/bin/env python3
"""Close the feedback edge: ledger outcomes -> the files the existing tools read.

This is THE step that turns the toolbox into a loop. It projects FINALIZED public
outcomes from the outcome ledger -- deterministically, with no human edit -- into:

1. The pair-selector `--candidates` CSV
   (schema: candidate,path,family,kind,replay_win_rate,fixed_win_rate,
            public_current,public_best,public_floor,ranker_mimic,notes)
   `public_current`/`public_best`/`public_floor` are filled from the ledger's
   DE-DUPLICATED MEDIAN public score per archive. `pair_strategy_selector.py`'s
   existing `public_risk()` logic then demotes a publicly-failed family on the
   NEXT selection cycle. (No `candidate_metadata.csv` is involved -- that file,
   named in earlier designs, does not exist.)

2. An anchor-status CSV consumed by `pre_submit_gate.py`
   (schema: candidate,archive,submit_eligible,anchor_state,reasons).

Shrinkage / noise guard: a family's public signal moves selection only when the
measurement is stable (verdict != drift) AND the deviation from the field median
clears the noise band. Otherwise the row is recorded but marked neutral, so a
single noisy score can never whipsaw the selector.
"""

from __future__ import annotations

import argparse
import csv
import sqlite3
import statistics
import sys
from collections import defaultdict
from pathlib import Path

DEFAULT_DB = Path("outcomes/ledger.sqlite")

# Existing-agent archives the selector should always see (kept minimal; the loop
# extends this from the ledger automatically). Maps alias -> (archive, family, kind).
KNOWN_RECOVERY = {
    "v8": ("submission-crustle.tar.gz", "pure_crustle", "public-recovery"),
    "v36": ("submission-kenn-ethan-patient-second-v36.tar.gz", "ethan_crustle", "public-recovery"),
}


def load_finalized(db: Path):
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """SELECT s.kaggle_filename AS archive, s.alias AS alias, s.family AS family,
                      o.realized_public_median AS median, o.observed_score_spread AS spread,
                      o.verdict AS verdict
               FROM outcomes o JOIN submissions s ON o.ref=s.ref"""
        ).fetchall()
    except sqlite3.OperationalError:
        rows = []
    finally:
        conn.close()
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Project ledger outcomes into selector/gate inputs")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--candidates-out", required=True, type=Path)
    parser.add_argument("--anchor-status-out", type=Path, default=None)
    parser.add_argument("--noise-band", type=float, default=94.0,
                        help="deviation from field median below which a result is treated as neutral")
    parser.add_argument("--fail-threshold", type=float, default=800.0,
                        help="median public below this marks a family as a public failure")
    parser.add_argument("--base-candidates", type=Path, default=None,
                        help="optional existing candidates CSV to merge local win-rates from")
    args = parser.parse_args(argv)

    rows = load_finalized(args.db)
    # de-duplicate to one median per archive (median of finalized medians).
    # Drift outcomes are recorded in the output but excluded from family priors:
    # they are too noisy to call public_ok/public_fail, but must not vanish.
    by_archive_scores: dict[str, list[float]] = defaultdict(list)
    drift_archive_scores: dict[str, list[float]] = defaultdict(list)
    drift_archive_spreads: dict[str, list[float]] = defaultdict(list)
    meta: dict[str, dict] = {}
    for r in rows:
        if r["verdict"] == "drift":
            drift_archive_scores[r["archive"]].append(float(r["median"]))
            drift_archive_spreads[r["archive"]].append(float(r["spread"]))
            meta[r["archive"]] = {"alias": r["alias"], "family": r["family"], "verdict": r["verdict"]}
            continue
        by_archive_scores[r["archive"]].append(float(r["median"]))
        meta[r["archive"]] = {"alias": r["alias"], "family": r["family"], "verdict": r["verdict"]}
    archive_median = {a: statistics.median(v) for a, v in by_archive_scores.items()}

    # family-level aggregates (selection attribution is family-level by design)
    family_scores: dict[str, list[float]] = defaultdict(list)
    for a, m in archive_median.items():
        family_scores[meta[a]["family"]].append(m)
    family_median = {f: statistics.median(v) for f, v in family_scores.items()}
    field_median = statistics.median(list(archive_median.values())) if archive_median else 0.0

    # optionally merge local win-rates keyed by alias from a base candidates CSV
    base_local: dict[str, dict] = {}
    if args.base_candidates and args.base_candidates.exists():
        for row in csv.DictReader(args.base_candidates.open(encoding="utf-8-sig")):
            alias = (row.get("candidate") or "").lower()
            base_local[alias] = row

    # build candidate rows
    fieldnames = ["candidate", "path", "family", "kind", "replay_win_rate",
                  "fixed_win_rate", "public_current", "public_best", "public_floor",
                  "ranker_mimic", "notes"]
    out_rows = []
    seen_archives = set()
    for archive, median in sorted(archive_median.items(), key=lambda kv: -kv[1]):
        info = meta[archive]
        alias = info["alias"]
        seen_archives.add(archive)
        best = max(by_archive_scores[archive])
        floor = min(by_archive_scores[archive])
        fam_med = family_median.get(info["family"], median)
        deviation = fam_med - field_median
        if median < args.fail_threshold:
            verdict_note = f"PUBLIC_FAIL archive_med={median:.0f}"
        elif abs(deviation) < args.noise_band:
            verdict_note = f"neutral (|dev|={abs(deviation):.0f}<{args.noise_band:.0f})"
        elif fam_med < args.fail_threshold:
            verdict_note = f"PUBLIC_FAIL family_med={fam_med:.0f}"
        else:
            verdict_note = f"public_ok family_med={fam_med:.0f}"
        base = base_local.get(alias.lower(), {})
        out_rows.append({
            "candidate": alias,
            "path": archive,
            "family": info["family"],
            "kind": base.get("kind", "submitted"),
            "replay_win_rate": base.get("replay_win_rate", ""),
            "fixed_win_rate": base.get("fixed_win_rate", ""),
            "public_current": f"{median:.1f}",
            "public_best": f"{best:.1f}",
            "public_floor": f"{floor:.1f}",
            "ranker_mimic": base.get("ranker_mimic", ""),
            "notes": f"ledger-derived; {verdict_note}; spread-dedup median",
        })

    for archive, values in sorted(drift_archive_scores.items(), key=lambda kv: -statistics.median(kv[1])):
        if archive in seen_archives:
            continue
        info = meta[archive]
        alias = info["alias"]
        seen_archives.add(archive)
        median = statistics.median(values)
        best = max(values)
        floor = min(values)
        max_spread = max(drift_archive_spreads.get(archive, [0.0]))
        base = base_local.get(alias.lower(), {})
        out_rows.append({
            "candidate": alias,
            "path": archive,
            "family": info["family"],
            "kind": base.get("kind", "submitted"),
            "replay_win_rate": base.get("replay_win_rate", ""),
            "fixed_win_rate": base.get("fixed_win_rate", ""),
            "public_current": f"{median:.1f}",
            "public_best": f"{best:.1f}",
            "public_floor": f"{floor:.1f}",
            "ranker_mimic": base.get("ranker_mimic", ""),
            "notes": (
                "ledger-derived; public_drift "
                f"spread={max_spread:.1f}; excluded from family prior"
            ),
        })

    # include known recovery shells even if not yet in ledger (so selector has floors)
    for alias, (archive, family, kind) in KNOWN_RECOVERY.items():
        if archive in seen_archives:
            continue
        out_rows.append({
            "candidate": alias, "path": archive, "family": family, "kind": kind,
            "replay_win_rate": "", "fixed_win_rate": "", "public_current": "",
            "public_best": "", "public_floor": "", "ranker_mimic": "",
            "notes": "recovery prior (no ledger outcome yet)",
        })

    args.candidates_out.parent.mkdir(parents=True, exist_ok=True)
    with args.candidates_out.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(out_rows)
    print(f"Wrote {len(out_rows)} candidate rows -> {args.candidates_out} "
          f"(field median {field_median:.0f}, {len(family_median)} families)")

    if args.anchor_status_out:
        with args.anchor_status_out.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=[
                "candidate", "archive", "submit_eligible", "anchor_state", "reasons"])
            writer.writeheader()
            for r in out_rows:
                cur = r["public_current"]
                if "public_drift" in r["notes"]:
                    writer.writerow({
                        "candidate": r["candidate"], "archive": r["path"],
                        "submit_eligible": "0", "anchor_state": "public_drift",
                        "reasons": f"archive has noisy mature public trajectory: {r['notes']}"})
                    continue
                try:
                    archive_score = float(cur)
                except ValueError:
                    archive_score = None
                if archive_score is not None and archive_score < args.fail_threshold:
                    writer.writerow({
                        "candidate": r["candidate"], "archive": r["path"],
                        "submit_eligible": "0", "anchor_state": "public_fail",
                        "reasons": f"archive_med={archive_score:.0f}<{args.fail_threshold:.0f}"})
                    continue
                fam_med = family_median.get(r["family"])
                if fam_med is None:
                    state, eligible, reason = "unknown", "1", "no ledger outcome"
                elif fam_med < args.fail_threshold:
                    state, eligible, reason = "public_fail", "0", f"family_med={fam_med:.0f}<{args.fail_threshold:.0f}"
                else:
                    state, eligible, reason = "public_ok", "1", f"family_med={fam_med:.0f}"
                writer.writerow({
                    "candidate": r["candidate"], "archive": r["path"],
                    "submit_eligible": eligible, "anchor_state": state, "reasons": reason})
        print(f"Wrote anchor status -> {args.anchor_status_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
