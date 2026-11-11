#!/usr/bin/env python3
"""Honest, cross-validated predictive-validity metric for the submit gate.

The original `backtest_local_vs_public.py` correlates local metrics vs realized
public scores **in-sample** and lets the gate pick the best-correlating metric --
which is the exact shape of the June-20 over-fit (fit the anchors, report a high
number, fail out-of-sample). This tool makes the gate honest in three ways while
writing the SAME `backtest_summary.csv` schema, so `pre_submit_gate.py` needs ZERO
changes:

1. **Median labels, not single reads.** Labels come from the outcome ledger's
   FINALIZED medians (median over multiple >=1h-watched reads), so the high
   label-noise (sigma ~94, see anchor_noise_ceiling.py) is averaged down before
   correlating. Falls back to the submissions CSV latest score if no ledger.

2. **Conservative cross-validated score.** Instead of the raw in-sample Spearman,
   the `spearman` column carries the **jackknife (leave-one-out) lower confidence
   bound**. If dropping any single anchor collapses the correlation, the bound
   drops, and the gate stays shut. The gate's existing `spearman >= 0.55` check
   thus becomes a check on the conservative bound -- honest by construction.

3. **Significance + firewall.** A permutation p-value guards against small-n luck;
   `--exclude-archive` reserves anchors used for training so they cannot also
   authorize the gate (the train/calibration firewall).

Leaky columns (anything starting with `public`) are never treated as predictive
metrics -- they ARE the label and would trivially "correlate".
"""

from __future__ import annotations

import argparse
import csv
import math
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
from scipy.stats import kendalltau, spearmanr

LEAKY_PREFIXES = ("public", "score", "private")


def alias_from_text(text: str) -> str:
    import re
    lowered = (text or "").lower()
    m = re.findall(r"(?<![a-z0-9])v(\d+)(?![a-z0-9])", lowered)
    if m:
        return f"v{m[-1]}"
    return lowered.removeprefix("submission-").removesuffix(".tar.gz").replace("_", "-")


def labels_from_ledger(db: Path, since: str | None = None) -> dict[str, float]:
    """archive(fileName) -> median public score from FINALIZED outcomes.

    `since` (ISO date/datetime) restricts labels to submissions made on/after
    that moment — REQUIRED after an environment change (e.g. June 30 48-battle
    shift): mixing pre/post-shift labels corrupts every correlation (see
    CRITICISM.md #5)."""
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    out: dict[str, list[float]] = defaultdict(list)
    try:
        query = (
            """SELECT s.kaggle_filename AS fn, o.realized_public_median AS med, o.verdict AS v
               FROM outcomes o JOIN submissions s ON o.ref=s.ref"""
        )
        params: tuple = ()
        if since:
            query += " WHERE s.submit_ts >= ?"
            params = (since,)
        rows = conn.execute(query, params).fetchall()
    except sqlite3.OperationalError:
        return {}
    finally:
        conn.close()
    for r in rows:
        if r["v"] == "drift":
            continue  # too noisy to use as a label
        out[r["fn"]].append(float(r["med"]))
    # multiple finalized submissions of the same archive -> median of medians
    return {a: float(np.median(v)) for a, v in out.items() if v}


def labels_from_submissions(path: Path, since: str | None = None) -> dict[str, float]:
    """archive(fileName) -> median of all complete public scores (robust to noise)."""
    by: dict[str, list[float]] = defaultdict(list)
    with path.open(encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            fn = (row.get("fileName") or "").strip()
            raw = (row.get("publicScore") or "").strip()
            if not fn or "COMPLETE" not in (row.get("status") or "").upper() or not raw:
                continue
            if since and (row.get("date") or "") < since:
                continue
            # [fix 6] immature scores are mid-drift; require >=3h age before a
            # submissions-CSV score may serve as a label (ledger labels already
            # enforce convergence).
            try:
                from datetime import datetime, timedelta, timezone
                sub_dt = datetime.fromisoformat((row.get("date") or "").split(".")[0]).replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) - sub_dt < timedelta(hours=3):
                    continue
            except ValueError:
                pass
            try:
                by[fn].append(float(raw))
            except ValueError:
                continue
    return {a: float(np.median(v)) for a, v in by.items()}


def load_metrics(path: Path) -> tuple[dict[str, dict[str, float]], list[str]]:
    """Return {archive_or_alias: {metric: value}} and the metric column names."""
    rows = list(csv.DictReader(path.open(encoding="utf-8-sig", newline="")))
    if not rows:
        return {}, []
    keycols = [c for c in ("fileName", "path", "archive", "candidate") if c in rows[0]]
    metric_cols: list[str] = []
    for col in rows[0]:
        if col in keycols:
            continue
        if col.lower().startswith(LEAKY_PREFIXES):
            continue
        # numeric if any row parses
        if any(_is_float(r.get(col)) for r in rows):
            metric_cols.append(col)
    table: dict[str, dict[str, float]] = {}
    for r in rows:
        archive = ""
        for kc in ("fileName", "path", "archive"):
            if r.get(kc):
                archive = r[kc].strip()
                break
        alias = alias_from_text(archive or r.get("candidate", ""))
        rec = {}
        for col in metric_cols:
            v = _to_float(r.get(col))
            if v is not None:
                rec[col] = v
        if rec:
            table.setdefault(alias, {}).update(rec)
    return table, metric_cols


def _is_float(v) -> bool:
    return _to_float(v) is not None


def _to_float(v):
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    try:
        return float(s)
    except ValueError:
        return None


def jackknife_lower_bound(x: np.ndarray, y: np.ndarray, z: float = 1.645) -> tuple[float, float]:
    """Leave-one-out jackknife of Spearman rho; return (mean_rho, lower_bound)."""
    n = len(x)
    if n < 4:
        rho = spearmanr(x, y).statistic
        return (rho if rho == rho else 0.0), -1.0
    loo = []
    for i in range(n):
        xi = np.delete(x, i)
        yi = np.delete(y, i)
        if len(set(xi.tolist())) < 2 or len(set(yi.tolist())) < 2:
            r = 0.0
        else:
            r = spearmanr(xi, yi).statistic
        loo.append(r if r == r else 0.0)
    loo = np.array(loo)
    mean = float(loo.mean())
    se = math.sqrt((n - 1) / n * np.sum((loo - mean) ** 2))
    return mean, mean - z * se


def permutation_p(x: np.ndarray, y: np.ndarray, observed: float, nperm: int, seed: int) -> float:
    rng = np.random.default_rng(seed)
    count = 0
    for _ in range(nperm):
        r = spearmanr(x, rng.permutation(y)).statistic
        if r == r and r >= observed:
            count += 1
    return (1 + count) / (1 + nperm)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Honest LOOCV predictive-validity gate metric")
    parser.add_argument("--metrics-csv", required=True, type=Path,
                        help="CSV with archive/alias key + numeric local metric columns")
    parser.add_argument("--ledger", type=Path, default=Path("outcomes/ledger.sqlite"))
    parser.add_argument("--submissions", type=Path, default=None,
                        help="fallback labels if ledger has no finalized outcomes")
    parser.add_argument("--exclude-archive", action="append", default=[],
                        help="alias reserved for training (firewall) -- excluded from gate metric")
    parser.add_argument("--required-alias", action="append", default=[])
    parser.add_argument("--min-trusted-spearman", type=float, default=0.55)
    parser.add_argument("--min-trusted-n", type=int, default=8)
    parser.add_argument("--max-perm-p", type=float, default=0.05)
    parser.add_argument("--nperm", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=20260622)
    parser.add_argument("--labels-since", default=None,
                        help="only use labels from submissions on/after this ISO "
                             "date (env-cohort split; e.g. 2026-06-30 for the "
                             "48-battle environment)")
    parser.add_argument("--summary-csv", required=True, type=Path)
    parser.add_argument("--report", type=Path, default=None)
    args = parser.parse_args(argv)

    labels = (labels_from_ledger(args.ledger, args.labels_since)
              if args.ledger and args.ledger.exists() else {})
    label_source = "ledger(median of finalized)"
    if not labels and args.submissions:
        labels = labels_from_submissions(args.submissions, args.labels_since)
        label_source = "submissions(median of reads)"
    if not labels:
        sys.stderr.write("ERROR: no labels (need a ledger with finalized outcomes or --submissions).\n")
        return 2
    label_by_alias = {alias_from_text(a): v for a, v in labels.items()}

    excluded = {e.lower() for e in args.exclude_archive}
    metrics, metric_cols = load_metrics(args.metrics_csv)

    report = ["# LOOCV Predictive-Validity Gate Metric", "",
              f"- Metrics: `{args.metrics_csv}`",
              f"- Labels: {label_source} ({len(label_by_alias)} archives)",
              f"- Firewall-excluded: {sorted(excluded) or '-'}",
              f"- Gate: jackknife lower-bound Spearman >= {args.min_trusted_spearman:.2f}, "
              f"kendall > 0, n >= {args.min_trusted_n}, perm p < {args.max_perm_p}", ""]
    report.append("| metric | n | spearman_pt | spearman_lb | kendall | perm_p | trusted |")
    report.append("| --- | ---: | ---: | ---: | ---: | ---: | --- |")

    rows_out = []
    required = {r.lower() for r in args.required_alias}
    for metric in metric_cols:
        pairs = []
        for alias, rec in metrics.items():
            if alias in excluded:
                continue
            if metric in rec and alias in label_by_alias:
                pairs.append((alias, rec[metric], label_by_alias[alias]))
        if len(pairs) < 4:
            continue
        aliases = [p[0] for p in pairs]
        x = np.array([p[1] for p in pairs], dtype=float)
        y = np.array([p[2] for p in pairs], dtype=float)
        if len(set(x.tolist())) < 2 or len(set(y.tolist())) < 2:
            continue
        rho_pt = spearmanr(x, y).statistic
        rho_pt = rho_pt if rho_pt == rho_pt else 0.0
        ktau = kendalltau(x, y).statistic
        ktau = ktau if ktau == ktau else 0.0
        _, rho_lb = jackknife_lower_bound(x, y)
        pval = permutation_p(x, y, rho_pt, args.nperm, args.seed)
        covered = sorted(required & set(aliases))
        missing = sorted(required - set(aliases))
        trusted = (
            rho_lb >= args.min_trusted_spearman
            and ktau > 0
            and len(pairs) >= args.min_trusted_n
            and pval < args.max_perm_p
            and not missing
        )
        rows_out.append({
            "public_target": "latest_public",
            "metric": metric,
            "n": len(pairs),
            "spearman": f"{rho_lb:.6f}",        # conservative bound -> what the gate reads
            "kendall": f"{ktau:.6f}",
            "required_covered": ";".join(covered),
            "required_missing": ";".join(missing),
            "trusted": "1" if trusted else "0",
            "public_order": f"pt={rho_pt:.4f}",
            "metric_order": f"perm_p={pval:.4f}",
        })
        report.append(f"| {metric} | {len(pairs)} | {rho_pt:.3f} | {rho_lb:.3f} | "
                      f"{ktau:.3f} | {pval:.4f} | {'yes' if trusted else 'no'} |")

    args.summary_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.summary_csv.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=[
            "public_target", "metric", "n", "spearman", "kendall",
            "required_covered", "required_missing", "trusted",
            "public_order", "metric_order"])
        writer.writeheader()
        for r in sorted(rows_out, key=lambda r: (r["trusted"], float(r["spearman"])), reverse=True):
            writer.writerow(r)

    any_trusted = any(r["trusted"] == "1" for r in rows_out)
    report += ["", f"**Gate status: {'OPEN-ELIGIBLE (a trusted metric exists)' if any_trusted else 'CLOSED (no trusted metric)'}**",
               f"- Wrote summary: `{args.summary_csv}`"]
    print("\n".join(report))
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text("\n".join(report) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
