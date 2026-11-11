#!/usr/bin/env python3
"""Phase-0 go/no-go: how learnable is the public score at all?

The June-20 over-fit was blamed on the local evaluator, but the deeper problem is
that the public score is a HIGH-VARIANCE label: the same byte-identical artifact
has scored 649 / 890 / 939 (v20) and 876 / 1017 / 950 (v39) across submissions,
because of opponent draw, shuffles/coin-flips, and the moving latest-2 window.

If the label is that noisy, then NO local metric -- however good -- can correlate
strongly with a single realized public score. This tool estimates that empirical
**noise ceiling**: the maximum rank correlation a *perfect* predictor (one that
knows each agent's true expected public score) could achieve against the single
noisy score the gate actually sees.

Method
------
1. Group submissions by archive (fileName). Archives submitted more than once give
   repeated measurements of the SAME agent -> the within-archive spread is pure
   label noise.
2. Pool the within-archive residuals (score - archive_mean) -> empirical noise.
3. Treat each archive's mean as its "true" score (what a perfect predictor would
   output). Monte-Carlo: draw one noisy realized score per archive from the pooled
   residual distribution and compute Spearman(true_means, noisy_draws). Repeat.
4. Report the distribution. The median/10th-percentile is the achievable ceiling.

Decision rule (printed): if the ceiling's lower band is below the gate threshold
(default 0.55), an AUTONOMOUS-submit gate can never honestly open -> build only an
advisory selection assistant, and humans keep pulling the trigger.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
from scipy.stats import spearmanr


def load_scores_by_archive(path: Path) -> dict[str, list[float]]:
    by_archive: dict[str, list[float]] = defaultdict(list)
    with path.open(encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            fname = (row.get("fileName") or "").strip()
            status = (row.get("status") or "").upper()
            raw = (row.get("publicScore") or "").strip()
            if not fname or "COMPLETE" not in status or not raw:
                continue
            try:
                by_archive[fname].append(float(raw))
            except ValueError:
                continue
    return dict(by_archive)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Estimate the public-score noise ceiling")
    parser.add_argument("--submissions", required=True, type=Path)
    parser.add_argument("--gate-threshold", type=float, default=0.55,
                        help="Spearman the predictive-validity gate requires")
    parser.add_argument("--trials", type=int, default=4000)
    parser.add_argument("--seed", type=int, default=20260622)
    parser.add_argument("--output", type=Path, default=None, help="optional markdown report")
    args = parser.parse_args(argv)

    by_archive = load_scores_by_archive(args.submissions)
    if not by_archive:
        sys.stderr.write("ERROR: no complete-scored submissions found.\n")
        return 2

    means = {a: float(np.mean(v)) for a, v in by_archive.items()}
    repeat_archives = {a: v for a, v in by_archive.items() if len(v) >= 2}
    residuals: list[float] = []
    for a, v in repeat_archives.items():
        m = means[a]
        residuals.extend([s - m for s in v])
    residuals_arr = np.array(residuals, dtype=float)

    n_archives = len(by_archive)
    n_repeat = len(repeat_archives)
    pooled_noise_std = float(np.std(residuals_arr)) if residuals_arr.size else float("nan")
    max_within_spread = max((max(v) - min(v) for v in repeat_archives.values()), default=0.0)
    signal_std = float(np.std(list(means.values()))) if n_archives > 1 else float("nan")

    lines: list[str] = []
    def out(s: str = "") -> None:
        lines.append(s)
        print(s)

    out("# Public-Score Noise Ceiling (Phase 0)")
    out("")
    out(f"- Source: `{args.submissions}`")
    out(f"- Distinct scored archives: {n_archives}")
    out(f"- Archives with >=2 measurements (give noise estimate): {n_repeat}")
    out(f"- Pooled within-archive noise std (label noise): "
        f"{pooled_noise_std:.1f}" if residuals_arr.size else "- Pooled within-archive noise std: n/a")
    out(f"- Largest within-archive spread (same artifact): {max_within_spread:.1f}")
    out(f"- Between-archive signal std (true differences): {signal_std:.1f}")

    if residuals_arr.size < 2 or n_archives < 4:
        out("")
        out("**Insufficient repeated measurements to estimate a reliable ceiling.** "
            "Submit a few known archives more than once (or accumulate history) before "
            "trusting any autonomous-submit decision. Stay advisory.")
        _write(args.output, lines)
        return 0

    reliability = signal_std**2 / (signal_std**2 + pooled_noise_std**2) if pooled_noise_std == pooled_noise_std else float("nan")

    # Monte-Carlo achievable Spearman: perfect predictor (true means) vs one noisy draw.
    rng = np.random.default_rng(args.seed)
    archs = list(means.keys())
    true_means = np.array([means[a] for a in archs])
    sims = []
    for _ in range(args.trials):
        noisy = true_means + rng.choice(residuals_arr, size=len(archs), replace=True)
        rho = spearmanr(true_means, noisy).statistic
        if rho == rho:  # not nan
            sims.append(rho)
    sims_arr = np.array(sims)
    p10, p50, p90 = np.percentile(sims_arr, [10, 50, 90])

    out("")
    out("## Achievable correlation for a PERFECT local predictor")
    out(f"- Test-retest reliability (signal²/(signal²+noise²)): {reliability:.3f}")
    out(f"- Monte-Carlo Spearman vs single realized score: "
        f"median **{p50:.3f}**, 10th pct {p10:.3f}, 90th pct {p90:.3f} "
        f"({len(sims)} trials)")
    out("")
    out("## Decision")
    threshold = args.gate_threshold
    if p50 < threshold:
        out(f"- **NO-GO for autonomous submission.** Even a perfect predictor would median "
            f"Spearman {p50:.3f} < gate threshold {threshold:.2f}. The predictive-validity "
            f"gate can essentially never honestly open on single-read labels.")
        out("- **Action:** run the loop in ADVISORY mode (propose pairs, humans submit), and "
            "reduce label noise first — finalize each submission as a MEDIAN over multiple "
            "reads (outcome_ledger), and gate on the median, not a single score.")
        verdict = "NO-GO (advisory only)"
    elif p10 < threshold <= p50:
        out(f"- **MARGINAL.** Median achievable Spearman {p50:.3f} >= {threshold:.2f}, but the "
            f"10th-pct {p10:.3f} is below it. Autonomous submission is only defensible with "
            f"MEDIAN-of-multiple-reads labels and a CI-lower-bound gate (not a point estimate).")
        verdict = "MARGINAL (median-labels required)"
    else:
        out(f"- **GO (cautiously).** Even the 10th-pct achievable Spearman {p10:.3f} >= "
            f"{threshold:.2f}. The public score is learnable enough for an honest gate, "
            f"provided labels use median-of-multiple-reads and LOOCV correlation.")
        verdict = "GO (with median labels + LOOCV)"
    out("")
    out(f"**Verdict: {verdict}**")
    _write(args.output, lines)
    return 0


def _write(output: Path | None, lines: list[str]) -> None:
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"\nWrote report: {output}")


if __name__ == "__main__":
    sys.exit(main())
