#!/usr/bin/env python3
"""Rank latest-two submission pairs across broad, focus, drift, and public risk.

Deck strength in this competition is conditional: type pressure, matchup
families, and policy timing can make a one-window local winner fail publicly.
This selector keeps the pair decision explicit by fusing:

* a broad replay-pool gauntlet,
* one or more focused gauntlets,
* optional drift/reset-fit evidence, and
* public-family risk from the reset candidate ledger.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class CandidateMeta:
    alias: str
    candidate: str
    path: str
    family: str
    kind: str
    replay_win_rate: float | None
    fixed_win_rate: float | None
    public_current: float | None
    public_best: float | None
    ranker_mimic: bool
    notes: str


@dataclass
class CandidateResult:
    alias: str
    label: str
    source: str = "gauntlet"
    weighted: float | None = None
    rates: dict[str, float] = field(default_factory=dict)
    weights: dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True)
class PairScore:
    left: str
    right: str
    score: float
    broad: float
    focus: float
    stability: float
    penalty: float
    bonus: float
    shared_blindspots: list[str]
    reasons: list[str]


@dataclass(frozen=True)
class BacktestGate:
    supplied: bool
    trusted: bool
    metric: str
    spearman: float | None
    kendall: float | None
    n: int | None
    missing: str


@dataclass(frozen=True)
class AnchorStatus:
    alias: str
    candidate: str
    archive: str
    eligible: bool
    state: str
    reasons: str


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

RECOVERY_PRIOR_FAMILIES = {"pure_crustle", "ethan_crustle", "hammer_crustle"}


def alias_from_text(text: str) -> str | None:
    lowered = text.lower()
    for needle, alias in ALIAS_OVERRIDES.items():
        if needle in lowered:
            return alias
    matches = re.findall(r"(?<![a-z0-9])v(\d+)(?![a-z0-9])", lowered)
    if matches:
        return f"v{matches[-1]}"
    return None


def parse_optional_float(value: str | None) -> float | None:
    if value is None or not value.strip():
        return None
    try:
        return float(value)
    except ValueError:
        return None


def parse_optional_int(value: str | None) -> int | None:
    if value is None or not value.strip():
        return None
    try:
        return int(value)
    except ValueError:
        return None


def parse_backtest_gate(path: Path | None, min_spearman: float) -> BacktestGate:
    if path is None:
        return BacktestGate(False, False, "", None, None, None, "missing backtest summary")
    if not path.exists():
        return BacktestGate(True, False, "", None, None, None, f"backtest summary not found: {path}")
    best: BacktestGate | None = None
    with path.open(encoding="utf-8-sig", newline="") as file:
        for row in csv.DictReader(file):
            if row.get("public_target") != "latest_public":
                continue
            spearman = parse_optional_float(row.get("spearman"))
            kendall = parse_optional_float(row.get("kendall"))
            n = parse_optional_int(row.get("n"))
            trusted = row.get("trusted") == "1" and spearman is not None and spearman >= min_spearman
            gate = BacktestGate(
                True,
                trusted,
                row.get("metric") or "",
                spearman,
                kendall,
                n,
                row.get("required_missing") or "",
            )
            if best is None:
                best = gate
                continue
            best_value = best.spearman if best.spearman is not None else -999.0
            gate_value = gate.spearman if gate.spearman is not None else -999.0
            if (gate.trusted, gate_value) > (best.trusted, best_value):
                best = gate
    if best is None:
        return BacktestGate(True, False, "", None, None, None, "no latest_public rows in backtest summary")
    return best


def load_anchor_status(path: Path | None) -> dict[str, AnchorStatus]:
    if path is None:
        return {}
    statuses: dict[str, AnchorStatus] = {}
    with path.open(encoding="utf-8-sig", newline="") as file:
        for row in csv.DictReader(file):
            candidate = row.get("candidate", "")
            archive = row.get("archive", "")
            alias = alias_from_text(candidate) or alias_from_text(archive)
            if alias is None:
                continue
            status = AnchorStatus(
                alias=alias,
                candidate=candidate,
                archive=archive,
                eligible=row.get("submit_eligible") == "1",
                state=row.get("anchor_state", ""),
                reasons=row.get("reasons", ""),
            )
            statuses[alias] = status
    return statuses


def load_candidate_meta(path: Path) -> dict[str, CandidateMeta]:
    metas: dict[str, CandidateMeta] = {}
    with path.open(encoding="utf-8-sig", newline="") as file:
        for row in csv.DictReader(file):
            alias = alias_from_text(row.get("candidate", "")) or alias_from_text(row.get("path", ""))
            if alias is None:
                continue
            metas[alias] = CandidateMeta(
                alias=alias,
                candidate=row["candidate"],
                path=row["path"],
                family=row["family"],
                kind=row["kind"],
                replay_win_rate=parse_optional_float(row.get("replay_win_rate")),
                fixed_win_rate=parse_optional_float(row.get("fixed_win_rate")),
                public_current=parse_optional_float(row.get("public_current")),
                public_best=parse_optional_float(row.get("public_best")),
                ranker_mimic=row.get("ranker_mimic", "").strip().lower() in {"1", "true", "yes"},
                notes=row.get("notes", ""),
            )
    return metas


def normalize_opponent(key: str) -> str:
    if ":" not in key:
        return key.replace("_", "-")
    left, right = key.split(":", 1)
    return f"{left.replace('_', '-')}:{right}"


def parse_gauntlet(path: Path) -> dict[str, CandidateResult]:
    results: dict[str, CandidateResult] = {}
    current: CandidateResult | None = None
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("Candidate "):
            label = Path(line.removeprefix("Candidate ").strip()).name
            alias = alias_from_text(label) or label
            current = CandidateResult(alias=alias, label=label)
            results[alias] = current
            continue
        if current is None:
            continue
        if line.startswith("weighted_win_rate,"):
            try:
                current.weighted = float(line.split(",", 1)[1])
            except ValueError:
                pass
            continue
        if line.startswith(("opponent,", "skipped,", "forward ", "swapped ")):
            continue
        row = next(csv.reader([line]))
        if len(row) < 7 or ":" not in row[0]:
            continue
        try:
            key = normalize_opponent(row[0])
            current.weights[key] = float(row[1])
            current.rates[key] = float(row[6])
        except ValueError:
            continue
    return results


def opponent_weight_template(results: dict[str, CandidateResult]) -> dict[str, float]:
    weights: dict[str, float] = {}
    for result in results.values():
        for key, weight in result.weights.items():
            weights[key] = max(weights.get(key, 0.0), weight)
    return weights


def candidate_prior_score(meta: CandidateMeta) -> float | None:
    values = [
        value
        for value in (meta.replay_win_rate, meta.fixed_win_rate)
        if value is not None and 0.0 <= value <= 1.0
    ]
    if not values:
        return None
    return sum(values) / len(values)


def should_fill_prior(meta: CandidateMeta) -> bool:
    return meta.kind == "public-recovery" or meta.family in RECOVERY_PRIOR_FAMILIES


def fill_recovery_priors(
    results: dict[str, CandidateResult],
    metas: dict[str, CandidateMeta],
) -> list[str]:
    """Add conservative uniform priors for public-recovery shells absent from gauntlets."""
    template = opponent_weight_template(results)
    if not template:
        return []
    added: list[str] = []
    for alias, meta in metas.items():
        if alias in results or not should_fill_prior(meta):
            continue
        prior = candidate_prior_score(meta)
        if prior is None:
            continue
        result = CandidateResult(
            alias=alias,
            label=f"candidate-prior:{alias}",
            source="candidate-prior",
            weighted=prior,
        )
        result.rates = {key: prior for key in template}
        result.weights = dict(template)
        results[alias] = result
        added.append(alias)
    return sorted(added)


def parse_drift(path: Path | None) -> dict[str, float]:
    if path is None or not path.exists():
        return {}
    drift: dict[str, float] = {}
    in_table = False
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line.startswith("| Candidate |"):
            in_table = True
            continue
        if not in_table:
            continue
        if line.startswith("| ---"):
            continue
        if not line.startswith("|"):
            if drift:
                break
            continue
        parts = [part.strip() for part in line.strip("|").split("|")]
        if len(parts) < 9:
            continue
        alias = parts[0].strip("`")
        try:
            drift[alias] = float(parts[8])
        except ValueError:
            continue
    return drift


def weighted_pair_coverage(
    left: CandidateResult | None,
    right: CandidateResult | None,
    blind_threshold: float,
) -> tuple[float, list[str]]:
    if left is None and right is None:
        return 0.0, []
    keys = set()
    if left is not None:
        keys.update(left.rates)
    if right is not None:
        keys.update(right.rates)

    weighted = 0.0
    total = 0.0
    blindspots: list[tuple[float, str, float, float]] = []
    for key in keys:
        weight = 0.0
        if left is not None:
            weight = max(weight, left.weights.get(key, 0.0))
        if right is not None:
            weight = max(weight, right.weights.get(key, 0.0))
        left_rate = left.rates.get(key, 0.0) if left is not None else 0.0
        right_rate = right.rates.get(key, 0.0) if right is not None else 0.0
        best = max(left_rate, right_rate)
        weighted += weight * best
        total += weight
        if left_rate < blind_threshold and right_rate < blind_threshold:
            blindspots.append((weight, key, left_rate, right_rate))
    blindspots.sort(key=lambda item: (-item[0], item[1]))
    return (weighted / total if total else 0.0), [
        f"`{key}` {left_rate:.3f}/{right_rate:.3f} (w {weight:.2f})"
        for weight, key, left_rate, right_rate in blindspots[:4]
    ]


def blindspot_key(text: str) -> str:
    match = re.match(r"`([^`]+)`", text)
    return match.group(1) if match else text


def public_risk(alias: str, metas: dict[str, CandidateMeta]) -> tuple[float, list[str]]:
    meta = metas.get(alias)
    if meta is None:
        return 0.02, ["missing_meta"]
    penalty = 0.0
    reasons: list[str] = []
    family_recent_failures = [
        item.public_current
        for item in metas.values()
        if item.family == meta.family and item.public_current is not None and item.public_current < 800
    ]
    if meta.kind == "local-variant":
        penalty += 0.060
        reasons.append("local_variant")
    if meta.family == "alakazam_battle_cage":
        penalty += 0.055
        reasons.append("battle_cage_public_miss_family")
    if meta.kind == "submitted" and meta.public_current is not None and meta.public_current < 900:
        penalty += 0.100
        reasons.append("submitted_below_900")
    if meta.public_current is not None and meta.public_current < 800:
        penalty += 0.050
        reasons.append("very_low_public")
    elif family_recent_failures:
        penalty += 0.075
        reasons.append(f"family_recent_public_failure={min(family_recent_failures):.1f}")
    return penalty, reasons


def shell_key(alias: str, metas: dict[str, CandidateMeta]) -> str:
    meta = metas.get(alias)
    if meta is None:
        return alias
    if meta.candidate.startswith("hiroingk-hammer-"):
        return "hiroingk-hammer-b9bcfb3e10"
    return meta.family


def score_pair(
    left: str,
    right: str,
    broad: dict[str, CandidateResult],
    focus_sets: list[dict[str, CandidateResult]],
    drift: dict[str, float],
    metas: dict[str, CandidateMeta],
    focus_weight: float,
    blind_threshold: float,
) -> PairScore:
    broad_score, broad_blind = weighted_pair_coverage(broad.get(left), broad.get(right), blind_threshold)
    focus_scores: list[float] = []
    focus_blinds: list[str] = []
    for focus in focus_sets:
        value, blinds = weighted_pair_coverage(focus.get(left), focus.get(right), blind_threshold)
        if value:
            focus_scores.append(value)
            focus_blinds.extend(blinds)
    focus_score = sum(focus_scores) / len(focus_scores) if focus_scores else broad_score

    stability_values = [drift.get(alias) for alias in (left, right) if drift.get(alias) is not None]
    stability = sum(stability_values) / len(stability_values) if stability_values else (
        ((broad.get(left).weighted or 0.0) + (broad.get(right).weighted or 0.0)) / 2.0
        if broad.get(left) and broad.get(right)
        else broad_score
    )

    left_penalty, left_reasons = public_risk(left, metas)
    right_penalty, right_reasons = public_risk(right, metas)
    penalty = left_penalty + right_penalty
    reasons = [f"{left}:{reason}" for reason in left_reasons] + [f"{right}:{reason}" for reason in right_reasons]

    bonus = 0.0
    left_meta = metas.get(left)
    right_meta = metas.get(right)
    if left_meta and right_meta:
        if shell_key(left, metas) == shell_key(right, metas):
            penalty += 0.060
            reasons.append("same_exact_shell_or_family")
        elif left_meta.family != right_meta.family:
            bonus += 0.020
            reasons.append("family_diversity")
        if left_meta.ranker_mimic and right_meta.ranker_mimic:
            bonus += 0.010
            reasons.append("double_ranker_mimic")

    shared_blindspots = []
    seen_blindspot_keys: set[str] = set()
    for item in broad_blind + focus_blinds:
        key = blindspot_key(item)
        if key in seen_blindspot_keys:
            continue
        seen_blindspot_keys.add(key)
        shared_blindspots.append(item)
    if shared_blindspots:
        penalty += min(0.060, 0.015 * len(shared_blindspots))
        reasons.append(f"shared_blindspots={len(shared_blindspots)}")

    broad_weight = max(0.0, 0.72 - focus_weight)
    raw = broad_weight * broad_score + focus_weight * focus_score + 0.28 * stability
    score = raw + bonus - penalty
    return PairScore(
        left=left,
        right=right,
        score=score,
        broad=broad_score,
        focus=focus_score,
        stability=stability,
        penalty=penalty,
        bonus=bonus,
        shared_blindspots=shared_blindspots[:5],
        reasons=reasons,
    )


def candidate_order(pair: PairScore, broad: dict[str, CandidateResult], drift: dict[str, float]) -> tuple[str, str]:
    def single(alias: str) -> float:
        return 0.70 * (broad.get(alias).weighted if broad.get(alias) and broad[alias].weighted is not None else 0.0) + 0.30 * drift.get(alias, 0.0)

    if single(pair.right) > single(pair.left):
        return pair.right, pair.left
    return pair.left, pair.right


def render(args: argparse.Namespace) -> str:
    metas = load_candidate_meta(args.candidates)
    anchor_status = load_anchor_status(args.anchor_status)
    broad = parse_gauntlet(args.broad)
    focus_sets = [parse_gauntlet(path) for path in args.focus]
    drift = parse_drift(args.drift)
    backtest_gate = parse_backtest_gate(args.backtest_summary, args.min_backtest_spearman)
    prior_aliases = fill_recovery_priors(broad, metas)
    focus_prior_aliases: set[str] = set()
    for focus in focus_sets:
        focus_prior_aliases.update(fill_recovery_priors(focus, metas))

    aliases = sorted(set(metas) & set(broad))
    pairs: list[PairScore] = []
    for index, left in enumerate(aliases):
        for right in aliases[index + 1 :]:
            pairs.append(
                score_pair(
                    left,
                    right,
                    broad,
                    focus_sets,
                    drift,
                    metas,
                    args.focus_weight,
                    args.blind_threshold,
                )
            )
    pairs.sort(key=lambda pair: (-pair.score, pair.left, pair.right))
    submit_pairs = [
        pair
        for pair in pairs
        if not anchor_status
        or (anchor_status.get(pair.left, AnchorStatus(pair.left, "", "", False, "missing-anchor-status", "missing anchor status")).eligible
            and anchor_status.get(pair.right, AnchorStatus(pair.right, "", "", False, "missing-anchor-status", "missing anchor status")).eligible)
    ]

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = []
    lines.append("# Pair Strategy Selector")
    lines.append("")
    lines.append(f"Generated: {now}")
    lines.append("")
    lines.append("## Research Agent Metadata")
    lines.append("")
    lines.append("- Research agent: Codex coding agent in the local workspace")
    lines.append("- Model family exposed to this thread: GPT-5")
    lines.append(f"- Host: {socket.gethostname()}")
    lines.append(f"- Workspace: `{Path.cwd()}`")
    lines.append(f"- Command cwd metadata: pid={os.getpid()} user={os.environ.get('USER', 'unknown')}")
    lines.append("- Strategy premise: Pokemon TCG has no single strongest deck; latest-two should cover different pressure axes after public-risk penalties.")
    lines.append("")
    lines.append("## Sources")
    lines.append("")
    lines.append(f"- Broad gauntlet: `{args.broad}`")
    for path in args.focus:
        lines.append(f"- Focus gauntlet: `{path}`")
    if args.drift:
        lines.append(f"- Drift evidence: `{args.drift}`")
    lines.append(f"- Candidate evidence: `{args.candidates}`")
    if args.anchor_status:
        lines.append(f"- Public-anchor status: `{args.anchor_status}`")
    if args.backtest_summary:
        lines.append(f"- Backtest summary: `{args.backtest_summary}`")
    if backtest_gate.supplied:
        spearman_text = "nan" if backtest_gate.spearman is None else f"{backtest_gate.spearman:.3f}"
        kendall_text = "nan" if backtest_gate.kendall is None else f"{backtest_gate.kendall:.3f}"
        lines.append(
            f"- Backtest gate: trusted={backtest_gate.trusted}; metric=`{backtest_gate.metric}`; "
            f"Spearman={spearman_text}; Kendall={kendall_text}; n={backtest_gate.n}; "
            f"missing={backtest_gate.missing or '-'}"
        )
    if prior_aliases or focus_prior_aliases:
        lines.append(
            "- Recovery prior fallback: "
            + ", ".join(f"`{alias}`" for alias in sorted(set(prior_aliases) | focus_prior_aliases))
            + " (uniform replay/fixed prior; absent from at least one gauntlet)"
        )
    lines.append("")

    backtest_blocks_submit = args.backtest_summary is not None and not backtest_gate.trusted
    anchor_blocks_submit = bool(anchor_status) and not submit_pairs
    if submit_pairs and not backtest_blocks_submit:
        best_pair = submit_pairs[0]
        first, second = candidate_order(best_pair, broad, drift)
        first_path = metas.get(first).path if metas.get(first) else first
        second_path = metas.get(second).path if metas.get(second) else second
        lines.append("## Recommendation")
        lines.append("")
        lines.append(f"- Pair: `{first_path}` then `{second_path}`")
        lines.append(f"- Pair aliases: `{first}` + `{second}`")
        lines.append(f"- Stress score: {best_pair.score:.4f}")
        lines.append(f"- Broad coverage: {best_pair.broad:.4f}; focus coverage: {best_pair.focus:.4f}; drift/stability: {best_pair.stability:.4f}")
        if best_pair.shared_blindspots:
            lines.append("- Shared blindspots: " + "; ".join(best_pair.shared_blindspots))
        lines.append("- Reasons: " + ("; ".join(best_pair.reasons) if best_pair.reasons else "passes stress gates"))
        lines.append("")
    elif pairs:
        lines.append("## Recommendation")
        lines.append("")
        lines.append("- Pair: **NO SUBMIT-SAFE PAIR**")
        if backtest_blocks_submit:
            lines.append(
                "- Blocker: predictive-validity backtest did not clear the trust gate; pair rankings below are research-only."
            )
        if anchor_blocks_submit:
            lines.append("- Blocker: no pair has two public-anchor-eligible candidates under the supplied anchor CSV.")
        lines.append("")

    lines.append("## Pair Rankings")
    lines.append("")
    lines.append("| Rank | Pair | Anchor Eligible | Stress | Broad | Focus | Stability | Bonus | Penalty | Shared Blindspots | Reasons |")
    lines.append("| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |")
    for rank, pair in enumerate(pairs[: args.limit], 1):
        blind = "; ".join(pair.shared_blindspots) if pair.shared_blindspots else "-"
        reasons = "; ".join(pair.reasons) if pair.reasons else "-"
        anchor_ok = "-"
        if anchor_status:
            left_ok = anchor_status.get(pair.left, AnchorStatus(pair.left, "", "", False, "missing-anchor-status", "")).eligible
            right_ok = anchor_status.get(pair.right, AnchorStatus(pair.right, "", "", False, "missing-anchor-status", "")).eligible
            anchor_ok = "yes" if left_ok and right_ok else "no"
        lines.append(
            f"| {rank} | `{pair.left}` + `{pair.right}` | {anchor_ok} | {pair.score:.4f} | {pair.broad:.4f} | "
            f"{pair.focus:.4f} | {pair.stability:.4f} | {pair.bonus:.3f} | {pair.penalty:.3f} | {blind} | {reasons} |"
        )
    lines.append("")

    lines.append("## Candidate Singles")
    lines.append("")
    lines.append("| Candidate | Broad | Drift | Family | Kind | Public | Anchor | Notes |")
    lines.append("| --- | ---: | ---: | --- | --- | --- | --- | --- |")
    for alias in aliases:
        meta = metas.get(alias)
        public = "-"
        if meta and meta.public_current is not None:
            public = f"{meta.public_current:.1f}"
        anchor = "-"
        if anchor_status:
            status = anchor_status.get(alias)
            anchor = f"{status.state}:{'eligible' if status and status.eligible else 'blocked'}" if status else "missing-anchor-status:blocked"
        lines.append(
            f"| `{alias}` | {(broad[alias].weighted or 0.0):.4f} | {drift.get(alias, 0.0):.4f} | "
            f"{meta.family if meta else '-'} | {meta.kind if meta else '-'} | {public} | {anchor} | {meta.notes if meta else '-'} |"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--broad", required=True, type=Path)
    parser.add_argument("--focus", action="append", type=Path, default=[])
    parser.add_argument("--drift", type=Path)
    parser.add_argument("--candidates", required=True, type=Path)
    parser.add_argument("--anchor-status", type=Path)
    parser.add_argument("--backtest-summary", type=Path)
    parser.add_argument("--min-backtest-spearman", type=float, default=0.55)
    parser.add_argument("--focus-weight", type=float, default=0.22)
    parser.add_argument("--blind-threshold", type=float, default=0.5)
    parser.add_argument("--limit", type=int, default=12)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = render(args)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report + "\n", encoding="utf-8")
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
