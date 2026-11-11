#!/usr/bin/env python3
"""Build a strategy-signal registry from ML/RL policy reports.

This is a coordination tool. It turns scattered public-action imitation reports
into a ranked curriculum of strategy features, while keeping submit/package
promotion fenced behind public-anchor and public-score backtest gates.
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


PAIR_RE = re.compile(r"(-?\d+(?:\.\d+)?)\s*->\s*(-?\d+(?:\.\d+)?)")
FIX_RE = re.compile(r"(\d+)\s*/\s*(\d+)")


@dataclass
class Signal:
    name: str
    source: str
    kind: str
    all_before: float | None = None
    all_after: float | None = None
    holdouts: dict[str, tuple[float, float]] = field(default_factory=dict)
    fires: int | None = None
    fixes: int | None = None
    regressions: int | None = None
    decision: str = ""
    notes: str = ""

    @property
    def all_delta(self) -> float:
        if self.all_before is None or self.all_after is None:
            return 0.0
        return self.all_after - self.all_before

    @property
    def worst_holdout_delta(self) -> float:
        if not self.holdouts:
            return 0.0
        return min(after - before for before, after in self.holdouts.values())

    @property
    def net_fixes(self) -> int:
        if self.fixes is None or self.regressions is None:
            return 0
        return self.fixes - self.regressions


def parse_metric_pair(text: str) -> tuple[float, float] | None:
    match = PAIR_RE.search(text)
    if not match:
        return None
    return float(match.group(1)), float(match.group(2))


def parse_fix_regress(text: str) -> tuple[int, int] | None:
    match = FIX_RE.search(text)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def table_rows(path: Path) -> list[list[str]]:
    rows: list[list[str]] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("|") or not stripped.endswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if not cells or all(set(cell) <= {"-", ":", " "} for cell in cells):
            continue
        rows.append(cells)
    return rows


def clean_cell(text: str) -> str:
    return text.replace("`", "").strip()


def parse_ability_summary(path: Path) -> list[Signal]:
    signals: list[Signal] = []
    for cells in table_rows(path):
        if len(cells) < 7 or clean_cell(cells[0]) in {"Predicate", "---"}:
            continue
        metric = parse_metric_pair(cells[1])
        if metric is None:
            continue
        signal = Signal(
            name=f"ability_attack_predicate:{clean_cell(cells[0])}",
            source=str(path),
            kind="predicate_overlay",
            all_before=metric[0],
            all_after=metric[1],
        )
        for label, index in [
            ("team", 2),
            ("opponent", 3),
            ("episode", 4),
            ("source", 5),
        ]:
            holdout_metric = parse_metric_pair(cells[index])
            if holdout_metric is not None:
                signal.holdouts[label] = holdout_metric
        fix_regress = parse_fix_regress(cells[6])
        if fix_regress is not None:
            signal.fixes, signal.regressions = fix_regress
        signal.decision = "offline-feature-positive"
        signal.notes = "Dudunsparce ability-before-attack timing feature; evaluate as value/ranker feature, not direct hard rule."
        signals.append(signal)
    return signals


def parse_pairwise_summary(path: Path) -> list[Signal]:
    signals: list[Signal] = []
    for cells in table_rows(path):
        if len(cells) < 6 or clean_cell(cells[0]) in {"Evaluation", "---"}:
            continue
        metric = parse_metric_pair(cells[1])
        holdout_metric = parse_metric_pair(cells[2])
        if metric is None or holdout_metric is None:
            continue
        fix_regress = parse_fix_regress(cells[4])
        signal = Signal(
            name=f"pairwise_reranker:{clean_cell(cells[0])}",
            source=str(path),
            kind="pairwise_runtime_reranker",
            all_before=metric[0],
            all_after=metric[1],
            fires=int(clean_cell(cells[3])) if clean_cell(cells[3]).isdigit() else None,
            decision=clean_cell(cells[5]),
            notes="Runtime-shaped public-anchor pairwise reranker result.",
        )
        signal.holdouts["reported"] = holdout_metric
        if fix_regress is not None:
            signal.fixes, signal.regressions = fix_regress
        signals.append(signal)
    return signals


def parse_ranker_summary(path: Path) -> list[Signal]:
    signals: list[Signal] = []
    for cells in table_rows(path):
        if len(cells) < 5:
            continue
        first = clean_cell(cells[0])
        if first in {"Holdout Key", "---"}:
            continue
        if "->" in cells[1]:
            continue
        try:
            before = float(clean_cell(cells[1]))
            after = float(clean_cell(cells[2]))
        except ValueError:
            continue
        kind = "trainable_ranker"
        decision = clean_cell(cells[-1])
        signal = Signal(
            name=f"{kind}:{first}",
            source=str(path),
            kind=kind,
            all_before=before,
            all_after=after,
            decision=decision,
            notes="Trainable ranker split result; promote only if every split is positive and gates clear.",
        )
        signals.append(signal)
    return signals


def parse_exception_summary(path: Path) -> list[Signal]:
    signals: list[Signal] = []
    for cells in table_rows(path):
        if len(cells) < 7:
            continue
        first = clean_cell(cells[0])
        if first in {"Exception Feature", "---"}:
            continue
        metric = parse_metric_pair(cells[1])
        if metric is None:
            continue
        signal = Signal(
            name=f"ability_attack_exception:{first}",
            source=str(path),
            kind="exception_feature",
            all_before=metric[0],
            all_after=metric[1],
            decision=clean_cell(cells[6]),
            notes=(
                "Candidate exception to the Dudunsparce ability-before-attack timing feature; "
                "use as an offline value/ranker feature only, not as a hard runtime rule."
            ),
        )
        for label, index in [
            ("opponent", 2),
            ("episode", 3),
            ("source", 4),
        ]:
            if index >= len(cells):
                continue
            holdout_metric = parse_metric_pair(cells[index])
            if holdout_metric is not None:
                signal.holdouts[label] = holdout_metric
        fix_regress = parse_fix_regress(cells[5])
        if fix_regress is not None:
            signal.fixes, signal.regressions = fix_regress
        signals.append(signal)
    return signals


def parse_timing_overlay_summary(path: Path) -> list[Signal]:
    if not path.exists():
        return []
    status_text = "timing-overlay-evaluated"
    text = path.read_text(encoding="utf-8")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("- Status:"):
            status_text = clean_cell(stripped.split(":", 1)[1]).replace("*", "").strip()
            break
    section = ""
    signals_by_name: dict[str, Signal] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "## All Rows":
            section = "all"
            continue
        if stripped.startswith("## Holdout:"):
            section = clean_cell(stripped.split(":", 1)[1])
            continue
        if not stripped.startswith("|") or not stripped.endswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) < 12 or clean_cell(cells[0]) in {"Variant", "---", "base ranker"}:
            continue
        try:
            before = float(clean_cell(cells[2]))
            after = float(clean_cell(cells[3]))
        except ValueError:
            continue
        name = clean_cell(cells[0])
        signal = signals_by_name.get(name)
        if signal is None:
            signal = Signal(
                name=f"timing_exception_overlay:{name}",
                source=str(path),
                kind="timing_exception_overlay",
                all_before=before if section == "all" else None,
                all_after=after if section == "all" else None,
                decision=status_text if name == "accepted exceptions cumulative" else "overlay-variant",
                notes=(
                    "Dudunsparce ability-before-attack overlay with mined exception features; "
                    "use as offline value/ranker evidence only."
                ),
            )
            signals_by_name[name] = signal
        if section == "all":
            signal.all_before = before
            signal.all_after = after
            try:
                signal.fires = int(clean_cell(cells[8]))
                signal.fixes = int(clean_cell(cells[10]))
                signal.regressions = int(clean_cell(cells[11]))
            except ValueError:
                pass
        elif section:
            signal.holdouts[section] = (before, after)
    return list(signals_by_name.values())


def parse_conservative_timing_summary(path: Path) -> list[Signal]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    status_text = "conservative-timing-evaluated"
    best_variant = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("- Status:"):
            status_text = clean_cell(stripped.split(":", 1)[1]).replace("*", "").strip()
        elif stripped.startswith("- Best stable scalar feature:"):
            best_variant = clean_cell(stripped.split(":", 1)[1]).strip(".")
    if not best_variant:
        return []
    signal = Signal(
        name=f"conservative_timing_ranker:{best_variant}",
        source=str(path),
        kind="conservative_timing_ranker",
        decision=status_text,
        notes=(
            "Frozen-base scalar timing value feature for Dudunsparce ability-before-attack, "
            "with stable exception suppressors; use as offline value/ranker evidence only."
        ),
    )
    section = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "## All Rows":
            section = "all"
            continue
        if stripped.startswith("## Holdout:"):
            section = clean_cell(stripped.split(":", 1)[1])
            continue
        if not stripped.startswith("|") or not stripped.endswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) < 13 or clean_cell(cells[0]) != best_variant:
            continue
        try:
            before = float(clean_cell(cells[2]))
            after = float(clean_cell(cells[3]))
            fires = int(clean_cell(cells[8]))
            fixes = int(clean_cell(cells[11]))
            regressions = int(clean_cell(cells[12]))
        except ValueError:
            continue
        if section == "all":
            signal.all_before = before
            signal.all_after = after
            signal.fires = fires
            signal.fixes = fixes
            signal.regressions = regressions
        elif section:
            signal.holdouts[section] = (before, after)
    if signal.all_before is None:
        return []
    return [signal]


def parse_public_anchor_feature_gate(path: Path) -> list[Signal]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    feature_name = "unknown_feature"
    status_text = "public-anchor-feature-gated"
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("- Feature:"):
            feature_name = clean_cell(stripped.split(":", 1)[1])
        elif stripped.startswith("- Status:"):
            status_text = clean_cell(stripped.split(":", 1)[1]).replace("*", "").strip()
    signal = Signal(
        name=f"public_anchor_feature_gate:{feature_name}",
        source=str(path),
        kind="public_anchor_feature_gate",
        decision=status_text,
        notes=(
            "Offline strategy feature checked against deterministic holdouts and public-anchor tiers; "
            "still blocked from submit promotion by public-score backtest and package gates."
        ),
    )
    section = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "## Overall":
            section = "overall"
            continue
        if stripped == "## Holdouts":
            section = "holdouts"
            continue
        if stripped == "## Public-Anchor Tiers":
            section = "tiers"
            continue
        if stripped == "## Top Fired Lanes":
            section = "lanes"
            continue
        if not stripped.startswith("|") or not stripped.endswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) < 12 or clean_cell(cells[0]) in {"Group", "---"}:
            continue
        try:
            before = float(clean_cell(cells[2]))
            after = float(clean_cell(cells[3]))
            fires = int(clean_cell(cells[8]))
            fixes = int(clean_cell(cells[10]))
            regressions = int(clean_cell(cells[11]))
        except ValueError:
            continue
        name = clean_cell(cells[0])
        if section == "overall" and name == "all rows":
            signal.all_before = before
            signal.all_after = after
            signal.fires = fires
            signal.fixes = fixes
            signal.regressions = regressions
        elif section == "holdouts":
            signal.holdouts[name] = (before, after)
        elif section == "tiers" and fires >= 10 and name != "thin-public-replay":
            signal.holdouts[f"tier:{name}"] = (before, after)
    if signal.all_before is None:
        return []
    return [signal]


def parse_attachment_timing_overlay(path: Path) -> list[Signal]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    decisions: dict[str, str] = {}
    current_detail = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("## Predicate Detail:"):
            current_detail = clean_cell(stripped.split(":", 1)[1])
        elif current_detail and stripped.startswith("- Decision:"):
            decisions[current_detail] = clean_cell(stripped.split(":", 1)[1])

    section = ""
    signals_by_name: dict[str, Signal] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "## Summary":
            section = "summary"
            continue
        if stripped == "## Holdouts":
            section = "holdouts"
            continue
        if stripped == "## Public-Anchor Tiers":
            section = "tiers"
            continue
        if not stripped.startswith("|") or not stripped.endswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) < 12 or clean_cell(cells[0]) in {"Predicate", "Predicate / Holdout", "Predicate / Tier", "---"}:
            continue
        try:
            before = float(clean_cell(cells[2]))
            after = float(clean_cell(cells[3]))
            fires = int(clean_cell(cells[8]))
            fixes = int(clean_cell(cells[10]))
            regressions = int(clean_cell(cells[11]))
        except ValueError:
            continue
        raw_name = clean_cell(cells[0])
        if " / " in raw_name:
            predicate_name, bucket = raw_name.split(" / ", 1)
        else:
            predicate_name, bucket = raw_name, ""
        signal = signals_by_name.get(predicate_name)
        if signal is None:
            signal = Signal(
                name=f"attachment_timing_overlay:{predicate_name}",
                source=str(path),
                kind="attachment_timing_overlay",
                decision=decisions.get(predicate_name, "attachment-overlay-evaluated"),
                notes=(
                    "Attach-now vs play/search-first public-action overlay; "
                    "use only if holdout and public-anchor tier gates are non-negative."
                ),
            )
            signals_by_name[predicate_name] = signal
        if section == "summary":
            signal.all_before = before
            signal.all_after = after
            signal.fires = fires
            signal.fixes = fixes
            signal.regressions = regressions
        elif section == "holdouts" and bucket:
            signal.holdouts[bucket] = (before, after)
        elif section == "tiers" and bucket and fires >= 10 and bucket != "thin-public-replay":
            signal.holdouts[f"tier:{bucket}"] = (before, after)
    return [signal for signal in signals_by_name.values() if signal.all_before is not None]


def parse_strategy_feature_stack(path: Path) -> list[Signal]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    decisions: dict[str, str] = {}
    current_detail = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("## Stack Detail:"):
            current_detail = clean_cell(stripped.split(":", 1)[1])
        elif current_detail and stripped.startswith("- Decision:"):
            decisions[current_detail] = clean_cell(stripped.split(":", 1)[1])

    section = ""
    signals_by_name: dict[str, Signal] = {}
    ns_by_name: dict[str, int] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "## Summary":
            section = "summary"
            continue
        if stripped == "## Holdout Minimums":
            section = "holdouts"
            continue
        if stripped == "## Public-Anchor Tier Deltas":
            section = "tiers"
            continue
        if stripped.startswith("## Stack Detail:"):
            section = ""
            continue
        if not stripped.startswith("|") or not stripped.endswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if not cells or clean_cell(cells[0]) in {"Stack", "Stack / Tier", "---"}:
            continue

        if section == "summary" and len(cells) >= 12:
            name = clean_cell(cells[0])
            if name == "base_ranker":
                continue
            try:
                n = int(clean_cell(cells[1]))
                before = float(clean_cell(cells[2]))
                after = float(clean_cell(cells[3]))
                fires = int(clean_cell(cells[8]))
                fixes = int(clean_cell(cells[10]))
                regressions = int(clean_cell(cells[11]))
            except ValueError:
                continue
            signal = Signal(
                name=f"strategy_feature_stack:{name}",
                source=str(path),
                kind="strategy_feature_stack",
                all_before=before,
                all_after=after,
                fires=fires,
                fixes=fixes,
                regressions=regressions,
                decision=decisions.get(name, "strategy-stack-evaluated"),
                notes=(
                    "Composed offline strategy-feature stack over public-action imitation data; "
                    "use as behavior-cloning/value/RL curriculum evidence only."
                ),
            )
            signals_by_name[name] = signal
            ns_by_name[name] = n
            continue

        if section == "holdouts" and len(cells) >= 3:
            name = clean_cell(cells[0])
            signal = signals_by_name.get(name)
            if signal is None:
                continue
            n = max(ns_by_name.get(name, 1), 1)
            for part in clean_cell(cells[2]).split(","):
                if "=" not in part:
                    continue
                key, raw_delta = part.strip().split("=", 1)
                try:
                    delta = int(raw_delta.replace("+", ""))
                except ValueError:
                    continue
                signal.holdouts[f"holdout:{key}"] = (0.0, delta / n)
            continue

        if section == "tiers" and len(cells) >= 12:
            raw_name = clean_cell(cells[0])
            if " / " not in raw_name:
                continue
            name, tier = raw_name.split(" / ", 1)
            signal = signals_by_name.get(name)
            if signal is None or tier == "thin-public-replay":
                continue
            try:
                before = float(clean_cell(cells[2]))
                after = float(clean_cell(cells[3]))
                fires = int(clean_cell(cells[8]))
            except ValueError:
                continue
            if fires >= 10:
                signal.holdouts[f"tier:{tier}"] = (before, after)
    return list(signals_by_name.values())


def parse_attack_play_tempo(path: Path) -> list[Signal]:
    signals: list[Signal] = []
    for cells in table_rows(path):
        if len(cells) < 11 or clean_cell(cells[0]) in {"Rank", "---"}:
            continue
        try:
            n = int(clean_cell(cells[5]))
            delta = int(clean_cell(cells[6]).replace("+", ""))
            fires = int(clean_cell(cells[7]))
            worst_delta = int(clean_cell(cells[9]).replace("+", ""))
            exact_delta = int(clean_cell(cells[10]).replace("+", ""))
        except ValueError:
            continue
        fix_regress = parse_fix_regress(cells[8])
        direction = clean_cell(cells[2])
        predicate = clean_cell(cells[3])
        denominator = max(n, 1)
        signal = Signal(
            name=f"attack_play_tempo:{direction}:{predicate}",
            source=str(path),
            kind="attack_play_tempo_predicate",
            all_before=0.0,
            all_after=delta / denominator,
            fires=fires,
            decision=clean_cell(cells[1]),
            notes=(
                "Attack-vs-play tempo predicate mined from public-action imitation rows; "
                "candidate curriculum evidence only, especially when broad attack overrides are rejected."
            ),
        )
        signal.holdouts["reported_worst"] = (0.0, worst_delta / denominator)
        signal.holdouts["tier:exact-public-replay-supported"] = (0.0, exact_delta / denominator)
        if fix_regress is not None:
            signal.fixes, signal.regressions = fix_regress
        signals.append(signal)
    return signals


def status(signal: Signal) -> str:
    decision = signal.decision.lower()
    if signal.kind == "trainable_ranker":
        if "reject" in decision or "mixed" in decision or "weak" in decision:
            return "reject"
        return "research-only"
    if signal.kind == "strategy_feature_stack":
        if "offline-stack-accepted" in decision and signal.all_delta > 0 and signal.worst_holdout_delta >= 0 and signal.net_fixes >= 0:
            return "offline-feature"
        if signal.all_delta <= 0 or signal.worst_holdout_delta < 0 or signal.net_fixes < 0:
            return "reject"
        return "research-only"
    if signal.kind == "attack_play_tempo_predicate":
        if "candidate-feature" in decision and signal.all_delta > 0 and signal.worst_holdout_delta >= 0 and signal.net_fixes >= 0:
            return "candidate-feature"
        if signal.all_delta <= 0 or signal.worst_holdout_delta < 0 or signal.net_fixes < 0:
            return "reject"
        return "research-only"
    if signal.kind == "attachment_timing_overlay":
        if "offline-feature-accepted" in decision:
            return "offline-feature"
        if signal.all_delta <= 0 or signal.worst_holdout_delta < 0 or signal.net_fixes < 0:
            return "reject"
        return "research-only"
    if "reject" in decision or "too blunt" in decision:
        return "reject"
    if signal.all_delta < -0.0005 or signal.worst_holdout_delta < -0.0005:
        return "reject"
    if signal.fixes is not None and signal.regressions is not None and signal.fixes < signal.regressions:
        return "reject"
    if "feature-only" in decision or "offline-feature" in decision or "exception-feature" in decision:
        return "offline-feature"
    if signal.kind == "timing_exception_overlay" and decision == "offline-feature-accepted":
        return "offline-feature"
    if signal.kind == "conservative_timing_ranker" and decision == "offline-feature-accepted":
        return "offline-feature"
    if signal.kind == "public_anchor_feature_gate" and decision == "offline-feature-accepted":
        return "offline-feature"
    if signal.regressions:
        return "offline-feature"
    if signal.all_delta > 0 and signal.worst_holdout_delta >= 0:
        return "candidate-feature"
    return "research-only"


def priority(signal: Signal) -> float:
    score = 0.0
    score += 1000.0 * signal.all_delta
    score += 500.0 * sum(after - before for before, after in signal.holdouts.values())
    score += 0.1 * signal.net_fixes
    if status(signal) == "reject":
        score -= 1000.0
    if signal.kind == "exception_feature":
        score -= 8.0
    if signal.kind == "timing_exception_overlay":
        score -= 3.0
    if signal.kind == "conservative_timing_ranker":
        score += 2.0
    if signal.kind == "public_anchor_feature_gate":
        score += 5.0
    if signal.kind == "attachment_timing_overlay":
        score -= 4.0
    if signal.kind == "strategy_feature_stack":
        score += 4.0
    if signal.kind == "attack_play_tempo_predicate":
        score -= 1.0
    if "rank 6" in signal.name.lower() or "ability_before_model_attack" in signal.name:
        score += 15.0
    if not signal.holdouts:
        score -= 5.0
    return score


def load_signals(args: argparse.Namespace) -> list[Signal]:
    signals: list[Signal] = []
    for path in args.ability_summary:
        signals.extend(parse_ability_summary(path))
    for path in args.pairwise_summary:
        signals.extend(parse_pairwise_summary(path))
    for path in args.ranker_summary:
        signals.extend(parse_ranker_summary(path))
    for path in args.exception_summary:
        signals.extend(parse_exception_summary(path))
    for path in args.timing_overlay_summary:
        signals.extend(parse_timing_overlay_summary(path))
    for path in args.conservative_timing_summary:
        signals.extend(parse_conservative_timing_summary(path))
    for path in args.public_anchor_feature_gate:
        signals.extend(parse_public_anchor_feature_gate(path))
    for path in args.attachment_timing_overlay:
        signals.extend(parse_attachment_timing_overlay(path))
    for path in args.strategy_feature_stack:
        signals.extend(parse_strategy_feature_stack(path))
    for path in args.attack_play_tempo:
        signals.extend(parse_attack_play_tempo(path))
    return signals


def write_csv(path: Path, signals: list[Signal]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "priority",
                "status",
                "name",
                "kind",
                "all_before",
                "all_after",
                "all_delta",
                "worst_holdout_delta",
                "fires",
                "fixes",
                "regressions",
                "decision",
                "source",
                "notes",
            ],
        )
        writer.writeheader()
        for signal in sorted(signals, key=priority, reverse=True):
            writer.writerow(
                {
                    "priority": f"{priority(signal):.3f}",
                    "status": status(signal),
                    "name": signal.name,
                    "kind": signal.kind,
                    "all_before": "" if signal.all_before is None else f"{signal.all_before:.3f}",
                    "all_after": "" if signal.all_after is None else f"{signal.all_after:.3f}",
                    "all_delta": f"{signal.all_delta:.3f}",
                    "worst_holdout_delta": f"{signal.worst_holdout_delta:.3f}",
                    "fires": "" if signal.fires is None else signal.fires,
                    "fixes": "" if signal.fixes is None else signal.fixes,
                    "regressions": "" if signal.regressions is None else signal.regressions,
                    "decision": signal.decision,
                    "source": signal.source,
                    "notes": signal.notes,
                }
            )


def write_report(path: Path, signals: list[Signal], args: argparse.Namespace) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(signals, key=priority, reverse=True)
    lines: list[str] = []
    lines.append("# Strategy Signal Registry")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    lines.append("## Metadata")
    lines.append("")
    lines.append("- Research agent: Codex coding agent in the local workspace")
    lines.append("- Model family exposed to this thread: GPT-5")
    lines.append(f"- Host: {socket.gethostname()}")
    lines.append(f"- Workspace: `{Path.cwd()}`")
    lines.append(f"- Process metadata: pid={os.getpid()} user={os.environ.get('USER', 'unknown')}")
    lines.append("- Strategy premise: Pokemon TCG is type-balanced and non-transitive; improve transferable policy timing before changing deck architecture.")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    for label, paths in [
        ("Ability summaries", args.ability_summary),
        ("Pairwise summaries", args.pairwise_summary),
        ("Ranker summaries", args.ranker_summary),
        ("Exception summaries", args.exception_summary),
        ("Timing overlay summaries", args.timing_overlay_summary),
        ("Conservative timing summaries", args.conservative_timing_summary),
        ("Public-anchor feature gates", args.public_anchor_feature_gate),
        ("Attachment timing overlays", args.attachment_timing_overlay),
        ("Strategy feature stacks", args.strategy_feature_stack),
        ("Attack/play tempo predicates", args.attack_play_tempo),
    ]:
        lines.append(f"- {label}:")
        if paths:
            for item in paths:
                lines.append(f"  - `{item}`")
        else:
            lines.append("  - none")
    lines.append(f"- CSV out: `{args.csv_out}`")
    lines.append("")
    lines.append("## Ranked Signals")
    lines.append("")
    lines.append("| Priority | Status | Signal | Kind | All Top-1 Delta | Worst Holdout Delta | Fixes / Regressions | Decision |")
    lines.append("| ---: | --- | --- | --- | ---: | ---: | ---: | --- |")
    for signal in ordered:
        fix_text = "-"
        if signal.fixes is not None and signal.regressions is not None:
            fix_text = f"{signal.fixes} / {signal.regressions}"
        lines.append(
            f"| {priority(signal):.3f} | `{status(signal)}` | `{signal.name}` | `{signal.kind}` | "
            f"{signal.all_delta:.3f} | {signal.worst_holdout_delta:.3f} | {fix_text} | {signal.decision or '-'} |"
        )
    if not ordered:
        lines.append("| 0.000 | `empty` | - | - | 0.000 | 0.000 | - | - |")
    lines.append("")
    lines.append("## Current Curriculum Decision")
    lines.append("")
    accepted = [signal for signal in ordered if status(signal) in {"offline-feature", "candidate-feature"}]
    rejected = [signal for signal in ordered if status(signal) == "reject"]
    lines.append("- Promote to offline feature/curriculum only:")
    for signal in accepted[: args.limit]:
        lines.append(
            f"  - `{signal.name}` ({signal.kind}), all delta {signal.all_delta:.3f}, "
            f"worst holdout {signal.worst_holdout_delta:.3f}, fixes/regressions {signal.fixes}/{signal.regressions}."
        )
    if not accepted:
        lines.append("  - none")
    lines.append("- Explicitly rejected or too broad:")
    for signal in rejected[: args.limit]:
        lines.append(f"  - `{signal.name}` ({signal.decision or 'negative no-regression evidence'}).")
    if not rejected:
        lines.append("  - none")
    lines.append("")
    lines.append("## Next Strategy Work")
    lines.append("")
    lines.append("1. Keep `public_ability_before_model_attack` as the strongest current policy-timing feature with consistent cross-split lift.")
    lines.append("2. Prefer the frozen-base scalar timing feature (`boost=4 stable-exceptions`) as the current conservative value-model target; its public-anchor feature gate is accepted for offline curriculum only.")
    lines.append("3. Treat accepted strategy feature stacks as curriculum/value-model evidence: they compose Dudunsparce timing with mined attachment timing, but remain offline-only.")
    lines.append("4. Treat attack/play tempo predicates as lower-confidence candidate features until they receive the same stack/public-anchor confirmation as Dudunsparce and attachment timing.")
    lines.append("5. Treat the mined attachment timing overlays as secondary offline curriculum features: the broad overlay remains a negative control, while lane/time-scoped predicates are now confirmation-gated.")
    lines.append("6. Do not package an agent from this registry. Promotion still requires public-anchor eligibility and a public-score backtest clearing the pre-submit gate.")
    lines.append("7. Use rejected broad pairwise, broad attack-over-play, and broad attachment overlay rows as negative controls when adding new ML/RL features; pairwise target accuracy alone is not a success metric.")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ability-summary", type=Path, action="append", default=[Path("strategy/ability_attack_predicate_overlay_summary_20260620T1830.md")])
    parser.add_argument("--pairwise-summary", type=Path, action="append", default=[Path("strategy/public_anchor_pairwise_reranker_summary_20260620T1848.md")])
    parser.add_argument("--ranker-summary", type=Path, action="append", default=[Path("strategy/strategy_ranker_experiment_summary_20260620T1840.md")])
    parser.add_argument("--exception-summary", type=Path, action="append", default=[Path("strategy/ability_attack_exception_summary_20260620T1900.md")])
    parser.add_argument("--timing-overlay-summary", type=Path, action="append", default=[Path("strategy/timing_exception_overlay_20260620T1910_stable_subset.md")])
    parser.add_argument("--conservative-timing-summary", type=Path, action="append", default=[Path("strategy/conservative_timing_ranker_20260620T1915.md")])
    parser.add_argument("--public-anchor-feature-gate", type=Path, action="append", default=[Path("strategy/public_anchor_feature_gate_20260620T1924_timing_boost4.md")])
    parser.add_argument(
        "--attachment-timing-overlay",
        type=Path,
        action="append",
        default=[
            Path("strategy/attachment_timing_overlay_20260620T1938.md"),
            Path("strategy/attachment_timing_overlay_20260620T1945_mined.md"),
        ],
    )
    parser.add_argument("--strategy-feature-stack", type=Path, action="append", default=[Path("strategy/strategy_feature_stack_20260620T2008_tempo.md")])
    parser.add_argument("--attack-play-tempo", type=Path, action="append", default=[Path("strategy/attack_play_tempo_predicates_20260620T1958.md")])
    parser.add_argument("--report-out", type=Path, default=Path("strategy/strategy_signal_registry.md"))
    parser.add_argument("--csv-out", type=Path, default=Path("strategy/strategy_signal_registry.csv"))
    parser.add_argument("--limit", type=int, default=8)
    args = parser.parse_args()

    signals = load_signals(args)
    write_csv(args.csv_out, signals)
    write_report(args.report_out, signals, args)
    print(f"signals={len(signals)} report={args.report_out} csv={args.csv_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
