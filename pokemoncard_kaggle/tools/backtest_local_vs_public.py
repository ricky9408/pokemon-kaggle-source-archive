#!/usr/bin/env python3
"""Backtest local selection metrics against actual Kaggle public scores.

The reset-window failure mode was not "a weak local metric"; it was a local
metric that looked precise while ranking bad public submissions highly. This
script keeps the calibration problem separate from candidate selection:

1. join submitted archives to their public score history,
2. extract local metrics from existing strategy artifacts,
3. compute rank correlations per metric, and
4. write a compact report plus machine-readable summary for submit gates.

It never submits and does not call Kaggle. Feed it a saved submissions export,
for example:

    uv run python tools/backtest_local_vs_public.py \
      --submissions strategy/kaggle_submissions_latest_20260620T1644.csv \
      --candidate-csv strategy/reset_candidates_20260620T0112_public_failure_overlay.csv \
      --gauntlet strategy/replay_pool_20260620T1529_strategy_broad_recovery.txt \
      --pair-selector strategy/pair_strategy_selector_20260620T0118_public_failure_overlay.md \
      --calibrated strategy/calibrated_rank_20260620T0118_public_failure_overlay.txt \
      --psro strategy/psro_payoff_20260620T1529_strategy.md
"""

from __future__ import annotations

import argparse
import csv
import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path


@dataclass(frozen=True)
class Submission:
    archive: str
    submitted_at: datetime
    description: str
    status: str
    public_score: float


@dataclass
class ArchiveRecord:
    archive: str
    alias: str
    submissions: list[Submission] = field(default_factory=list)
    metrics: dict[str, float] = field(default_factory=dict)

    @property
    def latest_public(self) -> float | None:
        complete = [row for row in self.submissions if row.status.endswith(".COMPLETE")]
        if not complete:
            return None
        return max(complete, key=lambda row: row.submitted_at).public_score

    @property
    def best_public(self) -> float | None:
        complete = [row.public_score for row in self.submissions if row.status.endswith(".COMPLETE")]
        return max(complete) if complete else None

    @property
    def latest_date(self) -> str:
        if not self.submissions:
            return "-"
        return max(row.submitted_at for row in self.submissions).strftime("%Y-%m-%d %H:%M:%S")


@dataclass(frozen=True)
class CorrelationRow:
    public_target: str
    metric: str
    n: int
    spearman: float
    kendall: float
    required_covered: tuple[str, ...]
    required_missing: tuple[str, ...]
    public_order: str
    metric_order: str


ARCHIVE_ALIAS_OVERRIDES = {
    "submission-crustle.tar.gz": "pure-crustle",
    "submission.tar.gz": "v1",
    "submission-crustle-cage.tar.gz": "v3",
    "submission-crustle-backup-v4.tar.gz": "v4",
    "submission-crustle-backup-v5.tar.gz": "v5",
}


def alias_from_text(text: str) -> str:
    lowered = text.lower()
    if lowered in ARCHIVE_ALIAS_OVERRIDES:
        return ARCHIVE_ALIAS_OVERRIDES[lowered]
    match = re.findall(r"(?<![a-z0-9])v(\d+)(?![a-z0-9])", lowered)
    if match:
        return f"v{match[-1]}"
    stripped = lowered
    stripped = stripped.removeprefix("submission-").removesuffix(".tar.gz")
    stripped = stripped.replace("_", "-")
    return stripped


def parse_float(value: str | None) -> float | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def parse_datetime(value: str) -> datetime:
    text = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def sanitize_metric_name(path: Path, suffix: str) -> str:
    stem = re.sub(r"[^a-zA-Z0-9]+", "_", path.stem).strip("_")
    suffix = re.sub(r"[^a-zA-Z0-9]+", "_", suffix).strip("_")
    return f"{stem}:{suffix}"


def load_submission_history(path: Path) -> dict[str, ArchiveRecord]:
    text = path.read_text(encoding="utf-8", errors="replace")
    records: dict[str, ArchiveRecord] = {}
    if text.lstrip().startswith("ref,"):
        reader = csv.DictReader(text.splitlines())
        for row in reader:
            score = parse_float(row.get("publicScore"))
            if score is None:
                continue
            archive = (row.get("fileName") or "").strip()
            if not archive:
                continue
            submission = Submission(
                archive=archive,
                submitted_at=parse_datetime(row.get("date", "")),
                description=(row.get("description") or "").strip(),
                status=(row.get("status") or "").strip(),
                public_score=score,
            )
            records.setdefault(archive, ArchiveRecord(archive=archive, alias=alias_from_text(archive))).submissions.append(
                submission
            )
        return records

    pattern = re.compile(
        r"^\s*\d+\s+(?P<archive>\S+)\s+"
        r"(?P<date>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
        r"(?P<desc>.+?)\s+"
        r"(?P<status>SubmissionStatus\.\w+)\s+"
        r"(?P<score>-?[\d.]+)\s*$"
    )
    for line in text.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        archive = match.group("archive")
        submission = Submission(
            archive=archive,
            submitted_at=parse_datetime(match.group("date")),
            description=match.group("desc").strip(),
            status=match.group("status"),
            public_score=float(match.group("score")),
        )
        records.setdefault(archive, ArchiveRecord(archive=archive, alias=alias_from_text(archive))).submissions.append(
            submission
        )
    return records


def archive_from_candidate_row(row: dict[str, str]) -> str | None:
    path = (row.get("path") or "").strip()
    if path.endswith(".tar.gz"):
        return Path(path).name
    candidate = (row.get("candidate") or "").strip()
    if candidate.endswith(".tar.gz"):
        return Path(candidate).name
    return None


def add_metric(records: dict[str, ArchiveRecord], archive: str, metric: str, value: float | None) -> None:
    if value is None or not math.isfinite(value):
        return
    record = records.setdefault(archive, ArchiveRecord(archive=archive, alias=alias_from_text(archive)))
    record.metrics[metric] = value


def load_candidate_csv(records: dict[str, ArchiveRecord], path: Path) -> None:
    with path.open(encoding="utf-8-sig", newline="") as file:
        for row in csv.DictReader(file):
            archive = archive_from_candidate_row(row)
            if not archive:
                continue
            for column in (
                "replay_win_rate",
                "fixed_win_rate",
                "public_current",
                "public_best",
                "public_floor",
            ):
                add_metric(records, archive, sanitize_metric_name(path, column), parse_float(row.get(column)))
            notes = row.get("notes") or ""
            broad_values = [float(value) for value in re.findall(r"reset-pipeline broad=([\d.]+)", notes)]
            if broad_values:
                add_metric(records, archive, sanitize_metric_name(path, "notes_broad_last"), broad_values[-1])
                add_metric(records, archive, sanitize_metric_name(path, "notes_broad_mean"), sum(broad_values) / len(broad_values))
                add_metric(records, archive, sanitize_metric_name(path, "notes_broad_min"), min(broad_values))


def parse_gauntlet_alias(line: str) -> str | None:
    if not line.startswith("Candidate "):
        return None
    label = Path(line.removeprefix("Candidate ").strip()).name
    alias = alias_from_text(label)
    return alias


def alias_to_archives(records: dict[str, ArchiveRecord]) -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = defaultdict(list)
    for archive, record in records.items():
        mapping[record.alias].append(archive)
    return mapping


def add_metric_by_alias(
    records: dict[str, ArchiveRecord],
    alias_map: dict[str, list[str]],
    alias: str,
    metric: str,
    value: float | None,
) -> None:
    archives = alias_map.get(alias, [])
    for archive in archives:
        add_metric(records, archive, metric, value)


def load_gauntlet(records: dict[str, ArchiveRecord], path: Path) -> None:
    alias_map = alias_to_archives(records)
    metric = sanitize_metric_name(path, "weighted_win_rate")
    current_alias: str | None = None
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line.startswith("Candidate "):
            current_alias = parse_gauntlet_alias(line)
            continue
        if current_alias and line.startswith("weighted_win_rate,"):
            add_metric_by_alias(records, alias_map, current_alias, metric, parse_float(line.split(",", 1)[1]))


def load_calibrated(records: dict[str, ArchiveRecord], path: Path) -> None:
    metric = sanitize_metric_name(path, "calibrated_score")
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw.strip() or raw.startswith("#") or raw.startswith("pair_rank"):
            continue
        if raw.startswith("rank,"):
            continue
        row = next(csv.reader([raw]))
        if len(row) < 4:
            continue
        score = parse_float(row[2])
        archive = row[3].strip()
        if archive.endswith(".tar.gz"):
            add_metric(records, Path(archive).name, metric, score)


def load_pair_selector(records: dict[str, ArchiveRecord], path: Path) -> None:
    alias_map = alias_to_archives(records)
    in_table = False
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line.startswith("| Candidate | Broad | Drift |"):
            in_table = True
            continue
        if not in_table:
            continue
        if line.startswith("| ---"):
            continue
        if not line.startswith("|"):
            if in_table:
                break
            continue
        parts = [part.strip() for part in line.strip("|").split("|")]
        if len(parts) < 3:
            continue
        alias = parts[0].strip("`")
        add_metric_by_alias(records, alias_map, alias, sanitize_metric_name(path, "selector_broad"), parse_float(parts[1]))
        add_metric_by_alias(records, alias_map, alias, sanitize_metric_name(path, "selector_drift"), parse_float(parts[2]))


def load_psro(records: dict[str, ArchiveRecord], path: Path) -> None:
    alias_map = alias_to_archives(records)
    in_table = False
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line.startswith("| Rank | Policy | Score | Weighted | Min |"):
            in_table = True
            continue
        if not in_table:
            continue
        if line.startswith("| ---"):
            continue
        if not line.startswith("|"):
            if in_table:
                break
            continue
        parts = [part.strip() for part in line.strip("|").split("|")]
        if len(parts) < 7:
            continue
        alias = parts[1].strip("`")
        add_metric_by_alias(records, alias_map, alias, sanitize_metric_name(path, "psro_score"), parse_float(parts[2]))
        add_metric_by_alias(records, alias_map, alias, sanitize_metric_name(path, "psro_weighted"), parse_float(parts[3]))
        add_metric_by_alias(records, alias_map, alias, sanitize_metric_name(path, "psro_min"), parse_float(parts[4]))
        add_metric_by_alias(records, alias_map, alias, sanitize_metric_name(path, "psro_weighted_regret_inverse"), negate(parse_float(parts[5])))
        add_metric_by_alias(records, alias_map, alias, sanitize_metric_name(path, "psro_max_regret_inverse"), negate(parse_float(parts[6])))


def negate(value: float | None) -> float | None:
    return None if value is None else -value


def average_ranks(values: list[float]) -> list[float]:
    indexed = sorted(enumerate(values), key=lambda item: item[1])
    ranks = [0.0] * len(values)
    index = 0
    while index < len(indexed):
        end = index + 1
        while end < len(indexed) and indexed[end][1] == indexed[index][1]:
            end += 1
        avg = (index + 1 + end) / 2.0
        for original, _ in indexed[index:end]:
            ranks[original] = avg
        index = end
    return ranks


def pearson(xs: list[float], ys: list[float]) -> float:
    if len(xs) != len(ys) or len(xs) < 2:
        return float("nan")
    mean_x = sum(xs) / len(xs)
    mean_y = sum(ys) / len(ys)
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    den_x = math.sqrt(sum((x - mean_x) ** 2 for x in xs))
    den_y = math.sqrt(sum((y - mean_y) ** 2 for y in ys))
    if den_x == 0.0 or den_y == 0.0:
        return float("nan")
    return num / (den_x * den_y)


def spearman(xs: list[float], ys: list[float]) -> float:
    return pearson(average_ranks(xs), average_ranks(ys))


def kendall_tau_b(xs: list[float], ys: list[float]) -> float:
    concordant = 0
    discordant = 0
    ties_x = 0
    ties_y = 0
    for i in range(len(xs)):
        for j in range(i + 1, len(xs)):
            dx = (xs[i] > xs[j]) - (xs[i] < xs[j])
            dy = (ys[i] > ys[j]) - (ys[i] < ys[j])
            if dx == 0 and dy == 0:
                continue
            if dx == 0:
                ties_x += 1
            elif dy == 0:
                ties_y += 1
            elif dx == dy:
                concordant += 1
            else:
                discordant += 1
    denominator = math.sqrt((concordant + discordant + ties_x) * (concordant + discordant + ties_y))
    if denominator == 0.0:
        return float("nan")
    return (concordant - discordant) / denominator


def public_targets(record: ArchiveRecord) -> dict[str, float]:
    targets: dict[str, float] = {}
    if record.latest_public is not None:
        targets["latest_public"] = record.latest_public
    if record.best_public is not None:
        targets["best_public"] = record.best_public
    return targets


def compute_correlations(records: dict[str, ArchiveRecord], min_n: int, required_aliases: set[str]) -> list[CorrelationRow]:
    metric_names = sorted({name for record in records.values() for name in record.metrics})
    correlations: list[CorrelationRow] = []
    for public_target in ("latest_public", "best_public"):
        for metric in metric_names:
            items: list[tuple[str, float, float]] = []
            for record in records.values():
                public_value = public_targets(record).get(public_target)
                metric_value = record.metrics.get(metric)
                if public_value is None or metric_value is None:
                    continue
                items.append((record.alias, public_value, metric_value))
            if len(items) < min_n:
                continue
            public_values = [item[1] for item in items]
            metric_values = [item[2] for item in items]
            aliases = {item[0] for item in items}
            required_covered = tuple(sorted(aliases & required_aliases))
            required_missing = tuple(sorted(required_aliases - aliases))
            public_order = " > ".join(alias for alias, _, _ in sorted(items, key=lambda item: (-item[1], item[0])))
            metric_order = " > ".join(alias for alias, _, _ in sorted(items, key=lambda item: (-item[2], item[0])))
            correlations.append(
                CorrelationRow(
                    public_target=public_target,
                    metric=metric,
                    n=len(items),
                    spearman=spearman(public_values, metric_values),
                    kendall=kendall_tau_b(public_values, metric_values),
                    required_covered=required_covered,
                    required_missing=required_missing,
                    public_order=public_order,
                    metric_order=metric_order,
                )
            )
    correlations.sort(key=lambda row: (-(row.spearman if math.isfinite(row.spearman) else -2.0), -row.n, row.metric))
    return correlations


def fmt(value: float | None, digits: int = 4) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and not math.isfinite(value):
        return "nan"
    return f"{value:.{digits}f}"


def write_calibration_csv(records: dict[str, ArchiveRecord], path: Path) -> None:
    metric_names = sorted({name for record in records.values() for name in record.metrics})
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["archive", "alias", "latest_public", "best_public", "latest_date", *metric_names])
        for record in sorted(records.values(), key=lambda item: (item.alias, item.archive)):
            if record.latest_public is None and not record.metrics:
                continue
            writer.writerow(
                [
                    record.archive,
                    record.alias,
                    fmt(record.latest_public, 1),
                    fmt(record.best_public, 1),
                    record.latest_date,
                    *[fmt(record.metrics.get(name), 6) for name in metric_names],
                ]
            )


def is_trusted(row: CorrelationRow, args: argparse.Namespace) -> bool:
    if row.public_target != "latest_public":
        return False
    if row.n < args.min_trusted_n:
        return False
    if not math.isfinite(row.spearman) or row.spearman < args.min_trusted_spearman:
        return False
    if not math.isfinite(row.kendall) or row.kendall <= 0.0:
        return False
    return not row.required_missing


def write_summary_csv(correlations: list[CorrelationRow], path: Path, args: argparse.Namespace) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(
            [
                "public_target",
                "metric",
                "n",
                "spearman",
                "kendall",
                "required_covered",
                "required_missing",
                "trusted",
                "public_order",
                "metric_order",
            ]
        )
        for row in correlations:
            writer.writerow(
                [
                    row.public_target,
                    row.metric,
                    row.n,
                    fmt(row.spearman, 6),
                    fmt(row.kendall, 6),
                    ";".join(row.required_covered),
                    ";".join(row.required_missing),
                    "1" if is_trusted(row, args) else "0",
                    row.public_order,
                    row.metric_order,
                ]
            )


def plot_best_metric(records: dict[str, ArchiveRecord], correlations: list[CorrelationRow], path: Path) -> str | None:
    latest_rows = [row for row in correlations if row.public_target == "latest_public" and math.isfinite(row.spearman)]
    if not latest_rows:
        return None
    best = latest_rows[0]
    points = [
        (record.alias, record.latest_public, record.metrics[best.metric])
        for record in records.values()
        if record.latest_public is not None and best.metric in record.metrics
    ]
    if len(points) < 3:
        return None
    try:
        import matplotlib.pyplot as plt  # type: ignore
    except Exception:
        return None

    path.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(8, 5))
    xs = [point[2] for point in points]
    ys = [point[1] for point in points]
    ax.scatter(xs, ys)
    for alias, public, metric_value in points:
        ax.annotate(alias, (metric_value, public), textcoords="offset points", xytext=(4, 4), fontsize=8)
    ax.set_xlabel(best.metric)
    ax.set_ylabel("latest public score")
    ax.set_title(f"Best observed calibration: Spearman {best.spearman:.3f}, n={best.n}")
    ax.grid(True, alpha=0.25)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    return str(path)


def render_report(
    records: dict[str, ArchiveRecord],
    correlations: list[CorrelationRow],
    args: argparse.Namespace,
    calibration_csv: Path,
    summary_csv: Path,
    plot_path: str | None,
) -> str:
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    latest = [row for row in correlations if row.public_target == "latest_public"]
    trusted_latest = [row for row in latest if is_trusted(row, args)]
    best_latest = latest[0] if latest else None
    lines: list[str] = [
        "# Local-vs-Public Backtest",
        "",
        f"Generated: {generated}",
        "",
        "## Sources",
        "",
        f"- Submissions history: `{args.submissions}`",
    ]
    for label, paths in (
        ("Candidate CSV", args.candidate_csv),
        ("Gauntlet", args.gauntlet),
        ("Calibrated rank", args.calibrated),
        ("Pair selector", args.pair_selector),
        ("PSRO", args.psro),
    ):
        for path in paths:
            lines.append(f"- {label}: `{path}`")
    lines.extend(
        [
            f"- Calibration CSV: `{calibration_csv}`",
            f"- Correlation summary CSV: `{summary_csv}`",
        ]
    )
    if plot_path:
        lines.append(f"- Plot: `{plot_path}`")
    lines.extend(["", "## Verdict", ""])
    if best_latest is None:
        lines.append("- No metric had enough overlap with submitted archives to backtest.")
    elif trusted_latest:
        trusted = trusted_latest[0]
        lines.append(
            f"- Trusted latest-public metric found: `{trusted.metric}` Spearman {trusted.spearman:.3f}, "
            f"Kendall {trusted.kendall:.3f}, n={trusted.n}, required covered={', '.join(trusted.required_covered) or '-'}."
        )
    else:
        lines.append(
            f"- **No trusted local metric yet.** Best latest-public metric is `{best_latest.metric}` "
            f"with Spearman {best_latest.spearman:.3f}, Kendall {best_latest.kendall:.3f}, n={best_latest.n}; "
            f"threshold is Spearman >= {args.min_trusted_spearman:.2f}, Kendall > 0, n >= {args.min_trusted_n}, "
            "and all required ground-truth aliases covered."
        )
        if best_latest.required_missing:
            lines.append("- Best metric missing required aliases: " + ", ".join(best_latest.required_missing) + ".")
        lines.append("- Submit gates should remain closed until a fresh held-out signal beats this backtest.")
    if args.required_alias:
        lines.append("- Required ground-truth aliases: " + ", ".join(f"`{alias}`" for alias in args.required_alias) + ".")
    lines.extend(["", "## Public Score Ground Truth", ""])
    lines.append("| Alias | Archive | Latest Public | Best Public | Latest Submission UTC | Runs |")
    lines.append("| --- | --- | ---: | ---: | --- | ---: |")
    for record in sorted(
        [item for item in records.values() if item.latest_public is not None],
        key=lambda item: (-(item.latest_public or -9999), item.alias),
    ):
        lines.append(
            f"| `{record.alias}` | `{record.archive}` | {record.latest_public:.1f} | "
            f"{record.best_public:.1f} | {record.latest_date} | {len(record.submissions)} |"
        )
    lines.extend(["", "## Metric Correlations", ""])
    lines.append("| Target | Metric | n | Spearman | Kendall | Trusted | Required Missing | Public Order | Metric Order |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | --- | --- | --- |")
    for row in correlations[: args.report_limit]:
        lines.append(
            f"| {row.public_target} | `{row.metric}` | {row.n} | {row.spearman:.3f} | "
            f"{row.kendall:.3f} | {'yes' if is_trusted(row, args) else 'no'} | "
            f"{', '.join(row.required_missing) or '-'} | {row.public_order} | {row.metric_order} |"
        )
    lines.extend(["", "## Calibration Table", ""])
    metric_names = sorted({name for record in records.values() for name in record.metrics})
    preferred_metrics = []
    for row in correlations:
        if row.public_target == "latest_public" and row.metric not in preferred_metrics:
            preferred_metrics.append(row.metric)
        if len(preferred_metrics) >= 6:
            break
    if not preferred_metrics:
        preferred_metrics = metric_names[:6]
    lines.append("| Alias | Archive | Latest Public | Best Public | " + " | ".join(f"`{name}`" for name in preferred_metrics) + " |")
    lines.append("| --- | --- | ---: | ---: | " + " | ".join(["---:"] * len(preferred_metrics)) + " |")
    for record in sorted(
        [item for item in records.values() if item.latest_public is not None or item.metrics],
        key=lambda item: (-(item.latest_public if item.latest_public is not None else -9999), item.alias),
    ):
        values = " | ".join(fmt(record.metrics.get(name), 4) or "-" for name in preferred_metrics)
        latest_text = fmt(record.latest_public, 1) or "-"
        best_text = fmt(record.best_public, 1) or "-"
        lines.append(f"| `{record.alias}` | `{record.archive}` | {latest_text} | {best_text} | {values} |")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- Positive Spearman/Kendall means the metric ranks submitted packages in the same order as public score.",
            "- Negative or near-zero values are evidence of replay-pool overfit, stale public priors, or a simulator-policy mismatch.",
            "- Public-score columns from candidate ledgers are treated as metrics too; they should only be used as sanity checks, not as a local evaluator.",
        ]
    )
    return "\n".join(lines) + "\n"


def default_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--submissions", required=True, type=Path)
    parser.add_argument("--candidate-csv", action="append", type=Path, default=[])
    parser.add_argument("--gauntlet", action="append", type=Path, default=[])
    parser.add_argument("--calibrated", action="append", type=Path, default=[])
    parser.add_argument("--pair-selector", action="append", type=Path, default=[])
    parser.add_argument("--psro", action="append", type=Path, default=[])
    parser.add_argument("--min-n", type=int, default=3)
    parser.add_argument("--min-trusted-spearman", type=float, default=0.55)
    parser.add_argument("--min-trusted-n", type=int, default=5)
    parser.add_argument("--required-alias", action="append", default=[])
    parser.add_argument("--report-limit", type=int, default=40)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--calibration-csv", type=Path)
    parser.add_argument("--summary-csv", type=Path)
    parser.add_argument("--plot", type=Path)
    args = parser.parse_args()

    stamp = default_stamp()
    output = args.output or Path(f"strategy/backtest_local_vs_public_{stamp}.md")
    calibration_csv = args.calibration_csv or output.with_suffix(".calibration.csv")
    summary_csv = args.summary_csv or output.with_suffix(".summary.csv")
    plot = args.plot or output.with_suffix(".png")

    records = load_submission_history(args.submissions)
    for path in args.candidate_csv:
        load_candidate_csv(records, path)
    for path in args.gauntlet:
        load_gauntlet(records, path)
    for path in args.calibrated:
        load_calibrated(records, path)
    for path in args.pair_selector:
        load_pair_selector(records, path)
    for path in args.psro:
        load_psro(records, path)

    required_aliases = set(args.required_alias)
    correlations = compute_correlations(records, args.min_n, required_aliases)
    write_calibration_csv(records, calibration_csv)
    write_summary_csv(correlations, summary_csv, args)
    plot_path = plot_best_metric(records, correlations, plot)
    report = render_report(records, correlations, args, calibration_csv, summary_csv, plot_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
