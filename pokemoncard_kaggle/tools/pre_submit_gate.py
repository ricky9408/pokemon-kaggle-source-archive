#!/usr/bin/env python3
"""Pre-submit gate for Kaggle candidate submissions.

This tool never submits. It checks the current UTC quota window, dynamic
candidate evidence, and the intended archives, then prints the exact submit
commands only when the gate is green.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import socket
import subprocess
import tarfile
from dataclasses import dataclass
from datetime import UTC, datetime, time
from pathlib import Path


@dataclass(frozen=True)
class SubmissionRow:
    ref: str
    file_name: str
    submitted_at: datetime
    description: str
    status: str
    public_score: str


@dataclass(frozen=True)
class BacktestGate:
    supplied: bool
    trusted: bool
    best_metric: str
    best_spearman: float | None
    best_kendall: float | None
    best_n: int | None
    missing: str


@dataclass(frozen=True)
class LeaguePublicGapGate:
    supplied: bool
    trusted: bool
    summary: str


@dataclass(frozen=True)
class CandidateCriticGate:
    supplied: bool
    trusted: bool
    verdict: str
    summary: str


@dataclass(frozen=True)
class SafetyReportGate:
    supplied: bool
    trusted: bool
    verdict: str
    summary: str


@dataclass(frozen=True)
class PublicActionReportGate:
    supplied: bool
    trusted: bool
    verdict: str
    summary: str
    shared_decisions: int | None = None
    changed_from_baseline: int | None = None
    fixes: int | None = None
    regressions: int | None = None
    weighted_net: float | None = None


@dataclass(frozen=True)
class ExplorationSlotGate:
    supplied: bool
    trusted: bool
    summary: str
    archives: tuple[str, ...]


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


def now_utc(value: str | None) -> datetime:
    if not value:
        return datetime.now(UTC)
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def run_submissions_cli(competition: str) -> str:
    command = ["uv", "run", "kaggle", "competitions", "submissions", competition]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return result.stdout


def read_submissions(args: argparse.Namespace) -> str:
    if args.submissions_output:
        return args.submissions_output.read_text(encoding="utf-8", errors="replace")
    return run_submissions_cli(args.competition)


def parse_submission_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def parse_submission_rows(text: str) -> list[SubmissionRow]:
    rows: list[SubmissionRow] = []
    lines = text.splitlines()
    csv_start = None
    for index, line in enumerate(lines):
        if line.startswith("ref,") and "fileName" in line:
            csv_start = index
            break
    if csv_start is not None:
        for row in csv.DictReader(lines[csv_start:]):
            ref = (row.get("ref") or "").strip()
            file_name = (row.get("fileName") or "").strip()
            submitted_at = (row.get("date") or "").strip()
            if not ref or not file_name or not submitted_at:
                continue
            rows.append(
                SubmissionRow(
                    ref=ref,
                    file_name=file_name,
                    submitted_at=parse_submission_datetime(submitted_at),
                    description=(row.get("description") or "").strip(),
                    status=(row.get("status") or "").strip(),
                    public_score=(row.get("publicScore") or "").strip(),
                )
            )
        return rows

    pattern = re.compile(
        r"^\s*(?P<ref>\d+)\s+"
        r"(?P<file>\S+)\s+"
        r"(?P<date>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
        r"(?P<rest>.+?)\s+"
        r"(?P<status>SubmissionStatus\.\w+)\s+"
        r"(?P<score>-?[\d.]+)?\s*$"
    )
    for raw in text.splitlines():
        match = pattern.match(raw)
        if not match:
            continue
        rows.append(
            SubmissionRow(
                ref=match.group("ref"),
                file_name=match.group("file"),
                submitted_at=parse_submission_datetime(match.group("date")),
                description=match.group("rest").strip(),
                status=match.group("status"),
                public_score=match.group("score") or "",
            )
        )
    return rows


def parse_optional_float(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def parse_optional_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def latest_score_by_archive(
    submissions: list[SubmissionRow],
    *,
    current: datetime,
    min_age_minutes: float,
) -> dict[str, tuple[float, SubmissionRow]]:
    latest: dict[str, tuple[float, SubmissionRow]] = {}
    for row in submissions:
        age_minutes = (current - row.submitted_at).total_seconds() / 60.0
        if age_minutes < min_age_minutes:
            continue
        score = parse_optional_float(row.public_score)
        if score is None:
            continue
        name = Path(row.file_name).name
        existing = latest.get(name)
        if existing is None or row.submitted_at > existing[1].submitted_at:
            latest[name] = (score, row)
    return latest


def parse_backtest_gate(path: Path | None, min_spearman: float, min_n: int) -> BacktestGate:
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
            missing = row.get("required_missing") or ""
            trusted = (
                row.get("trusted") == "1"
                and spearman is not None
                and spearman >= min_spearman
                and n is not None
                and n >= min_n
                and not missing
            )
            candidate = BacktestGate(
                True,
                trusted,
                row.get("metric") or "",
                spearman,
                kendall,
                n,
                missing,
            )
            if best is None:
                best = candidate
                continue
            best_value = best.best_spearman if best.best_spearman is not None else -999.0
            candidate_value = candidate.best_spearman if candidate.best_spearman is not None else -999.0
            if (trusted, candidate_value) > (best.trusted, best_value):
                best = candidate
    if best is None:
        return BacktestGate(True, False, "", None, None, None, "no latest_public rows in backtest summary")
    return best


def parse_league_public_gap_gate(path: Path | None) -> LeaguePublicGapGate:
    if path is None:
        return LeaguePublicGapGate(False, True, "not supplied")
    if not path.exists():
        return LeaguePublicGapGate(True, False, f"local-league public-gap audit not found: {path}")

    text = path.read_text(encoding="utf-8", errors="replace")
    if "Trust decision: **LOCAL LEAGUE CONTRADICTED BY PUBLIC ANCHORS**" in text:
        blockers = [line.removeprefix("- Blocker: ").strip() for line in text.splitlines() if line.startswith("- Blocker: ")]
        detail = blockers[0] if blockers else "audit reports local league contradiction"
        return LeaguePublicGapGate(True, False, detail)
    if "Trust decision: **LOCAL LEAGUE FAILS PUBLIC CORRELATION**" in text:
        failures = [
            line.removeprefix("- Correlation failure: ").strip()
            for line in text.splitlines()
            if line.startswith("- Correlation failure: ")
        ]
        detail = failures[0] if failures else "local league fails public-anchor rank correlation"
        return LeaguePublicGapGate(True, False, detail)
    if "Trust decision: **LOCAL LEAGUE HAS INSUFFICIENT PUBLIC ANCHORS**" in text:
        gaps = [line.removeprefix("- Evidence gap: ").strip() for line in text.splitlines() if line.startswith("- Evidence gap: ")]
        detail = gaps[0] if gaps else "local league has insufficient mature public anchors"
        return LeaguePublicGapGate(True, False, detail)
    if (
        "Trust decision: **LOCAL LEAGUE NOT CONTRADICTED BY PUBLIC ANCHORS**" in text
        or "Trust decision: no top-local public contradiction found in mapped mature anchors." in text
    ):
        return LeaguePublicGapGate(True, True, "no top-local public contradiction found in mapped mature anchors")
    return LeaguePublicGapGate(True, False, "unrecognized local-league public-gap audit decision")


def parse_candidate_critic_gate(
    path: Path | None,
    require: bool,
    required_archives: tuple[str, ...] = (),
) -> CandidateCriticGate:
    if path is None:
        if require:
            return CandidateCriticGate(False, False, "", "missing candidate critic report")
        return CandidateCriticGate(False, True, "", "not supplied")
    if not path.exists():
        return CandidateCriticGate(True, False, "", f"candidate critic report not found: {path}")

    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"Critic verdict:\s+\*\*([^*]+)\*\*", text)
    if not match:
        if "# Dudunsparce Safety Fix" in text or "Dudunsparce safety audit" in text:
            return CandidateCriticGate(
                True,
                False,
                "SAFETY_REPORT_ONLY",
                "safety report supplied as candidate critic; pass it with --safety-report and keep a separate promotion critic",
            )
        return CandidateCriticGate(True, False, "", "could not parse critic verdict")
    verdict = match.group(1).strip()
    reasons = [line.removeprefix("- Reason: ").strip() for line in text.splitlines() if line.startswith("- Reason: ")]
    if verdict != "PROMOTION_REVIEW":
        summary = reasons[0] if reasons else f"critic verdict {verdict}"
        return CandidateCriticGate(True, False, verdict, summary)

    coverage_match = re.search(r"League coverage sufficient:\s+(True|False)", text)
    if not coverage_match:
        return CandidateCriticGate(True, False, verdict, "candidate critic report does not prove league coverage")
    if coverage_match.group(1) != "True":
        reasons = [
            line.removeprefix("- League coverage reasons: ").strip()
            for line in text.splitlines()
            if line.startswith("- League coverage reasons: ")
        ]
        detail = reasons[0] if reasons else "league coverage insufficient"
        return CandidateCriticGate(True, False, verdict, detail)
    missing_archives = [
        Path(archive).name
        for archive in required_archives
        if archive and Path(archive).name not in text
    ]
    if missing_archives:
        return CandidateCriticGate(
            True,
            False,
            verdict,
            "candidate critic report does not cover intended archives: " + ", ".join(missing_archives),
        )
    if verdict == "PROMOTION_REVIEW":
        return CandidateCriticGate(True, True, verdict, "critic verdict PROMOTION_REVIEW with sufficient league coverage")

    return CandidateCriticGate(True, False, verdict, f"critic verdict {verdict}")


def parse_public_action_report_gate(path: Path | None) -> PublicActionReportGate:
    if path is None:
        return PublicActionReportGate(False, True, "", "not supplied")
    if not path.exists():
        return PublicActionReportGate(True, False, "", f"public-action report not found: {path}")

    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"Trust decision:\s+\*\*([^*]+)\*\*", text)
    if not match:
        return PublicActionReportGate(True, False, "", "could not parse public-action trust decision")
    verdict = match.group(1).strip()
    blockers = [line.removeprefix("- Blocker: ").strip() for line in text.splitlines() if line.startswith("- Blocker: ")]
    summary = blockers[0] if blockers else verdict
    delta = parse_public_action_delta(text)
    if verdict == "PUBLIC ACTION GATE PASSED":
        return PublicActionReportGate(True, True, verdict, "public-action gate passed", *delta)
    if verdict == "PUBLIC ACTION GATE FAILED":
        return PublicActionReportGate(True, False, verdict, summary, *delta)
    return PublicActionReportGate(True, False, verdict, f"unrecognized public-action verdict {verdict}", *delta)


def parse_public_action_delta(text: str) -> tuple[int | None, int | None, int | None, int | None, float | None]:
    """Parse the worst baseline-delta row from a public-action report.

    Reports normally contain one row because callers pass a single gate label.
    If several rows exist, use the smallest weighted net and corresponding row
    so exploration substitutes are conservative.
    """
    in_delta = False
    parsed: list[tuple[int, int, int, int, float]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line == "## Baseline Delta":
            in_delta = True
            continue
        if in_delta and line.startswith("## ") and line != "## Baseline Delta":
            break
        if not in_delta or not line.startswith("| `"):
            continue
        cells = [clean_table_cell(cell) for cell in line.strip("|").split("|")]
        if len(cells) < 11 or cells[0].lower() == "label":
            continue
        try:
            shared = int(float(cells[1]))
            changed = int(float(cells[2]))
            fixes = int(float(cells[3]))
            regressions = int(float(cells[4]))
            weighted_net = float(cells[10])
        except ValueError:
            continue
        parsed.append((shared, changed, fixes, regressions, weighted_net))
    if not parsed:
        return None, None, None, None, None
    return min(parsed, key=lambda row: row[4])


def clean_table_cell(value: str) -> str:
    value = value.strip()
    if value.startswith("`") and value.endswith("`") and len(value) >= 2:
        value = value[1:-1]
    return value.strip()


def parse_candidate_review_rows(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("| `"):
            continue
        cells = [clean_table_cell(cell) for cell in stripped.strip("|").split("|")]
        if len(cells) < 9:
            continue
        if cells[0] == "---" or cells[0].lower() == "candidate":
            continue
        rows.append(
            {
                "candidate": cells[0],
                "family": cells[1],
                "agent": cells[2],
                "archive": Path(cells[3]).name if cells[3] != "-" else "",
                "validation": cells[4],
                "league_rank": cells[5],
                "robust_rank": cells[6],
                "robust_score": cells[7],
                "worst_lane": cells[8],
                "notes": cells[9] if len(cells) > 9 else "",
            }
        )
    return rows


def parse_rank(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None


def validation_has_required_passes(validation: str) -> bool:
    required = ("py=pass", "card=pass", "smoke=pass", "archive=pass", "match=pass")
    lowered = validation.lower()
    return all(token in lowered for token in required)


def parse_exploration_slot_gate(
    path: Path | None,
    *,
    missing_anchor_archives: tuple[str, ...],
    policy: str,
    max_candidates: int,
    max_league_rank: int,
    max_robust_rank: int,
    min_robust_score: float,
    hypothesis: str,
) -> ExplorationSlotGate:
    if policy != "allow-exploration-slot":
        return ExplorationSlotGate(False, False, "exploration-slot policy not enabled", ())
    if not missing_anchor_archives:
        return ExplorationSlotGate(False, True, "no unanchored intended archive", ())
    if len(missing_anchor_archives) > max_candidates:
        return ExplorationSlotGate(
            True,
            False,
            f"{len(missing_anchor_archives)} unanchored archives exceeds exploration limit {max_candidates}",
            missing_anchor_archives,
        )
    if len(hypothesis.strip()) < 20:
        return ExplorationSlotGate(
            True,
            False,
            "missing explicit exploration hypothesis of at least 20 characters",
            missing_anchor_archives,
        )
    if path is None:
        return ExplorationSlotGate(
            True,
            False,
            "exploration slot requires a candidate critic report",
            missing_anchor_archives,
        )
    if not path.exists():
        return ExplorationSlotGate(
            True,
            False,
            f"exploration candidate critic report not found: {path}",
            missing_anchor_archives,
        )

    text = path.read_text(encoding="utf-8", errors="replace")
    rows = parse_candidate_review_rows(text)
    by_archive = {row["archive"]: row for row in rows if row["archive"]}
    failures: list[str] = []
    for archive in missing_anchor_archives:
        row = by_archive.get(Path(archive).name)
        if row is None:
            failures.append(f"{archive}: not covered in candidate critic review")
            continue
        if not validation_has_required_passes(row["validation"]):
            failures.append(f"{archive}: validation not fully pass ({row['validation']})")
            continue
        league_rank = parse_rank(row["league_rank"])
        robust_rank = parse_rank(row["robust_rank"])
        robust_score = parse_optional_float(row["robust_score"])
        league_ok = league_rank is not None and league_rank <= max_league_rank
        robust_rank_ok = robust_rank is not None and robust_rank <= max_robust_rank
        robust_score_ok = robust_score is not None and robust_score >= min_robust_score
        if not (league_ok or robust_rank_ok):
            failures.append(
                f"{archive}: local evidence too weak "
                f"(league_rank={row['league_rank']}, robust_rank={row['robust_rank']})"
            )
            continue
        if not robust_score_ok:
            failures.append(
                f"{archive}: robust score {row['robust_score']} below exploration floor {min_robust_score:.3f}"
            )
    if failures:
        return ExplorationSlotGate(True, False, "; ".join(failures), missing_anchor_archives)
    return ExplorationSlotGate(
        True,
        True,
        "explicit exploration slot accepted for: " + ", ".join(missing_anchor_archives),
        missing_anchor_archives,
    )


def parse_safety_report_gate(
    path: Path | None,
    require: bool,
    required_archives: tuple[str, ...] = (),
) -> SafetyReportGate:
    if path is None:
        if require:
            return SafetyReportGate(False, False, "", "missing safety report")
        return SafetyReportGate(False, True, "", "not supplied")
    if not path.exists():
        return SafetyReportGate(True, False, "", f"safety report not found: {path}")

    text = path.read_text(encoding="utf-8", errors="replace")
    lower = text.lower()
    if "# dudunsparce safety fix" not in lower and "dudunsparce safety audit" not in lower:
        return SafetyReportGate(True, False, "", "unrecognized safety report format")

    if "result: pass" not in lower:
        return SafetyReportGate(True, False, "FAIL_OR_UNKNOWN", "safety report does not record a PASS result")

    coverage_keys = {Path(archive).name for archive in required_archives if archive}
    coverage_keys.update(alias for archive in required_archives if (alias := alias_from_text(archive)))
    covered = sorted(key for key in coverage_keys if key and key in text)
    dudunsparce_archives = [
        archive
        for archive in required_archives
        if archive and "dudunsparce" in Path(archive).name.lower()
    ]
    missing_dudunsparce = []
    for archive in dudunsparce_archives:
        archive_name = Path(archive).name
        archive_alias = alias_from_text(archive)
        if archive_name not in covered and (not archive_alias or archive_alias not in covered):
            missing_dudunsparce.append(archive_name)
    if missing_dudunsparce:
        return SafetyReportGate(
            True,
            False,
            "PASS_BUT_MISSING_COVERAGE",
            "safety report does not cover intended Dudunsparce archive(s): " + ", ".join(missing_dudunsparce),
        )
    if required_archives and not covered:
        return SafetyReportGate(
            True,
            False,
            "PASS_BUT_UNMAPPED",
            "safety report passed but does not mention any intended archive or version alias",
        )

    summary = "Dudunsparce safety audit PASS"
    if covered:
        summary += "; covered " + ", ".join(covered)
    return SafetyReportGate(True, True, "PASS", summary)


def alias_from_text(text: str) -> str | None:
    lowered = text.lower()
    for needle, alias in ALIAS_OVERRIDES.items():
        if needle in lowered:
            return alias
    matches = re.findall(r"(?<![a-z0-9])v(\d+)(?![a-z0-9])", lowered)
    if matches:
        return f"v{matches[-1]}"
    return None


def load_anchor_status(path: Path | None) -> dict[str, tuple[bool, str, str]]:
    if path is None:
        return {}
    statuses: dict[str, tuple[bool, str, str]] = {}
    with path.open(encoding="utf-8-sig", newline="") as file:
        for row in csv.DictReader(file):
            eligible = row.get("submit_eligible") == "1"
            state = row.get("anchor_state", "")
            reasons = row.get("reasons", "")
            for key in (row.get("archive", ""), row.get("candidate", ""), alias_from_text(row.get("archive", "") or ""), alias_from_text(row.get("candidate", "") or "")):
                if key:
                    statuses[key] = (eligible, state, reasons)
    return statuses


def anchor_lookup(statuses: dict[str, tuple[bool, str, str]], archive: str) -> tuple[bool, str, str] | None:
    if not statuses:
        return None
    keys = [archive, Path(archive).name]
    alias = alias_from_text(archive)
    if alias:
        keys.append(alias)
    for key in keys:
        if key in statuses:
            return statuses[key]
    return False, "missing-anchor-status", "archive not present in supplied anchor CSV"


def parse_packet_pair(packet: Path | None) -> tuple[str, str] | None:
    if packet is None:
        return None
    text = packet.read_text(encoding="utf-8", errors="replace")
    match = re.search(
        r"Strategic latest-two pair:\s+`([^`]+)`\s+then\s+`([^`]+)`",
        text,
    )
    if not match:
        raise ValueError(f"Could not find strategic latest-two pair in {packet}")
    return match.group(1), match.group(2)


def version_alias(text: str) -> str | None:
    match = re.search(r"(?<![a-z0-9])v\d+(?![a-z0-9])", text.lower())
    return match.group(0) if match else None


def parse_resolver_winner(path: Path | None) -> str | None:
    if path is None:
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"Resolver winner:\s+\*\*([^*]+)\*\*", text)
    if not match:
        raise ValueError(f"Could not find resolver winner in {path}")
    return match.group(1).strip()


def parse_selector_pair(path: Path | None) -> tuple[str, str] | None:
    if path is None:
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    if "NO SUBMIT-SAFE PAIR" in text:
        return None
    match = re.search(r"Pair:\s+`([^`]+)`\s+then\s+`([^`]+)`", text)
    if not match:
        raise ValueError(f"Could not find recommended pair in {path}")
    return match.group(1), match.group(2)


def resolve_intended_archives(
    args: argparse.Namespace,
    packet_pair: tuple[str, str] | None,
) -> tuple[str, str | None]:
    """Resolve the intended submission window.

    The current default submit policy is single-agent: `--first archive.tar.gz`
    evaluates one archive without forcing a conservative/explorer companion.
    Passing both `--first` and `--second`, or passing only a legacy packet,
    keeps the old latest-two pair behavior available for explicit two-agent
    experiments.
    """
    if packet_pair is None:
        if not args.first:
            raise ValueError("--first is required when --packet is not supplied")
        return args.first, args.second

    if args.first or args.second:
        return args.first or packet_pair[0], args.second
    return packet_pair[0], packet_pair[1]


def resolver_allows_override(
    *,
    packet_first: str,
    packet_second: str,
    intended_first: str,
    intended_second: str,
    resolver_winner: str | None,
) -> bool:
    if resolver_winner is None:
        return False

    winner_alias = version_alias(resolver_winner)
    if not winner_alias:
        return False

    first_changed = intended_first != packet_first
    second_changed = intended_second != packet_second
    if first_changed == second_changed:
        return False

    if first_changed:
        intended_alias = version_alias(intended_first)
        packet_alias = version_alias(packet_first)
    else:
        intended_alias = version_alias(intended_second)
        packet_alias = version_alias(packet_second)
    if not intended_alias or not packet_alias:
        return False
    if winner_alias != intended_alias:
        return False
    # The resolver should be adjudicating a real one-slot conflict while the
    # other latest-two slot remains anchored to the packet.
    return packet_alias != winner_alias


def archive_sanity(path: Path) -> list[str]:
    problems: list[str] = []
    if not path.exists():
        return [f"missing archive: {path}"]
    try:
        with tarfile.open(path, "r:gz") as tar:
            names = {name.removeprefix("./") for name in tar.getnames()}
    except tarfile.TarError as exc:
        return [f"cannot read archive {path}: {exc}"]

    required = {"main.py", "deck.csv"}
    for name in sorted(required):
        if name not in names:
            problems.append(f"{path}: missing {name}")
    if not any(name == "cg" or name.startswith("cg/") for name in names):
        problems.append(f"{path}: missing cg runtime directory")
    return problems


def gate_report(args: argparse.Namespace) -> tuple[str, bool]:
    # `gate_report` is also a library API used by tests and older orchestration
    # code that construct Namespace objects directly. Keep parser additions
    # backward-compatible instead of requiring every caller to mirror argparse.
    library_defaults = {
        "public_action_report": None,
        "exploration_hypothesis": "",
        "max_exploration_candidates": 1,
        "max_exploration_league_rank": 4,
        "max_exploration_robust_rank": 4,
        "min_exploration_robust_score": -1.0,
        "min_exploration_public_action_changed": 10,
        "min_exploration_public_action_weighted_net": 5.0,
        "min_intended_public_score": 0.0,
        "min_public_score_age_minutes": 60.0,
    }
    for name, value in library_defaults.items():
        if not hasattr(args, name):
            setattr(args, name, value)
    current = now_utc(args.now)
    packet_pair = parse_packet_pair(args.packet)
    packet_first = packet_pair[0] if packet_pair else None
    packet_second = packet_pair[1] if packet_pair else None
    intended_first, intended_second = resolve_intended_archives(args, packet_pair)
    intended_archives = tuple(archive for archive in (intended_first, intended_second) if archive)
    single_intended = len(intended_archives) == 1
    if not intended_archives:
        raise ValueError("could not resolve intended submission archives")

    resolver_winner = parse_resolver_winner(args.resolver)
    selector_pair = parse_selector_pair(args.selector)
    backtest_gate = parse_backtest_gate(args.backtest_summary, args.min_backtest_spearman, args.min_backtest_n)
    league_gap_gate = parse_league_public_gap_gate(args.league_public_gap_audit)
    critic_gate = parse_candidate_critic_gate(
        args.candidate_critic_report,
        args.require_candidate_critic,
        intended_archives,
    )
    public_action_gate = parse_public_action_report_gate(args.public_action_report)
    safety_gate = parse_safety_report_gate(
        args.safety_report,
        args.require_safety_report,
        intended_archives,
    )
    anchor_statuses = load_anchor_status(args.anchor_status)
    missing_anchor_archives: list[str] = []
    for archive_name in intended_archives:
        anchor = anchor_lookup(anchor_statuses, archive_name)
        if anchor is not None and anchor[1] == "missing-anchor-status":
            missing_anchor_archives.append(Path(archive_name).name)
    exploration_gate = parse_exploration_slot_gate(
        args.candidate_critic_report,
        missing_anchor_archives=tuple(missing_anchor_archives),
        policy=args.unanchored_candidate_policy,
        max_candidates=args.max_exploration_candidates,
        max_league_rank=args.max_exploration_league_rank,
        max_robust_rank=args.max_exploration_robust_rank,
        min_robust_score=args.min_exploration_robust_score,
        hypothesis=args.exploration_hypothesis,
    )
    exploration_predictive_substitute = (
        args.unanchored_candidate_policy == "allow-exploration-slot"
        and bool(missing_anchor_archives)
        and exploration_gate.trusted
        and public_action_gate.trusted
        and public_action_gate.changed_from_baseline is not None
        and public_action_gate.changed_from_baseline >= args.min_exploration_public_action_changed
        and public_action_gate.weighted_net is not None
        and public_action_gate.weighted_net >= args.min_exploration_public_action_weighted_net
    )
    resolver_override = (
        not single_intended
        and packet_pair is not None
        and intended_second is not None
        and resolver_allows_override(
            packet_first=packet_first or "",
            packet_second=packet_second or "",
            intended_first=intended_first,
            intended_second=intended_second,
            resolver_winner=resolver_winner,
        )
    )
    selector_override = (
        not single_intended
        and intended_second is not None
        and selector_pair == (intended_first, intended_second)
    )
    packet_mismatch = (
        not single_intended
        and packet_pair is not None
        and intended_second is not None
        and (intended_first != packet_first or intended_second != packet_second)
    )

    submissions_text = read_submissions(args)
    submissions = parse_submission_rows(submissions_text)
    today_rows = [row for row in submissions if row.submitted_at.date() == current.date()]
    complete_today = [row for row in today_rows if row.status == "SubmissionStatus.COMPLETE"]
    archive_scores = latest_score_by_archive(
        submissions,
        current=current,
        min_age_minutes=args.min_public_score_age_minutes,
    )

    reasons: list[str] = []
    if current.time() < time(args.min_utc_hour, args.min_utc_minute):
        reasons.append(
            f"UTC time {current.strftime('%H:%M:%S')} is before "
            f"{args.min_utc_hour:02d}:{args.min_utc_minute:02d}."
        )
    if len(today_rows) >= args.max_daily_submissions:
        reasons.append(
            f"{len(today_rows)} submissions already exist on {current.date().isoformat()} UTC "
            f"(limit {args.max_daily_submissions})."
        )
    if args.selector and selector_pair is None and not single_intended:
        reasons.append(f"pair selector has no submit-safe pair: {args.selector}.")
    if args.selector and selector_pair is not None and not selector_override and not single_intended:
        reasons.append(
            "intended archives do not match the current pair selector: "
            f"selector {selector_pair[0]} then {selector_pair[1]}; "
            f"intended {intended_first} then {intended_second}."
        )
    if packet_mismatch and args.enforce_packet_pair and not resolver_override and not selector_override:
        reasons.append(
            "intended archives do not match the packet strategic pair: "
            f"packet {packet_first} then {packet_second}; intended {intended_first} then {intended_second}."
        )
    if not backtest_gate.trusted and not exploration_predictive_substitute:
        if not backtest_gate.supplied:
            reasons.append("missing predictive-validity backtest summary.")
        elif backtest_gate.best_metric:
            score_text = "nan" if backtest_gate.best_spearman is None else f"{backtest_gate.best_spearman:.3f}"
            kendall_text = "nan" if backtest_gate.best_kendall is None else f"{backtest_gate.best_kendall:.3f}"
            missing_text = f"; missing required aliases: {backtest_gate.missing}" if backtest_gate.missing else ""
            reasons.append(
                "predictive-validity gate failed: "
                f"best latest-public metric `{backtest_gate.best_metric}` has Spearman {score_text}, "
                f"Kendall {kendall_text}, n={backtest_gate.best_n}; "
                f"required Spearman >= {args.min_backtest_spearman:.2f}, n >= {args.min_backtest_n}, "
                f"trusted=1, and no missing required aliases{missing_text}."
            )
        else:
            reasons.append(f"predictive-validity gate failed: {backtest_gate.missing}.")
    league_gap_summary_lower = league_gap_gate.summary.lower()
    league_gap_is_insufficient_only = (
        "insufficient" in league_gap_summary_lower
        or "mapped mature public anchors" in league_gap_summary_lower
        or "require >=" in league_gap_summary_lower
    )
    # [fix: vacuous-exploration hole] a trusted exploration slot may only waive
    # other gates when it is a REAL slot (an unanchored intended archive exists);
    # allow-exploration-slot with a fully-anchored pair (or a missing
    # --anchor-status) yields trusted=True vacuously and must waive nothing.
    exploration_waiver_active = bool(exploration_gate.trusted and missing_anchor_archives)
    if league_gap_gate.supplied and not league_gap_gate.trusted:
        if exploration_waiver_active and league_gap_is_insufficient_only:
            pass
        else:
            reasons.append(f"local-league public-gap gate failed: {league_gap_gate.summary}")
    if args.unanchored_candidate_policy == "allow-exploration-slot" and missing_anchor_archives and not exploration_gate.trusted:
        reasons.append(f"exploration-slot gate failed: {exploration_gate.summary}")
    if not critic_gate.trusted:
        if exploration_waiver_active and critic_gate.verdict == "RESEARCH_ONLY":
            pass
        elif not critic_gate.supplied:
            reasons.append(f"candidate-critic gate failed: {critic_gate.summary}.")
        elif critic_gate.verdict:
            reasons.append(
                f"candidate-critic gate failed: verdict `{critic_gate.verdict}`; {critic_gate.summary}"
            )
        else:
            reasons.append(f"candidate-critic gate failed: {critic_gate.summary}.")
    if public_action_gate.supplied and not public_action_gate.trusted:
        if public_action_gate.verdict:
            reasons.append(
                f"public-action gate failed: verdict `{public_action_gate.verdict}`; "
                f"{public_action_gate.summary}"
            )
        else:
            reasons.append(f"public-action gate failed: {public_action_gate.summary}.")
    if not safety_gate.trusted:
        if not safety_gate.supplied:
            reasons.append(f"safety-report gate failed: {safety_gate.summary}.")
        elif safety_gate.verdict:
            reasons.append(f"safety-report gate failed: verdict `{safety_gate.verdict}`; {safety_gate.summary}")
        else:
            reasons.append(f"safety-report gate failed: {safety_gate.summary}.")

    if args.min_intended_public_score > 0:
        for archive_name in intended_archives:
            score_row = archive_scores.get(Path(archive_name).name)
            if score_row is None:
                continue
            score, row = score_row
            if score < args.min_intended_public_score:
                reasons.append(
                    f"{archive_name}: latest age-filtered public score {score:.1f} from ref {row.ref} "
                    f"is below required intended-archive floor {args.min_intended_public_score:.1f}."
                )

    for archive_name in intended_archives:
        anchor = anchor_lookup(anchor_statuses, archive_name)
        if anchor is None:
            continue
        eligible, state, note = anchor
        if state == "missing-anchor-status":
            if args.unanchored_candidate_policy == "block":
                reasons.append(f"{archive_name}: public-anchor gate failed ({state}); {note}")
            elif args.unanchored_candidate_policy == "allow-with-promotion-critic" and not critic_gate.trusted:
                reasons.append(
                    f"{archive_name}: public-anchor gate failed ({state}); "
                    "unanchored new candidates require a trusted PROMOTION_REVIEW critic"
                )
            elif args.unanchored_candidate_policy == "allow-exploration-slot" and not exploration_gate.trusted:
                reasons.append(
                    f"{archive_name}: public-anchor gate failed ({state}); "
                    f"exploration slot not accepted: {exploration_gate.summary}"
                )
            continue
        if not eligible:
            reasons.append(f"{archive_name}: public-anchor gate failed ({state}); {note}")

    for archive in (Path(name) for name in intended_archives):
        reasons.extend(archive_sanity(archive))

    lines: list[str] = []
    lines.append("# Pre-Submit Gate")
    lines.append("")
    lines.append(f"Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    lines.append("## Research Agent Metadata")
    lines.append("")
    lines.append("- Research agent: Codex coding agent in the local workspace")
    lines.append("- Model family exposed to this thread: GPT-5")
    lines.append(f"- Host: {socket.gethostname()}")
    lines.append(f"- Workspace: `{Path.cwd()}`")
    lines.append(f"- Process metadata: pid={os.getpid()} user={os.environ.get('USER', 'unknown')}")
    lines.append("- Gate premise: preserve strategy quality by blocking premature or unsupported submissions.")
    lines.append("")
    lines.append("## Inputs")
    lines.append("")
    lines.append(f"- UTC now: {current.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"- Competition: `{args.competition}`")
    lines.append(f"- Packet: `{args.packet}`")
    if args.resolver:
        lines.append(f"- Resolver: `{args.resolver}`")
        lines.append(f"- Resolver winner: `{resolver_winner}`")
    if args.selector:
        lines.append(f"- Pair selector: `{args.selector}`")
        if selector_pair:
            lines.append(f"- Selector pair: `{selector_pair[0]}` then `{selector_pair[1]}`")
        if single_intended:
            lines.append("- Pair selector mode: legacy advisory only; single submission is not blocked by missing/mismatched pairs")
    if args.backtest_summary:
        lines.append(f"- Backtest summary: `{args.backtest_summary}`")
    else:
        lines.append("- Backtest summary: not supplied")
    if args.anchor_status:
        lines.append(f"- Public-anchor status: `{args.anchor_status}`")
    if args.league_public_gap_audit:
        lines.append(f"- Local-league public-gap audit: `{args.league_public_gap_audit}`")
        lines.append(f"- Local-league public-gap trusted: {league_gap_gate.trusted}; {league_gap_gate.summary}")
    if args.candidate_critic_report:
        lines.append(f"- Candidate critic report: `{args.candidate_critic_report}`")
    else:
        lines.append(f"- Candidate critic report: not supplied; required={args.require_candidate_critic}")
    lines.append(
        f"- Candidate critic trusted: {critic_gate.trusted}; "
        f"verdict=`{critic_gate.verdict or '-'}`; {critic_gate.summary}"
    )
    if args.public_action_report:
        lines.append(f"- Public-action report: `{args.public_action_report}`")
    else:
        lines.append("- Public-action report: not supplied")
    lines.append(
        f"- Public-action trusted: {public_action_gate.trusted}; "
        f"verdict=`{public_action_gate.verdict or '-'}`; {public_action_gate.summary}"
    )
    if public_action_gate.supplied:
        delta_text = (
            f"shared={public_action_gate.shared_decisions}, "
            f"changed={public_action_gate.changed_from_baseline}, "
            f"fixes={public_action_gate.fixes}, "
            f"regressions={public_action_gate.regressions}, "
            f"weighted_net={public_action_gate.weighted_net}"
        )
        lines.append(f"- Public-action baseline delta: {delta_text}")
    if args.safety_report:
        lines.append(f"- Safety report: `{args.safety_report}`")
    else:
        lines.append(f"- Safety report: not supplied; required={args.require_safety_report}")
    lines.append(
        f"- Safety report trusted: {safety_gate.trusted}; "
        f"verdict=`{safety_gate.verdict or '-'}`; {safety_gate.summary}"
    )
    if backtest_gate.best_metric:
        lines.append(
            f"- Backtest best latest-public metric: `{backtest_gate.best_metric}` "
            f"Spearman={backtest_gate.best_spearman} Kendall={backtest_gate.best_kendall} "
            f"n={backtest_gate.best_n} trusted={backtest_gate.trusted}"
        )
    if packet_pair is None:
        lines.append("- Packet pair: not supplied; using intended archives directly")
    else:
        lines.append(f"- Packet pair: `{packet_first}` then `{packet_second}`")
        lines.append(f"- Packet pair enforcement: {args.enforce_packet_pair}")
    if single_intended:
        lines.append(f"- Submission mode: single agent")
        lines.append(f"- Intended submission: `{intended_archives[0]}`")
    else:
        lines.append("- Submission mode: explicit latest-two pair")
        lines.append(f"- Intended pair: `{intended_first}` then `{intended_second}`")
    if args.min_intended_public_score > 0:
        lines.append(f"- Intended archive public-score floor: {args.min_intended_public_score:.1f}")
        lines.append(
            "- Intended archive public-score floor age: "
            f"{args.min_public_score_age_minutes:.1f} minutes after submission timestamp"
        )
    if packet_mismatch and not args.enforce_packet_pair:
        lines.append("- Packet pair advisory: mismatch ignored because dynamic candidate evidence mode is active.")
    if resolver_override:
        lines.append("- Resolver override: one-slot packet mismatch is allowed by the boundary resolver.")
    if selector_override:
        lines.append("- Selector override: intended pair matches the current pair selector.")
    if anchor_statuses:
        lines.append(f"- Unanchored candidate policy: `{args.unanchored_candidate_policy}`")
    if args.unanchored_candidate_policy == "allow-exploration-slot":
        lines.append(
            "- Exploration slot criteria: "
            f"max_unanchored={args.max_exploration_candidates}, "
            f"max_league_rank={args.max_exploration_league_rank}, "
            f"max_robust_rank={args.max_exploration_robust_rank}, "
            f"min_robust_score={args.min_exploration_robust_score:.3f}"
        )
        lines.append(f"- Exploration hypothesis: `{args.exploration_hypothesis or '-'}`")
        lines.append(
            f"- Exploration slot trusted: {exploration_gate.trusted}; "
            f"{exploration_gate.summary}"
        )
        lines.append(
            "- Exploration predictive substitute: "
            f"{exploration_predictive_substitute}; "
            f"min_changed={args.min_exploration_public_action_changed}, "
            f"min_weighted_net={args.min_exploration_public_action_weighted_net:.2f}"
        )
    lines.append(f"- Today's submissions: {len(today_rows)} total, {len(complete_today)} complete")
    lines.append("")
    lines.append("## Decision")
    lines.append("")
    if reasons:
        lines.append("- Gate: **CLOSED**")
        for reason in reasons:
            lines.append(f"- Blocker: {reason}")
    else:
        lines.append("- Gate: **OPEN**")
        lines.append("- UTC reset time, daily quota, dynamic candidate evidence, and archive sanity checks agree.")
        lines.append("")
        lines.append("## Submit Commands")
        lines.append("")
        lines.append("```bash")
        for archive_name, message in (
            (intended_first, args.first_message),
            (intended_second, args.second_message),
        ):
            if archive_name:
                lines.append(
                    f"uv run kaggle competitions submit -c {args.competition} "
                    f"-f {archive_name} -m {message}"
                )
        lines.append("```")
    return "\n".join(lines), not reasons


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--competition", default="pokemon-tcg-ai-battle")
    parser.add_argument(
        "--packet",
        type=Path,
        help="optional legacy decision packet; advisory by default for new-candidate evaluation",
    )
    parser.add_argument("--first")
    parser.add_argument("--second")
    parser.add_argument("--first-message", default="codex-single-agent")
    parser.add_argument("--second-message", default="codex-second-agent")
    parser.add_argument("--submissions-output", type=Path)
    parser.add_argument("--resolver", type=Path)
    parser.add_argument("--selector", type=Path)
    parser.add_argument("--backtest-summary", type=Path)
    parser.add_argument("--league-public-gap-audit", type=Path)
    parser.add_argument("--candidate-critic-report", type=Path)
    parser.add_argument(
        "--safety-report",
        type=Path,
        help="optional rules-safety report, such as Dudunsparce Run Away Draw validation",
    )
    parser.add_argument(
        "--require-candidate-critic",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="require a candidate critic report with PROMOTION_REVIEW before opening the gate",
    )
    parser.add_argument(
        "--require-safety-report",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="require a parseable PASS safety report before opening the gate",
    )
    parser.add_argument(
        "--public-action-report",
        type=Path,
        help="optional public-action mismatch gate report; explicit failure blocks submission",
    )
    parser.add_argument("--anchor-status", type=Path)
    parser.add_argument(
        "--enforce-packet-pair",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="require intended archives to match the legacy packet pair unless resolver/selector allows the change",
    )
    parser.add_argument(
        "--unanchored-candidate-policy",
        choices=("block", "allow-with-promotion-critic", "allow-exploration-slot", "allow"),
        default="allow-with-promotion-critic",
        help=(
            "how to treat archives absent from the public-anchor CSV; direct public_fail anchors "
            "always block"
        ),
    )
    parser.add_argument(
        "--exploration-hypothesis",
        default="",
        help="explicit meta/risk hypothesis required by --unanchored-candidate-policy allow-exploration-slot",
    )
    parser.add_argument("--max-exploration-candidates", type=int, default=1)
    parser.add_argument("--max-exploration-league-rank", type=int, default=4)
    parser.add_argument("--max-exploration-robust-rank", type=int, default=4)
    parser.add_argument("--min-exploration-robust-score", type=float, default=-1.0)
    parser.add_argument(
        "--min-exploration-public-action-changed",
        type=int,
        default=10,
        help=(
            "minimum changed decisions versus the anchored baseline before an explicit "
            "unanchored exploration slot may substitute pre-public evidence for a missing "
            "global predictive-validity metric"
        ),
    )
    parser.add_argument(
        "--min-exploration-public-action-weighted-net",
        type=float,
        default=5.0,
        help=(
            "minimum weighted fixes minus weighted regressions before an explicit "
            "unanchored exploration slot may substitute pre-public evidence for a missing "
            "global predictive-validity metric"
        ),
    )
    parser.add_argument("--min-backtest-spearman", type=float, default=0.55)
    parser.add_argument("--min-backtest-n", type=int, default=5)
    parser.add_argument(
        "--min-intended-public-score",
        type=float,
        default=0.0,
        help=(
            "optional floor for intended archives that already have a public score; "
            "use this to block known weak resubmissions without affecting new unanchored archives"
        ),
    )
    parser.add_argument(
        "--min-public-score-age-minutes",
        type=float,
        default=60.0,
        help=(
            "minimum age from submission timestamp before --min-intended-public-score may judge "
            "an intended archive score; keep >=60 to avoid immature Kaggle public scores"
        ),
    )
    parser.add_argument("--now", help="UTC ISO timestamp override for dry checks")
    parser.add_argument("--min-utc-hour", type=int, default=0)
    parser.add_argument("--min-utc-minute", type=int, default=1)
    parser.add_argument("--max-daily-submissions", type=int, default=5)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report, open_gate = gate_report(args)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report + "\n", encoding="utf-8")
    print(report)
    return 0 if open_gate else 2


if __name__ == "__main__":
    raise SystemExit(main())
