#!/usr/bin/env python3
"""Evaluation-agent harness for candidate review.

This wraps the existing simulator and public-anchor tools into one repeatable
critic pass:

1. discover several local candidates, including latest Codex/Claude/Grok;
2. validate each candidate with py_compile, card-id audit, and deck/import smoke;
3. optionally run a Docker-backed local league through tools/local_top_league.py;
4. audit that league against mature public anchors;
5. emit a promotion verdict that is blocked when local evidence contradicts
   public evidence.

The point is to make "judge ourselves" mechanical. A local winner is only a
hypothesis until it survives validation and the public-gap audit.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import re
import shutil
import shlex
import subprocess
import sys
import tarfile
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class CommandResult:
    ok: bool
    returncode: int
    command: list[str]
    stdout_tail: str
    stderr_tail: str


@dataclass
class CandidateReview:
    label: str
    path: Path
    family: str
    version: int | None
    archive_hint: str
    py_compile: CommandResult | None = None
    card_audit: CommandResult | None = None
    import_smoke: CommandResult | None = None
    archive_sanity: CommandResult | None = None
    archive_consistency: CommandResult | None = None
    problems: list[str] = field(default_factory=list)
    league_rank: int | None = None
    league_points: float | None = None
    league_game_diff: float | None = None
    league_mean_rank: float | None = None
    league_rank_span: float | None = None
    league_candidate_best_count: int = 0
    league_record: str = ""
    robustness_rank: int | None = None
    robustness_score: float | None = None
    robustness_top_win_pct: float | None = None
    robustness_maximin: float | None = None
    robustness_max_regret: float | None = None
    robustness_rank_span: float | None = None
    robustness_best_count: int = 0
    robustness_worst_archetype: str = ""
    robustness_worst_opponent: str = ""

    @property
    def validation_ok(self) -> bool:
        checks = (
            self.py_compile,
            self.card_audit,
            self.import_smoke,
            self.archive_sanity,
            self.archive_consistency,
        )
        return all(check is not None and check.ok for check in checks) and not self.problems

    @property
    def hard_validation_ok(self) -> bool:
        checks = (self.py_compile, self.card_audit, self.import_smoke, self.archive_sanity)
        return all(check is not None and check.ok for check in checks) and not self.problems

    @property
    def league_ok(self) -> bool:
        checks = (self.py_compile, self.card_audit, self.import_smoke)
        return all(check is not None and check.ok for check in checks) and not self.problems


@dataclass
class LeagueStability:
    repeat_count: int = 0
    successful_repeats: int = 0
    aggregate_csv: Path | None = None
    repeat_csvs: list[Path] = field(default_factory=list)
    candidate_winner_counts: dict[str, int] = field(default_factory=dict)
    overall_winner_counts: dict[str, int] = field(default_factory=dict)
    robustness_winner_counts: dict[str, int] = field(default_factory=dict)
    unstable: bool = False
    reasons: list[str] = field(default_factory=list)


@dataclass
class LeagueCoverage:
    reference_rows: int = 0
    opponents: set[str] = field(default_factory=set)
    archetypes: set[str] = field(default_factory=set)
    decks: set[str] = field(default_factory=set)
    reasons: list[str] = field(default_factory=list)

    @property
    def sufficient(self) -> bool:
        return not self.reasons


def parse_float_value(value: str | None) -> float | None:
    if value is None or str(value).strip() == "":
        return None
    try:
        return float(str(value).strip())
    except ValueError:
        return None


def parse_int_value(value: str | None) -> int | None:
    parsed = parse_float_value(value)
    if parsed is None:
        return None
    return int(parsed)


def now_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%MZ")


def now_human() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def safe_label(text: str) -> str:
    return "_".join("".join(ch if ch.isalnum() else "_" for ch in text).split("_")) or "candidate"


def tail(text: str, max_lines: int = 8) -> str:
    lines = (text or "").strip().splitlines()
    return "\n".join(lines[-max_lines:])


def run_command(command: list[str], *, timeout: int = 120) -> CommandResult:
    try:
        result = subprocess.run(
            command,
            cwd=REPO,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return CommandResult(
            ok=result.returncode == 0,
            returncode=result.returncode,
            command=command,
            stdout_tail=tail(result.stdout),
            stderr_tail=tail(result.stderr),
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            ok=False,
            returncode=124,
            command=command,
            stdout_tail=tail(exc.stdout or ""),
            stderr_tail=f"timeout after {timeout}s\n{tail(exc.stderr or '')}".strip(),
        )


def parse_version(path: Path) -> int | None:
    match = re.search(r"(?<![a-z0-9])v(\d+)(?![a-z0-9])", path.name.lower())
    return int(match.group(1)) if match else None


def family_for(path: Path) -> str:
    name = path.name.lower()
    if "codex" in name:
        return "codex"
    if "claude" in name:
        return "claude"
    if "grok" in name:
        return "grok"
    return "anchor"


def label_for(path: Path) -> str:
    version = parse_version(path)
    family = family_for(path)
    if version is not None and family != "anchor":
        return f"{family}_v{version}"
    if version is not None:
        return f"v{version}_anchor"
    return safe_label(path.name)


def archive_hint_for(label: str, path: Path) -> str:
    name = path.name.lower()
    version = parse_version(path)
    family = family_for(path)
    if "v100" in name or label == "codex_v100":
        return "submission-psychic-control-final.tar.gz"
    if "v75" in name:
        return "submission-psychic-control-v75.tar.gz"
    if "v39" in name:
        return "submission-alakazam-denpa-v39.tar.gz"
    if "v105" in name:
        return "submission-codex-prize-guard-v105.tar.gz"
    if "v104" in name:
        return "submission-codex-anchor-tempo-v104.tar.gz"
    if "claude" in name and version is not None:
        if version == 102:
            return "submission-claude-alakazam-hammer-v102.tar.gz"
        if version == 103:
            return "submission-claude-ml-psychic-control-v103.tar.gz"
    discovered = discover_archive_hint(family, version)
    if discovered:
        return discovered
    if "grok" in name and version is None:
        # The live Grok final anchor was submitted with the old final filename.
        return "submission-grok-psychic-tempo-final.tar.gz"
    return ""


def discover_archive_hint(family: str, version: int | None) -> str:
    if version is None:
        return ""
    version_token = f"v{version}"
    archives = sorted(REPO.glob("submission*.tar.gz"), key=lambda item: item.name.lower())
    terminal_suffix = f"-{version_token}.tar.gz"
    all_terminal_matches = [
        archive
        for archive in archives
        if archive.name.lower().endswith(terminal_suffix)
    ]
    terminal_version_matches = [
        archive
        for archive in all_terminal_matches
        if family in archive.name.lower() or len(all_terminal_matches) == 1
    ]
    if terminal_version_matches:
        terminal_version_matches.sort(
            key=lambda item: (family in item.name.lower(), item.stat().st_mtime, item.name.lower()),
            reverse=True,
        )
        return terminal_version_matches[0].name

    family_matches = [
        archive
        for archive in archives
        if version_token in archive.name.lower() and family in archive.name.lower()
    ]
    if family_matches:
        family_matches.sort(key=lambda item: (item.stat().st_mtime, item.name.lower()), reverse=True)
        return family_matches[0].name

    version_matches = [
        archive
        for archive in archives
        if version_token in archive.name.lower()
    ]
    if len(version_matches) == 1:
        return version_matches[0].name
    return ""


def latest_paths(pattern: str, count: int) -> list[Path]:
    paths = [p for p in REPO.glob(pattern) if (p / "main.py").exists() and (p / "deck.csv").exists()]
    paths.sort(key=lambda p: (parse_version(p) or -1, p.stat().st_mtime), reverse=True)
    return paths[:count]


def discover_candidates(args: argparse.Namespace) -> list[Path]:
    if args.candidate:
        out: list[Path] = []
        for spec in args.candidate:
            path_text = spec.split("=", 1)[1] if "=" in spec else spec
            out.append((REPO / path_text).resolve() if not Path(path_text).is_absolute() else Path(path_text))
        return out

    ordered: list[Path] = []
    ordered.extend(latest_paths("agents/*codex*", args.max_codex))
    ordered.extend(latest_paths("agents/*claude*", args.max_claude))
    ordered.extend(latest_paths("agents/*grok*", args.max_grok))
    for anchor in args.anchor:
        path = REPO / anchor
        if path.exists():
            ordered.append(path)

    seen: set[Path] = set()
    deduped: list[Path] = []
    for path in ordered:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        deduped.append(path)
    return deduped


def is_agent_archive(path: Path) -> bool:
    return path.is_file() and (path.name.endswith(".tar.gz") or path.name.endswith(".tgz"))


def archive_agent_name(path: Path) -> str:
    name = path.name
    for suffix in (".tar.gz", ".tgz"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return safe_label(name)


def safe_archive_member_path(name: str) -> Path:
    normalized = name[2:] if name.startswith("./") else name
    relative = Path(normalized)
    if not normalized or relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"unsafe archive member path: {name}")
    return relative


def materialize_archive_agent(archive: Path, root: Path) -> Path:
    dest = root / archive_agent_name(archive)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive, "r:gz") as handle:
            for member in handle.getmembers():
                rel_path = safe_archive_member_path(member.name)
                target = dest / rel_path
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise ValueError(f"unsupported archive member type: {member.name}")
                target.parent.mkdir(parents=True, exist_ok=True)
                source = handle.extractfile(member)
                target.write_bytes(source.read() if source is not None else b"")
                os.chmod(target, member.mode & 0o777)
    except (tarfile.TarError, OSError, ValueError) as exc:
        shutil.rmtree(dest, ignore_errors=True)
        raise RuntimeError(f"could not materialize {archive}: {exc}") from exc

    for required in ("main.py", "deck.csv"):
        if not (dest / required).exists():
            shutil.rmtree(dest, ignore_errors=True)
            raise RuntimeError(f"materialized archive missing {required}: {archive}")
    return dest


def materialize_candidate_paths(
    paths: list[Path],
    output_prefix: Path,
    explicit_labels: dict[Path, str],
) -> tuple[list[Path], dict[Path, str], dict[Path, str], dict[Path, str]]:
    materialized_root = REPO / ".critic_materialized" / output_prefix.name
    out: list[Path] = []
    labels = dict(explicit_labels)
    archive_hints: dict[Path, str] = {}
    family_overrides: dict[Path, str] = {}
    for path in paths:
        resolved = path.resolve()
        if is_agent_archive(resolved):
            materialized = materialize_archive_agent(resolved, materialized_root).resolve()
            out.append(materialized)
            archive_hints[materialized] = resolved.name
            if resolved in explicit_labels:
                labels[materialized] = explicit_labels[resolved]
                if explicit_labels[resolved].startswith(("anchor_", "public_anchor_")):
                    family_overrides[materialized] = "anchor"
            continue
        out.append(path)
    return out, labels, archive_hints, family_overrides


def parse_utc_datetime(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def public_anchor_label(archive: Path) -> str:
    version = parse_version(archive)
    if version is not None:
        return f"public_anchor_v{version}"
    return "public_anchor_" + archive_agent_name(archive)


def existing_archive_names(paths: list[Path]) -> set[str]:
    names: set[str] = set()
    for path in paths:
        resolved = path.resolve()
        if is_agent_archive(resolved):
            names.add(resolved.name)
            continue
        hint = archive_hint_for(label_for(resolved), resolved)
        if hint:
            names.add(hint)
    return names


def discover_public_anchor_archives(
    args: argparse.Namespace,
    paths: list[Path],
    explicit_labels: dict[Path, str],
) -> list[Path]:
    if args.auto_public_anchors <= 0 or args.submissions is None or not args.submissions.exists():
        return []

    now = parse_utc_datetime(args.now) or datetime.now(UTC)
    cutoff = now - timedelta(minutes=args.maturity_minutes)
    seen_archives = existing_archive_names(paths)
    by_archive: dict[str, tuple[float, datetime]] = {}
    with args.submissions.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            archive = (row.get("fileName") or "").strip()
            status = (row.get("status") or "").strip()
            if not archive or status != "SubmissionStatus.COMPLETE":
                continue
            submitted_at = parse_utc_datetime(row.get("date") or "")
            if submitted_at is None or submitted_at > cutoff:
                continue
            score = parse_float_value(row.get("publicScore"))
            if score is None:
                continue
            archive_path = REPO / archive
            if not archive_path.exists() or archive in seen_archives:
                continue
            previous = by_archive.get(archive)
            if previous is None or submitted_at > previous[1]:
                by_archive[archive] = (score, submitted_at)

    rows = [
        (archive, score, submitted_at)
        for archive, (score, submitted_at) in by_archive.items()
    ]
    if not rows:
        return []

    high = sorted(rows, key=lambda item: (item[1], item[2]), reverse=True)
    low = sorted(rows, key=lambda item: (item[1], item[2]))
    selected: list[str] = []
    for pool in (high, low):
        for archive, _, _ in pool:
            if archive in selected:
                continue
            selected.append(archive)
            break
    cursor = 0
    interleaved = high + low
    while len(selected) < args.auto_public_anchors and cursor < len(interleaved):
        archive = interleaved[cursor][0]
        cursor += 1
        if archive not in selected:
            selected.append(archive)

    out: list[Path] = []
    for archive in selected[: args.auto_public_anchors]:
        archive_path = (REPO / archive).resolve()
        explicit_labels[archive_path] = public_anchor_label(archive_path)
        out.append(archive_path)
    return out


def latest_file(glob_text: str) -> Path | None:
    files = [p for p in REPO.glob(glob_text) if p.is_file()]
    if not files:
        return None
    return max(files, key=lambda p: p.stat().st_mtime)


def latest_file_any(glob_texts: list[str]) -> Path | None:
    files: list[Path] = []
    for glob_text in glob_texts:
        files.extend(p for p in REPO.glob(glob_text) if p.is_file())
    if not files:
        return None
    return max(files, key=lambda p: p.stat().st_mtime)


def latest_scout() -> Path | None:
    summaries = [p for p in REPO.glob("scouting/**/download_summary.csv") if p.is_file()]
    if not summaries:
        return None
    return max(summaries, key=lambda p: p.stat().st_mtime).parent


def rel_for_container(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO.resolve()))
    except ValueError:
        return str(path)


def smoke_script(agent_dir: Path) -> str:
    return (
        "from pathlib import Path\n"
        "from tools.run_local_battle import load_agent\n"
        f"agent, deck = load_agent(Path({str(agent_dir)!r}), 'critic_smoke')\n"
        "assert callable(agent)\n"
        "assert len(deck) == 60, len(deck)\n"
        "print('smoke ok deck_len=60')\n"
    )


def smoke_command(path: Path, args: argparse.Namespace) -> list[str]:
    if args.no_docker:
        return ["uv", "run", "python", "-c", smoke_script(path)]
    container_agent = Path("/work") / rel_for_container(path)
    return [
        "docker",
        "run",
        "-i",
        "--rm",
        "--platform",
        args.docker_platform,
        "-v",
        f"{REPO}:/work",
        "-w",
        "/work",
        args.docker_image,
        "python",
        "-c",
        smoke_script(container_agent),
    ]


def archive_sanity_check(archive_hint: str) -> CommandResult:
    command = ["archive-sanity", archive_hint or "-"]
    if not archive_hint:
        return CommandResult(False, 1, command, "", "missing archive hint")
    archive = REPO / archive_hint
    if not archive.exists():
        return CommandResult(False, 1, command, "", f"missing archive: {archive_hint}")

    try:
        with tarfile.open(archive, "r:gz") as handle:
            members = handle.getmembers()
    except (tarfile.TarError, OSError) as exc:
        return CommandResult(False, 1, command, "", f"could not read archive: {exc}")

    names = [member.name for member in members]
    normalized = [name[2:] if name.startswith("./") else name for name in names]
    name_set = set(normalized)
    problems: list[str] = []
    required = {"main.py", "deck.csv"}
    missing = sorted(required - name_set)
    if missing:
        problems.append("missing root files: " + ", ".join(missing))
    if not any(name == "cg" or name.startswith("cg/") for name in normalized):
        problems.append("missing root cg/ directory")
    if "cg/api.py" not in name_set:
        problems.append("missing cg/api.py")
    if "cg/libcg.so" not in name_set:
        problems.append("missing cg/libcg.so")
    if any(name.startswith("/") or ".." in Path(name).parts for name in names):
        problems.append("unsafe path member")
    if any("__pycache__" in Path(name).parts or name.endswith(".pyc") for name in normalized):
        problems.append("contains Python cache artifacts")
    if any(normalized_name.startswith("agent/") for normalized_name in normalized) and "main.py" not in name_set:
        problems.append("archive appears nested under agent/ instead of root")

    if problems:
        return CommandResult(False, 1, command, "", "; ".join(problems))
    summary = f"archive ok members={len(members)} root_files=main.py,deck.csv,cg/"
    return CommandResult(True, 0, command, summary, "")


def archive_consistency_check(archive_hint: str, agent_dir: Path) -> CommandResult:
    command = ["archive-match", archive_hint or "-", rel_for_container(agent_dir)]
    if not archive_hint:
        return CommandResult(False, 1, command, "", "missing archive hint")
    archive = REPO / archive_hint
    if not archive.exists():
        return CommandResult(False, 1, command, "", f"missing archive: {archive_hint}")
    if not agent_dir.exists():
        return CommandResult(False, 1, command, "", f"missing agent directory: {agent_dir}")

    compare_files = [
        "main.py",
        "deck.csv",
        "cg/__init__.py",
        "cg/api.py",
        "cg/game.py",
        "cg/sim.py",
        "cg/utils.py",
        "cg/libcg.so",
        "cg/cg.dll",
    ]
    problems: list[str] = []
    checked = 0
    try:
        with tarfile.open(archive, "r:gz") as handle:
            member_by_name = {
                (member.name[2:] if member.name.startswith("./") else member.name): member
                for member in handle.getmembers()
                if member.isfile()
            }
            for rel_path in compare_files:
                source = agent_dir / rel_path
                if not source.exists():
                    continue
                member = member_by_name.get(rel_path)
                if member is None:
                    problems.append(f"archive missing agent file: {rel_path}")
                    continue
                extracted = handle.extractfile(member)
                archive_bytes = extracted.read() if extracted is not None else b""
                source_bytes = source.read_bytes()
                if archive_bytes != source_bytes:
                    archive_hash = hashlib.sha256(archive_bytes).hexdigest()[:16]
                    source_hash = hashlib.sha256(source_bytes).hexdigest()[:16]
                    problems.append(
                        f"archive differs from agent file: {rel_path} "
                        f"(archive_sha256={archive_hash}, agent_sha256={source_hash})"
                    )
                checked += 1
    except (tarfile.TarError, OSError) as exc:
        return CommandResult(False, 1, command, "", f"could not compare archive: {exc}")

    if checked == 0:
        problems.append("no comparable agent files found in archive")
    if problems:
        return CommandResult(False, 1, command, "", "; ".join(problems))
    return CommandResult(True, 0, command, f"archive matches agent files checked={checked}", "")


def validate_candidate(
    path: Path,
    args: argparse.Namespace,
    explicit_label: str | None = None,
    archive_hint_override: str | None = None,
    family_override: str | None = None,
) -> CandidateReview:
    label = safe_label(explicit_label or label_for(path))
    review = CandidateReview(
        label=label,
        path=path,
        family=family_override or family_for(path),
        version=parse_version(path),
        archive_hint=archive_hint_override or archive_hint_for(label, path),
    )
    if not path.exists():
        review.problems.append(f"missing agent directory: {path}")
        return review
    for required in ("main.py", "deck.csv"):
        if not (path / required).exists():
            review.problems.append(f"missing {required}")
    if review.problems:
        return review
    review.py_compile = run_command(["uv", "run", "python", "-m", "py_compile", str(path / "main.py")])
    review.card_audit = run_command(["uv", "run", "python", "tools/audit_card_id_usage.py", "--agent", str(path)])
    review.import_smoke = run_command(smoke_command(path, args), timeout=180)
    review.archive_sanity = archive_sanity_check(review.archive_hint)
    review.archive_consistency = archive_consistency_check(review.archive_hint, path)
    return review


def candidate_specs(reviews: list[CandidateReview], include_invalid: bool) -> list[str]:
    specs = []
    for review in reviews:
        if not include_invalid and not review.league_ok:
            continue
        specs.append(f"{review.label}={rel_for_container(review.path)}")
    return specs


def promotion_candidate_labels(reviews: list[CandidateReview]) -> set[str]:
    return {review.label for review in reviews if review.family != "anchor"}


def run_single_league(args: argparse.Namespace, reviews: list[CandidateReview], output_prefix: Path) -> CommandResult | None:
    specs = candidate_specs(reviews, args.include_invalid_in_league)
    if not specs:
        return None
    if args.scout_dir is None:
        return None
    command = [
        "uv",
        "run",
        "python",
        "tools/local_top_league.py",
        "--scout-dir",
        str(args.scout_dir),
        "--top-limit",
        str(args.top_limit),
        "--selection-mode",
        args.league_selection_mode,
        "--scan-limit",
        str(args.league_scan_limit),
        "--min-archetypes",
        str(args.min_reference_archetypes),
        "--min-decks",
        str(args.min_reference_decks),
        "--games-per-seat",
        str(args.games_per_seat),
        "--max-steps",
        str(args.max_steps),
        "--output-prefix",
        str(output_prefix),
        "--allow-partial-top",
        "--quiet",
    ]
    if args.no_docker:
        command.append("--no-docker")
    else:
        command.append("--docker")
        command.extend(["--docker-image", args.docker_image, "--docker-platform", args.docker_platform])
    for spec in specs:
        command.extend(["--candidate", spec])
    return run_command(command, timeout=args.league_timeout)


def read_league_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def robustness_companion(path: Path) -> Path:
    return path.with_name(path.stem + "_robustness.csv")


def league_row_win_pct(row: dict[str, str]) -> float:
    explicit = parse_float_value(row.get("win_pct") or row.get("Win%"))
    if explicit is not None:
        return explicit
    game_wins = parse_float_value(row.get("game_wins")) or 0.0
    game_losses = parse_float_value(row.get("game_losses")) or 0.0
    game_draws = parse_float_value(row.get("game_draws")) or 0.0
    total = game_wins + game_losses + game_draws
    if total <= 0:
        return 0.0
    return (game_wins + 0.5 * game_draws) / total


def aggregate_league_repeats(
    *,
    args: argparse.Namespace,
    reviews: list[CandidateReview],
    repeat_csvs: list[Path],
    aggregate_csv: Path,
) -> LeagueStability:
    stability = LeagueStability(
        repeat_count=args.league_repeats,
        successful_repeats=len(repeat_csvs),
        aggregate_csv=aggregate_csv,
        repeat_csvs=repeat_csvs,
    )
    if not repeat_csvs:
        stability.unstable = True
        stability.reasons.append("no successful league repeat CSVs")
        return stability

    candidate_labels = promotion_candidate_labels(reviews)
    by_entry: dict[str, list[dict[str, str]]] = {}
    first_rows: dict[str, dict[str, str]] = {}
    for csv_path in repeat_csvs:
        rows = read_league_rows(csv_path)
        if not rows:
            continue
        overall_best = min(rows, key=lambda row: parse_int_value(row.get("rank")) or 999999)
        stability.overall_winner_counts[overall_best.get("entry", "")] = (
            stability.overall_winner_counts.get(overall_best.get("entry", ""), 0) + 1
        )
        candidate_rows = [row for row in rows if row.get("entry") in candidate_labels]
        if candidate_rows:
            candidate_best = min(candidate_rows, key=lambda row: parse_int_value(row.get("rank")) or 999999)
            label = candidate_best.get("entry", "")
            stability.candidate_winner_counts[label] = stability.candidate_winner_counts.get(label, 0) + 1
        for row in rows:
            entry = row.get("entry", "")
            if not entry:
                continue
            by_entry.setdefault(entry, []).append(row)
            first_rows.setdefault(entry, row)

    if args.league_repeats > 1 and len(stability.candidate_winner_counts) > 1:
        stability.unstable = True
        winners = ", ".join(f"{entry}={count}" for entry, count in sorted(stability.candidate_winner_counts.items()))
        stability.reasons.append(f"candidate winner changed across repeats ({winners})")

    numeric_sum_fields = [
        "match_wins",
        "match_losses",
        "match_draws",
        "points",
        "game_wins",
        "game_losses",
        "game_draws",
        "unfinished",
        "game_diff",
    ]
    aggregate_rows: list[dict[str, str | float | int]] = []
    for entry, rows in by_entry.items():
        ranks = [parse_float_value(row.get("rank")) for row in rows]
        ranks = [rank for rank in ranks if rank is not None]
        first = first_rows[entry]
        sums = {field: sum(parse_float_value(row.get(field)) or 0.0 for row in rows) for field in numeric_sum_fields}
        mean_points = sums["points"] / max(1, len(rows))
        mean_game_diff = sums["game_diff"] / max(1, len(rows))
        total_games = sums["game_wins"] + sums["game_losses"] + sums["game_draws"]
        if total_games > 0:
            win_pct = (sums["game_wins"] + 0.5 * sums["game_draws"]) / total_games
        else:
            win_pct = sum(league_row_win_pct(row) for row in rows) / max(1, len(rows))
        best_rank = min(ranks) if ranks else float("nan")
        worst_rank = max(ranks) if ranks else float("nan")
        rank_span = worst_rank - best_rank if ranks else float("nan")
        mean_rank = sum(ranks) / len(ranks) if ranks else float("nan")
        if entry in candidate_labels and args.league_repeats > 1 and rank_span > args.rank_span_threshold:
            stability.unstable = True
            stability.reasons.append(
                f"{entry} rank span {rank_span:.1f} exceeds threshold {args.rank_span_threshold:.1f}"
            )
        aggregate_rows.append(
            {
                "entry": entry,
                "repeats_seen": len(rows),
                "win_pct": win_pct,
                "points": mean_points,
                "game_diff": mean_game_diff,
                "match_wins": int(sums["match_wins"]),
                "match_losses": int(sums["match_losses"]),
                "match_draws": int(sums["match_draws"]),
                "game_wins": int(sums["game_wins"]),
                "game_losses": int(sums["game_losses"]),
                "game_draws": int(sums["game_draws"]),
                "unfinished": int(sums["unfinished"]),
                "mean_rank": mean_rank,
                "best_rank": best_rank,
                "worst_rank": worst_rank,
                "rank_span": rank_span,
                "candidate_best_count": stability.candidate_winner_counts.get(entry, 0),
                "overall_best_count": stability.overall_winner_counts.get(entry, 0),
                "archetype": first.get("archetype", ""),
                "deck_hash": first.get("deck_hash", ""),
                "kind": first.get("kind", ""),
                "source_team": first.get("source_team", ""),
                "public_rank": first.get("public_rank", ""),
                "public_score": first.get("public_score", ""),
                "policy": first.get("policy", ""),
                "source_replay": first.get("source_replay", ""),
            }
        )

    aggregate_rows.sort(
        key=lambda row: (
            -float(row["win_pct"]),
            -float(row["points"]),
            -float(row["game_diff"]),
            float(row["mean_rank"]) if float(row["mean_rank"]) == float(row["mean_rank"]) else 999999.0,
            str(row["entry"]),
        )
    )
    aggregate_csv.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "rank",
        "entry",
        "repeats_seen",
        "win_pct",
        "points",
        "game_diff",
        "match_wins",
        "match_losses",
        "match_draws",
        "game_wins",
        "game_losses",
        "game_draws",
        "unfinished",
        "mean_rank",
        "best_rank",
        "worst_rank",
        "rank_span",
        "candidate_best_count",
        "overall_best_count",
        "archetype",
        "deck_hash",
        "kind",
        "source_team",
        "public_rank",
        "public_score",
        "policy",
        "source_replay",
    ]
    with aggregate_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for rank, row in enumerate(aggregate_rows, 1):
            out = dict(row)
            out["rank"] = rank
            for key in ("win_pct", "points", "game_diff", "mean_rank", "best_rank", "worst_rank", "rank_span"):
                value = float(out[key])
                out[key] = "" if value != value else f"{value:.6f}"
            writer.writerow(out)

    if args.league_repeats > 1 and stability.successful_repeats < args.league_repeats:
        stability.unstable = True
        stability.reasons.append(
            f"only {stability.successful_repeats}/{args.league_repeats} league repeats produced CSVs"
        )
    if args.league_repeats > 1 and not stability.candidate_winner_counts:
        stability.unstable = True
        stability.reasons.append("no candidate winner rows were found in repeats")
    return stability


def aggregate_robustness_repeats(
    *,
    args: argparse.Namespace,
    reviews: list[CandidateReview],
    repeat_csvs: list[Path],
    aggregate_csv: Path,
    stability: LeagueStability,
) -> Path | None:
    candidate_labels = promotion_candidate_labels(reviews)
    repeat_robustness_csvs = [robustness_companion(path) for path in repeat_csvs]
    repeat_robustness_csvs = [path for path in repeat_robustness_csvs if path.exists()]
    if not repeat_robustness_csvs:
        if args.league_repeats > 1:
            stability.unstable = True
            stability.reasons.append("no robustness CSVs were produced by league repeats")
        return None

    by_entry: dict[str, list[dict[str, str]]] = {}
    for csv_path in repeat_robustness_csvs:
        rows = read_league_rows(csv_path)
        if not rows:
            continue
        candidate_rows = [row for row in rows if row.get("entry") in candidate_labels]
        if candidate_rows:
            robust_best = min(candidate_rows, key=lambda row: parse_int_value(row.get("rank")) or 999999)
            label = robust_best.get("entry", "")
            stability.robustness_winner_counts[label] = stability.robustness_winner_counts.get(label, 0) + 1
        for row in rows:
            entry = row.get("entry", "")
            if entry:
                by_entry.setdefault(entry, []).append(row)

    if args.league_repeats > 1 and len(stability.robustness_winner_counts) > 1:
        stability.unstable = True
        winners = ", ".join(
            f"{entry}={count}" for entry, count in sorted(stability.robustness_winner_counts.items())
        )
        stability.reasons.append(f"robustness winner changed across repeats ({winners})")

    aggregate_rows: list[dict[str, str | float | int]] = []
    for entry, rows in by_entry.items():
        ranks = [parse_float_value(row.get("rank")) for row in rows]
        ranks = [rank for rank in ranks if rank is not None]
        top_games = sum(parse_float_value(row.get("top_games")) or 0.0 for row in rows)

        def mean_field(name: str) -> float:
            values = [parse_float_value(row.get(name)) for row in rows]
            values = [value for value in values if value is not None]
            return sum(values) / len(values) if values else 0.0

        def weighted_field(name: str) -> float:
            weighted_total = 0.0
            weight_total = 0.0
            for row in rows:
                value = parse_float_value(row.get(name))
                weight = parse_float_value(row.get("top_games")) or 0.0
                if value is None:
                    continue
                weighted_total += value * max(1.0, weight)
                weight_total += max(1.0, weight)
            return weighted_total / weight_total if weight_total > 0 else 0.0

        mean_rank = sum(ranks) / len(ranks) if ranks else float("nan")
        best_rank = min(ranks) if ranks else float("nan")
        worst_rank = max(ranks) if ranks else float("nan")
        rank_span = worst_rank - best_rank if ranks else float("nan")
        robustness_score = mean_field("robustness_score")
        worst_archetypes = [
            row.get("worst_archetype", "")
            for row in rows
            if row.get("worst_archetype")
        ]
        worst_opponents = [
            row.get("worst_opponent", "")
            for row in rows
            if row.get("worst_opponent")
        ]
        if entry in candidate_labels and args.league_repeats > 1 and rank_span > args.rank_span_threshold:
            stability.unstable = True
            stability.reasons.append(
                f"{entry} robustness rank span {rank_span:.1f} exceeds threshold {args.rank_span_threshold:.1f}"
            )
        aggregate_rows.append(
            {
                "entry": entry,
                "repeats_seen": len(rows),
                "top_games": int(top_games),
                "top_win_pct": weighted_field("top_win_pct"),
                "maximin_archetype_win_pct": mean_field("maximin_archetype_win_pct"),
                "max_regret": mean_field("max_regret"),
                "avg_regret": mean_field("avg_regret"),
                "archetype_stddev": mean_field("archetype_stddev"),
                "worst_archetype": ";".join(sorted(set(worst_archetypes))) or "-",
                "worst_opponent": ";".join(sorted(set(worst_opponents))) or "-",
                "robustness_score": robustness_score,
                "local_strength": robustness_score,
                "mean_rank": mean_rank,
                "best_rank": best_rank,
                "worst_rank": worst_rank,
                "rank_span": rank_span,
                "robustness_best_count": stability.robustness_winner_counts.get(entry, 0),
            }
        )

    aggregate_rows.sort(
        key=lambda row: (
            -float(row["robustness_score"]),
            -float(row["maximin_archetype_win_pct"]),
            float(row["max_regret"]),
            -float(row["top_win_pct"]),
            str(row["entry"]),
        )
    )
    aggregate_csv.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "rank",
        "entry",
        "repeats_seen",
        "top_games",
        "top_win_pct",
        "maximin_archetype_win_pct",
        "max_regret",
        "avg_regret",
        "archetype_stddev",
        "worst_archetype",
        "worst_opponent",
        "robustness_score",
        "local_strength",
        "mean_rank",
        "best_rank",
        "worst_rank",
        "rank_span",
        "robustness_best_count",
    ]
    with aggregate_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for rank, row in enumerate(aggregate_rows, 1):
            out = dict(row)
            out["rank"] = rank
            for key in (
                "top_win_pct",
                "maximin_archetype_win_pct",
                "max_regret",
                "avg_regret",
                "archetype_stddev",
                "robustness_score",
                "local_strength",
                "mean_rank",
                "best_rank",
                "worst_rank",
                "rank_span",
            ):
                value = float(out[key])
                out[key] = "" if value != value else f"{value:.6f}"
            writer.writerow(out)
    return aggregate_csv


def combine_league_results(results: list[CommandResult], stability: LeagueStability) -> CommandResult | None:
    if not results:
        return None
    ok = all(result.ok for result in results) and stability.successful_repeats > 0
    stdout_lines = [
        f"league repeats requested={stability.repeat_count} successful={stability.successful_repeats}",
        "candidate winners: "
        + (", ".join(f"{entry}={count}" for entry, count in sorted(stability.candidate_winner_counts.items())) or "-"),
        "overall winners: "
        + (", ".join(f"{entry}={count}" for entry, count in sorted(stability.overall_winner_counts.items())) or "-"),
        "robustness winners: "
        + (", ".join(f"{entry}={count}" for entry, count in sorted(stability.robustness_winner_counts.items())) or "-"),
        f"unstable={stability.unstable} reasons={'; '.join(stability.reasons) or '-'}",
    ]
    return CommandResult(
        ok=ok,
        returncode=0 if ok else max((result.returncode for result in results if not result.ok), default=1),
        command=["repeated-league", f"--league-repeats={stability.repeat_count}"],
        stdout_tail="\n".join(stdout_lines),
        stderr_tail="\n".join(result.stderr_tail for result in results if result.stderr_tail),
    )


def run_league(
    args: argparse.Namespace,
    reviews: list[CandidateReview],
    output_prefix: Path,
) -> tuple[CommandResult | None, LeagueStability]:
    repeats = max(1, args.league_repeats)
    if repeats == 1:
        result = run_single_league(args, reviews, output_prefix)
        csv_path = output_prefix.with_suffix(".csv")
        successful = [csv_path] if result is not None and result.ok and csv_path.exists() else []
        stability = LeagueStability(
            repeat_count=1,
            successful_repeats=len(successful),
            aggregate_csv=csv_path if successful else None,
            repeat_csvs=successful,
        )
        if successful:
            rows = read_league_rows(csv_path)
            if rows:
                overall_best = min(rows, key=lambda row: parse_int_value(row.get("rank")) or 999999)
                stability.overall_winner_counts[overall_best.get("entry", "")] = 1
                candidate_labels = promotion_candidate_labels(reviews)
                candidate_rows = [row for row in rows if row.get("entry") in candidate_labels]
                if candidate_rows:
                    candidate_best = min(candidate_rows, key=lambda row: parse_int_value(row.get("rank")) or 999999)
                    stability.candidate_winner_counts[candidate_best.get("entry", "")] = 1
            aggregate_robustness_repeats(
                args=args,
                reviews=reviews,
                repeat_csvs=successful,
                aggregate_csv=robustness_companion(csv_path),
                stability=stability,
            )
        return result, stability

    results: list[CommandResult] = []
    repeat_csvs: list[Path] = []
    for repeat_index in range(1, repeats + 1):
        repeat_prefix = output_prefix.with_name(f"{output_prefix.name}_r{repeat_index:02d}")
        result = run_single_league(args, reviews, repeat_prefix)
        if result is not None:
            results.append(result)
        repeat_csv = repeat_prefix.with_suffix(".csv")
        if result is not None and result.ok and repeat_csv.exists():
            repeat_csvs.append(repeat_csv)
    aggregate_csv = output_prefix.with_suffix(".csv")
    stability = aggregate_league_repeats(
        args=args,
        reviews=reviews,
        repeat_csvs=repeat_csvs,
        aggregate_csv=aggregate_csv,
    )
    aggregate_robustness_repeats(
        args=args,
        reviews=reviews,
        repeat_csvs=repeat_csvs,
        aggregate_csv=robustness_companion(aggregate_csv),
        stability=stability,
    )
    return combine_league_results(results, stability), stability


def attach_league_rows(reviews: list[CandidateReview], league_csv: Path) -> None:
    if not league_csv.exists():
        return
    with league_csv.open(encoding="utf-8-sig", newline="") as handle:
        by_entry = {row.get("entry", ""): row for row in csv.DictReader(handle)}
    for review in reviews:
        row = by_entry.get(review.label)
        if not row:
            continue
        review.league_rank = parse_int_value(row.get("rank"))
        review.league_points = parse_float_value(row.get("points"))
        review.league_game_diff = parse_float_value(row.get("game_diff"))
        review.league_mean_rank = parse_float_value(row.get("mean_rank"))
        review.league_rank_span = parse_float_value(row.get("rank_span"))
        review.league_candidate_best_count = parse_int_value(row.get("candidate_best_count")) or 0
        review.league_record = (
            f"{row.get('match_wins', '0')}-{row.get('match_losses', '0')}-"
            f"{row.get('match_draws', '0')} matches, "
            f"{row.get('game_wins', '0')}-{row.get('game_losses', '0')}-"
            f"{row.get('game_draws', '0')} games"
        )
        if row.get("repeats_seen"):
            review.league_record += f", repeats={row.get('repeats_seen')}"


def attach_robustness_rows(reviews: list[CandidateReview], robustness_csv: Path) -> None:
    if not robustness_csv.exists():
        return
    with robustness_csv.open(encoding="utf-8-sig", newline="") as handle:
        by_entry = {row.get("entry", ""): row for row in csv.DictReader(handle)}
    for review in reviews:
        row = by_entry.get(review.label)
        if not row:
            continue
        review.robustness_rank = parse_int_value(row.get("rank"))
        review.robustness_score = parse_float_value(row.get("robustness_score"))
        review.robustness_top_win_pct = parse_float_value(row.get("top_win_pct"))
        review.robustness_maximin = parse_float_value(row.get("maximin_archetype_win_pct"))
        review.robustness_max_regret = parse_float_value(row.get("max_regret"))
        review.robustness_rank_span = parse_float_value(row.get("rank_span"))
        review.robustness_best_count = parse_int_value(row.get("robustness_best_count")) or 0
        review.robustness_worst_archetype = row.get("worst_archetype", "")
        review.robustness_worst_opponent = row.get("worst_opponent", "")


def run_public_gap_audit(args: argparse.Namespace, reviews: list[CandidateReview], league_csv: Path, output: Path) -> CommandResult | None:
    if not league_csv.exists() or args.submissions is None:
        return None
    command = [
        "uv",
        "run",
        "python",
        "tools/audit_local_league_public_gap.py",
        "--league-csv",
        str(league_csv),
        "--submissions",
        str(args.submissions),
        "--output",
        str(output),
        "--now",
        args.now,
        "--top-local-rank",
        str(args.top_local_rank),
        "--min-public-score",
        str(args.min_public_score),
        "--maturity-minutes",
        str(args.maturity_minutes),
        "--min-public-spearman",
        str(args.min_public_spearman),
    ]
    for review in reviews:
        if review.archive_hint and review.archive_consistency and review.archive_consistency.ok:
            command.extend(["--map", f"{review.label}={review.archive_hint}"])
    return run_command(command, timeout=120)


def audit_contradicted(path: Path) -> bool:
    if not path.exists():
        return False
    text = path.read_text(encoding="utf-8", errors="replace")
    return "Trust decision: **LOCAL LEAGUE CONTRADICTED BY PUBLIC ANCHORS**" in text


def audit_insufficient(path: Path) -> bool:
    if not path.exists():
        return False
    text = path.read_text(encoding="utf-8", errors="replace")
    return "Trust decision: **LOCAL LEAGUE HAS INSUFFICIENT PUBLIC ANCHORS**" in text


def audit_low_correlation(path: Path) -> bool:
    if not path.exists():
        return False
    text = path.read_text(encoding="utf-8", errors="replace")
    return "Trust decision: **LOCAL LEAGUE FAILS PUBLIC CORRELATION**" in text


def audit_decision(path: Path) -> str:
    if not path.exists():
        return "missing"
    text = path.read_text(encoding="utf-8", errors="replace")
    if "Trust decision: **LOCAL LEAGUE CONTRADICTED BY PUBLIC ANCHORS**" in text:
        return "contradicted"
    if "Trust decision: **LOCAL LEAGUE FAILS PUBLIC CORRELATION**" in text:
        return "low_public_correlation"
    if "Trust decision: **LOCAL LEAGUE HAS INSUFFICIENT PUBLIC ANCHORS**" in text:
        return "insufficient_public_anchors"
    if (
        "Trust decision: **LOCAL LEAGUE NOT CONTRADICTED BY PUBLIC ANCHORS**" in text
        or "Trust decision: no top-local public contradiction found in mapped mature anchors." in text
    ):
        return "not_contradicted"
    return "unrecognized"


def analyze_league_coverage(
    league_csv: Path,
    reviews: list[CandidateReview],
    *,
    min_reference_opponents: int,
    min_reference_archetypes: int,
    min_reference_decks: int,
) -> LeagueCoverage:
    coverage = LeagueCoverage()
    if not league_csv.exists():
        coverage.reasons.append("league CSV missing")
        return coverage

    candidate_labels = {review.label for review in reviews}
    for row in read_league_rows(league_csv):
        entry = row.get("entry", "")
        kind = row.get("kind", "")
        if entry in candidate_labels or kind == "ours":
            continue
        coverage.reference_rows += 1
        opponent = row.get("source_team") or entry
        archetype = row.get("archetype") or "unknown"
        deck_hash = row.get("deck_hash") or ""
        if opponent:
            coverage.opponents.add(opponent)
        if archetype:
            coverage.archetypes.add(archetype)
        if deck_hash:
            coverage.decks.add(deck_hash)

    if len(coverage.opponents) < min_reference_opponents:
        coverage.reasons.append(
            f"only {len(coverage.opponents)} reference opponents; need >= {min_reference_opponents}"
        )
    if len(coverage.archetypes) < min_reference_archetypes:
        coverage.reasons.append(
            f"only {len(coverage.archetypes)} reference archetypes; need >= {min_reference_archetypes}"
        )
    if len(coverage.decks) < min_reference_decks:
        coverage.reasons.append(
            f"only {len(coverage.decks)} reference deck hashes; need >= {min_reference_decks}"
        )
    return coverage


def command_text(result: CommandResult | None) -> str:
    if result is None:
        return "-"
    return "`" + " ".join(shlex.quote(part) for part in result.command) + "`"


def status_word(result: CommandResult | None) -> str:
    if result is None:
        return "skipped"
    return "pass" if result.ok else f"fail({result.returncode})"


def public_action_failed(path: Path) -> bool:
    if not path.exists():
        return False
    text = path.read_text(encoding="utf-8", errors="replace")
    return "Trust decision: **PUBLIC ACTION GATE FAILED**" in text


def run_public_action_gate(args: argparse.Namespace, reviews: list[CandidateReview], output_prefix: Path) -> CommandResult | None:
    if not args.run_public_action_gate or args.scout_dir is None:
        return None
    replays = sorted(args.scout_dir.glob("**/episode-*-replay.json"))
    if args.public_action_scan_replays > 0:
        replays = replays[: args.public_action_scan_replays]
    if not replays:
        return CommandResult(False, 1, ["public-action-gate"], "", f"no replay files under {args.scout_dir}")

    specs = [
        f"{review.label}={rel_for_container(review.path)}"
        for review in reviews
        if review.league_ok or review.family == "anchor"
    ]
    available_labels = {
        review.label
        for review in reviews
        if review.league_ok or review.family == "anchor"
    }
    if args.public_action_gate_label:
        missing_gate_labels = sorted(
            label for label in args.public_action_gate_label if label not in available_labels
        )
        if missing_gate_labels:
            return CommandResult(
                False,
                1,
                ["public-action-gate"],
                "",
                "public-action gate labels missing or not runnable: "
                + ", ".join(missing_gate_labels),
            )
        gate_labels = [
            label
            for label in args.public_action_gate_label
            if label != args.public_action_baseline_label
        ]
    else:
        gate_labels = [review.label for review in reviews if review.family != "anchor" and review.league_ok]
    if not specs:
        return CommandResult(False, 1, ["public-action-gate"], "", "no runnable agents for public-action gate")

    report_path = output_prefix.with_name(output_prefix.name + "_public_action.md")
    csv_path = output_prefix.with_name(output_prefix.name + "_public_action.csv")
    report_arg = str(report_path if args.no_docker else rel_for_container(report_path))
    csv_arg = str(csv_path if args.no_docker else rel_for_container(csv_path))
    command = [
        "python",
        "tools/public_action_mismatch_gate.py",
        "--baseline-label",
        args.public_action_baseline_label,
        "--gate-context",
        args.public_action_context,
        "--context",
        args.public_action_context,
        "--max-replays",
        str(args.public_action_max_replays),
        "--min-compared",
        str(args.public_action_min_compared),
        "--min-same-rate",
        str(args.public_action_min_same_rate),
        "--max-regression",
        str(args.public_action_max_regression),
        "--max-net-regressions",
        str(args.public_action_max_net_regressions),
        "--max-net-weighted-regression",
        str(args.public_action_max_net_weighted_regression),
        "--min-agent-deck-overlap",
        str(args.public_action_min_agent_deck_overlap),
        "--output",
        report_arg,
        "--csv-output",
        csv_arg,
    ]
    for spec in specs:
        command.extend(["--candidate", spec])
    for label in gate_labels:
        command.extend(["--gate-label", label])
    command.extend(rel_for_container(path) for path in replays)

    if args.no_docker:
        return run_command(["uv", "run", *command], timeout=args.public_action_timeout)

    docker_command = [
        "docker",
        "run",
        "-i",
        "--rm",
        "--platform",
        args.docker_platform,
        "-v",
        f"{REPO}:/work",
        "-w",
        "/work",
        args.docker_image,
        *command,
    ]
    return run_command(docker_command, timeout=args.public_action_timeout)


def render_report(
    *,
    args: argparse.Namespace,
    reviews: list[CandidateReview],
    league_result: CommandResult | None,
    league_stability: LeagueStability,
    league_csv: Path,
    gap_result: CommandResult | None,
    gap_report: Path,
    robustness_gap_result: CommandResult | None,
    robustness_gap_report: Path,
    public_action_result: CommandResult | None,
    public_action_report: Path,
    output_prefix: Path,
) -> str:
    contradiction = audit_contradicted(gap_report)
    robustness_contradiction = audit_contradicted(robustness_gap_report)
    low_correlation = audit_low_correlation(gap_report)
    robustness_low_correlation = audit_low_correlation(robustness_gap_report)
    insufficient = audit_insufficient(gap_report)
    robustness_insufficient = audit_insufficient(robustness_gap_report)
    gap_decision = audit_decision(gap_report)
    robustness_gap_decision = audit_decision(robustness_gap_report)
    any_contradiction = contradiction or robustness_contradiction
    any_low_correlation = low_correlation or robustness_low_correlation
    any_insufficient = insufficient or robustness_insufficient
    public_action_gate_failed = public_action_failed(public_action_report)
    public_action_command_failed = (
        public_action_result is not None
        and not public_action_result.ok
        and not public_action_gate_failed
    )
    unstable_league = league_stability.unstable
    robustness_csvs = [
        robustness_companion(path)
        for path in league_stability.repeat_csvs
        if robustness_companion(path).exists()
    ]
    aggregate_robustness = robustness_companion(league_csv)
    if aggregate_robustness.exists() and aggregate_robustness not in robustness_csvs:
        robustness_csvs.insert(0, aggregate_robustness)
    validation_failures = [review for review in reviews if not review.hard_validation_ok]
    candidate_validation_failures = [
        review for review in validation_failures if review.family != "anchor"
    ]
    anchor_validation_failures = [
        review for review in validation_failures if review.family == "anchor"
    ]
    archive_mismatches = [
        review for review in reviews
        if review.archive_consistency is not None and not review.archive_consistency.ok
    ]
    candidate_archive_mismatches = [
        review for review in archive_mismatches if review.family != "anchor"
    ]
    anchor_archive_mismatches = [
        review for review in archive_mismatches if review.family == "anchor"
    ]
    local_best = min(
        (review for review in reviews if review.family != "anchor" and review.league_rank is not None),
        key=lambda review: review.league_rank or 999999,
        default=None,
    )
    league_coverage = analyze_league_coverage(
        league_csv,
        reviews,
        min_reference_opponents=args.min_reference_opponents,
        min_reference_archetypes=args.min_reference_archetypes,
        min_reference_decks=args.min_reference_decks,
    )

    if candidate_validation_failures:
        verdict = "BLOCK"
        reason = "one or more candidates failed static/deck/import/archive validation"
    elif candidate_archive_mismatches:
        verdict = "RESEARCH_ONLY"
        reason = "one or more candidate archives do not match the validated agent directory"
    elif public_action_gate_failed or public_action_command_failed:
        verdict = "RESEARCH_ONLY"
        reason = "candidate policy regresses public-action agreement versus the trusted anchor"
    elif league_result is None or not league_result.ok:
        verdict = "RESEARCH_ONLY"
        reason = "no successful local league was available"
    elif not league_coverage.sufficient:
        verdict = "RESEARCH_ONLY"
        reason = "local league opponent coverage is too narrow for promotion evidence"
    elif any_contradiction:
        verdict = "RESEARCH_ONLY"
        reason = "local league or robustness evidence is contradicted by mature public anchors"
    elif any_low_correlation:
        verdict = "RESEARCH_ONLY"
        reason = "local league or robustness evidence fails mature public-anchor rank correlation"
    elif any_insufficient:
        verdict = "RESEARCH_ONLY"
        reason = "local league or robustness evidence lacks enough mature public anchors"
    elif unstable_league:
        verdict = "RESEARCH_ONLY"
        reason = "repeated local league is unstable across schedules/seeds"
    elif gap_result is None or not gap_report.exists():
        verdict = "RESEARCH_ONLY"
        reason = "public-gap audit was not available"
    else:
        verdict = "PROMOTION_REVIEW"
        reason = "validation passed and no mapped top-local public contradiction was found"

    lines = [
        "# Candidate Critic Harness Report",
        "",
        f"Generated: {now_human()}",
        "",
        "## Verdict",
        "",
        f"- Critic verdict: **{verdict}**",
        f"- Reason: {reason}.",
        "- Submit implication: this tool never submits; a candidate still needs the normal pre-submit gate or explicit user override.",
        "",
        "## Inputs",
        "",
        f"- Scout dir: `{args.scout_dir or '-'}`",
        f"- Submissions: `{args.submissions or '-'}`",
        f"- Output prefix: `{output_prefix}`",
        f"- Docker league: {'no' if args.no_docker else 'yes'}",
        f"- Auto public anchors: {', '.join(getattr(args, 'auto_public_anchor_names', [])) or '-'}",
        f"- League repeats: {args.league_repeats}",
        f"- League selection mode: {args.league_selection_mode}",
        f"- League scan limit: {args.league_scan_limit}",
        f"- Candidate rank-span threshold: {args.rank_span_threshold}",
        f"- Top limit: {args.top_limit}",
        f"- Minimum reference opponents: {args.min_reference_opponents}",
        f"- Minimum reference archetypes: {args.min_reference_archetypes}",
        f"- Minimum reference deck hashes: {args.min_reference_decks}",
        f"- Games per seat: {args.games_per_seat}",
        f"- Max steps: {args.max_steps}",
        f"- Public-action gate: {'yes' if args.run_public_action_gate else 'no'}",
        f"- Public-action baseline: `{args.public_action_baseline_label}`",
        f"- Public-action gate labels: {', '.join(args.public_action_gate_label) if args.public_action_gate_label else 'default runnable non-anchor labels'}",
        f"- Public-action max replays: {args.public_action_max_replays}",
        f"- Public-action minimum agent deck overlap: {args.public_action_min_agent_deck_overlap}",
        "",
        "## Candidate Reviews",
        "",
        "| Candidate | Family | Agent | Archive hint | Validation | League rank | Robust rank | Robust score | Worst lane | Notes |",
        "| --- | --- | --- | --- | --- | ---: | ---: | ---: | --- | --- |",
    ]
    for review in reviews:
        checks = (
            f"py={status_word(review.py_compile)}, "
            f"card={status_word(review.card_audit)}, "
            f"smoke={status_word(review.import_smoke)}, "
            f"archive={status_word(review.archive_sanity)}, "
            f"match={status_word(review.archive_consistency)}"
        )
        notes = "; ".join(review.problems)
        if review.league_rank is None and league_result and league_result.ok:
            notes = "; ".join(filter(None, [notes, "not in league output"]))
        worst_lane = "-"
        if review.robustness_worst_archetype or review.robustness_worst_opponent:
            worst_lane = f"{review.robustness_worst_archetype or '-'} / {review.robustness_worst_opponent or '-'}"
        lines.append(
            f"| `{review.label}` | {review.family} | `{review.path}` | "
            f"`{review.archive_hint or '-'}` | {checks} | "
            f"{review.league_rank or ''} | {review.robustness_rank or ''} | "
            f"{'' if review.robustness_score is None else f'{review.robustness_score:.3f}'} | "
            f"{worst_lane} | {notes or '-'} |"
        )

    lines.extend(
        [
            "",
            "## League And Public-Gap Audit",
            "",
            f"- League command: {command_text(league_result)}",
            f"- League status: {status_word(league_result)}",
            f"- League CSV: `{league_csv if league_csv.exists() else '-'}`",
            f"- League repeat CSVs: {', '.join(f'`{path}`' for path in league_stability.repeat_csvs) or '-'}",
            f"- League robustness CSVs: {', '.join(f'`{path}`' for path in robustness_csvs) or '-'}",
            f"- League repeats successful: {league_stability.successful_repeats}/{league_stability.repeat_count}",
            f"- League reference opponents: {len(league_coverage.opponents)} "
            f"({', '.join(sorted(league_coverage.opponents)) or '-'})",
            f"- League reference archetypes: {len(league_coverage.archetypes)} "
            f"({', '.join(sorted(league_coverage.archetypes)) or '-'})",
            f"- League reference deck hashes: {len(league_coverage.decks)} "
            f"({', '.join(sorted(league_coverage.decks)) or '-'})",
            f"- League coverage sufficient: {league_coverage.sufficient}",
            f"- League coverage reasons: {'; '.join(league_coverage.reasons) or '-'}",
            f"- Candidate winner counts: {league_stability.candidate_winner_counts or {}}",
            f"- Overall winner counts: {league_stability.overall_winner_counts or {}}",
            f"- Robustness winner counts: {league_stability.robustness_winner_counts or {}}",
            f"- League instability: {unstable_league}",
            f"- League instability reasons: {'; '.join(league_stability.reasons) or '-'}",
            f"- Public-gap command: {command_text(gap_result)}",
            f"- Public-gap status: {status_word(gap_result)}",
            f"- Public-gap report: `{gap_report if gap_report.exists() else '-'}`",
            f"- Public-gap decision: {gap_decision}",
            f"- Public-gap contradiction: {contradiction}",
            f"- Public-gap low correlation: {low_correlation}",
            f"- Robustness public-gap command: {command_text(robustness_gap_result)}",
            f"- Robustness public-gap status: {status_word(robustness_gap_result)}",
            f"- Robustness public-gap report: `{robustness_gap_report if robustness_gap_report.exists() else '-'}`",
            f"- Robustness public-gap decision: {robustness_gap_decision}",
            f"- Robustness public-gap contradiction: {robustness_contradiction}",
            f"- Robustness public-gap low correlation: {robustness_low_correlation}",
            f"- Public-action command: {command_text(public_action_result)}",
            f"- Public-action status: {status_word(public_action_result)}",
            f"- Public-action report: `{public_action_report if public_action_report.exists() else '-'}`",
            f"- Public-action gate failed: {public_action_gate_failed}",
            f"- Public-action command failed: {public_action_command_failed}",
            "",
            "## Critic Notes",
            "",
        ]
    )
    if local_best:
        lines.append(
            f"- Local best candidate in this review is `{local_best.label}` "
            f"(rank {local_best.league_rank}), but local rank is not a public-score forecast."
        )
    if any_contradiction:
        lines.append("- The evaluator blocks promotion because public anchors already falsify the local ordering.")
    if any_low_correlation:
        lines.append("- The evaluator blocks promotion because local strength does not rank-correlate with mature public anchors.")
    if any_insufficient:
        lines.append("- The evaluator blocks promotion because the local leaders do not yet have enough mature public-anchor evidence.")
    if unstable_league:
        lines.append("- The evaluator blocks promotion because the local winner is not stable across repeated league schedules.")
    if public_action_gate_failed:
        lines.append("- The evaluator blocks promotion because a candidate regresses public replay action agreement versus the trusted anchor.")
    if public_action_command_failed and not public_action_gate_failed:
        lines.append("- The evaluator blocks promotion because the public-action gate command failed before producing a trusted pass.")
    if not league_coverage.sufficient:
        lines.append(
            "- The evaluator blocks promotion because the local league does not cover enough distinct "
            "public opponents, archetypes, or deck hashes."
        )
    if candidate_validation_failures:
        failed = ", ".join(f"`{review.label}`" for review in candidate_validation_failures)
        lines.append(f"- Validation failures must be fixed before those candidates enter a submit league: {failed}.")
    if anchor_validation_failures:
        failed = ", ".join(f"`{review.label}`" for review in anchor_validation_failures)
        lines.append(
            f"- Historical/reference anchor validation failures are reported but do not by themselves "
            f"block candidate review: {failed}."
        )
    lines.append("- Next improvement should target replay fidelity/public-anchor correlation before policy tuning.")
    static_validation_failures: list[tuple[str, str, CommandResult]] = []
    for review in reviews:
        for check_name, result in (
            ("py_compile", review.py_compile),
            ("card_audit", review.card_audit),
            ("import_smoke", review.import_smoke),
        ):
            if result is not None and not result.ok:
                static_validation_failures.append((review.label, check_name, result))
    if static_validation_failures:
        lines.extend(["", "### Static Validation Failures", ""])
        for label, check_name, result in static_validation_failures:
            detail = result.stderr_tail or result.stdout_tail or "(no output)"
            lines.append(f"- `{label}` {check_name}: {detail}")
    archive_failures = [
        review for review in reviews
        if review.archive_sanity is not None and not review.archive_sanity.ok
    ]
    if archive_failures:
        lines.extend(["", "### Archive Sanity Failures", ""])
        for review in archive_failures:
            detail = review.archive_sanity.stderr_tail or review.archive_sanity.stdout_tail or "(no output)"
            lines.append(f"- `{review.label}`: {detail}")
    if archive_mismatches:
        lines.extend(["", "### Archive Consistency Mismatches", ""])
        for review in archive_mismatches:
            detail = review.archive_consistency.stderr_tail or review.archive_consistency.stdout_tail or "(no output)"
            lines.append(
                f"- `{review.label}` archive `{review.archive_hint or '-'}` does not match "
                f"`{review.path}`: {detail}"
            )
        if anchor_archive_mismatches:
            labels = ", ".join(f"`{review.label}`" for review in anchor_archive_mismatches)
            lines.append(
                f"- Anchor archive mismatches are provenance warnings unless that anchor is an intended submit candidate: {labels}."
            )

    lines.extend(
        [
            "",
            "## Command Tails",
            "",
        ]
    )
    for title, result in (
        ("league", league_result),
        ("public_gap", gap_result),
        ("robustness_public_gap", robustness_gap_result),
        ("public_action", public_action_result),
    ):
        if result is None:
            continue
        lines.extend(
            [
                f"### {title}",
                "",
                "```text",
                result.stdout_tail or result.stderr_tail or "(no output)",
                "```",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def write_review_csv(path: Path, reviews: list[CandidateReview]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "label",
                "family",
                "version",
                "agent",
                "archive_hint",
                "validation_ok",
                "py_compile",
                "card_audit",
                "import_smoke",
                "archive_sanity",
                "archive_consistency",
                "league_rank",
                "league_points",
                "league_game_diff",
                "league_mean_rank",
                "league_rank_span",
                "league_candidate_best_count",
                "league_record",
                "robustness_rank",
                "robustness_score",
                "robustness_top_win_pct",
                "robustness_maximin",
                "robustness_max_regret",
                "robustness_rank_span",
                "robustness_best_count",
                "robustness_worst_archetype",
                "robustness_worst_opponent",
                "problems",
            ]
        )
        for review in reviews:
            writer.writerow(
                [
                    review.label,
                    review.family,
                    review.version or "",
                    review.path,
                    review.archive_hint,
                    int(review.validation_ok),
                    status_word(review.py_compile),
                    status_word(review.card_audit),
                    status_word(review.import_smoke),
                    status_word(review.archive_sanity),
                    status_word(review.archive_consistency),
                    review.league_rank or "",
                    review.league_points or "",
                    review.league_game_diff or "",
                    review.league_mean_rank or "",
                    review.league_rank_span or "",
                    review.league_candidate_best_count,
                    review.league_record,
                    review.robustness_rank or "",
                    review.robustness_score or "",
                    review.robustness_top_win_pct or "",
                    review.robustness_maximin or "",
                    review.robustness_max_regret or "",
                    review.robustness_rank_span or "",
                    review.robustness_best_count,
                    review.robustness_worst_archetype,
                    review.robustness_worst_opponent,
                    "; ".join(review.problems),
                ]
            )


def parse_explicit_labels(candidate_specs: list[str]) -> dict[Path, str]:
    labels: dict[Path, str] = {}
    for spec in candidate_specs:
        if "=" not in spec:
            continue
        label, path_text = spec.split("=", 1)
        path = (REPO / path_text).resolve() if not Path(path_text).is_absolute() else Path(path_text).resolve()
        labels[path] = safe_label(label)
    return labels


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", action="append", default=[], help="Optional LABEL=AGENT_DIR or AGENT_DIR; omitted means discover latest candidates.")
    parser.add_argument("--anchor", action="append", default=["agents/v100_psychic_control_final", "submission-psychic-control-v75.tar.gz"])
    parser.add_argument("--max-codex", type=int, default=3)
    parser.add_argument("--max-claude", type=int, default=1)
    parser.add_argument("--max-grok", type=int, default=1)
    parser.add_argument("--auto-public-anchors", type=int, default=4,
                        help="Automatically add this many mature submitted archive anchors when discovering default candidates.")
    parser.add_argument("--scout-dir", type=Path, default=None)
    parser.add_argument("--submissions", type=Path, default=None)
    parser.add_argument("--output-prefix", type=Path, default=None)
    parser.add_argument("--run-league", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--include-invalid-in-league", action="store_true")
    parser.add_argument("--league-repeats", type=int, default=1,
                        help="Run the local league this many times and aggregate; >1 enables instability blocking.")
    parser.add_argument("--rank-span-threshold", type=float, default=3.0,
                        help="Candidate rank span across repeated leagues that marks local evidence unstable.")
    parser.add_argument("--top-limit", type=int, default=8)
    parser.add_argument("--league-selection-mode", choices=("rank", "diverse"), default="diverse",
                        help="Opponent selection mode passed to local_top_league.py.")
    parser.add_argument("--league-scan-limit", type=int, default=20,
                        help="Highest public rank to scan when diverse league selection is enabled.")
    parser.add_argument("--min-reference-opponents", type=int, default=4,
                        help="Minimum distinct non-candidate public opponents required for promotion evidence.")
    parser.add_argument("--min-reference-archetypes", type=int, default=3,
                        help="Minimum distinct non-candidate archetypes required for promotion evidence.")
    parser.add_argument("--min-reference-decks", type=int, default=3,
                        help="Minimum distinct non-candidate deck hashes required for promotion evidence.")
    parser.add_argument("--games-per-seat", type=int, default=1)
    parser.add_argument("--max-steps", type=int, default=1200)
    parser.add_argument("--league-timeout", type=int, default=1800)
    parser.add_argument("--no-docker", action="store_true")
    parser.add_argument("--docker-image", default="python:3.11-slim")
    parser.add_argument("--docker-platform", default="linux/amd64")
    parser.add_argument("--top-local-rank", type=int, default=8)
    parser.add_argument("--min-public-score", type=float, default=1000.0)
    parser.add_argument("--min-public-spearman", type=float, default=0.55)
    parser.add_argument("--maturity-minutes", type=int, default=60)
    parser.add_argument("--run-public-action-gate", action=argparse.BooleanOptionalAction, default=False,
                        help="Compare candidates with public replay actions and block promotion on regressions.")
    parser.add_argument("--public-action-baseline-label", default="v100_anchor",
                        help="Trusted review label used as the public-action agreement baseline.")
    parser.add_argument("--public-action-gate-label", action="append", default=[],
                        help="Specific label to enforce with the public-action gate; repeatable. Defaults to all runnable non-anchor labels.")
    parser.add_argument("--public-action-context", default="MAIN")
    parser.add_argument("--public-action-scan-replays", type=int, default=80,
                        help="Replay files passed to the public-action gate before its own max-replays cap.")
    parser.add_argument("--public-action-max-replays", type=int, default=40)
    parser.add_argument("--public-action-min-compared", type=int, default=100)
    parser.add_argument("--public-action-min-same-rate", type=float, default=0.0)
    parser.add_argument("--public-action-max-regression", type=float, default=0.03)
    parser.add_argument("--public-action-max-net-regressions", type=int, default=0)
    parser.add_argument("--public-action-max-net-weighted-regression", type=float, default=0.0)
    parser.add_argument("--public-action-min-agent-deck-overlap", type=int, default=0,
                        help="Skip public-action states with fewer revealed controlled-player card IDs overlapping the candidate deck.")
    parser.add_argument("--public-action-timeout", type=int, default=900)
    parser.add_argument("--now", default=lambda: datetime.now(UTC).isoformat())
    parser.add_argument("--fail-on-block", action="store_true")
    args = parser.parse_args()

    if callable(args.now):
        args.now = args.now()
    args.league_repeats = max(1, args.league_repeats)
    if args.scout_dir is None:
        args.scout_dir = latest_scout()
    if args.submissions is None:
        args.submissions = latest_file_any(
            [
                "strategy/kaggle_submissions_latest.csv",
                "strategy/kaggle_submissions_*.csv",
                "strategy/kaggle_submissions_latest_*.txt",
            ]
        )
    output_prefix = args.output_prefix or (REPO / "strategy" / f"candidate_critic_{now_stamp()}")
    output_prefix = output_prefix if output_prefix.is_absolute() else REPO / output_prefix

    explicit_labels = parse_explicit_labels(args.candidate)
    discovered_paths = discover_candidates(args)
    auto_public_anchor_paths: list[Path] = []
    if not args.candidate:
        auto_public_anchor_paths = discover_public_anchor_archives(args, discovered_paths, explicit_labels)
        discovered_paths.extend(auto_public_anchor_paths)
    args.auto_public_anchor_names = [path.name for path in auto_public_anchor_paths]
    candidates, explicit_labels, archive_hints, family_overrides = materialize_candidate_paths(
        discovered_paths,
        output_prefix,
        explicit_labels,
    )
    reviews = [
        validate_candidate(
            path,
            args,
            explicit_labels.get(path.resolve()),
            archive_hints.get(path.resolve()),
            family_overrides.get(path.resolve()),
        )
        for path in candidates
    ]

    league_prefix = output_prefix.with_name(output_prefix.name + "_league")
    league_csv = league_prefix.with_suffix(".csv")
    robustness_csv = robustness_companion(league_csv)
    gap_report = output_prefix.with_name(output_prefix.name + "_public_gap.md")
    robustness_gap_report = output_prefix.with_name(output_prefix.name + "_robustness_public_gap.md")
    public_action_report = output_prefix.with_name(output_prefix.name + "_public_action.md")

    league_result = None
    league_stability = LeagueStability()
    if args.run_league:
        league_result, league_stability = run_league(args, reviews, league_prefix)
        attach_league_rows(reviews, league_csv)
        attach_robustness_rows(reviews, robustness_csv)

    gap_result = None
    if args.run_league and league_csv.exists():
        gap_result = run_public_gap_audit(args, reviews, league_csv, gap_report)
    robustness_gap_result = None
    if args.run_league and robustness_csv.exists():
        robustness_gap_result = run_public_gap_audit(args, reviews, robustness_csv, robustness_gap_report)
    public_action_result = run_public_action_gate(args, reviews, output_prefix)

    report = render_report(
        args=args,
        reviews=reviews,
        league_result=league_result,
        league_stability=league_stability,
        league_csv=league_csv,
        gap_result=gap_result,
        gap_report=gap_report,
        robustness_gap_result=robustness_gap_result,
        robustness_gap_report=robustness_gap_report,
        public_action_result=public_action_result,
        public_action_report=public_action_report,
        output_prefix=output_prefix,
    )
    report_path = output_prefix.with_suffix(".md")
    csv_path = output_prefix.with_suffix(".csv")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report, encoding="utf-8")
    write_review_csv(csv_path, reviews)
    print(report)
    print(f"wrote {report_path}")
    print(f"wrote {csv_path}")

    blocked = "**BLOCK**" in report or "**RESEARCH_ONLY**" in report
    return 2 if blocked and args.fail_on_block else 0


if __name__ == "__main__":
    raise SystemExit(main())
