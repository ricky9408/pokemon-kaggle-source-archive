#!/usr/bin/env python3
"""Durable outcome ledger for the self-improving submission loop.

This is the loop's MEMORY. It replaces the scattered markdown/CSV history with a
single append-only SQLite database that every stage of the heartbeat loop reads
and writes. It is intentionally dependency-light (stdlib only) so it can run on
the Mac host without importing the simulator (`libcg`).

Schema
------
candidates   one row per agent/deck we might submit.
submissions  one row per Kaggle submission (ref). Stores the LOCAL feature/metric
             vector SNAPSHOTTED at submit time, so (local_features -> realized
             public score) labels accumulate cleanly for the predictive-validity
             gate. state in {SUBMITTED, WATCHING, FINALIZED}.
score_ticks  one row per observed public-score reading. The full trajectory, not
             a point estimate -- public scores are extremely noisy (the same
             byte-identical artifact has scored 649/890/939), so a single read is
             never a label.
outcomes     one row per FINALIZED submission: median + spread of its ticks and a
             stability verdict. A submission can only finalize after it has been
             watched >= min-watch-seconds AND has >= min-ticks readings.

The deliberate separation of concerns:
  * the ledger decides whether a measurement is STABLE (drift vs measured);
  * `derive_priors.py` decides whether a stable measurement is GOOD/BAD relative
    to the field (win/loss/neutral, with shrinkage).

CLI examples
------------
  uv run python tools/outcome_ledger.py init
  uv run python tools/outcome_ledger.py ingest-submissions \
      --submissions strategy/kaggle_submissions_latest_20260620T1644.csv --tick-ts auto
  uv run python tools/outcome_ledger.py finalize --min-watch-seconds 3600 --min-ticks 2
  uv run python tools/outcome_ledger.py list --table submissions
"""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
import statistics
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

DEFAULT_DB = Path("outcomes/ledger.sqlite")

# --------------------------------------------------------------------------- #
# Archive -> family mapping (kept aligned with pair_strategy_selector families)
# --------------------------------------------------------------------------- #
FAMILY_KEYWORDS: list[tuple[str, str]] = [
    ("codex-active-attach", "codex_active_attach"),
    ("claude-grimm", "grimmsnarl"),
    ("codex-grimm", "grimmsnarl"),
    ("codex-grimmsnarl", "grimmsnarl"),
    ("grimmsnarl-froslass", "grimmsnarl_froslass"),
    ("grimm", "grimmsnarl"),
    ("grimmsnarl", "grimmsnarl"),
    ("claude-kanga", "mega_kangaskhan"),
    ("codex-kanga", "mega_kangaskhan"),
    ("mega-kangaskhan", "mega_kangaskhan"),
    ("kanga", "mega_kangaskhan"),
    ("codex-arch-pokegear", "archaludon_cinderace"),
    ("codex-arch-layer", "archaludon_cinderace"),
    ("codex-arch-cinderace", "archaludon_cinderace"),
    ("codex-arch-lucario", "archaludon_cinderace"),
    ("codex-arch-setup-evolve", "archaludon_cinderace"),
    ("codex-arch-", "archaludon_cinderace"),
    ("codex-archaludon", "archaludon_cinderace"),
    ("codex-psychic-search", "alakazam_control"),
    ("claude-v155", "alakazam_hammer"),
    ("claude-zam", "alakazam_hammer"),
    ("codex-setup-evolve", "codex_setup_guard"),
    ("codex-setup-aware", "codex_setup_guard"),
    ("codex-strict-dudun", "codex_setup_guard"),
    ("codex-endgame-deck", "codex_setup_guard"),
    ("codex-solo-runaway", "codex_setup_guard"),
    ("codex-setup-tension", "codex_setup_tension"),
    ("codex-v107-safety", "codex_setup_guard"),
    ("codex-dudunsparce-safety", "codex_setup_guard"),
    ("codex-setup-guard", "codex_setup_guard"),
    ("grok-psychic-tempo", "grok_psychic_tempo"),
    ("codex-psychic-ml", "alakazam_control"),
    ("psychic-control", "alakazam_control"),
    ("plain-alakazam", "alakazam_plain"),
    ("codex-nightmine", "alakazam_nighttime_mine"),
    ("nighttime-hammer", "alakazam_nighttime_hammer"),
    ("nighttime", "alakazam_nighttime_hammer"),
    ("hammer-setup-restraint", "alakazam_hammer"),
    ("hammer-mid", "alakazam_hammer"),
    ("hammer", "alakazam_hammer"),
    ("alakazam-denpa", "alakazam_plain"),
    ("alakazam", "alakazam_hammer"),
    ("ethan", "ethan_crustle"),
    ("strayuru", "hammer_crustle"),
    ("crustle", "pure_crustle"),
    ("festival", "festival"),
    ("mega-lucario", "mega_lucario"),
    ("lucario", "mega_lucario"),
    ("trevenant", "hops_trevenant"),
    ("dragapult", "dragapult"),
]


def family_from_archive(archive: str) -> str:
    lowered = (archive or "").lower()
    for needle, family in FAMILY_KEYWORDS:
        if needle in lowered:
            return family
    return "unknown"


def alias_from_archive(archive: str) -> str:
    """Best-effort short alias, matching the vNN convention used elsewhere."""
    import re

    lowered = (archive or "").lower()
    matches = re.findall(r"(?<![a-z0-9])v(\d+)(?![a-z0-9])", lowered)
    if matches:
        return f"v{matches[-1]}"
    stripped = lowered.removeprefix("submission-").removesuffix(".tar.gz").replace("_", "-")
    return stripped or "unknown"


# --------------------------------------------------------------------------- #
# Time helpers
# --------------------------------------------------------------------------- #
def parse_ts(value: str) -> datetime:
    text = (value or "").strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat()


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #
SCHEMA = """
CREATE TABLE IF NOT EXISTS candidates (
    id                   TEXT PRIMARY KEY,
    family               TEXT NOT NULL,
    agent_path           TEXT,
    deck_hash            TEXT,
    created_ts           TEXT NOT NULL,
    source_regret_target TEXT,
    notes                TEXT
);
CREATE TABLE IF NOT EXISTS submissions (
    ref                   TEXT PRIMARY KEY,
    candidate_id          TEXT,
    kaggle_filename       TEXT NOT NULL,
    family                TEXT NOT NULL,
    alias                 TEXT,
    submit_ts             TEXT NOT NULL,
    description           TEXT,
    predicted_local_metric REAL,
    frozen_feature_vector TEXT,     -- JSON snapshot of local metrics at submit time
    state                 TEXT NOT NULL DEFAULT 'SUBMITTED',
    FOREIGN KEY (candidate_id) REFERENCES candidates(id)
);
CREATE TABLE IF NOT EXISTS score_ticks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ref          TEXT NOT NULL,
    tick_ts      TEXT NOT NULL,
    public_score REAL NOT NULL,
    UNIQUE (ref, tick_ts, public_score),
    FOREIGN KEY (ref) REFERENCES submissions(ref)
);
CREATE TABLE IF NOT EXISTS outcomes (
    ref                    TEXT PRIMARY KEY,
    finalized_ts           TEXT NOT NULL,
    n_ticks                INTEGER NOT NULL,
    watched_seconds        REAL NOT NULL,
    realized_public_median REAL NOT NULL,
    observed_score_std     REAL NOT NULL,
    observed_score_spread  REAL NOT NULL,
    public_delta           REAL,
    verdict                TEXT NOT NULL,   -- measured | drift
    FOREIGN KEY (ref) REFERENCES submissions(ref)
);
CREATE INDEX IF NOT EXISTS idx_ticks_ref ON score_ticks(ref);
CREATE INDEX IF NOT EXISTS idx_sub_family ON submissions(family);
"""


@dataclass
class Submission:
    ref: str
    kaggle_filename: str
    family: str
    submit_ts: datetime
    state: str


class Ledger:
    def __init__(self, path: Path = DEFAULT_DB):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # -- writes ----------------------------------------------------------- #
    def upsert_candidate(
        self,
        cid: str,
        family: str,
        agent_path: str | None = None,
        deck_hash: str | None = None,
        source_regret_target: str | None = None,
        notes: str | None = None,
    ) -> None:
        self.conn.execute(
            """INSERT INTO candidates (id, family, agent_path, deck_hash, created_ts,
                                       source_regret_target, notes)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                   family=excluded.family,
                   agent_path=COALESCE(excluded.agent_path, candidates.agent_path),
                   deck_hash=COALESCE(excluded.deck_hash, candidates.deck_hash),
                   source_regret_target=COALESCE(excluded.source_regret_target, candidates.source_regret_target),
                   notes=COALESCE(excluded.notes, candidates.notes)""",
            (cid, family, agent_path, deck_hash, iso(now_utc()), source_regret_target, notes),
        )
        self.conn.commit()

    def record_submission(
        self,
        ref: str,
        kaggle_filename: str,
        submit_ts: datetime,
        candidate_id: str | None = None,
        family: str | None = None,
        alias: str | None = None,
        description: str | None = None,
        predicted_local_metric: float | None = None,
        frozen_feature_vector: dict | None = None,
        state: str = "SUBMITTED",
    ) -> None:
        fam = family or family_from_archive(kaggle_filename)
        al = alias or alias_from_archive(kaggle_filename)
        fv = json.dumps(frozen_feature_vector, sort_keys=True) if frozen_feature_vector else None
        self.conn.execute(
            """INSERT INTO submissions (ref, candidate_id, kaggle_filename, family, alias,
                                        submit_ts, description, predicted_local_metric,
                                        frozen_feature_vector, state)
               VALUES (?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(ref) DO UPDATE SET
                   kaggle_filename=excluded.kaggle_filename,
                   family=excluded.family,
                   alias=excluded.alias,
                   description=COALESCE(excluded.description, submissions.description),
                   predicted_local_metric=COALESCE(excluded.predicted_local_metric, submissions.predicted_local_metric),
                   frozen_feature_vector=COALESCE(excluded.frozen_feature_vector, submissions.frozen_feature_vector)
               """,
            (ref, candidate_id, kaggle_filename, fam, al, iso(submit_ts), description,
             predicted_local_metric, fv, state),
        )
        # never downgrade a FINALIZED/WATCHING state on re-ingest
        self.conn.commit()

    def add_tick(self, ref: str, tick_ts: datetime, public_score: float) -> bool:
        try:
            self.conn.execute(
                "INSERT INTO score_ticks (ref, tick_ts, public_score) VALUES (?,?,?)",
                (ref, iso(tick_ts), float(public_score)),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # duplicate tick, ignore

    def set_state(self, ref: str, state: str) -> None:
        self.conn.execute("UPDATE submissions SET state=? WHERE ref=?", (state, ref))
        self.conn.commit()

    # -- reads ------------------------------------------------------------ #
    def submission(self, ref: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM submissions WHERE ref=?", (ref,)).fetchone()

    def ticks(self, ref: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT tick_ts, public_score FROM score_ticks WHERE ref=? ORDER BY tick_ts", (ref,)
        ).fetchall()

    def open_submissions(self, *, include_finalized: bool = False) -> list[sqlite3.Row]:
        if include_finalized:
            return self.conn.execute(
                "SELECT * FROM submissions ORDER BY submit_ts"
            ).fetchall()
        return self.conn.execute(
            "SELECT * FROM submissions WHERE state != 'FINALIZED' ORDER BY submit_ts"
        ).fetchall()

    def finalized_outcomes(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            """SELECT o.*, s.kaggle_filename, s.family, s.alias, s.submit_ts, s.predicted_local_metric
               FROM outcomes o JOIN submissions s ON o.ref = s.ref
               ORDER BY o.finalized_ts""",
        ).fetchall()

    def submissions_on_utc_date(self, date_str: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM submissions WHERE substr(submit_ts,1,10)=?", (date_str,)
        ).fetchall()

    # -- finalize logic --------------------------------------------------- #
    def try_finalize(
        self,
        ref: str,
        now: datetime,
        min_watch_seconds: float,
        min_ticks: int,
        drift_margin: float,
        refresh_finalized: bool = False,
    ) -> dict | None:
        """Finalize a submission iff it has been watched long enough and has
        enough readings. Returns the outcome dict if finalized, else None."""
        sub = self.submission(ref)
        if sub is None:
            return None
        already_finalized = sub["state"] == "FINALIZED"
        if already_finalized and not refresh_finalized:
            return None
        ticks = self.ticks(ref)
        submit_ts = parse_ts(sub["submit_ts"])
        maturity_cutoff = submit_ts.timestamp() + min_watch_seconds
        mature_ticks = [
            t for t in ticks
            if parse_ts(t["tick_ts"]).timestamp() >= maturity_cutoff
        ]
        scores = [t["public_score"] for t in mature_ticks]
        if len(scores) < min_ticks:
            self.set_state(ref, "WATCHING")
            return None
        last_tick = parse_ts(mature_ticks[-1]["tick_ts"])
        watched = (last_tick - submit_ts).total_seconds()
        if watched < min_watch_seconds:
            self.set_state(ref, "WATCHING")
            return None

        median = statistics.median(scores)
        std = statistics.pstdev(scores) if len(scores) > 1 else 0.0
        spread = max(scores) - min(scores)

        # Convergence guard (measured failure: ref 54268328 was finalized
        # 'measured' at 845.4 while mid-climb to 909, then slid to ~817 — and
        # even its t=150 "settled band" of ~897 was not converged).
        # A rating counts as CONVERGED only when its recent TAIL is flat:
        #   * tail = mature ticks within the trailing CONV_TAIL_S window,
        #   * the tail itself must span >= CONV_TAIL_MIN_SPAN_S and hold
        #     >= 4 readings (a short/sparse tail proves nothing),
        #   * the tail's max-min must fit inside drift_margin/2.
        # When converged, the LABEL is the TAIL median — the converged rating —
        # not the whole-history median polluted by the entry ramp.
        # A submission that never converges still gets a terminal 'drift'
        # verdict once it has been watched >= DRIFT_GIVEUP_S (label excluded
        # from gate metrics, but the record is preserved).
        CONV_TAIL_S = 10800.0          # look at the last 3h of readings
        CONV_TAIL_MIN_SPAN_S = 5400.0  # tail must itself cover >= 1.5h
        DRIFT_GIVEUP_S = 172800.0      # 48h without convergence -> drift label
        last_ts = parse_ts(mature_ticks[-1]["tick_ts"])
        tail = [
            t for t in mature_ticks
            if (last_ts - parse_ts(t["tick_ts"])).total_seconds() <= CONV_TAIL_S
        ]
        tail_scores = [t["public_score"] for t in tail]
        tail_span = (
            (last_ts - parse_ts(tail[0]["tick_ts"])).total_seconds() if tail else 0.0
        )
        half = len(tail_scores) // 2
        halves_flat = (
            half >= 2
            and abs(
                statistics.median(tail_scores[:half])
                - statistics.median(tail_scores[half:])
            ) <= drift_margin / 4.0
        )
        converged = (
            len(tail_scores) >= 4
            and tail_span >= CONV_TAIL_MIN_SPAN_S
            and (max(tail_scores) - min(tail_scores)) <= drift_margin / 2.0
            and halves_flat
        )
        watched_total = (last_ts - submit_ts).total_seconds()
        if converged:
            # the converged tail is the honest measurement
            median = statistics.median(tail_scores)
            std = statistics.pstdev(tail_scores) if len(tail_scores) > 1 else 0.0
            spread = max(tail_scores) - min(tail_scores)
            scores = tail_scores
        elif watched_total < DRIFT_GIVEUP_S:
            # Still moving: record/refresh a PROVISIONAL drift outcome so
            # downstream label loaders (which skip verdict='drift') never use
            # it, and keep the submission WATCHING (incl. reopening a
            # previously FINALIZED row when new ticks contradict it).
            self.conn.execute(
                """INSERT INTO outcomes (ref, finalized_ts, n_ticks, watched_seconds,
                                         realized_public_median, observed_score_std,
                                         observed_score_spread, public_delta, verdict)
                   VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(ref) DO UPDATE SET
                       finalized_ts=excluded.finalized_ts,
                       n_ticks=excluded.n_ticks,
                       watched_seconds=excluded.watched_seconds,
                       realized_public_median=excluded.realized_public_median,
                       observed_score_std=excluded.observed_score_std,
                       observed_score_spread=excluded.observed_score_spread,
                       verdict=excluded.verdict""",
                (ref, iso(now), len(scores),
                 (parse_ts(mature_ticks[-1]["tick_ts"]) - submit_ts).total_seconds(),
                 median, std, spread, None, "drift"),
            )
            self.set_state(ref, "WATCHING")
            self.conn.commit()
            return None

        # A measurement whose spread exceeds the drift margin is too noisy to
        # call a win or a loss -- record it but mark it as drift.
        verdict = "drift" if spread > drift_margin else "measured"

        existing = self.conn.execute(
            "SELECT * FROM outcomes WHERE ref=?", (ref,)
        ).fetchone()
        if existing is not None:
            unchanged = (
                int(existing["n_ticks"]) == len(scores)
                and abs(float(existing["realized_public_median"]) - median) < 1e-9
                and abs(float(existing["observed_score_std"]) - std) < 1e-9
                and abs(float(existing["observed_score_spread"]) - spread) < 1e-9
                and existing["verdict"] == verdict
            )
            if unchanged:
                return None

        self.conn.execute(
            """INSERT INTO outcomes (ref, finalized_ts, n_ticks, watched_seconds,
                                     realized_public_median, observed_score_std,
                                     observed_score_spread, public_delta, verdict)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(ref) DO UPDATE SET
                   finalized_ts=excluded.finalized_ts,
                   n_ticks=excluded.n_ticks,
                   watched_seconds=excluded.watched_seconds,
                   realized_public_median=excluded.realized_public_median,
                   observed_score_std=excluded.observed_score_std,
                   observed_score_spread=excluded.observed_score_spread,
                   verdict=excluded.verdict""",
            (ref, iso(now), len(scores), watched, median, std, spread, None, verdict),
        )
        self.set_state(ref, "FINALIZED")
        self.conn.commit()
        return {
            "ref": ref,
            "family": sub["family"],
            "median": median,
            "std": std,
            "spread": spread,
            "verdict": verdict,
            "n_ticks": len(scores),
            "watched_seconds": watched,
            "refreshed": already_finalized,
        }

    def close(self) -> None:
        self.conn.close()


def now_utc() -> datetime:
    # The harness forbids argless datetime.now in workflow scripts, but this is a
    # normal CLI tool; wall-clock time is required for watch-duration accounting.
    return datetime.now(UTC)


# --------------------------------------------------------------------------- #
# Submissions CSV ingest (kaggle competitions submissions --csv)
# --------------------------------------------------------------------------- #
def ingest_submissions_csv(ledger: Ledger, path: Path, tick_ts: datetime) -> dict:
    """Import a kaggle submissions CSV. Each row records/updates a submission and
    appends one score tick (the score observed at this pull time)."""
    added_subs = 0
    added_ticks = 0
    with path.open(encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            ref = (row.get("ref") or "").strip()
            fname = (row.get("fileName") or "").strip()
            if not ref or not fname:
                continue
            status = (row.get("status") or "").strip()
            score_raw = (row.get("publicScore") or "").strip()
            try:
                submit_ts = parse_ts(row.get("date", ""))
            except ValueError:
                continue
            existing = ledger.submission(ref)
            ledger.record_submission(
                ref=ref,
                kaggle_filename=fname,
                submit_ts=submit_ts,
                description=(row.get("description") or "").strip() or None,
                state="SUBMITTED",
            )
            if existing is None:
                added_subs += 1
            # only complete submissions carry a meaningful public score
            if score_raw and "COMPLETE" in status.upper():
                try:
                    score = float(score_raw)
                except ValueError:
                    continue
                if ledger.add_tick(ref, tick_ts, score):
                    added_ticks += 1
    return {"submissions_added": added_subs, "ticks_added": added_ticks}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def cmd_init(args: argparse.Namespace) -> int:
    Ledger(args.db)
    print(f"Initialized ledger at {args.db}")
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    ledger = Ledger(args.db)
    tick_ts = now_utc() if args.tick_ts == "auto" else parse_ts(args.tick_ts)
    stats = ingest_submissions_csv(ledger, Path(args.submissions), tick_ts)
    print(f"Ingested {args.submissions}: +{stats['submissions_added']} submissions, "
          f"+{stats['ticks_added']} ticks at {iso(tick_ts)}")
    ledger.close()
    return 0


def cmd_finalize(args: argparse.Namespace) -> int:
    ledger = Ledger(args.db)
    now = now_utc() if args.now == "auto" else parse_ts(args.now)
    finalized = []
    for sub in ledger.open_submissions(include_finalized=args.refresh_finalized):
        result = ledger.try_finalize(
            sub["ref"],
            now,
            args.min_watch_seconds,
            args.min_ticks,
            args.drift_margin,
            refresh_finalized=args.refresh_finalized,
        )
        if result:
            finalized.append(result)
    if not finalized:
        print("No submissions ready to finalize "
              f"(need >= {args.min_watch_seconds:.0f}s watch and >= {args.min_ticks} ticks).")
    for f in finalized:
        verb = "REFRESHED" if f.get("refreshed") else "FINALIZED"
        print(f"{verb} {f['ref']} [{f['family']}] median={f['median']:.1f} "
              f"spread={f['spread']:.1f} verdict={f['verdict']} "
              f"(n={f['n_ticks']}, watched={f['watched_seconds']/3600:.1f}h)")
    ledger.close()
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    ledger = Ledger(args.db)
    if args.table == "submissions":
        rows = ledger.conn.execute(
            "SELECT ref, alias, family, submit_ts, state FROM submissions ORDER BY submit_ts"
        ).fetchall()
        for r in rows:
            n = ledger.conn.execute(
                "SELECT COUNT(*) c FROM score_ticks WHERE ref=?", (r["ref"],)
            ).fetchone()["c"]
            print(f"{r['ref']:>10}  {r['alias']:<10} {r['family']:<26} "
                  f"{r['submit_ts'][:19]}  {r['state']:<10} ticks={n}")
    elif args.table == "outcomes":
        for r in ledger.finalized_outcomes():
            print(f"{r['ref']:>10}  {r['alias']:<10} {r['family']:<26} "
                  f"median={r['realized_public_median']:.1f} "
                  f"spread={r['observed_score_spread']:.1f} verdict={r['verdict']}")
    elif args.table == "candidates":
        for r in ledger.conn.execute("SELECT * FROM candidates ORDER BY created_ts").fetchall():
            print(f"{r['id']:<28} {r['family']:<26} {r['agent_path'] or '-'}")
    ledger.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Outcome ledger for the self-improving loop")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create the database/schema")

    p_ing = sub.add_parser("ingest-submissions", help="import a kaggle submissions CSV as ticks")
    p_ing.add_argument("--submissions", required=True)
    p_ing.add_argument("--tick-ts", default="auto", help="'auto' (now) or ISO timestamp")

    p_fin = sub.add_parser("finalize", help="finalize submissions watched long enough")
    p_fin.add_argument("--now", default="auto")
    p_fin.add_argument("--min-watch-seconds", type=float, default=3600.0)
    p_fin.add_argument("--min-ticks", type=int, default=4)
    p_fin.add_argument("--drift-margin", type=float, default=100.0,
                       help="spread above which a measurement is 'drift' (inconclusive)")
    p_fin.add_argument("--refresh-finalized", action="store_true",
                       help="recompute finalized outcomes when later mature ticks changed")

    p_list = sub.add_parser("list", help="list ledger contents")
    p_list.add_argument("--table", choices=["submissions", "outcomes", "candidates"],
                        default="submissions")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "init":
        return cmd_init(args)
    if args.command == "ingest-submissions":
        return cmd_ingest(args)
    if args.command == "finalize":
        return cmd_finalize(args)
    if args.command == "list":
        return cmd_list(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
