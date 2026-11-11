#!/usr/bin/env python3
"""Download the complete Kaggle leaderboard through the paginated API."""

from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import csv
from datetime import datetime, timezone
import io
import os
from pathlib import Path
import re
import tempfile
import time
from typing import Any

from kaggle.api.kaggle_api_extended import KaggleApi


_TOKEN_RE = re.compile(r"^Next Page Token = (\S+)$", re.MULTILINE)
_FIELDS = ("teamId", "teamName", "submissionDate", "score")
_OUTPUT_FIELDS = ("Rank", "TeamId", "TeamName", "LastSubmissionDate", "Score")


def _page(api: KaggleApi, competition: str, token: str | None) -> tuple[list[dict[str, Any]], str | None]:
    captured = io.StringIO()
    with redirect_stdout(captured):
        values = api.competition_leaderboard_view(competition, 200, token) or []
    matches = _TOKEN_RE.findall(captured.getvalue())
    if len(matches) > 1:
        raise RuntimeError("Kaggle emitted multiple next-page tokens")
    rows = [value.to_dict() for value in values if value is not None]
    return rows, matches[0] if matches else None


def _pull_once(api: KaggleApi, competition: str) -> tuple[list[dict[str, Any]], set[int]]:
    rows: list[dict[str, Any]] = []
    seen_tokens: set[str] = set()
    seen_teams: set[int] = set()
    duplicate_teams: set[int] = set()
    token: str | None = None
    while True:
        page, next_token = _page(api, competition, token)
        if not page:
            if token is None:
                raise RuntimeError("Kaggle returned an empty first leaderboard page")
            break
        for row in page:
            if set(row) != set(_FIELDS):
                raise RuntimeError(f"unexpected leaderboard fields: {sorted(row)}")
            team_id = int(row["teamId"])
            if team_id in seen_teams:
                duplicate_teams.add(team_id)
                continue
            seen_teams.add(team_id)
            rows.append({field: row[field] for field in _FIELDS})
        if next_token is None:
            break
        if next_token in seen_tokens:
            raise RuntimeError("Kaggle repeated a leaderboard page token")
        seen_tokens.add(next_token)
        token = next_token
    return rows, duplicate_teams


def pull_full_leaderboard(
    competition: str,
    *,
    attempts: int = 8,
    api: KaggleApi | None = None,
) -> list[dict[str, Any]]:
    """Return a duplicate-free pass whose team set repeats on the next pass."""

    if attempts <= 0:
        raise ValueError("attempts must be positive")
    if api is None:
        api = KaggleApi()
        api.authenticate()
    failures: list[str] = []
    prior_clean_team_ids: set[int] | None = None
    for attempt in range(1, attempts + 1):
        rows, duplicates = _pull_once(api, competition)
        scores = [float(row["score"]) for row in rows]
        monotone = all(left >= right for left, right in zip(scores, scores[1:]))
        if not duplicates and monotone:
            team_ids = {int(row["teamId"]) for row in rows}
            if prior_clean_team_ids == team_ids:
                return rows
            prior_clean_team_ids = team_ids
            failures.append(
                f"attempt={attempt} clean_but_waiting_for_team_set_confirmation rows={len(rows)}"
            )
            continue
        prior_clean_team_ids = None
        failures.append(
            f"attempt={attempt} duplicates={len(duplicates)} monotone={monotone} rows={len(rows)}"
        )
        time.sleep(0.25)
    raise RuntimeError("could not obtain a stable leaderboard pass: " + "; ".join(failures))


def write_csv_atomic(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=_OUTPUT_FIELDS)
            writer.writeheader()
            writer.writerows(
                {
                    "Rank": rank,
                    "TeamId": row["teamId"],
                    "TeamName": row["teamName"],
                    "LastSubmissionDate": row["submissionDate"],
                    "Score": row["score"],
                }
                for rank, row in enumerate(rows, start=1)
            )
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--competition", default="pokemon-tcg-ai-battle")
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rows = pull_full_leaderboard(args.competition)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    output = args.output_dir / f"{args.competition}-publicleaderboard-{stamp}.csv"
    write_csv_atomic(output, rows)
    print(f"Wrote {len(rows)} rows to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
