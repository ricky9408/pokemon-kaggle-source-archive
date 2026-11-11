from __future__ import annotations

import csv
from pathlib import Path

from tools.pull_full_leaderboard_paginated import (
    _page,
    _pull_once,
    pull_full_leaderboard,
    write_csv_atomic,
)


class _Row:
    def __init__(self, team_id: int, name: str, score: str) -> None:
        self._value = {
            "teamId": team_id,
            "teamName": name,
            "submissionDate": "2026-07-12T00:00:00.000Z",
            "score": score,
        }

    def to_dict(self) -> dict[str, object]:
        return dict(self._value)


class _Api:
    def competition_leaderboard_view(
        self,
        competition: str,
        page_size: int,
        token: str | None,
    ) -> list[_Row]:
        assert competition == "competition"
        assert page_size == 200
        if token is None:
            print("Next Page Token = page-2")
            return [_Row(1, "one", "10.0"), _Row(2, "two", "9.0")]
        assert token == "page-2"
        return [_Row(3, "three", "8.0")]


def test_page_extracts_rows_and_next_token() -> None:
    rows, token = _page(_Api(), "competition", None)  # type: ignore[arg-type]
    assert [row["teamId"] for row in rows] == [1, 2]
    assert token == "page-2"


def test_pull_once_covers_all_pages_without_duplicates() -> None:
    rows, duplicates = _pull_once(_Api(), "competition")  # type: ignore[arg-type]
    assert [row["teamId"] for row in rows] == [1, 2, 3]
    assert duplicates == set()


def test_full_pull_requires_two_matching_clean_team_sets() -> None:
    api = _Api()
    rows = pull_full_leaderboard("competition", attempts=2, api=api)  # type: ignore[arg-type]
    assert [row["teamId"] for row in rows] == [1, 2, 3]


def test_atomic_csv_writer_preserves_schema(tmp_path: Path) -> None:
    rows, _ = _pull_once(_Api(), "competition")  # type: ignore[arg-type]
    output = tmp_path / "leaderboard.csv"
    write_csv_atomic(output, rows)
    with output.open(newline="", encoding="utf-8") as handle:
        loaded = list(csv.DictReader(handle))
    assert [row["TeamId"] for row in loaded] == ["1", "2", "3"]
    assert [row["Rank"] for row in loaded] == ["1", "2", "3"]
    assert list(loaded[0]) == ["Rank", "TeamId", "TeamName", "LastSubmissionDate", "Score"]
