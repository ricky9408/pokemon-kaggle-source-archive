#!/usr/bin/env python3
"""Pull OUR Kaggle submission history into a canonical CSV.

The existing pipeline only had `scout_top_replays.py`, which pulls *other* teams'
replays. Nothing pulled our own submission history except ad-hoc commands. This
tool is the dedicated, idempotent source of the public-score signal the
self-improving loop learns from.

Output schema (matches what backtest_local_vs_public.py + outcome_ledger.py read):
    ref,fileName,date,description,status,publicScore,privateScore

It uses `kaggle competitions submissions <comp> --csv` (auth via the now-fixed
credentials). Fail-closed: if the pull errors or returns no rows, it exits
non-zero WITHOUT overwriting a good prior CSV, so a transient auth blip can never
be misread as "quota free / no submissions".
"""

from __future__ import annotations

import argparse
import io
import subprocess
import sys
import csv as csvmod
from datetime import UTC, datetime
from pathlib import Path

EXPECTED_COLS = ["ref", "fileName", "date", "description", "status", "publicScore", "privateScore"]


def run_cli(competition: str, page_size: int) -> str:
    cmd = ["uv", "run", "kaggle", "competitions", "submissions", competition,
           "--csv", "--page-size", str(page_size)]
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return result.stdout


def extract_csv(stdout: str) -> list[dict]:
    """The kaggle CLI may print warnings before the CSV header; find the header
    line and parse from there."""
    lines = stdout.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.startswith("ref,fileName") or (line.startswith("ref,") and "fileName" in line):
            start = i
            break
    if start is None:
        return []
    reader = csvmod.DictReader(io.StringIO("\n".join(lines[start:])))
    rows = []
    for row in reader:
        if (row.get("ref") or "").strip():
            rows.append(row)
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pull our Kaggle submission history to CSV")
    parser.add_argument("--competition", default="pokemon-tcg-ai-battle")
    parser.add_argument("--page-size", type=int, default=500)
    parser.add_argument("--output", type=Path, required=True,
                        help="canonical CSV path to write")
    parser.add_argument("--stamped-dir", type=Path, default=None,
                        help="optional dir to also drop a timestamped copy")
    parser.add_argument("--from-file", type=Path, default=None,
                        help="parse this raw CLI output instead of calling kaggle (testing)")
    args = parser.parse_args(argv)

    try:
        stdout = args.from_file.read_text(encoding="utf-8") if args.from_file else run_cli(
            args.competition, args.page_size)
    except subprocess.CalledProcessError as exc:
        sys.stderr.write(f"ERROR: kaggle submissions pull failed (rc={exc.returncode}). "
                         f"Refusing to overwrite {args.output}.\n{exc.stderr}\n")
        return 3

    rows = extract_csv(stdout)
    if not rows:
        sys.stderr.write("ERROR: no submission rows parsed (auth blip or empty). "
                         f"Refusing to overwrite {args.output}.\n")
        return 4

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as fh:
        writer = csvmod.DictWriter(fh, fieldnames=EXPECTED_COLS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({c: row.get(c, "") for c in EXPECTED_COLS})

    complete = sum(1 for r in rows if "COMPLETE" in (r.get("status") or "").upper())
    print(f"Wrote {len(rows)} submissions ({complete} complete) to {args.output}")
    if len(rows) >= args.page_size:
        # [fix 2] single-page pull: silent truncation would freeze old refs in
        # the ledger. Fail loudly so the page size gets raised / pagination added.
        sys.stderr.write(f"WARNING: row count == page size ({args.page_size}); "
                         "results may be TRUNCATED — raise --page-size.\n")

    if args.stamped_dir:
        args.stamped_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
        copy = args.stamped_dir / f"kaggle_submissions_{stamp}.csv"
        copy.write_text(args.output.read_text(encoding="utf-8"), encoding="utf-8")
        print(f"Stamped copy: {copy}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
