#!/usr/bin/env python3
"""Refresh the official Kaggle top-episodes dataset index.

The index is small and safe to sync frequently. Daily episode datasets can be
very large, so this tool records them and only downloads a daily dataset when
explicitly requested with a size guard.
"""

from __future__ import annotations

import argparse
import csv
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


INDEX_DATASET = "kaggle/pokemon-tcg-ai-battle-episodes-index"


@dataclass
class EpisodeDataset:
    date: str
    slug: str
    url: str
    episode_count: int
    total_bytes: int
    top_avg_score: float
    median_avg_score: float


def kaggle_command() -> list[str]:
    if shutil.which("uv"):
        return ["uv", "run", "kaggle"]
    return ["kaggle"]


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(kaggle_command() + args, text=True, capture_output=True, check=False)


def refresh_manifest(output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    result = run(
        [
            "datasets",
            "download",
            INDEX_DATASET,
            "-f",
            "manifest.csv",
            "-p",
            str(output_dir),
            "--unzip",
        ]
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr or result.stdout)
    manifest = output_dir / "manifest.csv"
    if not manifest.exists():
        raise FileNotFoundError(manifest)
    return manifest


def read_manifest(path: Path) -> list[EpisodeDataset]:
    rows: list[EpisodeDataset] = []
    with path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            rows.append(
                EpisodeDataset(
                    date=row["date"],
                    slug=row["daily_dataset_slug"],
                    url=row["daily_dataset_url"],
                    episode_count=int(row["episode_count"]),
                    total_bytes=int(row["total_bytes"]),
                    top_avg_score=float(row["top_avg_score"]),
                    median_avg_score=float(row["median_avg_score"]),
                )
            )
    return rows


def maybe_download_daily(dataset: EpisodeDataset, args: argparse.Namespace) -> tuple[str, str]:
    if not args.date or args.date != dataset.date:
        return "not-requested", ""
    if dataset.total_bytes > args.max_bytes and not args.allow_large:
        return (
            "blocked-size-guard",
            f"{dataset.total_bytes} bytes exceeds --max-bytes {args.max_bytes}; pass --allow-large to download",
        )
    target = args.output_dir / dataset.date
    target.mkdir(parents=True, exist_ok=True)
    result = run(["datasets", "download", f"kaggle/{dataset.slug}", "-p", str(target), "--unzip"])
    status = "downloaded" if result.returncode == 0 else "failed"
    return status, result.stderr.strip() or result.stdout.strip()


def write_report(path: Path, manifest: Path, datasets: list[EpisodeDataset], download_status: tuple[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append("# Episode Dataset Index Sync")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    lines.append(f"- Index dataset: `{INDEX_DATASET}`")
    lines.append(f"- Manifest: `{manifest}`")
    lines.append(f"- Daily datasets listed: {len(datasets)}")
    lines.append(f"- Download status: {download_status[0]}")
    if download_status[1]:
        lines.append(f"- Download note: {download_status[1]}")
    lines.append("")
    lines.append("| Date | Slug | Episodes | Size GiB | Top Avg | Median Avg |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: |")
    for dataset in datasets:
        lines.append(
            f"| {dataset.date} | `{dataset.slug}` | {dataset.episode_count} | "
            f"{dataset.total_bytes / (1024 ** 3):.2f} | {dataset.top_avg_score:.1f} | "
            f"{dataset.median_avg_score:.1f} |"
        )
    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- The manifest is the safe default input for daily automation.")
    lines.append("- Full daily datasets are multi-GB; use date-specific downloads only when training needs them.")
    lines.append("- If a daily dataset returns 403, keep using live scouting and retry after credentials/access are refreshed.")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=Path("data/kaggle_episode_index"))
    parser.add_argument("--report-out", type=Path, default=None)
    parser.add_argument("--date", default="", help="Optional YYYY-MM-DD daily dataset to download")
    parser.add_argument("--max-bytes", type=int, default=2_000_000_000)
    parser.add_argument("--allow-large", action="store_true")
    args = parser.parse_args()

    manifest = refresh_manifest(args.output_dir)
    datasets = read_manifest(manifest)
    selected = next((dataset for dataset in datasets if dataset.date == args.date), None)
    if args.date and selected is None:
        raise SystemExit(f"No dataset for date {args.date}")
    status = ("not-requested", "")
    if selected is not None:
        status = maybe_download_daily(selected, args)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report = args.report_out or Path(f"strategy/episode_index_sync_{stamp}.md")
    write_report(report, manifest, datasets, status)
    print(f"manifest={manifest}")
    print(f"datasets={len(datasets)}")
    print(f"download_status={status[0]}")
    print(f"report={report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
