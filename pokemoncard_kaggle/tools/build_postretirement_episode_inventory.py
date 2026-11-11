#!/usr/bin/env python3
"""Build a deterministic metadata-only inventory from scout episodes.csv files."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluation_v3.episode_inventory import build_episode_inventory, write_episode_inventory


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--strict-utc-cutoff", required=True)
    parser.add_argument("--source-leaderboard", required=True, type=Path)
    parser.add_argument("--collection-timestamp-utc", required=True)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    inventory = build_episode_inventory(
        source_root=args.source_root,
        strict_utc_cutoff=args.strict_utc_cutoff,
        source_leaderboard=args.source_leaderboard,
        collection_timestamp_utc=args.collection_timestamp_utc,
    )
    write_episode_inventory(args.output, inventory)
    print(f"inventory,{args.output}")
    print(f"content_sha256,{inventory['content_sha256']}")
    print(f"episodes,{len(inventory['episodes'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
