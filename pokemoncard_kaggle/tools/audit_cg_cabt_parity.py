#!/usr/bin/env python3
"""Audit card-pool parity across cg/cabt simulator bundles.

Run this inside Linux/amd64 because the competition ships a Linux libcg.so.
The tool intentionally avoids importing cg.api so it can inspect both the
submission-template cg package and the slimmer kaggle-environments cabt/cg
package, which may not include api.py.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import hashlib
import json
import platform
import re
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BundleAudit:
    label: str
    root: Path
    lib_path: Path
    lib_sha256: str
    card_count: int
    card_min: int
    card_max: int
    card_ids: set[int]
    all_card_sha256: str
    all_attack_sha256: str
    attack_count: int


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def norm_header(value: str) -> str:
    return re.sub(r"[^a-z0-9一-龯ぁ-んァ-ンー]+", "", value.lower())


def find_lib(root: Path) -> Path:
    candidates = [root / "cg" / "libcg.so", root / "libcg.so"]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"could not find cg/libcg.so under {root}")


def load_bundle(label: str, root: Path) -> BundleAudit:
    lib_path = find_lib(root)
    lib = ctypes.cdll.LoadLibrary(str(lib_path))
    lib.GameInitialize()
    lib.AllCard.restype = ctypes.c_char_p
    lib.AllAttack.restype = ctypes.c_char_p

    all_card_raw = lib.AllCard()
    all_attack_raw = lib.AllAttack()
    cards = json.loads(all_card_raw.decode())
    attacks = json.loads(all_attack_raw.decode())
    ids = {int(card["cardId"]) for card in cards}
    return BundleAudit(
        label=label,
        root=root,
        lib_path=lib_path,
        lib_sha256=sha256_file(lib_path),
        card_count=len(ids),
        card_min=min(ids),
        card_max=max(ids),
        card_ids=ids,
        all_card_sha256=sha256_bytes(all_card_raw),
        all_attack_sha256=sha256_bytes(all_attack_raw),
        attack_count=len(attacks),
    )


def read_card_csv_ids(path: Path) -> set[int]:
    with path.open(newline="", encoding="utf-8-sig") as file:
        rows = list(csv.DictReader(file))
    if not rows:
        return set()
    id_col = next(
        (
            column
            for column in rows[0].keys()
            if norm_header(column) in {"cardid", "カードid"}
        ),
        None,
    )
    if id_col is None:
        raise ValueError(f"could not find Card ID column in {path}")
    ids: set[int] = set()
    for row in rows:
        value = (row.get(id_col) or "").strip()
        if value:
            ids.add(int(value))
    return ids


def read_episode_ids(path: Path) -> set[int]:
    ids: set[int] = set()
    paths = sorted(path.glob("*.json")) if path.is_dir() else [path]
    for episode_path in paths:
        data = json.loads(episode_path.read_text(encoding="utf-8"))
        for step in data.get("steps") or []:
            for agent_step in step:
                for vis in agent_step.get("visualize") or []:
                    for deck in vis.get("action") or []:
                        if isinstance(deck, list):
                            ids.update(card_id for card_id in deck if isinstance(card_id, int))
                    current = vis.get("current") or {}
                    for player in current.get("players") or []:
                        for zone in ("deck", "hand", "active", "bench", "discard", "prize"):
                            for card in player.get(zone) or []:
                                if isinstance(card, dict) and isinstance(card.get("id"), int):
                                    ids.add(card["id"])
    ids.discard(0)  # API uses 0 for special-condition handling, not a real card.
    return ids


def format_set(values: set[int], limit: int = 30) -> str:
    if not values:
        return "[]"
    ordered = sorted(values)
    suffix = "" if len(ordered) <= limit else f" ... (+{len(ordered) - limit} more)"
    return "[" + ", ".join(str(v) for v in ordered[:limit]) + "]" + suffix


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--cg-root",
        action="append",
        default=[],
        metavar="LABEL=PATH",
        help="Simulator root to inspect. PATH may contain cg/libcg.so or be the cg directory.",
    )
    parser.add_argument("--card-csv", action="append", default=[], type=Path)
    parser.add_argument("--episodes", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    if platform.system() != "Linux":
        print(
            "ERROR: libcg.so is a Linux shared library; run this audit inside "
            "linux/amd64 Docker.",
            file=sys.stderr,
        )
        return 3

    roots = args.cg_root or [
        "sample=data/sample_submission",
        "submission=submission",
    ]
    audits: list[BundleAudit] = []
    for item in roots:
        if "=" in item:
            label, raw_path = item.split("=", 1)
        else:
            raw_path = item
            label = Path(raw_path).name
        audits.append(load_bundle(label, Path(raw_path)))

    lines: list[str] = []
    lines.append("# cg/cabt Parity Audit")
    lines.append("")
    lines.append(f"- Python platform: {platform.platform()}")
    lines.append("")
    lines.append("## Bundles")
    lines.append("")
    for audit in audits:
        lines.append(f"### {audit.label}")
        lines.append("")
        lines.append(f"- Root: `{audit.root}`")
        lines.append(f"- libcg.so: `{audit.lib_path}`")
        lines.append(f"- libcg.so sha256: `{audit.lib_sha256}`")
        lines.append(f"- AllCard count/range: {audit.card_count} / {audit.card_min}..{audit.card_max}")
        lines.append(f"- AllCard raw sha256: `{audit.all_card_sha256}`")
        lines.append(f"- AllAttack count: {audit.attack_count}")
        lines.append(f"- AllAttack raw sha256: `{audit.all_attack_sha256}`")
        lines.append("")

    base = audits[0]
    lines.append("## Bundle Pairwise Diffs")
    lines.append("")
    for audit in audits[1:]:
        lines.append(f"### {base.label} vs {audit.label}")
        lines.append("")
        lines.append(f"- lib hash same: {base.lib_sha256 == audit.lib_sha256}")
        lines.append(f"- card ID set same: {base.card_ids == audit.card_ids}")
        lines.append(f"- AllCard raw same: {base.all_card_sha256 == audit.all_card_sha256}")
        lines.append(f"- AllAttack raw same: {base.all_attack_sha256 == audit.all_attack_sha256}")
        lines.append(f"- IDs only in {base.label}: {format_set(base.card_ids - audit.card_ids)}")
        lines.append(f"- IDs only in {audit.label}: {format_set(audit.card_ids - base.card_ids)}")
        lines.append("")

    if args.card_csv:
        lines.append("## CSV Card ID Checks")
        lines.append("")
        for csv_path in args.card_csv:
            ids = read_card_csv_ids(csv_path)
            lines.append(f"### {csv_path}")
            lines.append("")
            lines.append(f"- CSV card IDs: {len(ids)}")
            lines.append(f"- CSV IDs match {base.label}: {ids == base.card_ids}")
            lines.append(f"- CSV-only IDs: {format_set(ids - base.card_ids)}")
            lines.append(f"- {base.label}-only IDs: {format_set(base.card_ids - ids)}")
            lines.append("")

    if args.episodes:
        episode_ids = read_episode_ids(args.episodes)
        lines.append("## Public Episode Card ID Checks")
        lines.append("")
        lines.append(f"- Source: `{args.episodes}`")
        lines.append(f"- Real card IDs observed: {len(episode_ids)}")
        for audit in audits:
            missing = episode_ids - audit.card_ids
            lines.append(f"- Missing from {audit.label}: {format_set(missing)}")
        lines.append("")

    report = "\n".join(lines)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report + "\n", encoding="utf-8")
    print(report)

    failed = False
    for audit in audits[1:]:
        failed = failed or audit.card_ids != base.card_ids
    for csv_path in args.card_csv:
        failed = failed or read_card_csv_ids(csv_path) != base.card_ids
    if args.episodes:
        failed = failed or any(read_episode_ids(args.episodes) - audit.card_ids for audit in audits)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
