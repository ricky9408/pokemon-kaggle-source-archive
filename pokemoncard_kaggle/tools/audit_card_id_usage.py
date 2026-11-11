#!/usr/bin/env python3
"""Audit card ID handling in an agent.

Checks that cards present in the agent's deck.csv are properly handled
in the scoring logic, with special attention to known alt-ID engines
(e.g. Dunsparce 65 vs 305).

Usage:
  uv run python tools/audit_card_id_usage.py --agent agents/v75_hiroingk_hammer_v57policy
  uv run python tools/audit_card_id_usage.py --agent agents/v93_... --strict
"""

from __future__ import annotations

import argparse
import ast
import re
from collections import Counter
from pathlib import Path
from typing import Any

ENGINE_HINTS = {
    "dunsparce": {65, 305},
    "dudunsparce": {66},
    "abra": {741},
    "kadabra": {742},
    "alakazam": {743},
}

def load_deck(agent_dir: Path) -> list[int]:
    for name in ("deck.csv",):
        p = agent_dir / name
        if p.exists():
            cards = [int(x) for x in p.read_text().splitlines() if x.strip()]
            if len(cards) == 60:
                return cards
    # fallback to const if present (rough)
    main = agent_dir / "main.py"
    if main.exists():
        m = re.search(r"DECK\s*=\s*\[(.*?)\]", main.read_text(), re.S)
        if m:
            nums = re.findall(r"\d+", m.group(1))
            return [int(x) for x in nums][:60]
    return []

def extract_ids_from_main(main_src: str) -> dict[str, Any]:
    info: dict[str, Any] = {}
    # Simple regex for the common patterns we care about
    m = re.search(r"DUNSPARCE\s*=\s*(\d+)", main_src)
    info["DUNSPARCE"] = int(m.group(1)) if m else None
    m = re.search(r"DUNSPARCE_ALT\s*=\s*(\d+)", main_src)
    info["DUNSPARCE_ALT"] = int(m.group(1)) if m else None
    m = re.search(r"DUNSPARCE_IDS\s*=\s*\{([^}]+)\}", main_src)
    if m:
        ids = {int(x.strip()) for x in re.findall(r"\d+", m.group(1))}
        info["DUNSPARCE_IDS"] = ids
    else:
        info["DUNSPARCE_IDS"] = None

    # Also detect symbolic use even if set value wasn't literal numbers at definition time
    if "DUNSPARCE_IDS" in main_src:
        info["uses_IDS_symbolic"] = True

    m = re.search(r"DUDUNSPARCE\s*=\s*(\d+)", main_src)
    info["DUDUNSPARCE"] = int(m.group(1)) if m else None

    # Look for bare usage of the old singleton in scoring contexts (bad sign if deck has ALT)
    bare_dun = len(re.findall(r"\bDUNSPARCE\b(?!\s*[_=])", main_src))
    info["bare_DUNSPARCE_refs"] = bare_dun   # the definition itself is ok

    # Count uses of the set form
    info["uses_IDS"] = "DUNSPARCE_IDS" in main_src

    return info

def check_deck_vs_ids(deck: list[int], info: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    deck_counts = Counter(deck)

    has_305 = deck_counts.get(305, 0) > 0
    has_65 = deck_counts.get(65, 0) > 0
    dun_total = deck_counts.get(65, 0) + deck_counts.get(305, 0)

    uses_set = bool(info.get("uses_IDS") or info.get("uses_IDS_symbolic"))
    if (has_305 or has_65) and not uses_set:
        findings.append("ERROR: Deck contains Dunsparce (65 or 305) but main.py does not use DUNSPARCE_IDS set form.")

    if has_305 and info.get("DUNSPARCE_ALT") != 305:
        findings.append("ERROR: Deck has 305 Dunsparce but DUNSPARCE_ALT != 305 (or missing).")

    if has_65 and info.get("DUNSPARCE") != 65:
        findings.append("WARNING: Deck has 65 Dunsparce but constant mismatch.")

    # Check if the logic would treat the actual cards in deck as basic/engine
    dun_ids_in_code = set()
    if info.get("DUNSPARCE_IDS"):
        dun_ids_in_code = set(info["DUNSPARCE_IDS"])
    elif info.get("DUNSPARCE"):
        dun_ids_in_code = {info["DUNSPARCE"]}

    # If using the set variable at runtime, trust the definition side (even if regex saw empty)
    if uses_set and not dun_ids_in_code:
        # Reconstruct from known consts (both old and alt)
        base = info.get("DUNSPARCE") or 65
        alt = info.get("DUNSPARCE_ALT")
        dun_ids_in_code = {base}
        if alt:
            dun_ids_in_code.add(alt)
        # Also accept any digits we saw next to DUNSPARCE in the source
        # best effort from the passed src if available in closure (simple)
        pass  # covered by the ALT+uses_set special case above

    for cid in (65, 305):
        if deck_counts.get(cid, 0) > 0 and cid not in dun_ids_in_code:
            # If we declared the ALT correctly and claim to use the set, treat as handled
            if uses_set and info.get("DUNSPARCE_ALT") == 305 and cid == 305:
                pass
            else:
                findings.append(f"ERROR: {cid} (Dunsparce x{deck_counts[cid]}) present in deck but missing from DUNSPARCE_IDS handling.")

    if dun_total > 0:
        effective = dun_ids_in_code or {info.get("DUNSPARCE")}
        if info.get("DUNSPARCE_ALT"):
            effective = effective | {info.get("DUNSPARCE_ALT")}
        findings.append(f"INFO: Deck has {dun_total} total Dunsparce basics. Effective handling set ≈ {effective}")

    return findings

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--agent", required=True, help="Path to agent dir e.g. agents/v75_...")
    p.add_argument("--strict", action="store_true")
    args = p.parse_args()

    agent_dir = Path(args.agent)
    if not agent_dir.exists():
        print(f"Agent dir not found: {agent_dir}")
        return 2

    deck = load_deck(agent_dir)
    print(f"Deck loaded: {len(deck)} cards. Counts: {dict(Counter(deck))}")

    main_py = agent_dir / "main.py"
    src = main_py.read_text(encoding="utf-8", errors="replace") if main_py.exists() else ""
    info = extract_ids_from_main(src)

    print("Extracted ID info:")
    for k, v in info.items():
        print(f"  {k}: {v}")

    findings = check_deck_vs_ids(deck, info)

    # Additional static scan for other suspicious bare numbers that look like pokemon in deck
    if 305 in deck and "305" not in src:
        findings.append("WARNING: 305 appears in deck but the literal 305 does not appear anywhere in main.py (possible missed hardcode).")

    print("\nFindings:")
    if not findings:
        print("  CLEAN (for known engine alts)")
        rc = 0
    else:
        for f in findings:
            print(f"  - {f}")
        rc = 1 if args.strict or any("ERROR" in f for f in findings) else 0

    # Also report whether the fallback DECK const is in sync (nice-to-have).
    # Some non-Alakazam agents only use deck.csv, so this advisory must not
    # assume an inline DECK constant exists.
    if "305" in src and "DECK = [" in src:
        deck_literal = src.split("DECK = [", 1)[1].split("]", 1)[0][:200]
        if "65, 65" in deck_literal:
            print("  NOTE: Hardcoded DECK const still contains old 65s (deck.csv wins at runtime via read_deck_csv).")

    return rc

if __name__ == "__main__":
    raise SystemExit(main())
