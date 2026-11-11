#!/usr/bin/env python3
"""Audit whether the local simulator can replay a Kaggle public episode.

This script intentionally separates three questions that were previously
blurred together:

1. Can the local ``cg`` engine be advanced along the public action path?
2. Do local legal-action sets match Kaggle's replay observations?
3. Is the submitted Python policy deterministic on identical observations?

Run inside the linux/amd64 simulator environment, for example:

docker run -i --rm --platform linux/amd64 \
  -v "$PWD:/work" -w /work python:3.11-slim \
  python tools/replay_fidelity_audit.py \
    --replay diagnostics/june20_failures/v39/episode-80775062-replay.json \
    --agent strategy/extracted_submissions_20260620T1658/v39 \
    --team GarlicToday \
    --output strategy/replay_fidelity_audit_YYYYMMDDTHHMM_v39.md
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib
import importlib.util
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SEED_SYMBOL_CANDIDATES = (
    "SetSeed",
    "GameSetSeed",
    "BattleSetSeed",
    "SetRandomSeed",
    "GameInitializeWithSeed",
    "BattleStartWithSeed",
)

CONTROL_SYMBOL_CANDIDATES = (
    "GameInitialize",
    "AgentStart",
    "BattleStart",
    "BattleFinish",
    "GetBattleData",
    "Select",
    "VisualizeData",
    "SearchBegin",
    "SearchStep",
    "SearchEnd",
    "SearchRelease",
) + SEED_SYMBOL_CANDIDATES

NATIVE_KEYWORDS = (
    "seed",
    "random",
    "rand",
    "shuffle",
    "battle",
    "search",
    "restore",
    "replay",
    "serialize",
    "state",
)


def canonical_name(value: Any) -> str:
    return str(value).replace("_", "").replace(" ", "").replace("-", "").lower()


def enum_name(enum_class: Any, value: Any) -> str:
    for name in dir(enum_class):
        if name.isupper() and getattr(enum_class, name) == value:
            return "".join(part.title() for part in name.lower().split("_"))
    return str(value)


def normalize_option(option: dict[str, Any], option_type_enum: Any) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for key, value in option.items():
        if key == "type" and isinstance(value, int):
            normalized[key] = enum_name(option_type_enum, value)
        else:
            normalized[key] = value
    return normalized


def normalize_select(select: dict[str, Any] | None, select_context_enum: Any, option_type_enum: Any) -> dict[str, Any] | None:
    if not isinstance(select, dict):
        return None
    context = select.get("context")
    select_type = select.get("type")
    if isinstance(context, int):
        context = enum_name(select_context_enum, context)
    if isinstance(select_type, int):
        # SelectType and OptionType overlap only by accident; use raw numeric
        # type in the compact signature and context/options for matching.
        select_type = str(select_type)
    return {
        "context": context,
        "contextCanonical": canonical_name(context),
        "type": select_type,
        "minCount": select.get("minCount"),
        "maxCount": select.get("maxCount"),
        "option": [normalize_option(option, option_type_enum) for option in (select.get("option") or [])],
    }


def compact_select_signature(select: dict[str, Any] | None, select_context_enum: Any, option_type_enum: Any) -> dict[str, Any] | None:
    normalized = normalize_select(select, select_context_enum, option_type_enum)
    if normalized is None:
        return None
    return {
        "context": normalized["contextCanonical"],
        "minCount": normalized["minCount"],
        "maxCount": normalized["maxCount"],
        "option": normalized["option"],
    }


def scrub_state(value: Any) -> Any:
    """Remove fields that are timing-only or too bulky for useful hashes."""
    if isinstance(value, dict):
        return {
            key: scrub_state(item)
            for key, item in sorted(value.items())
            if key not in {"remainingOverageTime", "search_begin_input", "obs"}
        }
    if isinstance(value, list):
        return [scrub_state(item) for item in value]
    return value


def state_hash(obs: dict[str, Any] | None) -> str:
    if not isinstance(obs, dict):
        return "none"
    payload = json.dumps(scrub_state(obs), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]


def json_compact(value: Any, limit: int | None = None) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if limit is not None and len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def native_library_scan(lib: Any) -> dict[str, Any]:
    """Inspect wrapper-visible and raw native-library strings for replay hooks.

    The linux/amd64 competition bundle may be inspected inside Docker where
    binutils are not guaranteed to exist. We therefore avoid depending on
    ``nm`` here and use two complementary signals:

    * ctypes symbol resolution for known public/control names;
    * printable strings in the shared object for RNG/seed/restore hints.
    """

    lib_path = Path(getattr(lib, "_name", ""))
    available = [name for name in CONTROL_SYMBOL_CANDIDATES if hasattr(lib, name)]
    strings: list[str] = []
    read_error = ""
    try:
        raw = lib_path.read_bytes()
        strings = [
            match.decode("utf-8", errors="replace")
            for match in re.findall(rb"[\x20-\x7e]{4,}", raw)
        ]
    except Exception as exc:  # pragma: no cover - diagnostic only
        read_error = f"{type(exc).__name__}: {exc}"

    keyword_hits = []
    seen: set[str] = set()
    for item in strings:
        lowered = item.lower()
        if any(keyword in lowered for keyword in NATIVE_KEYWORDS):
            if item not in seen:
                seen.add(item)
                keyword_hits.append(item)

    seed_string_hits = [item for item in keyword_hits if "seed" in item.lower()]
    rng_string_hits = [
        item
        for item in keyword_hits
        if "random" in item.lower() or "rand" in item.lower() or "mersenne" in item.lower()
    ]
    restore_string_hits = [
        item
        for item in keyword_hits
        if any(keyword in item.lower() for keyword in ("restore", "replay", "serialize", "state"))
    ]

    return {
        "lib_path": str(lib_path),
        "available_control_symbols": available,
        "seed_exports": [name for name in SEED_SYMBOL_CANDIDATES if name in available],
        "search_restore_exports": [
            name
            for name in ("SearchBegin", "SearchStep", "SearchEnd", "SearchRelease")
            if name in available
        ],
        "seed_string_hits": seed_string_hits[:40],
        "rng_string_hits": rng_string_hits[:40],
        "restore_string_hits": restore_string_hits[:40],
        "keyword_hit_count": len(keyword_hits),
        "read_error": read_error,
    }


def load_agent(agent_dir: Path):
    agent_dir = agent_dir.resolve()
    sys.path.insert(0, str(agent_dir))
    old_cwd = os.getcwd()
    os.chdir(agent_dir)
    try:
        spec = importlib.util.spec_from_file_location(f"fidelity_agent_{hash(agent_dir)}", agent_dir / "main.py")
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Could not load {agent_dir / 'main.py'}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.agent
    finally:
        os.chdir(old_cwd)


def valid_action(action: Any, select: dict[str, Any] | None) -> bool:
    if not isinstance(select, dict):
        return False
    options = select.get("option") or []
    minimum = select.get("minCount", 0)
    maximum = select.get("maxCount", len(options))
    return (
        isinstance(action, list)
        and minimum <= len(action) <= maximum
        and all(isinstance(item, int) and 0 <= item < len(options) for item in action)
    )


def public_action_for_observation(steps: list[Any], step_index: int, slot: int) -> Any:
    """Replay action chosen for the observation at ``step_index``.

    Kaggle replay JSON stores the action responding to ``steps[t][slot]["observation"]``
    on ``steps[t + 1][slot]["action"]``.
    """

    next_index = step_index + 1
    if next_index >= len(steps):
        return None
    try:
        return steps[next_index][slot].get("action")
    except (AttributeError, IndexError, TypeError):
        return None


def decision_state_key(obs: dict[str, Any]) -> str:
    current = dict(obs.get("current") or {})
    current.pop("result", None)
    return json.dumps(
        {"current": current, "select": obs.get("select") or {}},
        sort_keys=True,
        separators=(",", ":"),
    )


@dataclass
class PublicDecision:
    index: int
    player: int | None
    team: str | None
    context: str
    selected: list[int]
    select: dict[str, Any]
    current: dict[str, Any]
    source: str


def extract_decks(data: dict[str, Any]) -> tuple[list[int], list[int]]:
    for step in data.get("steps", []):
        if len(step) < 2:
            continue
        a0 = step[0].get("action")
        a1 = step[1].get("action")
        if isinstance(a0, list) and isinstance(a1, list) and len(a0) == 60 and len(a1) == 60:
            return a0, a1
    visualize = (((data.get("steps") or [[{}]])[0][0]).get("visualize") or [])
    for entry in visualize:
        action = entry.get("action")
        if (
            isinstance(action, list)
            and len(action) == 2
            and all(isinstance(deck, list) and len(deck) == 60 for deck in action)
        ):
            return action[0], action[1]
    raise ValueError("Could not find both submitted deck lists in replay")


def infer_is_first_action(decisions: list[dict[str, Any]], is_first_index: int) -> list[int]:
    entry = decisions[is_first_index]
    current = entry.get("current") or {}
    chooser = current.get("yourIndex")
    for later in decisions[is_first_index + 1 :]:
        first = (later.get("current") or {}).get("firstPlayer")
        if first in (0, 1) and chooser in (0, 1):
            return [0] if first == chooser else [1]
    return [0]


def public_decisions_from_visualize(data: dict[str, Any]) -> list[PublicDecision]:
    teams = (data.get("info") or {}).get("TeamNames") or [None, None]
    visualize = (((data.get("steps") or [[{}]])[0][0]).get("visualize") or [])
    raw: list[dict[str, Any]] = [
        entry
        for entry in visualize
        if isinstance(entry.get("select"), dict) and (entry.get("select") or {}).get("option") is not None
    ]
    decisions: list[PublicDecision] = []
    for index, entry in enumerate(raw):
        select = entry["select"]
        current = entry.get("current") or {}
        player = current.get("yourIndex")
        selected = entry.get("selected")
        if selected is None and canonical_name(select.get("context")) == "isfirst":
            selected = infer_is_first_action(raw, index)
        if selected is None:
            continue
        team = teams[player] if isinstance(player, int) and player < len(teams) else None
        decisions.append(
            PublicDecision(
                index=len(decisions),
                player=player,
                team=team,
                context=str(select.get("context")),
                selected=list(selected),
                select=select,
                current=current,
                source=f"visualize[{index}]",
            )
        )
    return decisions


def public_step_records_for_team(data: dict[str, Any], team: str | None) -> list[tuple[int, int, dict[str, Any], list[int]]]:
    teams = (data.get("info") or {}).get("TeamNames") or [None, None]
    steps = data.get("steps", [])
    seen_decision_states: set[tuple[int, str]] = set()
    rows: list[tuple[int, int, dict[str, Any], list[int]]] = []
    for step_index, step in enumerate(steps):
        for slot, record in enumerate(step):
            if team and (slot >= len(teams) or teams[slot] != team):
                continue
            obs = record.get("observation") or {}
            select = obs.get("select") if isinstance(obs, dict) else None
            if not isinstance(select, dict):
                continue
            state_key = (slot, decision_state_key(obs))
            if state_key in seen_decision_states:
                continue
            seen_decision_states.add(state_key)
            action = public_action_for_observation(steps, step_index, slot)
            if not isinstance(action, list):
                continue
            if len(action) == 60 or not valid_action(action, select):
                continue
            rows.append((step_index, slot, obs, action))
    return rows


def compare_policy_twice(agent, obs: dict[str, Any]) -> tuple[Any, Any, bool, str | None]:
    try:
        first = agent(obs)
        second = agent(obs)
        return first, second, first == second, None
    except Exception as exc:  # pragma: no cover - diagnostic path
        return None, None, False, f"{type(exc).__name__}: {exc}"


def classify_divergence(
    decision: PublicDecision,
    public_sig: dict[str, Any] | None,
    local_sig: dict[str, Any] | None,
    local_obs: dict[str, Any] | None,
    seed_control_available: bool,
) -> str:
    if local_sig is None:
        return "state_reconstruction_gap"
    local_player = ((local_obs or {}).get("current") or {}).get("yourIndex")
    if local_player != decision.player:
        return "state_reconstruction_gap"
    if public_sig and local_sig and public_sig.get("context") != local_sig.get("context"):
        return "state_reconstruction_gap"
    if not seed_control_available and decision.context in {"IsFirst", "SetupActivePokemon", "SetupBenchPokemon"}:
        return "rng_seed_mismatch_uncontrolled"
    if not seed_control_available:
        return "rng_seed_mismatch_uncontrolled"
    return "legal_action_set_mismatch"


def audit_engine_path(
    data: dict[str, Any],
    agent,
    rng_trials: int,
    max_decisions: int,
    select_context_enum: Any,
    option_type_enum: Any,
):
    from cg.game import battle_finish, battle_select, battle_start  # type: ignore
    from cg.sim import lib  # type: ignore

    decks = extract_decks(data)
    decisions = public_decisions_from_visualize(data)[:max_decisions]
    native_scan = native_library_scan(lib)
    seed_symbols = list(native_scan["seed_exports"])
    seed_control_available = bool(seed_symbols)
    trials: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []

    for trial in range(rng_trials):
        obs = None
        first_divergence: dict[str, Any] | None = None
        exact_legal_prefix = 0
        legal_matches_total = 0
        stepped = 0
        try:
            obs, start_data = battle_start(*decks)
            if not obs:
                trials.append(
                    {
                        "trial": trial,
                        "start_error_player": getattr(start_data, "errorPlayer", None),
                        "start_error_type": getattr(start_data, "errorType", None),
                        "first_divergence": "battle_start_failed",
                        "exact_legal_prefix": 0,
                    }
                )
                continue

            for decision in decisions:
                local_select = (obs or {}).get("select") if isinstance(obs, dict) else None
                public_sig = compact_select_signature(decision.select, select_context_enum, option_type_enum)
                local_sig = compact_select_signature(local_select, select_context_enum, option_type_enum)
                local_player = ((obs or {}).get("current") or {}).get("yourIndex")
                actor_match = local_player == decision.player
                legal_match = public_sig == local_sig
                action_valid_local = valid_action(decision.selected, local_select)
                local_first, local_second, local_deterministic, local_policy_error = compare_policy_twice(agent, obs)
                row_classification = ""
                if not actor_match or not legal_match:
                    row_classification = classify_divergence(
                        decision, public_sig, local_sig, obs, seed_control_available
                    )
                elif not action_valid_local:
                    row_classification = "public_action_illegal_local"

                row = {
                    "trial": trial,
                    "decision": decision.index,
                    "source": decision.source,
                    "team": decision.team,
                    "public_player": decision.player,
                    "local_player": local_player,
                    "public_context": decision.context,
                    "local_context": (normalize_select(local_select, select_context_enum, option_type_enum) or {}).get("context"),
                    "public_action": json.dumps(decision.selected),
                    "local_policy_first": json.dumps(local_first),
                    "local_policy_second": json.dumps(local_second),
                    "local_policy_deterministic": local_deterministic,
                    "local_policy_error": local_policy_error or "",
                    "actor_match": actor_match,
                    "legal_match": legal_match,
                    "action_valid_local": action_valid_local,
                    "classification": row_classification,
                    "public_option_count": len(decision.select.get("option") or []),
                    "local_option_count": len((local_select or {}).get("option") or []),
                    "public_signature": json_compact(public_sig),
                    "local_signature": json_compact(local_sig),
                    "public_state_hash": state_hash({"current": decision.current, "select": decision.select}),
                    "local_state_hash": state_hash(obs),
                }
                rows.append(row)

                if actor_match and legal_match:
                    legal_matches_total += 1
                if first_divergence is None and actor_match and legal_match:
                    exact_legal_prefix += 1
                elif first_divergence is None:
                    first_divergence = {
                        **row,
                        "classification": row_classification,
                        "public_signature": public_sig,
                        "local_signature": local_sig,
                    }

                if not action_valid_local:
                    if first_divergence is None:
                        first_divergence = {
                            **row,
                            "classification": "public_action_illegal_local",
                            "public_signature": public_sig,
                            "local_signature": local_sig,
                        }
                    break
                try:
                    obs = battle_select(decision.selected)
                    stepped += 1
                except Exception as exc:
                    if first_divergence is None:
                        first_divergence = {
                            **row,
                            "classification": "battle_select_error",
                            "select_error": f"{type(exc).__name__}: {exc}",
                            "public_signature": public_sig,
                            "local_signature": local_sig,
                        }
                    break
        finally:
            try:
                battle_finish()
            except Exception:
                pass

        trials.append(
            {
                "trial": trial,
                "exact_legal_prefix": exact_legal_prefix,
                "legal_matches_total": legal_matches_total,
                "stepped": stepped,
                "first_divergence": first_divergence,
            }
        )
    return decisions, native_scan, trials, rows


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def render_report(
    data: dict[str, Any],
    replay_path: Path,
    agent_path: Path,
    team: str | None,
    decisions: list[PublicDecision],
    native_scan: dict[str, Any],
    trials: list[dict[str, Any]],
    public_policy_rows: list[tuple[int, int, dict[str, Any], list[int]]],
    policy_determinism: list[dict[str, Any]],
) -> str:
    info = data.get("info") or {}
    teams = info.get("TeamNames")
    config = data.get("configuration") or {}
    seed = config.get("seed")
    best = max(trials, key=lambda item: item.get("exact_legal_prefix", -1)) if trials else {}
    first = best.get("first_divergence")
    seed_symbols = list(native_scan.get("seed_exports") or [])
    lines = [
        "# Replay Fidelity Audit",
        "",
        f"- Replay: `{replay_path}`",
        f"- EpisodeId: `{info.get('EpisodeId')}`",
        f"- Teams: `{teams}`",
        f"- Kaggle replay seed: `{seed}`",
        f"- Agent archive/dir: `{agent_path}`",
        f"- Target team for policy determinism: `{team or 'all teams'}`",
        f"- Public visual decisions parsed: `{len(decisions)}`",
        f"- Public step observations for determinism: `{len(public_policy_rows)}`",
        f"- Native seed-control symbols found: `{seed_symbols or []}`",
        "",
        "## Verdict",
        "",
    ]
    if not seed_symbols:
        lines.append(
            "The distributed `cg` Python/native API exposes no seed setter, while public replays contain a Kaggle seed. "
            "The local engine therefore cannot be forced onto the same shuffle/RNG path from the public replay alone."
        )
    if first:
        lines.extend(
            [
                "",
                f"Best trial exact legal-prefix length: `{best.get('exact_legal_prefix')}` decisions.",
                f"First divergence classification: `{first.get('classification')}`.",
                f"First divergence source: `{first.get('source')}`, public player `{first.get('public_player')}`, local player `{first.get('local_player')}`.",
                f"Public context `{first.get('public_context')}`, local context `{first.get('local_context')}`.",
                f"Public action `{first.get('public_action')}`, local policy `{first.get('local_policy_first')}`.",
            ]
        )
        if first.get("classification") == "rng_seed_mismatch_uncontrolled":
            lines.append(
                "This is evidence for blocker (A) at the RNG/replay-harness layer, not for submitted-agent non-determinism. "
                "Legal options diverge before the game reaches a stable public state, so later local win-rate metrics are not calibrated to Kaggle public episodes."
            )
        elif first.get("classification") == "state_reconstruction_gap":
            lines.append(
                "The local replay state is not reconstructing the public state path. This may be RNG seed loss or a step-order reconstruction bug; inspect the signatures below."
            )
        elif first.get("classification") == "legal_action_set_mismatch":
            lines.append(
                "The local engine reached the same actor/context but enumerated a different legal set despite seed control being available; this is the strongest rule-drift signal."
            )
    else:
        lines.append("No divergence found within the audited decision window.")

    nondet = [row for row in policy_determinism if not row["same"]]
    errors = [row for row in policy_determinism if row["error"]]
    lines.extend(
        [
            "",
            "## Native API / Restore Hook Inspection",
            "",
            f"- Native library: `{native_scan.get('lib_path')}`",
            "- Wrapper-resolvable control symbols: "
            + (", ".join(f"`{name}`" for name in native_scan.get("available_control_symbols", [])) or "`[]`"),
            "- Seed-control exports: "
            + (", ".join(f"`{name}`" for name in native_scan.get("seed_exports", [])) or "`[]`"),
            "- Search/restore-like exports: "
            + (", ".join(f"`{name}`" for name in native_scan.get("search_restore_exports", [])) or "`[]`"),
            "- RNG string hints: "
            + (
                ", ".join(f"`{item[:80]}`" for item in native_scan.get("rng_string_hits", [])[:8])
                or "`[]`"
            ),
            "- Seed string hints: "
            + (
                ", ".join(f"`{item[:80]}`" for item in native_scan.get("seed_string_hits", [])[:8])
                or "`[]`"
            ),
            "- Restore/state string hints: "
            + (
                ", ".join(f"`{item[:80]}`" for item in native_scan.get("restore_string_hits", [])[:8])
                or "`[]`"
            ),
        ]
    )
    if native_scan.get("read_error"):
        lines.append(f"- Native string scan error: `{native_scan['read_error']}`")
    lines.append(
        "- `SearchBegin` is not treated as a full public-replay restore hook: it requires an existing observation `search_begin_input` plus guessed hidden zones, "
        "and it creates a search state rather than a seeded `BattleStart` state with the public opening shuffle/prizes."
    )
    lines.extend(
        [
            "",
            "## Policy Determinism",
            "",
            f"- Identical public observations checked: `{len(policy_determinism)}`",
            f"- Non-deterministic repeated calls: `{len(nondet)}`",
            f"- Policy call errors: `{len(errors)}`",
        ]
    )
    if nondet[:5]:
        lines.append("")
        lines.append("First non-deterministic examples:")
        for row in nondet[:5]:
            lines.append(
                f"- step `{row['step']}` slot `{row['slot']}` action1 `{row['first']}` action2 `{row['second']}`"
            )

    local_first_signatures = []
    for trial in trials:
        div = trial.get("first_divergence") or {}
        signature = div.get("local_signature")
        if signature is not None:
            local_first_signatures.append(json.dumps(signature, ensure_ascii=False, sort_keys=True))
    unique_local_first = sorted(set(local_first_signatures))
    lines.extend(
        [
            "",
            "## Same-Deck Local Trace Variation",
            "",
            f"- Repeated same-deck scripted local trials: `{len(trials)}`",
            f"- Unique local first-divergence legal signatures: `{len(unique_local_first)}`",
        ]
    )
    if not seed_symbols:
        lines.append(
            "- No same-seed trace diff can be performed faithfully because the native API does not accept the Kaggle replay seed; this is the isolation result."
        )
    if len(unique_local_first) > 1:
        lines.append(
            "- Repeated runs with identical deck lists and the same public action script produced different local setup legal sets, confirming uncontrolled engine RNG."
        )
    for item in unique_local_first[:3]:
        lines.append(f"- Example local signature: `{item[:500]}`")

    lines.extend(["", "## Trial Summary", ""])
    lines.append("| trial | exact legal prefix | legal matches total | stepped | first classification | first context | local context |")
    lines.append("|---:|---:|---:|---:|---|---|---|")
    for trial in trials:
        div = trial.get("first_divergence") or {}
        lines.append(
            f"| {trial.get('trial')} | {trial.get('exact_legal_prefix')} | {trial.get('legal_matches_total')} | {trial.get('stepped')} | "
            f"{div.get('classification', 'none')} | {div.get('public_context', '')} | {div.get('local_context', '')} |"
        )

    if first:
        lines.extend(["", "## First Divergence Signatures", ""])
        lines.append("Public:")
        lines.append("```json")
        lines.append(json.dumps(first.get("public_signature"), ensure_ascii=False, sort_keys=True, indent=2)[:4000])
        lines.append("```")
        lines.append("Local:")
        lines.append("```json")
        lines.append(json.dumps(first.get("local_signature"), ensure_ascii=False, sort_keys=True, indent=2)[:4000])
        lines.append("```")

    lines.extend(
        [
            "",
            "## Implication For Candidate Selection",
            "",
            "Until the public replay seed/RNG stream can be injected into `BattleStart`, move-for-move public replay reproduction is not available. "
            "Backtest gates should remain closed for metrics based on ordinary local replay-pool win rate. "
            "The fallback signal should be public-anchor calibration: require enough real public submissions/replays per candidate family, and only use local held-out metrics as weak secondary evidence.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--replay", required=True, type=Path)
    parser.add_argument("--agent", required=True, type=Path)
    parser.add_argument("--team", default=None)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--csv-output", type=Path)
    parser.add_argument("--rng-trials", type=int, default=8)
    parser.add_argument("--max-decisions", type=int, default=160)
    args = parser.parse_args()

    agent_dir = args.agent.resolve()
    sys.path.insert(0, str(agent_dir))
    api = importlib.import_module("cg.api")

    data = json.loads(args.replay.read_text(encoding="utf-8"))
    agent = load_agent(agent_dir)
    decisions, native_scan, trials, engine_rows = audit_engine_path(
        data=data,
        agent=agent,
        rng_trials=args.rng_trials,
        max_decisions=args.max_decisions,
        select_context_enum=api.SelectContext,
        option_type_enum=api.OptionType,
    )

    public_rows = public_step_records_for_team(data, args.team)
    policy_determinism: list[dict[str, Any]] = []
    for step, slot, obs, action in public_rows:
        first, second, same, error = compare_policy_twice(agent, obs)
        policy_determinism.append(
            {
                "step": step,
                "slot": slot,
                "expected": action,
                "first": first,
                "second": second,
                "same": same,
                "error": error or "",
            }
        )

    if args.csv_output:
        write_csv(args.csv_output, engine_rows)

    report = render_report(
        data=data,
        replay_path=args.replay,
        agent_path=args.agent,
        team=args.team,
        decisions=decisions,
        native_scan=native_scan,
        trials=trials,
        public_policy_rows=public_rows,
        policy_determinism=policy_determinism,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report, encoding="utf-8")
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
