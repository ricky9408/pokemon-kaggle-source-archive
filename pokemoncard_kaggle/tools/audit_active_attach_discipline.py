#!/usr/bin/env python3
"""Audit active-Alakazam energy attachment restraint.

The v112 public failure showed that forcing active Psychic attachment into a
high setup-priority band can destroy the stronger v107 sequencing. This audit
therefore checks the score layer directly: active Psychic attachment should stay
available, but it must not outrank core Hilda/Dawn/Poffin/Rare Candy setup
choices and must not weaken the Dudunsparce no-energy discipline.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from collections import Counter
from pathlib import Path
from types import SimpleNamespace


def load_agent(agent_dir: Path):
    main_py = agent_dir / "main.py"
    if not main_py.exists():
        raise FileNotFoundError(f"missing main.py under {agent_dir}")

    module_name = f"_active_attach_audit_{agent_dir.name}"
    sys.path.insert(0, str(agent_dir))
    try:
        spec = importlib.util.spec_from_file_location(module_name, main_py)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot load import spec for {main_py}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        try:
            sys.path.remove(str(agent_dir))
        except ValueError:
            pass


def pokemon(card_id: int, hp: int, serial: int):
    return SimpleNamespace(
        id=card_id,
        serial=serial,
        hp=hp,
        maxHp=hp,
        appearThisTurn=False,
        energies=[],
        energyCards=[],
        tools=[],
        preEvolution=[],
    )


def make_obs(module, hand_card_id: int, target_card_id: int | None = None):
    my_active = pokemon(target_card_id or module.ALAKAZAM, hp=310, serial=1)
    bench = [pokemon(module.DUDUNSPARCE, hp=100, serial=2), pokemon(module.ABRA, hp=70, serial=3)]
    my_state = SimpleNamespace(
        active=[my_active],
        bench=bench,
        benchMax=5,
        deckCount=30,
        discard=[],
        prize=[None] * 6,
        handCount=10,
        hand=[SimpleNamespace(id=hand_card_id, serial=10, playerIndex=0)],
        poisoned=False,
        burned=False,
        asleep=False,
        paralyzed=False,
        confused=False,
    )
    op_state = SimpleNamespace(
        active=[pokemon(module.ABRA, hp=120, serial=90)],
        bench=[],
        benchMax=5,
        deckCount=30,
        discard=[],
        prize=[None] * 6,
        handCount=5,
        hand=[],
        poisoned=False,
        burned=False,
        asleep=False,
        paralyzed=False,
        confused=False,
    )
    state = SimpleNamespace(
        turn=5,
        turnActionCount=0,
        yourIndex=0,
        firstPlayer=0,
        supporterPlayed=False,
        stadiumPlayed=False,
        energyAttached=False,
        retreated=False,
        result=-1,
        stadium=[],
        looking=None,
        players=[my_state, op_state],
    )
    return SimpleNamespace(current=state, select=SimpleNamespace(context=module.SelectContext.MAIN))


def attach_score(module, energy_id: int, target_card_id: int = 743) -> float:
    obs = make_obs(module, energy_id, target_card_id)
    option = SimpleNamespace(
        type=module.OptionType.ATTACH,
        area=module.AreaType.HAND,
        index=0,
        playerIndex=0,
        inPlayArea=module.AreaType.ACTIVE,
        inPlayIndex=0,
    )
    field_counts = Counter({module.ALAKAZAM: 1, module.DUDUNSPARCE: 1, module.ABRA: 1})
    return module.score_option(obs, option, field_counts, Counter({energy_id: 1}), Counter())


def play_score(module, card_id: int, extra_hand: Counter[int] | None = None) -> float:
    obs = make_obs(module, card_id)
    option = SimpleNamespace(type=module.OptionType.PLAY, index=0, playerIndex=0)
    field_counts = Counter({module.ALAKAZAM: 1, module.DUDUNSPARCE: 1, module.ABRA: 1})
    hand_counts = Counter({card_id: 1})
    if extra_hand:
        hand_counts.update(extra_hand)
    return module.score_option(obs, option, field_counts, hand_counts, Counter())


def run_checks(module, max_setup_contested_attach: float) -> list[str]:
    failures: list[str] = []
    active_basic = attach_score(module, module.BASIC_PSYCHIC)
    active_telepath = attach_score(module, module.TELEPATH_PSYCHIC)
    if active_basic <= 0:
        failures.append(f"active Basic Psychic attach should remain available: {active_basic}")
    if active_telepath <= 0:
        failures.append(f"active Telepath Psychic attach should remain available: {active_telepath}")
    if active_basic > max_setup_contested_attach:
        failures.append(
            "active Basic Psychic attach is in the high setup-priority band "
            f"without public-anchor support: {active_basic} > {max_setup_contested_attach}"
        )
    if active_telepath > max_setup_contested_attach:
        failures.append(
            "active Telepath Psychic attach is in the high setup-priority band "
            f"without public-anchor support: {active_telepath} > {max_setup_contested_attach}"
        )

    ceilings = [
        ("Hilda", play_score(module, module.HILDA)),
        ("Dawn", play_score(module, module.DAWN)),
        ("Poffin", play_score(module, module.BUDDY_BUDDY_POFFIN)),
        ("Rare Candy", play_score(module, module.RARE_CANDY, Counter({module.ALAKAZAM: 1}))),
    ]
    for card_name, score in ceilings:
        if active_basic >= score or active_telepath >= score:
            failures.append(
                f"active attach should stay below {card_name}; "
                f"basic={active_basic}, telepath={active_telepath}, play={score}"
            )

    dudun_basic = attach_score(module, module.BASIC_PSYCHIC, target_card_id=module.DUDUNSPARCE)
    if dudun_basic >= 0:
        failures.append(f"Dudunsparce active attach should remain negative: {dudun_basic}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", required=True, type=Path)
    parser.add_argument(
        "--max-setup-contested-attach",
        type=float,
        default=30000,
        help=(
            "Maximum active Alakazam Psychic attach score in the synthetic "
            "setup-contested state. Higher values require separate public-anchor evidence."
        ),
    )
    args = parser.parse_args()

    module = load_agent(args.agent)
    failures = run_checks(module, args.max_setup_contested_attach)
    if failures:
        print("Active attach discipline audit FAILED:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(f"Active attach discipline audit passed for {args.agent}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
