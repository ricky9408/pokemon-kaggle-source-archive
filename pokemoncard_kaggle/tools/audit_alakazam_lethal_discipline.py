#!/usr/bin/env python3
"""Audit that an agent takes an available Alakazam knockout.

Alakazam's attack damage scales with hand size. If the agent plays a setup card
before attacking, it can spend a card from hand and lose the knockout. This
audit checks the score layer directly: when Alakazam already has lethal damage
on the opposing Active Pokemon, ATTACK must outrank common setup PLAY options.
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

    module_name = f"_lethal_audit_{agent_dir.name}"
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


def make_obs(module, hand_card_id: int, attack_id: int, hand_count: int = 10):
    my_active = pokemon(module.ALAKAZAM, hp=310, serial=1)
    op_active = pokemon(module.ABRA, hp=120, serial=90)
    my_state = SimpleNamespace(
        active=[my_active],
        bench=[pokemon(module.DUDUNSPARCE, hp=100, serial=2)],
        benchMax=5,
        deckCount=30,
        discard=[],
        prize=[None] * 6,
        handCount=hand_count,
        hand=[SimpleNamespace(id=hand_card_id, serial=10, playerIndex=0)],
        poisoned=False,
        burned=False,
        asleep=False,
        paralyzed=False,
        confused=False,
    )
    op_state = SimpleNamespace(
        active=[op_active],
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
    play = SimpleNamespace(type=module.OptionType.PLAY, index=0, playerIndex=0)
    attack = SimpleNamespace(type=module.OptionType.ATTACK, attackId=attack_id, playerIndex=0)
    select = SimpleNamespace(
        context=module.SelectContext.MAIN,
        option=[play, attack],
        minCount=1,
        maxCount=1,
    )
    return SimpleNamespace(current=state, select=select), play, attack, my_state


def run_checks(module, mode: str) -> list[str]:
    failures: list[str] = []
    field_counts = Counter({module.ALAKAZAM: 1, module.DUDUNSPARCE: 1})
    setup_field_counts = Counter({module.ALAKAZAM: 1, module.DUDUNSPARCE: 1, module.ABRA: 1})
    required_attack_over = [("Hilda", module.HILDA), ("Dawn", module.DAWN), ("Poke Pad", module.POKE_PAD), ("Rare Candy", module.RARE_CANDY)]
    required_setup_over: list[tuple[str, int]] = []
    if mode == "conservative":
        required_attack_over = [("Poke Pad", module.POKE_PAD)]
        required_setup_over = [("Hilda", module.HILDA), ("Dawn", module.DAWN)]

    for card_name, card_id in required_attack_over:
        obs, play, attack, my_state = make_obs(module, card_id, attack_id=-1, hand_count=10)
        hand_counts = Counter({card_id: 1})
        play_score = module.score_option(obs, play, field_counts, hand_counts, Counter())
        attack_score = module.score_option(obs, attack, field_counts, hand_counts, Counter())
        if attack_score <= play_score:
            failures.append(
                f"Alakazam lethal ATTACK should outrank {card_name} PLAY; "
                f"attack={attack_score}, play={play_score}"
            )
        damage = module.attack_damage(my_state.active[0], obs.current.players[1].active[0], -1, my_state.handCount)
        if damage < obs.current.players[1].active[0].hp:
            failures.append(f"test setup no longer has lethal Alakazam damage; damage={damage}")

    for card_name, card_id in required_setup_over:
        obs, play, attack, _ = make_obs(module, card_id, attack_id=-1, hand_count=10)
        hand_counts = Counter({card_id: 1})
        play_score = module.score_option(obs, play, setup_field_counts, hand_counts, Counter())
        attack_score = module.score_option(obs, attack, setup_field_counts, hand_counts, Counter())
        if attack_score >= play_score:
            failures.append(
                f"Conservative Alakazam discipline should not outrank {card_name} PLAY; "
                f"attack={attack_score}, play={play_score}"
            )
        if attack_score >= 100000:
            failures.append(
                f"Conservative Alakazam discipline score is too broad; "
                f"attack={attack_score} should stay below 100000"
            )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", required=True, type=Path)
    parser.add_argument("--mode", choices=("broad", "conservative"), default="broad")
    args = parser.parse_args()

    module = load_agent(args.agent)
    failures = run_checks(module, args.mode)
    if failures:
        print(f"Alakazam lethal discipline audit FAILED ({args.mode}):")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(f"Alakazam lethal discipline audit passed for {args.agent} ({args.mode})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
