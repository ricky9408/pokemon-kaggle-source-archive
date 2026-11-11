#!/usr/bin/env python3
"""Audit Dudunsparce Run Away Draw safety in an agent.

This catches two high-impact rules mistakes:
- Using Dudunsparce's ability when it is our only Pokemon in play.
- Attaching energy to Dudunsparce/Dunsparce engine pieces instead of attackers.

The dynamic import loads the agent's bundled ``cg`` package, so run this in the
same Linux smoke environment used for submission validation when needed.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace


@dataclass(frozen=True)
class AuditCase:
    name: str
    score: float
    expectation: str
    passed: bool


def load_agent(agent_dir: Path):
    main_py = agent_dir / "main.py"
    if not main_py.exists():
        raise FileNotFoundError(f"missing main.py under {agent_dir}")

    module_name = f"_dudun_audit_{agent_dir.name}"
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


def pokemon(card_id: int, serial: int = 1, energy_ids: tuple[int, ...] = (), tool_ids: tuple[int, ...] = ()):
    energy_cards = [SimpleNamespace(id=cid, serial=100 + i, playerIndex=0) for i, cid in enumerate(energy_ids)]
    tools = [SimpleNamespace(id=cid, serial=200 + i, playerIndex=0) for i, cid in enumerate(tool_ids)]
    return SimpleNamespace(
        id=card_id,
        serial=serial,
        hp=100,
        maxHp=100,
        appearThisTurn=False,
        energies=list(energy_ids),
        energyCards=energy_cards,
        tools=tools,
        preEvolution=[],
    )


def player_state(active, bench, hand_count: int = 5):
    return SimpleNamespace(
        active=active,
        bench=bench,
        benchMax=5,
        deckCount=30,
        discard=[],
        prize=[None] * 6,
        handCount=hand_count,
        hand=[],
        poisoned=False,
        burned=False,
        asleep=False,
        paralyzed=False,
        confused=False,
    )


def observation(module, my_state, option):
    opponent = player_state([pokemon(module.ABRA, serial=90)], [], hand_count=5)
    state = SimpleNamespace(
        turn=3,
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
        players=[my_state, opponent],
    )
    select = SimpleNamespace(
        context=module.SelectContext.MAIN,
        option=[option],
        minCount=1,
        maxCount=1,
    )
    return SimpleNamespace(current=state, select=select)


def score_ability(module, my_state, area, index) -> float:
    option = SimpleNamespace(
        type=module.OptionType.ABILITY,
        area=area,
        index=index,
        playerIndex=0,
    )
    obs = observation(module, my_state, option)
    field_counts = module.count_cards([card for _, _, card in module.all_field_pokemon(my_state)])
    return module.score_option(obs, option, field_counts, Counter(), Counter())


def run_checks(module) -> tuple[list[str], list[AuditCase]]:
    failures: list[str] = []
    cases: list[AuditCase] = []
    dunsparce_ids = set(getattr(module, "DUNSPARCE_IDS", set()))
    if not dunsparce_ids and hasattr(module, "DUNSPARCE"):
        dunsparce_ids = {module.DUNSPARCE}
    if not dunsparce_ids:
        failures.append("agent does not expose DUNSPARCE_IDS or DUNSPARCE for engine safety checks")

    solo = player_state([pokemon(module.DUDUNSPARCE)], [], hand_count=3)
    solo_score = score_ability(module, solo, module.AreaType.ACTIVE, 0)
    solo_passed = solo_score <= -100000
    cases.append(
        AuditCase(
            "lethal_solo_active_dudunsparce",
            solo_score,
            "must be strongly negative because Run Away Draw leaves no Pokemon in play",
            solo_passed,
        )
    )
    if not solo_passed:
        failures.append(f"solo Dudunsparce ability score must be strongly negative; got {solo_score}")

    active_with_backup = player_state(
        [pokemon(module.DUDUNSPARCE)],
        [pokemon(module.ALAKAZAM)],
        hand_count=3,
    )
    active_with_backup_score = score_ability(module, active_with_backup, module.AreaType.ACTIVE, 0)
    active_with_backup_passed = active_with_backup_score > 0
    cases.append(
        AuditCase(
            "nonlethal_active_dudunsparce_with_bench_backup",
            active_with_backup_score,
            "should remain usable because a bench Pokemon prevents immediate loss",
            active_with_backup_passed,
        )
    )
    if not active_with_backup_passed:
        failures.append(
            "active Dudunsparce ability with a bench backup should remain usable; "
            f"got {active_with_backup_score}"
        )

    safe = player_state([pokemon(module.ALAKAZAM)], [pokemon(module.DUDUNSPARCE)], hand_count=3)
    safe_score = score_ability(module, safe, module.AreaType.BENCH, 0)
    safe_passed = safe_score > 0
    cases.append(
        AuditCase(
            "nonlethal_bench_dudunsparce_with_active_backup",
            safe_score,
            "should remain usable because active Pokemon stays in play",
            safe_passed,
        )
    )
    if not safe_passed:
        failures.append(f"bench Dudunsparce ability with another Pokemon should remain usable; got {safe_score}")

    attached = player_state(
        [pokemon(module.ALAKAZAM)],
        [pokemon(module.DUDUNSPARCE, energy_ids=(module.TELEPATH_PSYCHIC,))],
        hand_count=3,
    )
    attached_score = score_ability(module, attached, module.AreaType.BENCH, 0)
    attached_discount_passed = attached_score < safe_score
    cases.append(
        AuditCase(
            "nonlethal_attached_energy_dudunsparce_discount",
            attached_score,
            "should be below clean Dudunsparce because shuffling attached energy is costly",
            attached_discount_passed,
        )
    )
    if not attached_discount_passed:
        failures.append(
            "attached-energy Dudunsparce ability should be discounted below a clean "
            f"Dudunsparce ability; got attached={attached_score}, clean={safe_score}"
        )
    attached_usable_passed = attached_score > 0
    cases.append(
        AuditCase(
            "nonlethal_attached_energy_dudunsparce_still_usable",
            attached_score,
            "should remain usable when not solo despite the energy-loss discount",
            attached_usable_passed,
        )
    )
    if not attached_usable_passed:
        failures.append(f"attached-energy Dudunsparce ability should remain usable when not solo; got {attached_score}")

    attach_dudun = module.energy_attach_score(
        module.TELEPATH_PSYCHIC,
        pokemon(module.DUDUNSPARCE),
        False,
        Counter(),
    )
    attach_dudun_passed = attach_dudun < 0
    cases.append(
        AuditCase(
            "manual_energy_attach_to_dudunsparce",
            attach_dudun,
            "should be negative because Dudunsparce usually returns itself to deck",
            attach_dudun_passed,
        )
    )
    if not attach_dudun_passed:
        failures.append(f"energy attach to Dudunsparce should be negative; got {attach_dudun}")

    if dunsparce_ids:
        attach_dunsparce = module.energy_attach_score(
            module.TELEPATH_PSYCHIC,
            pokemon(next(iter(dunsparce_ids))),
            False,
            Counter(),
        )
        attach_dunsparce_passed = attach_dunsparce < 0
        cases.append(
            AuditCase(
                "manual_energy_attach_to_dunsparce",
                attach_dunsparce,
                "should be negative because Dunsparce is an engine piece, not an attacker",
                attach_dunsparce_passed,
            )
        )
        if not attach_dunsparce_passed:
            failures.append(f"energy attach to Dunsparce should be negative; got {attach_dunsparce}")

    attach_alakazam = module.energy_attach_score(
        module.TELEPATH_PSYCHIC,
        pokemon(module.ALAKAZAM),
        True,
        Counter({module.ALAKAZAM: 1}),
    )
    attach_alakazam_passed = attach_alakazam > 0
    cases.append(
        AuditCase(
            "manual_energy_attach_to_active_alakazam",
            attach_alakazam,
            "should remain positive for the main attacker",
            attach_alakazam_passed,
        )
    )
    if not attach_alakazam_passed:
        failures.append(f"energy attach to Alakazam should remain positive; got {attach_alakazam}")

    return failures, cases


def render_report(agent: Path, archive: str | None, failures: list[str], cases: list[AuditCase]) -> str:
    result = "FAIL" if failures else "PASS"
    lines = [
        "# Dudunsparce Safety Audit",
        "",
        f"- Result: {result}",
        f"- Agent: `{agent}`",
    ]
    if archive:
        lines.append(f"- Archive: `{archive}`")
    lines.extend(
        [
            "",
            "## Cases",
            "",
            "| Case | Score | Passed | Expectation |",
            "| --- | ---: | --- | --- |",
        ]
    )
    for case in cases:
        lines.append(
            f"| `{case.name}` | {case.score:.1f} | {'yes' if case.passed else 'no'} | {case.expectation} |"
        )
    if failures:
        lines.extend(["", "## Failures", ""])
        lines.extend(f"- {failure}" for failure in failures)
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", required=True, type=Path)
    parser.add_argument("--archive", help="archive name to include in the optional markdown report")
    parser.add_argument("--output", type=Path, help="write a markdown audit report")
    args = parser.parse_args()

    module = load_agent(args.agent)
    failures, cases = run_checks(module)
    report = render_report(args.agent, args.archive, failures, cases)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    if failures:
        print("Dudunsparce safety audit FAILED:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(f"Dudunsparce safety audit passed for {args.agent}")
    for case in cases:
        print(f"- {case.name}: score={case.score:.1f} passed={case.passed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
