#!/usr/bin/env python3
import argparse
import importlib.util
import os
import sys
from collections import Counter
from pathlib import Path


def cg_override_parent() -> Path | None:
    """Optional parent directory containing a replacement `cg` package."""

    raw = os.environ.get("POKEMON_CG_OVERRIDE_PARENT", "").strip()
    if not raw:
        return None
    parent = Path(raw).resolve()
    if not (parent / "cg" / "__init__.py").exists():
        raise FileNotFoundError(f"POKEMON_CG_OVERRIDE_PARENT must contain cg/__init__.py: {parent}")
    return parent


def purge_cg_modules() -> None:
    for name in list(sys.modules):
        if name == "cg" or name.startswith("cg."):
            del sys.modules[name]


def read_deck(agent_dir: Path) -> list[int]:
    deck_path = agent_dir / "deck.csv"
    with deck_path.open() as file:
        deck = [int(line) for line in file.read().splitlines() if line.strip()]
    if len(deck) != 60:
        raise ValueError(f"{deck_path} must contain 60 cards, got {len(deck)}")
    return deck


def load_agent(agent_dir: Path, label: str):
    """Load an agent in a way that minimizes environment pollution.

    Restores sys.path and cwd after loading. This fixes leakage when
    evaluating multiple agents in the same process (common in leagues and
    gauntlets). Each agent gets its local cg/ and modules during import.
    """
    agent_dir = agent_dir.resolve()
    module_path = agent_dir / "main.py"
    if not module_path.exists():
        raise FileNotFoundError(module_path)

    cg_override = cg_override_parent()
    orig_sys_path = list(sys.path)
    old_cwd = os.getcwd()
    if cg_override is not None:
        purge_cg_modules()
    sys.path.insert(0, str(agent_dir))
    if cg_override is not None:
        sys.path.insert(0, str(cg_override))
    os.chdir(agent_dir)
    try:
        spec = importlib.util.spec_from_file_location(f"local_agent_{label}", module_path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Could not load {module_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        os.chdir(old_cwd)
        sys.path[:] = orig_sys_path  # restore exactly to prevent pollution

    if not hasattr(module, "agent"):
        raise AttributeError(f"{module_path} does not define agent(obs_dict)")
    return module.agent, read_deck(agent_dir)


def record_logs(obs: dict, stats: Counter) -> None:
    current = obs.get("current") or {}
    viewer = current.get("yourIndex", -1)
    for log in obs.get("logs") or []:
        player = log.get("playerIndex", -1)
        if player != viewer:
            continue
        log_type = log.get("type")
        card_id = log.get("cardId")
        if log_type == 10 and card_id is not None:
            stats[("play", player, card_id)] += 1
        elif log_type == 11 and card_id is not None:
            stats[("attach", player, card_id)] += 1
        elif log_type == 15:
            stats[("attack", player, card_id, log.get("attackId"))] += 1
        elif log_type == 22:
            stats[("coin", player, bool(log.get("head")))] += 1
        elif log_type == 6 and card_id is not None:
            stats[("move", player, card_id, log.get("fromArea"), log.get("toArea"))] += 1
        stats[("viewer", viewer, log_type)] += 1


def run_one(agent0, deck0, agent1, deck1, max_steps: int, collect_stats: bool = False):
    cg_override = cg_override_parent()
    if cg_override is not None and str(cg_override) not in sys.path:
        sys.path.insert(0, str(cg_override))
    from cg.game import battle_finish, battle_select, battle_start

    obs, start_data = battle_start(deck0, deck1)
    if obs is None:
        return {
            "result": 1 - start_data.errorPlayer if start_data.errorPlayer in (0, 1) else 2,
            "steps": 0,
            "error": f"battle_start errorPlayer={start_data.errorPlayer} errorType={start_data.errorType}",
        }

    agents = [agent0, agent1]
    stats = Counter()
    try:
        for step in range(max_steps):
            if collect_stats:
                record_logs(obs, stats)
            current = obs.get("current") or {}
            result = current.get("result", -1)
            if result != -1:
                return {"result": result, "steps": step, "error": "", "stats": stats}

            player_index = current.get("yourIndex")
            if player_index not in (0, 1):
                return {"result": 2, "steps": step, "error": f"invalid yourIndex={player_index}", "stats": stats}

            action = agents[player_index](obs)
            obs = battle_select(action)

        current = obs.get("current") or {}
        if collect_stats:
            record_logs(obs, stats)
        return {"result": current.get("result", -1), "steps": max_steps, "error": "max_steps", "stats": stats}
    except Exception as exc:
        current = obs.get("current") if isinstance(obs, dict) else {}
        player_index = (current or {}).get("yourIndex")
        loser = player_index if player_index in (0, 1) else -1
        winner = 1 - loser if loser in (0, 1) else 2
        return {"result": winner, "steps": -1, "error": f"{type(exc).__name__}: {exc}", "stats": stats}
    finally:
        battle_finish()


def run_games(agent0, deck0, agent1, deck1, games: int, max_steps: int, collect_stats: bool, quiet: bool, label: str):
    results = []
    for game_index in range(games):
        result = run_one(agent0, deck0, agent1, deck1, max_steps, collect_stats)
        results.append(result)
        if not quiet:
            print(
                f"{label} game={game_index + 1} result={result['result']} "
                f"steps={result['steps']} error={result['error']}"
            )
    return results


def print_stats(results) -> None:
    combined = Counter()
    for result in results:
        combined.update(result.get("stats") or Counter())
    interesting_cards = {
        1: "Basic Grass",
        2: "Basic Fire",
        11: "Mist",
        14: "Spiky",
        18: "Grow",
        344: "Dwebble",
        345: "Crustle",
        352: "Ethan Cyndaquil",
        353: "Ethan Quilava",
        354: "Ethan Typhlosion",
        1079: "Rare Candy",
        1086: "Poffin",
        1121: "Ultra Ball",
        1120: "Crushing Hammer",
        1122: "Pokegear",
        1147: "Jumbo",
        1152: "Poke Pad",
        1159: "Hero Cape",
        1182: "Boss",
        1192: "Carmine",
        1212: "Cook",
        1215: "Ethan Adventure",
        1227: "Lillie",
        1235: "Waitress",
        1264: "Battle Cage",
    }
    for kind in ("play", "attach"):
        print(kind + ":")
        for player in (0, 1):
            parts = []
            for card_id, name in interesting_cards.items():
                count = combined[(kind, player, card_id)]
                if count:
                    parts.append(f"p{player} {name}={count}")
            if parts:
                print("  " + ", ".join(parts))
    print("discard moves:")
    for player in (0, 1):
        parts = []
        for card_id, name in interesting_cards.items():
            count = sum(
                combined[("move", player, card_id, from_area, 3)]
                for from_area in range(1, 13)
            )
            if count:
                parts.append(f"p{player} {name}={count}")
        if parts:
            print("  " + ", ".join(parts))
    print(
        "coins:",
        f"p0 heads={combined[('coin', 0, True)]} tails={combined[('coin', 0, False)]}",
        f"p1 heads={combined[('coin', 1, True)]} tails={combined[('coin', 1, False)]}",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent0", default="submission")
    parser.add_argument("--agent1", default="submission")
    parser.add_argument("--games", type=int, default=10)
    parser.add_argument("--max-steps", type=int, default=1000)
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--stats", action="store_true")
    parser.add_argument("--swap", action="store_true", help="also run the same number of games with seats reversed")
    args = parser.parse_args()

    agent0, deck0 = load_agent(Path(args.agent0), "p0")
    agent1, deck1 = load_agent(Path(args.agent1), "p1")

    results = run_games(agent0, deck0, agent1, deck1, args.games, args.max_steps, args.stats, args.quiet, "forward")

    counts = Counter(result["result"] for result in results)
    errors = [result["error"] for result in results if result["error"]]
    print(f"summary p0={counts[0]} p1={counts[1]} draw={counts[2]} unfinished={counts[-1]}")

    if args.swap:
        swapped_results = run_games(
            agent1, deck1, agent0, deck0, args.games, args.max_steps, args.stats, args.quiet, "swapped"
        )
        swapped_counts = Counter(result["result"] for result in swapped_results)
        errors.extend(result["error"] for result in swapped_results if result["error"])
        original_agent0 = counts[0] + swapped_counts[1]
        original_agent1 = counts[1] + swapped_counts[0]
        draws = counts[2] + swapped_counts[2]
        unfinished = counts[-1] + swapped_counts[-1]
        print(
            f"swapped-summary original_agent0={original_agent0} "
            f"original_agent1={original_agent1} draw={draws} unfinished={unfinished}"
        )
        results.extend(swapped_results)

    if args.stats:
        print_stats(results)
    if errors:
        print("errors:")
        for error in errors:
            print(error)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
