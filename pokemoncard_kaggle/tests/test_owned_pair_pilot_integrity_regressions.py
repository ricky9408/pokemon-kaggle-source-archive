from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from evaluation_v5_1.owned_pair_pilot import OwnedPairPilotError, add_canonical_root, validate_design_freeze
from evaluation_v5_1.canonical import canonical_sha256
from tests.test_owned_pair_pilot_artifacts import build_all, ts, write_json
from tools.owned_pair_pilot_artifacts import (
    ArtifactComposerError,
    build_future_inventory,
    collect_baseline_inventory,
)


def _episode_csv(submission_ref: str, *, include_future: bool = False) -> str:
    rows = [
        f"old-{submission_ref},2026-07-15 01:02:00.000000,2026-07-15 01:03:00.000000,EpisodeState.COMPLETED,EpisodeType.EPISODE_TYPE_PUBLIC",
    ]
    if include_future:
        rows.append(
            f"new-{submission_ref},2026-07-15 01:06:00.000000,2026-07-15 01:07:00.000000,EpisodeState.COMPLETED,EpisodeType.EPISODE_TYPE_PUBLIC"
        )
    return "\n".join(["id,createTime,endTime,state,type", *rows])


def _future_fixture(tmp_path: Path) -> tuple[dict, Path, Path, Path, dict[str, Path]]:
    design, _, _, _, design_path, local_path, activation_path = build_all(tmp_path)
    baseline = collect_baseline_inventory(
        design_path,
        local_path,
        activation_path,
        collected_at_utc=ts(5),
        episode_fetcher=lambda ref: _episode_csv(ref),
    )
    observation = collect_baseline_inventory(
        design_path,
        local_path,
        activation_path,
        collected_at_utc=ts(20),
        episode_fetcher=lambda ref: _episode_csv(ref, include_future=True),
    )
    baseline_path = tmp_path / "baseline.json"
    observation_path = tmp_path / "observation.json"
    write_json(baseline_path, baseline)
    write_json(observation_path, observation)

    replay_dirs = {pair["pair_id"]: tmp_path / f"replays-{pair['pair_id']}" for pair in design["pairs"]}
    for pair in design["pairs"]:
        replay_path = replay_dirs[pair["pair_id"]] / f"episode-new-{pair['submission_ref']}-replay.json"
        write_json(
            replay_path,
            {
                "info": {"EpisodeId": f"new-{pair['submission_ref']}", "TeamNames": ["GarlicToday", "Opponent"]},
                "rewards": [-1, 1],
                "statuses": ["DONE", "DONE"],
                "steps": [],
            },
        )
    return design, design_path, local_path, activation_path, replay_dirs | {
        "baseline": baseline_path,
        "observation": observation_path,
    }


def test_rehashed_schedule_cannot_substitute_a_control_seed_seat_cell(tmp_path: Path) -> None:
    design, *_ = build_all(tmp_path)
    changed = deepcopy(design)
    target = next(
        cell
        for cell in changed["schedule"]["cells"]
        if cell["pair_id"] == "v160" and cell["control_label"] == "grok_v123" and cell["seat"] == 0
    )
    replacement = next(control for control in changed["controls"] if control["control_label"] == "claude_v103")
    target.update(
        {
            "cell_id": "v160:claude_v103:202:1",
            "control_label": replacement["control_label"],
            "control_role": replacement["role"],
            "control_archive_sha256": replacement["archive_sha256"],
            "seed": 202,
            "seat": 1,
        }
    )
    changed["schedule"]["seed_root_sha256"] = canonical_sha256(
        sorted({cell["seed"] for cell in changed["schedule"]["cells"]})
    )
    changed = add_canonical_root(changed, "design_root_sha256")

    with pytest.raises(OwnedPairPilotError):
        validate_design_freeze(changed)


def test_authenticated_inventory_rejects_episode_ending_after_collection(tmp_path: Path) -> None:
    _, _, _, _, design_path, local_path, activation_path = build_all(tmp_path)

    def fetcher(submission_ref: str) -> str:
        return "\n".join(
            [
                "id,createTime,endTime,state,type",
                f"late-{submission_ref},2026-07-15 01:19:00.000000,2026-07-15 01:21:00.000000,EpisodeState.COMPLETED,EpisodeType.EPISODE_TYPE_PUBLIC",
            ]
        )

    with pytest.raises(ArtifactComposerError, match="ends after collected_at_utc"):
        collect_baseline_inventory(
            design_path,
            local_path,
            activation_path,
            collected_at_utc=ts(20),
            episode_fetcher=fetcher,
        )


@pytest.mark.parametrize(
    ("state", "episode_type"),
    [
        ("EpisodeState.NOT_COMPLETED", "EpisodeType.EPISODE_TYPE_PUBLIC"),
        ("EpisodeState.COMPLETED", "EpisodeType.EPISODE_TYPE_NOT_PUBLIC"),
    ],
)
def test_inventory_filter_requires_exact_completed_public_enums(
    tmp_path: Path, state: str, episode_type: str
) -> None:
    _, _, _, _, design_path, local_path, activation_path = build_all(tmp_path)

    def fetcher(submission_ref: str) -> str:
        return "\n".join(
            [
                "id,createTime,endTime,state,type",
                f"not-eligible-{submission_ref},2026-07-15 01:02:00.000000,2026-07-15 01:03:00.000000,{state},{episode_type}",
            ]
        )

    baseline = collect_baseline_inventory(
        design_path,
        local_path,
        activation_path,
        collected_at_utc=ts(20),
        episode_fetcher=fetcher,
    )
    for inventory in baseline["inventories"]:
        assert inventory["completed_public_count"] == 0
        assert inventory["pre_t0_public_episode_ids"] == []
        assert inventory["future_metadata_episode_ids"] == []


def test_rehashed_stored_snapshot_rejects_duplicate_episode_ids(tmp_path: Path) -> None:
    _, design_path, local_path, activation_path, paths = _future_fixture(tmp_path)
    baseline = json.loads(paths["baseline"].read_text(encoding="utf-8"))
    inventory = baseline["inventories"][0]
    inventory["query_inventory"].insert(1, deepcopy(inventory["query_inventory"][0]))
    inventory["query_inventory_root_sha256"] = canonical_sha256(inventory["query_inventory"])
    baseline = add_canonical_root(baseline, "baseline_root_sha256")
    bad_baseline_path = tmp_path / "baseline-duplicate.json"
    write_json(bad_baseline_path, baseline)

    with pytest.raises(ArtifactComposerError, match="duplicate episode IDs"):
        build_future_inventory(
            design_path,
            local_path,
            activation_path,
            bad_baseline_path,
            paths["observation"],
            replay_dirs={key: value for key, value in paths.items() if key.startswith("v")},
        )


def test_failed_agent_status_cannot_be_paired_with_win(tmp_path: Path) -> None:
    _, design_path, local_path, activation_path, paths = _future_fixture(tmp_path)
    replay_path = paths["v160"] / "episode-new-160-replay.json"
    replay = json.loads(replay_path.read_text(encoding="utf-8"))
    replay["rewards"] = [1, -1]
    replay["statuses"] = ["ERROR", "DONE"]
    write_json(replay_path, replay)

    with pytest.raises(ArtifactComposerError, match="failure cannot be a win"):
        build_future_inventory(
            design_path,
            local_path,
            activation_path,
            paths["baseline"],
            paths["observation"],
            replay_dirs={key: value for key, value in paths.items() if key.startswith("v")},
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("rewards", []),
        ("rewards", [1]),
        ("rewards", [1, -1, 0]),
        ("statuses", ["DONE"]),
        ("statuses", ["DONE", "DONE", "DONE"]),
        ("statuses", ["DONE", 0]),
    ],
)
def test_replay_reward_and_status_arrays_are_strictly_shaped_and_typed(
    tmp_path: Path, field: str, value: list[object]
) -> None:
    _, design_path, local_path, activation_path, paths = _future_fixture(tmp_path)
    replay_path = paths["v160"] / "episode-new-160-replay.json"
    replay = json.loads(replay_path.read_text(encoding="utf-8"))
    replay[field] = value
    write_json(replay_path, replay)

    with pytest.raises(ArtifactComposerError, match="replay (reward|terminal status|agent status)"):
        build_future_inventory(
            design_path,
            local_path,
            activation_path,
            paths["baseline"],
            paths["observation"],
            replay_dirs={key: value for key, value in paths.items() if key.startswith("v")},
        )
