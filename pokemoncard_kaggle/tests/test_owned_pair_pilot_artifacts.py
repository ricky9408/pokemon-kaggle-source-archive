from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from evaluation_v5_1.owned_pair_pilot import COMPLETE, add_canonical_root, validate_rehearsal
from tools.owned_pair_pilot_artifacts import (
    ArtifactComposerError,
    build_activation,
    build_design,
    build_hosted,
    build_local,
    build_future_inventory,
    collect_baseline_inventory,
)


BASE = datetime(2026, 7, 15, 1, 0, tzinfo=timezone.utc)


def ts(minutes: int) -> str:
    return (BASE + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def create_sources(tmp_path: Path) -> tuple[Path, Path, dict, dict]:
    pair_specs = [
        ("v160", "pair-v160.tar.gz", 160, b"pair-v160"),
        ("v161", "pair-v161.tar.gz", 161, b"pair-v161"),
    ]
    sources = []
    units = []
    pair_hashes = {}
    for label, archive_name, submission_ref, content in pair_specs:
        archive = tmp_path / archive_name
        archive.write_bytes(content)
        digest = file_sha(archive)
        pair_hashes[label] = digest
        sources.append(
            {
                "label": label,
                "submission_ref": submission_ref,
                "archive_path": archive_name,
                "replay_dir": "unused",
                "max_games": 0,
                "window_quality": "future_only_after_activation",
            }
        )
        units.append(
            {
                "archive_path": archive_name,
                "archive_sha256": digest,
                "submission_id": str(submission_ref),
            }
        )
    sources_path = tmp_path / "sources.json"
    write_json(sources_path, {"schema": "public_transfer_sources_v1", "sources": sources})

    controls = []
    control_specs = [
        ("claude_v103", "claude", "claude.tar.gz"),
        ("grok_v123", "grok", "grok.tar.gz"),
        ("top_a", "top_tier", "top-a.tar.gz"),
        ("top_b", "top_tier", "top-b.tar.gz"),
    ]
    control_hashes = {}
    for label, role, archive_name in control_specs:
        archive = tmp_path / archive_name
        archive.write_bytes(label.encode("ascii"))
        digest = file_sha(archive)
        control_hashes[label] = digest
        controls.append(
            {
                "label": label,
                "role": role,
                "archive_path": archive_name,
                "archive_sha256": digest,
            }
        )

    engine_dir = tmp_path / "engine"
    library = engine_dir / "cg" / "libcg.so"
    library.parent.mkdir(parents=True)
    library.write_bytes(b"engine-library")
    manifest = {"libcg_sha256": file_sha(library), "patch": {"patch_version": "test-v1"}}
    manifest_path = engine_dir / "build_manifest.json"
    write_json(manifest_path, manifest)
    runner = tmp_path / "runner.py"
    runner.write_text("print('runner')\n", encoding="utf-8")

    prereg = {
        "schema": "owned_pair_development_design_v1",
        "authority": False,
        "candidate_development_authorized": False,
        "sealed_holdout_access_authorized": False,
        "submission_authorized": False,
        "design_frozen_at_ns": int(BASE.timestamp()) * 1_000_000_000,
        "units": units,
        "controls": controls,
        "local_evaluator": {
            "source_config_sha256": file_sha(sources_path),
            "engine_manifest_path": "engine/build_manifest.json",
            "engine_manifest_sha256": file_sha(manifest_path),
            "engine_library_sha256": file_sha(library),
            "runner_path": "runner.py",
            "runner_sha256": file_sha(runner),
            "seeds": [101],
            "seats": [0, 1],
            "required_cells_per_unit": 8,
        },
        "future_hosted_protocol": {"required_games_per_unit": 2},
    }
    prereg_path = tmp_path / "prereg.json"
    write_json(prereg_path, prereg)
    return prereg_path, sources_path, manifest, {"pairs": pair_hashes, "controls": control_hashes}


def make_panel(manifest: dict, hashes: dict, *, timing: float = 0.1) -> dict:
    controls = ["claude_v103", "grok_v123", "top_a", "top_b"]
    rows = []
    for pair_index, pair in enumerate(("v160", "v161")):
        for control_index, control in enumerate(controls):
            for anchor_left in (0, 1):
                left = pair if anchor_left else control
                right = control if anchor_left else pair
                rows.append(
                    {
                        "anchor": pair,
                        "control": control,
                        "seed": 101,
                        "anchor_left": anchor_left,
                        "left": left,
                        "right": right,
                        "winner": (pair_index + control_index + anchor_left) % 3,
                        "steps": 100 + pair_index * 20 + control_index * 2 + anchor_left,
                        "error": None,
                        "transcript_sha256": hashlib.sha256(
                            f"{pair}:{control}:{anchor_left}".encode("ascii")
                        ).hexdigest(),
                        "max_action_seconds": timing,
                        "max_action_seconds_by_label": {left: timing, right: timing / 2},
                    }
                )
    rows.sort(key=lambda row: (row["anchor"], row["control"], row["seed"], row["anchor_left"]))
    return {
        "schema": "seeded_transfer_feature_panel_v1",
        "engine_manifest": manifest,
        "baseline_label": "v160",
        "seeds": [101],
        "controls": controls,
        "source_identities": {
            pair: {"archive_sha256": hashes["pairs"][pair]} for pair in ("v160", "v161")
        },
        "rows": rows,
        "features": {},
        "errors": 0,
        "complete": True,
    }


def build_all(tmp_path: Path) -> tuple[dict, dict, dict, dict, Path, Path, Path]:
    prereg_path, sources_path, manifest, hashes = create_sources(tmp_path)
    design = build_design(prereg_path, sources_path, repository_root=tmp_path)
    design_path = tmp_path / "design.json"
    write_json(design_path, design)

    primary_path = tmp_path / "primary.json"
    repeat_path = tmp_path / "repeat.json"
    write_json(primary_path, make_panel(manifest, hashes, timing=0.1))
    write_json(repeat_path, make_panel(manifest, hashes, timing=9.9))
    local = build_local(
        design_path,
        primary_path,
        repeat_path,
        started_at_utc=ts(1),
        completed_at_utc=ts(2),
        repository_root=tmp_path,
    )
    local_path = tmp_path / "local.json"
    write_json(local_path, local)
    activation = build_activation(
        design_path,
        local_path,
        activation_frozen_at_utc=ts(3),
        t0_utc=ts(4),
    )
    activation_path = tmp_path / "activation.json"
    write_json(activation_path, activation)

    inventory = []
    for pair_index, pair in enumerate(design["pairs"]):
        for episode_index in range(3):
            minute = 5 + pair_index * 10 + episode_index
            inventory.append(
                {
                    "pair_id": pair["pair_id"],
                    "submission_ref": pair["submission_ref"],
                    "submission_id": pair["submission_id"],
                    "archive_sha256": pair["archive_sha256"],
                    "episode_id": f"{pair['pair_id']}-{episode_index}",
                    "created_at_utc": ts(minute),
                    "started_at_utc": ts(minute + 1),
                    "ended_at_utc": ts(minute + 2),
                    "outcome": "WIN" if episode_index % 2 else "LOSS",
                    "seat": episode_index % 2,
                    "agent_status": "DONE",
                    "runtime_or_package_failure": False,
                    "source_sha256": hashlib.sha256(
                        f"source:{pair['pair_id']}:{episode_index}".encode("ascii")
                    ).hexdigest(),
                }
            )
    inventory_path = tmp_path / "inventory.json"
    write_json(inventory_path, inventory)
    hosted = build_hosted(design_path, local_path, activation_path, inventory_path)
    return design, local, activation, hosted, design_path, local_path, activation_path


def test_composer_builds_complete_zero_authority_rehearsal(tmp_path: Path) -> None:
    design, local, activation, hosted, *_ = build_all(tmp_path)
    receipt = validate_rehearsal(design, local, activation, hosted)
    assert receipt["decision"] == COMPLETE
    assert receipt["predictive_validity_authorized"] is False
    assert receipt["submission_authorized"] is False
    assert design["pre_registration_sha256"] == file_sha(tmp_path / "prereg.json")
    assert local["reproducibility"]["semantic_reproduction_equal"] is True
    assert len(hosted["rows"]) == 4


def test_composer_rejects_repeat_semantic_drift(tmp_path: Path) -> None:
    prereg_path, sources_path, manifest, hashes = create_sources(tmp_path)
    design = build_design(prereg_path, sources_path, repository_root=tmp_path)
    design_path = tmp_path / "design.json"
    write_json(design_path, design)
    primary_path = tmp_path / "primary.json"
    repeat_path = tmp_path / "repeat.json"
    primary = make_panel(manifest, hashes)
    repeat = deepcopy(primary)
    repeat["rows"][0]["transcript_sha256"] = "f" * 64
    write_json(primary_path, primary)
    write_json(repeat_path, repeat)
    with pytest.raises(ArtifactComposerError, match="not semantically identical"):
        build_local(
            design_path,
            primary_path,
            repeat_path,
            started_at_utc=ts(1),
            completed_at_utc=ts(2),
            repository_root=tmp_path,
        )


def test_composer_rejects_control_archive_change_after_preregistration(tmp_path: Path) -> None:
    prereg_path, sources_path, _, _ = create_sources(tmp_path)
    (tmp_path / "grok.tar.gz").write_bytes(b"changed")
    with pytest.raises(ArtifactComposerError, match="control archive.*SHA-256 mismatch"):
        build_design(prereg_path, sources_path, repository_root=tmp_path)


def test_baseline_inventory_binds_pre_t0_and_future_metadata(tmp_path: Path) -> None:
    _, _, _, _, design_path, local_path, activation_path = build_all(tmp_path)

    def fetcher(submission_ref: str) -> str:
        return "\n".join(
            [
                "id,createTime,endTime,state,type",
                f"old-{submission_ref},2026-07-15 01:02:00.000000,2026-07-15 01:03:00.000000,EpisodeState.COMPLETED,EpisodeType.EPISODE_TYPE_PUBLIC",
                f"new-{submission_ref},2026-07-15 01:05:00.000000,2026-07-15 01:06:00.000000,EpisodeState.COMPLETED,EpisodeType.EPISODE_TYPE_PUBLIC",
                f"validation-{submission_ref},2026-07-15 01:07:00.000000,2026-07-15 01:08:00.000000,EpisodeState.COMPLETED,EpisodeType.EPISODE_TYPE_VALIDATION",
                "",
                'Use "kaggle competitions replay <episode_id>" to download a replay.',
            ]
        )

    baseline = collect_baseline_inventory(
        design_path,
        local_path,
        activation_path,
        collected_at_utc=ts(20),
        episode_fetcher=fetcher,
    )
    assert baseline["submission_authorized"] is False
    for inventory in baseline["inventories"]:
        assert inventory["completed_public_count"] == 2
        assert inventory["pre_t0_public_episode_ids"] == [f"old-{inventory['submission_ref']}"]
        assert inventory["future_metadata_episode_ids"] == [f"new-{inventory['submission_ref']}"]


def test_future_inventory_derives_all_post_t0_replays_without_outcome_filtering(tmp_path: Path) -> None:
    design, _, _, _, design_path, local_path, activation_path = build_all(tmp_path)

    def csv_for(submission_ref: str, *, future_count: int) -> str:
        lines = [
            "id,createTime,endTime,state,type",
            f"old-{submission_ref},2026-07-15 01:02:00.000000,2026-07-15 01:03:00.000000,EpisodeState.COMPLETED,EpisodeType.EPISODE_TYPE_PUBLIC",
        ]
        if future_count >= 1:
            lines.append(
                f"new-{submission_ref},2026-07-15 01:06:00.000000,2026-07-15 01:07:00.000000,EpisodeState.COMPLETED,EpisodeType.EPISODE_TYPE_PUBLIC"
            )
        if future_count >= 2:
            lines.append(
                f"newer-{submission_ref},2026-07-15 01:08:00.000000,2026-07-15 01:09:00.000000,EpisodeState.COMPLETED,EpisodeType.EPISODE_TYPE_PUBLIC"
            )
        return "\n".join([*lines, "", "Use kaggle competitions replay to download a replay."])

    baseline = collect_baseline_inventory(
        design_path,
        local_path,
        activation_path,
        collected_at_utc=ts(5),
        episode_fetcher=lambda ref: csv_for(ref, future_count=0),
    )
    observation = collect_baseline_inventory(
        design_path,
        local_path,
        activation_path,
        collected_at_utc=ts(20),
        episode_fetcher=lambda ref: csv_for(ref, future_count=1),
    )
    baseline_path = tmp_path / "baseline.json"
    observation_path = tmp_path / "observation.json"
    write_json(baseline_path, baseline)
    write_json(observation_path, observation)

    replay_dirs = {pair["pair_id"]: tmp_path / f"replays-{pair['pair_id']}" for pair in design["pairs"]}
    for pair in design["pairs"]:
        pair_id = pair["pair_id"]
        ref = pair["submission_ref"]
        seat = 0 if pair_id == "v160" else 1
        teams = ["GarlicToday", "Opponent"] if seat == 0 else ["Opponent", "GarlicToday"]
        rewards = [-1, 1] if pair_id == "v160" else [0, 0]
        statuses = ["DONE", "DONE"] if pair_id == "v160" else ["DONE", "ERROR"]
        replay_path = replay_dirs[pair_id] / f"episode-new-{ref}-replay.json"
        write_json(
            replay_path,
            {
                "info": {"EpisodeId": f"new-{ref}", "TeamNames": teams},
                "rewards": rewards,
                "statuses": statuses,
                "steps": [],
            },
        )

    future = build_future_inventory(
        design_path,
        local_path,
        activation_path,
        baseline_path,
        observation_path,
        replay_dirs=replay_dirs,
    )
    assert [row["pair_id"] for row in future["rows"]] == ["v160", "v161"]
    assert [row["outcome"] for row in future["rows"]] == ["LOSS", "DRAW"]
    assert future["rows"][0]["runtime_or_package_failure"] is False
    assert future["rows"][1]["runtime_or_package_failure"] is True
    assert all(row["started_at_utc"] == row["created_at_utc"] for row in future["rows"])
    assert future["submission_authorized"] is False

    previous_path = tmp_path / "future-previous.json"
    write_json(previous_path, future)
    later_observation = collect_baseline_inventory(
        design_path,
        local_path,
        activation_path,
        collected_at_utc=ts(30),
        episode_fetcher=lambda ref: csv_for(ref, future_count=2),
    )
    later_observation_path = tmp_path / "observation-later.json"
    write_json(later_observation_path, later_observation)
    for pair in design["pairs"]:
        pair_id = pair["pair_id"]
        ref = pair["submission_ref"]
        seat = 0 if pair_id == "v160" else 1
        teams = ["GarlicToday", "Opponent"] if seat == 0 else ["Opponent", "GarlicToday"]
        rewards = [1, -1] if pair_id == "v160" else [-1, 1]
        replay_path = replay_dirs[pair_id] / f"episode-newer-{ref}-replay.json"
        write_json(
            replay_path,
            {
                "info": {"EpisodeId": f"newer-{ref}", "TeamNames": teams},
                "rewards": rewards,
                "statuses": ["DONE", "DONE"],
                "steps": [],
            },
        )

    extended = build_future_inventory(
        design_path,
        local_path,
        activation_path,
        baseline_path,
        later_observation_path,
        replay_dirs=replay_dirs,
        previous_path=previous_path,
    )
    assert extended["rows"][: len(future["rows"])] == future["rows"]
    assert len(extended["rows"]) == 4

    tampered = deepcopy(future)
    tampered["rows"][0]["outcome"] = "WIN"
    tampered = add_canonical_root(tampered, "future_inventory_root_sha256")
    tampered_path = tmp_path / "future-tampered.json"
    write_json(tampered_path, tampered)
    with pytest.raises(ArtifactComposerError, match="not append-only"):
        build_future_inventory(
            design_path,
            local_path,
            activation_path,
            baseline_path,
            later_observation_path,
            replay_dirs=replay_dirs,
            previous_path=tampered_path,
        )


def test_future_inventory_rejects_changed_pre_t0_history(tmp_path: Path) -> None:
    design, _, _, _, design_path, local_path, activation_path = build_all(tmp_path)

    def baseline_csv(submission_ref: str) -> str:
        return "\n".join(
            [
                "id,createTime,endTime,state,type",
                f"old-{submission_ref},2026-07-15 01:02:00.000000,2026-07-15 01:03:00.000000,EpisodeState.COMPLETED,EpisodeType.EPISODE_TYPE_PUBLIC",
            ]
        )

    baseline = collect_baseline_inventory(
        design_path,
        local_path,
        activation_path,
        collected_at_utc=ts(5),
        episode_fetcher=baseline_csv,
    )
    changed = collect_baseline_inventory(
        design_path,
        local_path,
        activation_path,
        collected_at_utc=ts(20),
        episode_fetcher=lambda ref: baseline_csv(ref).replace(f"old-{ref}", f"changed-{ref}"),
    )
    baseline_path = tmp_path / "baseline.json"
    observation_path = tmp_path / "observation.json"
    write_json(baseline_path, baseline)
    write_json(observation_path, changed)
    with pytest.raises(ArtifactComposerError, match="pre-T0 inventory changed"):
        build_future_inventory(
            design_path,
            local_path,
            activation_path,
            baseline_path,
            observation_path,
            replay_dirs={pair["pair_id"]: tmp_path / pair["pair_id"] for pair in design["pairs"]},
        )
