from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from evaluation_v5.cohort import (
    CohortCustodyError,
    append_observation,
    append_observations_batch,
    append_registration,
    build_archive_registration,
    build_outcome_observation,
    canonical_json_bytes,
    compose_first48,
    new_observation_log,
    new_registry,
    validate_first48_manifest,
    validate_observation,
    validate_registry,
    write_registry_create_once,
)


def _utc(index: int, *, base: datetime = datetime(2026, 7, 1, tzinfo=timezone.utc)) -> str:
    return (base + timedelta(minutes=index)).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _registration(
    *,
    archive: str = "a" * 64,
    model_input: str = "d" * 64,
    team_pseudonym: str = "team-a",
    submission_slot_id: str = "slot-1",
    intended_window_start: str = _utc(50),
    intended_window_end: str = _utc(70),
    consent: str = "e" * 64,
    registered_at: str = _utc(0),
) -> dict[str, object]:
    return build_archive_registration(
        archive_sha256=archive,
        deck_sha256="b" * 64,
        policy_sha256="c" * 64,
        model_input_sha256=model_input,
        team_pseudonym=team_pseudonym,
        submission_slot_id=submission_slot_id,
        intended_window_start_utc=intended_window_start,
        intended_window_end_utc=intended_window_end,
        consent_sha256=consent,
        family_provenance={"family_id": "family-a", "parents": ["parent-a"]},
        registered_at_utc=registered_at,
    )


def _registry() -> dict[str, object]:
    return append_registration(new_registry(), _registration())


def _observation(
    index: int,
    *,
    archive: str = "a" * 64,
    game_prefix: str = "hosted",
    scope: str = "public",
    replay_content_sha256: str | None = None,
) -> dict[str, object]:
    created = _utc(61 + index)
    return build_outcome_observation(
        archive_sha256=archive,
        game_id=f"{game_prefix}-{index:02d}",
        created_at_utc=created,
        completion_observed_at_utc=_utc(0),
        completion_evidence_sha256="f" * 64,
        seat=index % 2,
        opponent_rating=1500 + index,
        outcome="win" if index % 3 else "loss",
        hosted_scope=scope,
        replay_content_sha256=replay_content_sha256,
    )


def _observations(
    count: int = 48,
    *,
    archive: str = "a" * 64,
    game_prefix: str = "hosted",
) -> list[dict[str, object]]:
    return [
        _observation(index, archive=archive, game_prefix=game_prefix)
        for index in range(count)
    ]


def _observation_log(
    observations: list[dict[str, object]] | None = None,
    *,
    registry: dict[str, object] | None = None,
) -> dict[str, object]:
    checked_registry = _registry() if registry is None else registry
    source = _observations() if observations is None else observations
    return append_observations_batch(
        new_observation_log(), source, registry=checked_registry
    )


def _rehash_manifest(manifest: dict[str, object]) -> None:
    from evaluation_v5.canonical import canonical_sha256

    content = {key: manifest[key] for key in manifest if key != "manifest_sha256"}
    manifest["manifest_sha256"] = canonical_sha256(content)


def test_registration_is_exact_and_outcome_free() -> None:
    record = _registration()
    assert set(record) == {
        "schema",
        "archive_sha256",
        "deck_sha256",
        "policy_sha256",
        "model_input_sha256",
        "family_provenance_sha256",
        "team_pseudonym",
        "submission_slot_id",
        "intended_window_start_utc",
        "intended_window_end_utc",
        "consent_sha256",
        "registered_at_utc",
    }
    poisoned = deepcopy(record)
    poisoned["outcome"] = "win"
    with pytest.raises(CohortCustodyError, match="fields must exactly"):
        append_registration(new_registry(), poisoned)
    with pytest.raises(CohortCustodyError, match="fields must exactly"):
        append_registration(new_registry(), {**record, "first_hosted_game_at_utc": _utc(1)})
    missing_model_input = deepcopy(record)
    missing_model_input.pop("model_input_sha256")
    with pytest.raises(CohortCustodyError, match="fields must exactly"):
        append_registration(new_registry(), missing_model_input)


@pytest.mark.parametrize(
    "field",
    [
        "team_pseudonym",
        "submission_slot_id",
        "intended_window_start_utc",
        "intended_window_end_utc",
        "consent_sha256",
    ],
)
def test_registration_rejects_external_eligibility_omissions(field: str) -> None:
    registration = _registration()
    registration.pop(field)
    with pytest.raises(CohortCustodyError, match="fields must exactly"):
        append_registration(new_registry(), registration)


def test_registration_rejects_identifier_types_and_invalid_windows() -> None:
    bad_team = _registration()
    bad_team["team_pseudonym"] = 7
    with pytest.raises(CohortCustodyError, match="team_pseudonym"):
        append_registration(new_registry(), bad_team)

    bad_slot = _registration()
    bad_slot["submission_slot_id"] = " slot-1"
    with pytest.raises(CohortCustodyError, match="submission_slot_id"):
        append_registration(new_registry(), bad_slot)

    with pytest.raises(CohortCustodyError, match="must be after"):
        _registration(
            intended_window_start=_utc(70),
            intended_window_end=_utc(70),
        )


def test_first_hosted_timestamp_is_later_observation_metadata_only() -> None:
    observation = build_outcome_observation(
        archive_sha256="a" * 64,
        game_id="hosted-00",
        created_at_utc=_utc(62),
        completion_observed_at_utc=_utc(1),
        completion_evidence_sha256="f" * 64,
        seat=0,
        opponent_rating=1500,
        outcome="win",
        first_hosted_game_at_utc=_utc(1),
    )
    assert observation["first_hosted_game_at_utc"] == _utc(1)
    assert observation["mature_after_utc"] == _utc(61)


def test_registry_append_only_duplicate_retroactive_and_tamper() -> None:
    registry = _registry()
    later = _registration(archive="d" * 64, registered_at=_utc(2))
    expanded = append_registration(registry, later)
    assert len(expanded["records"]) == 2
    with pytest.raises(CohortCustodyError, match="duplicate archive"):
        append_registration(expanded, _registration())
    with pytest.raises(CohortCustodyError, match="retroactive"):
        append_registration(expanded, _registration(archive="e" * 64, registered_at=_utc(1)))

    mutated = deepcopy(expanded)
    mutated["records"][0]["model_input_sha256"] = "f" * 64
    with pytest.raises(CohortCustodyError, match="chain hash mismatch"):
        validate_registry(mutated)
    reordered = deepcopy(expanded)
    reordered["records"] = list(reversed(reordered["records"]))
    with pytest.raises(CohortCustodyError):
        validate_registry(reordered)


def test_create_once_writer_refuses_mutation(tmp_path) -> None:
    path = tmp_path / "registry.json"
    write_registry_create_once(path, _registry())
    with pytest.raises(CohortCustodyError, match="create-once"):
        write_registry_create_once(path, _registry())


def test_observation_requires_registration_and_rejects_validation_substitution() -> None:
    log = new_observation_log()
    with pytest.raises(TypeError):
        append_observation(log, _observation(0))
    with pytest.raises(CohortCustodyError, match="not registered"):
        append_observation(log, _observation(0), registry=new_registry())
    with pytest.raises(CohortCustodyError, match="only literal public"):
        append_observation(log, _observation(0, scope="validation"), registry=_registry())
    with pytest.raises(CohortCustodyError, match="after archive registration"):
        append_observation(
            log,
            build_outcome_observation(
                archive_sha256="a" * 64,
                game_id="hosted-before-registration",
                created_at_utc=_utc(-1),
                completion_observed_at_utc=_utc(-61),
                completion_evidence_sha256="f" * 64,
                seat=0,
                opponent_rating=1500,
                outcome="loss",
            ),
            registry=_registry(),
        )


def test_observation_log_rejects_duplicate_ids_and_tamper() -> None:
    first = _observation(0, replay_content_sha256="1" * 64)
    log = append_observation(new_observation_log(), first, registry=_registry())
    with pytest.raises(CohortCustodyError, match="duplicate hosted game id"):
        append_observation(log, first, registry=_registry())
    changed = deepcopy(log)
    changed["records"][0]["replay_content_sha256"] = "2" * 64
    with pytest.raises(CohortCustodyError, match="chain hash mismatch"):
        append_observation(changed, _observation(1), registry=_registry())


def test_observation_append_rejects_retroactive_archive_timestamp() -> None:
    registry = _registry()
    log = append_observation(
        new_observation_log(), _observation(0), registry=registry
    )
    log = append_observation(log, _observation(2), registry=registry)

    with pytest.raises(CohortCustodyError, match="strictly later"):
        append_observation(log, _observation(1), registry=registry)


def test_observation_batch_is_equivalent_to_sequential_append() -> None:
    other_archive = "2" * 64
    registry = append_registration(
        _registry(),
        _registration(
            archive=other_archive,
            model_input="3" * 64,
            team_pseudonym="team-b",
            submission_slot_id="slot-2",
        ),
    )
    primary = _observations(4)
    other = _observations(
        4,
        archive=other_archive,
        game_prefix="other-hosted",
    )
    observations = [
        observation
        for pair in zip(primary, other)
        for observation in pair
    ]

    sequential = new_observation_log()
    for observation in observations:
        sequential = append_observation(
            sequential, observation, registry=registry
        )
    batched = append_observations_batch(
        new_observation_log(), observations, registry=registry
    )

    assert canonical_json_bytes(batched) == canonical_json_bytes(sequential)


def test_observation_batch_failure_is_atomic() -> None:
    registry = _registry()
    starting_log = append_observation(
        new_observation_log(), _observation(0), registry=registry
    )
    original_log = deepcopy(starting_log)
    observations = [_observation(2), _observation(1)]
    original_observations = deepcopy(observations)

    with pytest.raises(CohortCustodyError, match="strictly later"):
        append_observations_batch(starting_log, observations, registry=registry)

    assert starting_log == original_log
    assert observations == original_observations


def test_observation_replay_hash_field_is_exact_and_typed() -> None:
    missing = _observation(0)
    missing.pop("replay_content_sha256")
    with pytest.raises(CohortCustodyError, match="fields must exactly"):
        append_observation(new_observation_log(), missing, registry=_registry())

    wrong_type = _observation(0)
    wrong_type["replay_content_sha256"] = 123
    with pytest.raises(CohortCustodyError, match="replay_content_sha256"):
        append_observation(new_observation_log(), wrong_type, registry=_registry())


def test_observation_derives_one_hour_maturity_and_rejects_arbitrary_boundary() -> None:
    observation = _observation(0)
    assert observation["mature_after_utc"] == _utc(60)

    arbitrary = deepcopy(observation)
    arbitrary["mature_after_utc"] = "2026-07-01T01:00:01.000000Z"
    with pytest.raises(CohortCustodyError, match="exactly one hour"):
        validate_observation(arbitrary)

    with pytest.raises(TypeError, match="mature_after_utc"):
        build_outcome_observation(
            archive_sha256="a" * 64,
            game_id="hosted-no-manual-boundary",
            created_at_utc=_utc(61),
            completion_observed_at_utc=_utc(0),
            completion_evidence_sha256="f" * 64,
            seat=0,
            opponent_rating=1500,
            outcome="win",
            mature_after_utc=_utc(61),
        )


@pytest.mark.parametrize(
    "completion_observed_at_utc",
    [
        "2026-02-30T00:00:00.000000Z",
        "2026-07-01T00:00:00Z",
        " 2026-07-01T00:00:00.000000Z",
    ],
)
def test_observation_rejects_invalid_or_noncanonical_completion_timestamp(
    completion_observed_at_utc: str,
) -> None:
    observation = _observation(0)
    observation["completion_observed_at_utc"] = completion_observed_at_utc
    with pytest.raises(CohortCustodyError, match="completion_observed_at_utc"):
        validate_observation(observation)


def test_first48_is_exact_and_chronological() -> None:
    registry = _registry()
    log = _observation_log(registry=registry)
    manifest = compose_first48(registry, log, as_of_utc=_utc(200))
    assert [game["game_id"] for game in manifest["games"]] == [
        f"hosted-{index:02d}" for index in range(48)
    ]
    assert manifest["games"][-1]["created_at_utc"] > _registration()[
        "intended_window_end_utc"
    ]
    assert manifest["observation_chain_head"] == log["chain_hashes"][47]
    assert manifest["observation_log_prefix_length"] == 48
    assert validate_first48_manifest(manifest) == manifest


def test_first48_rejects_games_created_after_as_of() -> None:
    registry = _registry()
    log = _observation_log(registry=registry)
    with pytest.raises(CohortCustodyError, match="created after as_of_utc"):
        compose_first48(registry, log, as_of_utc=_utc(107))

    manifest = compose_first48(registry, log, as_of_utc=_utc(200))
    manifest["as_of_utc"] = _utc(107)
    _rehash_manifest(manifest)
    with pytest.raises(CohortCustodyError, match="created after as_of_utc"):
        validate_first48_manifest(manifest)


def test_first48_rejects_raw_observation_list() -> None:
    with pytest.raises(CohortCustodyError, match="observation log fields must exactly"):
        compose_first48(_registry(), _observations(), as_of_utc=_utc(200))


def test_first48_rejects_substituted_or_reordered_observation_chain() -> None:
    registry = _registry()
    log = _observation_log(registry=registry)

    substituted = deepcopy(log)
    substituted["records"][10]["outcome"] = "loss"
    with pytest.raises(CohortCustodyError, match="chain hash mismatch"):
        compose_first48(registry, substituted, as_of_utc=_utc(200))

    reordered = deepcopy(log)
    reordered["chain_hashes"][10], reordered["chain_hashes"][11] = (
        reordered["chain_hashes"][11],
        reordered["chain_hashes"][10],
    )
    with pytest.raises(CohortCustodyError, match="chain hash mismatch"):
        compose_first48(registry, reordered, as_of_utc=_utc(200))


def test_first48_supports_interleaved_global_observation_log() -> None:
    other_archive = "2" * 64
    registry = append_registration(
        _registry(),
        _registration(
            archive=other_archive,
            model_input="3" * 64,
            team_pseudonym="team-b",
            submission_slot_id="slot-2",
        ),
    )
    primary = _observations()
    other = _observations(
        archive=other_archive,
        game_prefix="other-hosted",
    )
    interleaved = [
        observation
        for pair in zip(primary, other)
        for observation in pair
    ]
    log = _observation_log(interleaved, registry=registry)

    primary_manifest = compose_first48(
        registry,
        log,
        archive_sha256="a" * 64,
        as_of_utc=_utc(200),
    )
    other_manifest = compose_first48(
        registry,
        log,
        archive_sha256=other_archive,
        as_of_utc=_utc(200),
    )

    assert [game["game_id"] for game in primary_manifest["games"]] == [
        f"hosted-{index:02d}" for index in range(48)
    ]
    assert primary_manifest["observation_log_prefix_length"] == 95
    assert primary_manifest["observation_chain_head"] == log["chain_hashes"][94]
    assert other_manifest["observation_log_prefix_length"] == 96
    assert other_manifest["observation_chain_head"] == log["chain_hashes"][95]


def test_first48_is_stable_after_later_append_only_target_games() -> None:
    registry = _registry()
    log = _observation_log(registry=registry)
    first = compose_first48(registry, log, as_of_utc=_utc(200))

    expanded = append_observation(log, _observation(48), registry=registry)
    expanded = append_observation(expanded, _observation(49), registry=registry)
    second = compose_first48(registry, expanded, as_of_utc=_utc(200))

    assert canonical_json_bytes(second) == canonical_json_bytes(first)


def test_first_hosted_game_must_be_inside_registered_window() -> None:
    registry = append_registration(
        new_registry(),
        _registration(intended_window_start=_utc(50), intended_window_end=_utc(60)),
    )
    with pytest.raises(CohortCustodyError, match="outside the registered intended"):
        append_observation(new_observation_log(), _observation(0), registry=registry)
    valid_log = _observation_log(registry=_registry())
    with pytest.raises(CohortCustodyError, match="outside the registered intended"):
        compose_first48(registry, valid_log, as_of_utc=_utc(200))

    normal_registry = _registry()
    log = append_observation(
        new_observation_log(), _observation(0), registry=normal_registry
    )
    log = append_observation(log, _observation(20), registry=normal_registry)
    assert log["records"][-1]["created_at_utc"] > _utc(70)


def test_distinct_in_window_first_hosted_claims_are_rejected() -> None:
    games = _observations()
    games[0] = {**games[0], "first_hosted_game_at_utc": _utc(61)}
    games[1] = {**games[1], "first_hosted_game_at_utc": _utc(62)}

    log = append_observation(
        new_observation_log(), games[0], registry=_registry()
    )
    with pytest.raises(CohortCustodyError, match="must equal the computed earliest"):
        append_observation(log, games[1], registry=_registry())


def test_first48_registration_hash_binds_model_input_identity() -> None:
    games = _observations()
    first_registry = append_registration(
        new_registry(), _registration(model_input="d" * 64)
    )
    second_registry = append_registration(
        new_registry(), _registration(model_input="e" * 64)
    )
    first = compose_first48(
        first_registry,
        _observation_log(games, registry=first_registry),
        as_of_utc=_utc(200),
    )
    second = compose_first48(
        second_registry,
        _observation_log(games, registry=second_registry),
        as_of_utc=_utc(200),
    )

    assert first["registration_sha256"] != second["registration_sha256"]
    assert first["manifest_sha256"] != second["manifest_sha256"]


def test_first48_rejects_detached_raw_registration() -> None:
    with pytest.raises(CohortCustodyError, match="registry fields must exactly"):
        compose_first48(_registration(), _observation_log(), as_of_utc=_utc(200))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("team_pseudonym", "team-b"),
        ("submission_slot_id", "slot-2"),
        ("intended_window_start_utc", _utc(49)),
        ("intended_window_end_utc", _utc(71)),
        ("consent_sha256", "f" * 64),
    ],
)
def test_first48_registration_hash_binds_external_eligibility_identity(
    field: str, value: str
) -> None:
    original = _registration()
    changed = deepcopy(original)
    changed[field] = value
    original_registry = append_registration(new_registry(), original)
    changed_registry = append_registration(new_registry(), changed)
    first = compose_first48(
        original_registry,
        _observation_log(registry=original_registry),
        as_of_utc=_utc(200),
    )
    second = compose_first48(
        changed_registry,
        _observation_log(registry=changed_registry),
        as_of_utc=_utc(200),
    )
    assert first["registration_sha256"] != second["registration_sha256"]
    assert first["manifest_sha256"] != second["manifest_sha256"]


def test_first48_rejects_fewer_than_48_target_games() -> None:
    registry = _registry()
    log = _observation_log(_observations(47), registry=registry)
    with pytest.raises(CohortCustodyError, match="at least 48"):
        compose_first48(registry, log, as_of_utc=_utc(200))


def test_observation_rejects_created_before_derived_maturity() -> None:
    with pytest.raises(CohortCustodyError, match="at or after"):
        build_outcome_observation(
            archive_sha256="a" * 64,
            game_id="hosted-00",
            created_at_utc=_utc(59),
            completion_observed_at_utc=_utc(0),
            completion_evidence_sha256="f" * 64,
            seat=0,
            opponent_rating=1500,
            outcome="loss",
        )


def test_first48_requires_one_common_maturity_boundary() -> None:
    games = _observations()
    games[-1] = build_outcome_observation(
        archive_sha256="a" * 64,
        game_id="hosted-47",
        created_at_utc=_utc(108),
        completion_observed_at_utc=_utc(1),
        completion_evidence_sha256="f" * 64,
        seat=1,
        opponent_rating=1547,
        outcome="win",
    )
    log = _observation_log(games, registry=_registry())
    with pytest.raises(CohortCustodyError, match="one mature_after_utc boundary"):
        compose_first48(_registry(), log, as_of_utc=_utc(200))


def test_manifest_binds_common_boundary_and_game_eligibility() -> None:
    registry = _registry()
    manifest = compose_first48(
        registry, _observation_log(registry=registry), as_of_utc=_utc(200)
    )
    assert manifest["mature_after_utc"] == _utc(60)

    tampered = deepcopy(manifest)
    tampered["games"][0]["mature_after_utc"] = _utc(61)
    _rehash_manifest(tampered)
    with pytest.raises(CohortCustodyError, match="exactly one hour"):
        validate_first48_manifest(tampered)

    replay_tampered = deepcopy(manifest)
    replay_tampered["games"][0]["replay_content_sha256"] = "1" * 64
    with pytest.raises(CohortCustodyError, match="manifest hash mismatch"):
        validate_first48_manifest(replay_tampered)


def test_manifest_rejects_mismatched_completion_evidence_and_duplicate_ids() -> None:
    registry = _registry()
    manifest = compose_first48(
        registry, _observation_log(registry=registry), as_of_utc=_utc(200)
    )

    mismatched_evidence = deepcopy(manifest)
    mismatched_evidence["games"][0]["completion_evidence_sha256"] = "1" * 64
    _rehash_manifest(mismatched_evidence)
    with pytest.raises(CohortCustodyError, match="completion evidence hash"):
        validate_first48_manifest(mismatched_evidence)

    duplicate_game_id = deepcopy(manifest)
    duplicate_game_id["games"][1]["game_id"] = duplicate_game_id["games"][0]["game_id"]
    _rehash_manifest(duplicate_game_id)
    with pytest.raises(CohortCustodyError, match="duplicate hosted game ids"):
        validate_first48_manifest(duplicate_game_id)


def test_manifest_rejects_mismatched_completion_observation_boundary() -> None:
    registry = _registry()
    manifest = compose_first48(
        registry, _observation_log(registry=registry), as_of_utc=_utc(200)
    )
    mismatched_completion = deepcopy(manifest)
    mismatched_completion["games"][0]["completion_observed_at_utc"] = _utc(1)
    mismatched_completion["games"][0]["mature_after_utc"] = _utc(61)
    _rehash_manifest(mismatched_completion)
    with pytest.raises(CohortCustodyError, match="common maturity boundary"):
        validate_first48_manifest(mismatched_completion)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("observation_chain_head", "not-a-hash", "observation_chain_head"),
        ("observation_log_prefix_length", True, "integer of at least 48"),
        ("observation_log_prefix_length", 47, "integer of at least 48"),
    ],
)
def test_manifest_validates_observation_chain_binding_structure(
    field: str, value: object, message: str
) -> None:
    registry = _registry()
    manifest = compose_first48(
        registry, _observation_log(registry=registry), as_of_utc=_utc(200)
    )
    manifest[field] = value
    _rehash_manifest(manifest)

    with pytest.raises(CohortCustodyError, match=message):
        validate_first48_manifest(manifest)


def test_malformed_hashes_and_timestamps_are_rejected() -> None:
    with pytest.raises(CohortCustodyError, match="SHA-256"):
        _registration(archive="A" * 64)
    with pytest.raises(CohortCustodyError, match="UTC offset"):
        _registration(registered_at="2026-07-01T00:00:00.000000")
    with pytest.raises(CohortCustodyError, match="model_input_sha256"):
        _registration(model_input="D" * 64)
    with pytest.raises(CohortCustodyError, match="consent_sha256"):
        _registration(consent="E" * 64)
