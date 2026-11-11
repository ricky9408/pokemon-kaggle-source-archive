from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import warnings

import pytest
from sklearn.exceptions import ConvergenceWarning

from evaluation_v5.charter import FEATURE_NAMES
from evaluation_v5.development_fit import (
    DEVELOPMENT_ROW_SCHEMA,
    DevelopmentFitError,
    fit_development_models,
    write_manifest_once,
)
from evaluation_v5.engine_capabilities import CAPABILITY_NAMES, HASH_NAMES
from evaluation_v5.model import COMPARATOR_INPUT_KEYS, build_prediction_manifest


STAMP = "2026-07-14T03:00:00.000000Z"
EVIDENCE = "a" * 64
EXECUTABLE = "b" * 64
ROOT = Path(__file__).parents[1]


def _backend(*, enabled: bool = True, **changes: object) -> dict[str, object]:
    value: dict[str, object] = {name: f"{index + 1:064x}" for index, name in enumerate(HASH_NAMES)}
    value.update({name: enabled for name in CAPABILITY_NAMES})
    value.update(changes)
    value["capability_evidence_sha256"] = {
        name: f"{index + 20:064x}" for index, name in enumerate(CAPABILITY_NAMES) if value[name]
    }
    return value


def _engine(*, feasible: bool = True) -> dict[str, object]:
    return {
        "schema": "evaluation_v5_engine_capability_manifest_v1",
        "protocol_id": "MCI_TRANSFER_V1",
        "backends": {
            "opened_source": _backend(),
            "official_wrapper": _backend() if feasible else _backend(enabled=False),
        },
    }


def _row(index: int, *, lineage: str | None = None, family: str | None = None) -> dict[str, object]:
    key_values = {
        key: (index % 5) / 4.0 for key in COMPARATOR_INPUT_KEYS.values() if key is not None
    }
    return {
        "schema": DEVELOPMENT_ROW_SCHEMA,
        "protocol_id": "MCI_TRANSFER_V1",
        "partition": "DEV_BURNED",
        "engine_manifest_sha256": "pending",
        "archive_id": f"archive-{index // 4:02d}",
        "lineage_id": lineage or f"lineage-{index // 4:02d}",
        "family_id": family or f"family-{index // 8:02d}",
        "game_id": f"game-{index:03d}",
        "features": {name: ((index + feature_index) % 5) / 4.0 for feature_index, name in enumerate(FEATURE_NAMES)},
        "comparator_inputs": key_values,
        "era": "2026Q3" if index % 2 else "2026Q2",
        "seat": index % 2,
        "opponent_rating": 700 + (index % 12) * 100,
        "outcome": float(index % 2),
    }


def _rows() -> list[dict[str, object]]:
    return [_row(index) for index in range(16)]


def _bind(rows: list[dict[str, object]], engine: dict[str, object]) -> list[dict[str, object]]:
    from evaluation_v5.engine_capabilities import engine_capability_manifest_sha256

    bound = deepcopy(rows)
    for row in bound:
        row["engine_manifest_sha256"] = engine_capability_manifest_sha256(engine)
    return bound


def _fit(
    rows: list[dict[str, object]] | None = None,
    *,
    engine: dict[str, object] | None = None,
    created_at_utc: str = STAMP,
) -> dict[str, object]:
    checked_engine = engine or _engine()
    return fit_development_models(
        _bind(rows or _rows(), checked_engine),
        engine_capability_manifest=checked_engine,
        development_evidence_sha256=EVIDENCE,
        executable_sha256=EXECUTABLE,
        created_at_utc=created_at_utc,
    )


def test_realistic_capability_gap_closes_before_sklearn_fit(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_fit(*args: object, **kwargs: object) -> None:
        raise AssertionError("sklearn must not be called")

    monkeypatch.setattr("evaluation_v5.development_fit.LogisticRegression.fit", fail_fit)
    current_engine = json.loads(
        (ROOT / "strategy/evaluation_v5_current_engine_capability_manifest_20260713.json").read_text()
    )
    result = _fit(engine=current_engine)
    assert result["decision"] == "FAIL_CLOSED"
    assert result["reason"] == "NO_LOCAL_FEATURE_EXTRACTION"
    assert result["fit_performed"] is False
    assert result["authority"] is False


def test_valid_data_is_reproducible_order_invariant_and_has_no_authority() -> None:
    rows = _rows()
    first = _fit(rows)
    second = _fit(list(reversed(rows)))
    assert first == second
    assert first["authority"] is False
    assert first["submission_authorized"] is False
    assert first["holdout_access_authorized"] is False
    assert first["fit_performed"] is True
    assert first["fit_config"]["numpy_version"] == first["runtime_versions"]["numpy"]  # type: ignore[index]
    assert first["fit_config"]["sklearn_version"] == first["runtime_versions"]["sklearn"]  # type: ignore[index]
    assert first["reproduction"]["mci_max_absolute_error"] <= 1e-12  # type: ignore[index]
    assert first["reproduction"]["comparator_max_absolute_error"] <= 1e-12  # type: ignore[index]
    assert first["cv_report"]["family_out_role"] == "DESCRIPTIVE_ONLY_NOT_A_SELECTOR"  # type: ignore[index]


def test_created_at_rejects_calendar_invalid_date() -> None:
    with pytest.raises(DevelopmentFitError, match="valid calendar datetime"):
        _fit(created_at_utc="2026-02-30T03:00:00.000000Z")


@pytest.mark.parametrize("failure_mode", ["warning", "iteration_budget"])
def test_nonconvergence_fails_before_manifest_emission(
    monkeypatch: pytest.MonkeyPatch, failure_mode: str
) -> None:
    import evaluation_v5.development_fit as fitter

    original_fit = fitter.LogisticRegression.fit

    def nonconverged(estimator, *args, **kwargs):
        result = original_fit(estimator, *args, **kwargs)
        if failure_mode == "warning":
            warnings.warn("forced nonconvergence", ConvergenceWarning)
        else:
            estimator.n_iter_ = [estimator.max_iter]
        return result

    def manifest_must_not_be_built(*args, **kwargs):
        raise AssertionError("manifest construction must not run after nonconvergence")

    monkeypatch.setattr(fitter.LogisticRegression, "fit", nonconverged)
    monkeypatch.setattr(fitter, "_mci_manifest", manifest_must_not_be_built)
    monkeypatch.setattr(fitter, "_comparator_manifest", manifest_must_not_be_built)
    with pytest.raises(DevelopmentFitError, match="ConvergenceWarning|reached or exceeded max_iter"):
        _fit()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda rows: rows[0].update({"rank": 1}),
        lambda rows: rows[0].update({"public_action": "attack"}),
        lambda rows: rows[0].update({"candidate": "x"}),
        lambda rows: rows[0].update({"holdout": True}),
        lambda rows: rows[0]["features"].update({"extra": 0.1}),  # type: ignore[index]
        lambda rows: rows[1].__setitem__("game_id", rows[0]["game_id"]),
    ],
)
def test_exact_row_schema_rejects_leakage_and_extra_fields(mutate) -> None:
    rows = _rows()
    mutate(rows)
    with pytest.raises(DevelopmentFitError):
        _fit(rows)


def test_lolo_comparator_selection_uses_lexical_tie_break(monkeypatch: pytest.MonkeyPatch) -> None:
    import evaluation_v5.development_fit as fitter

    original = fitter._comparator_cv

    def tied(rows, weights, *, group_key):
        report = original(rows, weights, group_key=group_key)
        if group_key == "lineage_id":
            for value in report.values():
                value["archive_balanced_log_loss"] = 0.5
        return report

    monkeypatch.setattr(fitter, "_comparator_cv", tied)
    result = _fit()
    assert result["selected_comparator_identity"] == "L/T mean model"
    assert result["cv_report"]["selection_basis"] == "leave_one_lineage_out_archive_balanced_log_loss"  # type: ignore[index]


def test_missing_comparator_inputs_are_centered_at_the_frozen_mean(monkeypatch: pytest.MonkeyPatch) -> None:
    import evaluation_v5.development_fit as fitter

    original = fitter._comparator_cv

    def select_raw(rows, weights, *, group_key):
        report = original(rows, weights, group_key=group_key)
        if group_key == "lineage_id":
            for identity, value in report.items():
                value["archive_balanced_log_loss"] = 1.0
                if identity == "raw local win-rate model":
                    value["archive_balanced_log_loss"] = 0.0
        return report

    monkeypatch.setattr(fitter, "_comparator_cv", select_raw)
    rows = _rows()
    for row in rows[::3]:
        row["comparator_inputs"]["raw_local_win_rate"] = None  # type: ignore[index]
    result = _fit(rows)
    manifest = build_prediction_manifest(result["comparator_manifest"])  # type: ignore[arg-type]
    assert manifest.comparator_identity == "raw local win-rate model"
    missing = manifest.predict_probability(None, era="2026Q2", seat=0, opponent_rating=1000)
    explicit = manifest.predict_probability(
        None,
        era="2026Q2",
        seat=0,
        opponent_rating=1000,
        comparator_input=manifest.comparator_input_mean,
    )
    assert missing == explicit


def test_manifest_roundtrip_and_create_once_writer(tmp_path: Path) -> None:
    result = _fit()
    manifest = build_prediction_manifest(result["mci_manifest"])  # type: ignore[arg-type]
    path = tmp_path / "mci.json"
    assert write_manifest_once(path, manifest) == manifest.manifest_sha256
    assert path.read_bytes()
    with pytest.raises(FileExistsError):
        write_manifest_once(path, manifest.as_dict())
