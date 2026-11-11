from __future__ import annotations

from copy import deepcopy
from collections import Counter
import hashlib
import unittest
from unittest.mock import patch

import evaluation_v2.branch_support_v2 as support
from evaluation_v2.branch_support_v2 import (
    EXECUTION_MANIFEST_DEPENDENCIES,
    canonical_json,
    evaluate_stage_a,
    flatten_representation,
    leave_one_pilot_out_folds,
    run_stage_a,
    sha_derived_seed,
    type7_quantile,
)


def _action(selection: list[int], family: str, payload: dict) -> dict:
    payload_key = canonical_json(payload)
    return {
        "selection": selection,
        "payload": payload,
        "payload_key": payload_key,
        "action_key": canonical_json({"selection": selection, "payload": payload}),
        "family": family,
    }


def _row(pilot: str, game: str, step: int, *, category: str = "known") -> dict:
    attack = _action([0], "ATTACK", {"type": "ATTACK", "attack_id": 1})
    end = _action([1], "END", {"type": "END"})
    selected = attack if step % 2 == 0 else end
    return {
        "game_id": game,
        "replay_sha256": f"replay-{game}",
        "pilot": pilot,
        "side_id": f"side-{pilot}",
        "native_root_id": f"root-{pilot}-{step}",
        "selected_family": selected["family"],
        "selected_action": selected,
        "selected_action_key": selected["action_key"],
        "legal_actions": [attack, end],
        "representation": {
            "numeric": {"turn": step, "legal": {"attack": 1, "end": 1}},
            "categorical": {"phase": category, "counts": {"basic": step % 3, "item": 1}, "number_kind": 7},
        },
    }


def _rows() -> list[dict]:
    return [_row(f"p{pilot}", f"g{pilot}-{step}", step) for pilot in range(5) for step in range(4)]


def _schedule(rows: list[dict]) -> list[dict]:
    slots: Counter[str] = Counter()
    result = []
    for row in rows:
        slot = slots[row["side_id"]]
        slots[row["side_id"]] += 1
        result.append({
            "schema": "branch_bridge_root_schedule_v2",
            "side_id": row["side_id"],
            "slot_index": slot,
            "native_root_id": row["native_root_id"],
            "root_priority_sha256": f"priority-{row['native_root_id']}",
            "status": "scheduled",
        })
    return result


TEST_CONFIG = {
    "families": ("ATTACK", "END"),
    "min_selected_training_games": 2,
    "min_selected_training_pilots": 2,
    "accepted_low": 0.0,
    "accepted_high": 1.0,
    "bootstrap_samples": 3,
    "bootstrap_min_q10": 0.0,
    "bootstrap_max_q90": 1.0,
    "conformal_min_games": 2,
    "conformal_min_pilots": 2,
    "conformal_min_p": 0.0,
    "activation_min_overall_supported_mass": 0.0,
    "activation_min_every_pilot_supported_mass": 0.0,
}


def _preregistration() -> dict:
    return {
        "schema": "branch_bridge_preregistration_v2",
        "support_families": ["ATTACK", "END"],
        "stage_a": {
            "family_eligibility": {"min_selected_training_games": 2, "min_selected_training_pilots": 2},
            "propensity": {
                "model": "L2 logistic regression", "solver": "lbfgs", "class_weight": None,
                "sample_weight": "within each independent game, divide weight one equally across eligible rows",
                "accepted_interval_inclusive": [0.0, 1.0], "c": 1.0, "max_iter": 2000, "random_state": 2026071100,
            },
            "bootstrap_stability": {
                "samples": 3, "master_seed": 17, "min_q10_inclusive": 0.0, "max_q90_inclusive": 1.0,
                "unit": "whole game_id with replacement; a repeated game is retained once per draw and receives one unit of total draw weight",
                "quantile_method": "type7", "failed_or_single_class_replicate": "invalidate the entire family-fold result; never skip a replicate",
            },
            "prestate_conformal": {"min_games": 2, "min_pilots": 2, "min_p_inclusive": 0.0},
        },
        "activation": {"min_overall_supported_mass": 0.0, "min_every_pilot_supported_mass": 0.0},
    }


class BranchSupportV2Tests(unittest.TestCase):
    def test_flattening_is_strict_and_defers_scalar_categories_to_one_hot(self) -> None:
        numeric, categorical = flatten_representation({
            "numeric": {"a": 1, "nested": {"b": 2.5}},
            "categorical": {"label": "z", "scalar_number": 3, "counts": {"basic": 4}},
        })
        self.assertEqual(numeric, {"numeric.a": 1.0, "numeric.nested.b": 2.5, "categorical.counts.basic": 4.0})
        self.assertEqual(categorical, {"categorical.label": '"z"', "categorical.scalar_number": "3"})
        with self.assertRaises(ValueError):
            flatten_representation({"numeric": {"a": True}, "categorical": {"kind": "x"}})

    def test_leave_one_pilot_out_removes_shared_game_and_replay(self) -> None:
        rows = _rows()
        shared = deepcopy(rows[0])
        shared["pilot"] = "p1"
        shared["native_root_id"] = "shared-root"
        shared["side_id"] = "side-p1"
        rows.append(shared)
        folds = leave_one_pilot_out_folds(rows)
        held_games = {rows[index]["game_id"] for index in folds["p0"]["test"]}
        held_replays = {rows[index]["replay_sha256"] for index in folds["p0"]["test"]}
        self.assertTrue(held_games)
        self.assertTrue(all(rows[index]["game_id"] not in held_games for index in folds["p0"]["train"]))
        self.assertTrue(all(rows[index]["replay_sha256"] not in held_replays for index in folds["p0"]["train"]))

    def test_stage_a_is_deterministic_and_reports_exact_action_root_support(self) -> None:
        rows = _rows()
        schedule = _schedule(rows)
        first = run_stage_a(rows, schedule, config=TEST_CONFIG)
        second = run_stage_a(rows, schedule, config=TEST_CONFIG)
        self.assertEqual(first, second)
        self.assertTrue(first["outcome_free"])
        self.assertFalse(first["native_successor_accessed"])
        self.assertEqual(first["support_rates"]["denominator"], len(schedule))
        self.assertTrue(all(item["selected_exact_action"] for item in first["root_diagnostics"]))
        self.assertTrue(all(len(item["actions"]) == 2 for item in first["root_diagnostics"]))
        self.assertTrue(all(item["reason"] == "supported" for item in first["root_diagnostics"]))
        self.assertEqual(type7_quantile([0.0, 2.0, 4.0, 10.0], 0.25), 1.5)
        expected = int.from_bytes(hashlib.sha256(b"17\x00p0\x00ATTACK\x000").digest()[:8], "big")
        self.assertEqual(sha_derived_seed(17, "p0", "ATTACK", 0), expected)

    def test_missing_slots_are_unsupported_and_counted(self) -> None:
        rows = _rows()
        schedule = _schedule(rows)
        schedule[0] = {
            "schema": "branch_bridge_root_schedule_v2", "side_id": rows[0]["side_id"], "slot_index": 0,
            "native_root_id": None, "root_priority_sha256": None, "status": "missing_eligible_root",
        }
        payload = run_stage_a(rows, schedule, config=TEST_CONFIG)
        self.assertFalse(payload["root_diagnostics"][0]["supported"])
        self.assertEqual(payload["root_diagnostics"][0]["reason"], "missing_scheduled_root")
        self.assertEqual(payload["support_rates"]["denominator"], len(schedule))
        self.assertLess(payload["support_rates"]["overall"], 1.0)

    def test_unseen_categories_and_forbidden_future_data_fail_closed(self) -> None:
        rows = _rows()
        for row in rows[:4]:
            row["representation"]["categorical"]["phase"] = "only-p0"
        payload = run_stage_a(rows, _schedule(rows), config=TEST_CONFIG)
        p0 = [item for item in payload["row_diagnostics"] if item["pilot"] == "p0"]
        self.assertTrue(all(item["family_support"][item["selected_family"]]["reason"].startswith("unseen_category") for item in p0))
        poisoned = deepcopy(rows)
        poisoned[0]["outcome"] = 1
        with self.assertRaisesRegex(ValueError, "forbids outcome/future"):
            run_stage_a(poisoned, _schedule(poisoned), config=TEST_CONFIG)
        invalid = deepcopy(rows)
        invalid[0]["legal_actions"][0]["action_key"] = "not-canonical"
        with self.assertRaises(ValueError):
            run_stage_a(invalid, _schedule(invalid), config=TEST_CONFIG)

    def test_unseen_category_is_local_to_the_affected_row(self) -> None:
        rows = _rows()
        rows[0]["representation"]["categorical"]["phase"] = "held-only"
        payload = run_stage_a(rows, _schedule(rows), config=TEST_CONFIG)
        p0 = [item for item in payload["row_diagnostics"] if item["pilot"] == "p0"]
        affected = next(item for item in p0 if item["native_root_id"] == rows[0]["native_root_id"])
        self.assertTrue(
            affected["family_support"][affected["selected_family"]]["reason"].startswith("unseen_category")
        )
        unaffected = [item for item in p0 if item["native_root_id"] != rows[0]["native_root_id"]]
        self.assertTrue(
            all(
                not item["family_support"][item["selected_family"]]["reason"].startswith("unseen_category")
                for item in unaffected
            )
        )

    def test_public_entry_derives_settings_from_preregistration(self) -> None:
        payload = evaluate_stage_a(_rows(), _schedule(_rows()), _preregistration())
        self.assertEqual(payload["config"]["bootstrap_samples"], 3)
        self.assertEqual(payload["execution_manifest_dependencies"], EXECUTION_MANIFEST_DEPENDENCIES)
        bad = _preregistration()
        bad["stage_a"]["propensity"]["c"] = 0.5
        with self.assertRaises(ValueError):
            evaluate_stage_a(_rows(), _schedule(_rows()), bad)

    def test_invalid_bootstrap_refit_invalidates_entire_family_fold(self) -> None:
        rows = _rows()
        prepared = tuple(support._prepare_row(row, index) for index, row in enumerate(rows))
        fold = leave_one_pilot_out_folds(rows)["p0"]
        initial = support._LogisticModel(0.0, (0.0,) * 7)
        with patch("evaluation_v2.branch_support_v2._fit_logistic", side_effect=[initial, None]):
            result = support._evaluate_family_fold(
                prepared, fold["train"], fold["test"], "p0", "ATTACK", support.StageAConfig.from_mapping(TEST_CONFIG)
            )
        self.assertEqual(result["diagnostic"]["reason"], "bootstrap_replicate_invalid")
        self.assertTrue(all(not item["supported"] for item in result["supports"].values()))

    def test_zero_weight_class_is_not_a_valid_bootstrap_fit(self) -> None:
        model = support._fit_logistic(
            [[0.0], [1.0]],
            [0, 1],
            [1.0, 0.0],
            random_state=1,
            max_iter=2000,
        )
        self.assertIsNone(model)

    def test_convergence_failure_invalidates_stage_globally(self) -> None:
        with patch(
            "evaluation_v2.branch_support_v2._fit_logistic",
            side_effect=support.StageAExecutionError("lbfgs convergence failure"),
        ):
            with self.assertRaisesRegex(support.StageAExecutionError, "convergence"):
                run_stage_a(_rows(), _schedule(_rows()), config=TEST_CONFIG)


if __name__ == "__main__":
    unittest.main()
