from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from evaluation_v2.stage_guard import (
    canonical_json,
    load_preregistration,
    reject_denylisted_artifact,
    require_outcome_blind,
    stage_execution_manifest,
    verify_execution_manifest,
)


class StageGuardTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[Path, Path]:
        artifact = root / "rows.jsonl"
        artifact.write_text("{}\n", encoding="utf-8")
        code = root / "stage.py"
        code.write_text("VALUE = 1\n", encoding="utf-8")
        lock = root / "requirements.txt"
        lock.write_text("numpy==1\n", encoding="utf-8")
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        code_digest = hashlib.sha256(code.read_bytes()).hexdigest()
        preregistration = {
            "schema": "branch_bridge_preregistration_v2",
            "experiment_id": "branch_bridge_v2",
            "status": "frozen_before_stage_a_metrics",
            "data": {"rows": {"path": "rows.jsonl", "sha256": digest}},
            "frozen_code": {"code": {"path": "stage.py", "sha256": code_digest}},
            "forbidden_artifacts": [{"sha256": "f" * 64}],
        }
        path = root / "prereg.json"
        path.write_text(json.dumps(preregistration), encoding="utf-8")
        return path, code

    def test_preregistration_verifies_every_bound_byte(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, _ = self._fixture(root)
            self.assertEqual(load_preregistration(path, root=root)["experiment_id"], "branch_bridge_v2")
            (root / "rows.jsonl").write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                load_preregistration(path, root=root)

    def test_outcome_fields_fail_at_any_depth(self) -> None:
        require_outcome_blind({"representation": {"turn": 2}})
        with self.assertRaisesRegex(ValueError, "forbidden"):
            require_outcome_blind({"safe": [{"winner": "pilot"}]})

    def test_denylisted_artifact_is_rejected_by_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "burned.json"
            path.write_text("burned", encoding="utf-8")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "denylisted"):
                reject_denylisted_artifact(path, {"forbidden_artifacts": [{"sha256": digest}]})

    def test_execution_manifest_binds_code_and_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prereg, code = self._fixture(root)
            manifest = stage_execution_manifest(
                stage="stage_a",
                preregistration_path=prereg,
                code_paths=[code],
                lock_paths=[root / "requirements.txt"],
                dependency_versions={"numpy": "1"},
            )
            verify_execution_manifest(
                manifest,
                stage="stage_a",
                preregistration_path=prereg,
                code_paths=[code],
                lock_paths=[root / "requirements.txt"],
                dependency_versions={"numpy": "1"},
            )
            changed = copy.deepcopy(manifest)
            changed["dependencies"]["numpy"] = "2"
            with self.assertRaisesRegex(ValueError, "does not match"):
                verify_execution_manifest(
                    changed,
                    stage="stage_a",
                    preregistration_path=prereg,
                    code_paths=[code],
                    lock_paths=[root / "requirements.txt"],
                    dependency_versions={"numpy": "1"},
                )
            self.assertEqual(manifest["content_sha256"], hashlib.sha256(canonical_json({k: v for k, v in manifest.items() if k != "content_sha256"}).encode("ascii")).hexdigest())


if __name__ == "__main__":
    unittest.main()
