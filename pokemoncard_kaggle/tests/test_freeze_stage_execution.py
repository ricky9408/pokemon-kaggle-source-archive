from __future__ import annotations

from pathlib import Path
import unittest

from tools.freeze_stage_execution import code_paths


class FreezeStageExecutionTests(unittest.TestCase):
    def test_code_paths_are_deduplicated_and_include_guard_and_tool(self) -> None:
        current = Path(__file__)
        paths = code_paths([current, current])
        self.assertEqual(len(paths), len(set(paths)))
        self.assertIn(current.resolve(), paths)
        self.assertTrue(any(path.name == "stage_guard.py" for path in paths))
        self.assertTrue(any(path.name == "freeze_stage_execution.py" for path in paths))


if __name__ == "__main__":
    unittest.main()
