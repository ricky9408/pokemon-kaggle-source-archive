from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools.run_branch_support_v2 import _read_jsonl


class RunBranchSupportV2Tests(unittest.TestCase):
    def test_jsonl_loader_is_strict_and_order_preserving(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rows.jsonl"
            path.write_text('{"value":1}\n{"value":2}\n', encoding="utf-8")
            self.assertEqual(_read_jsonl(path), [{"value": 1}, {"value": 2}])
            path.write_text('{"value":1}\n\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "blank"):
                _read_jsonl(path)


if __name__ == "__main__":
    unittest.main()
