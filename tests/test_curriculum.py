from pathlib import Path
import json
import tempfile
import unittest

from scripts.curriculum import discover_units, write_manifest

ROOT = Path(__file__).resolve().parents[1]


class CurriculumTests(unittest.TestCase):
    def test_repository_has_216_unique_course_units(self):
        units = discover_units(ROOT, {})
        self.assertEqual(216, len(units))
        self.assertEqual(216, len({unit.unit_id for unit in units}))

    def test_every_unit_points_to_existing_course_example_and_exercise(self):
        for unit in discover_units(ROOT, {}):
            self.assertTrue((ROOT / unit.course).is_file(), unit.unit_id)
            self.assertTrue((ROOT / unit.example).is_file(), unit.unit_id)
            self.assertTrue((ROOT / unit.exercise).is_file(), unit.unit_id)

    def test_manifest_is_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            overrides = ROOT / "content/status-overrides.json"
            write_manifest(ROOT, first, overrides)
            write_manifest(ROOT, second, overrides)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            payload = json.loads(first.read_text(encoding="utf-8"))
            self.assertEqual(216, payload["unit_count"])


if __name__ == "__main__":
    unittest.main()
