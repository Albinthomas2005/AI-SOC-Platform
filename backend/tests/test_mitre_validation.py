import json
import tempfile
import unittest
from pathlib import Path

from mitre_validation import (
    load_techniques,
    validate_mitre_references,
    validate_technique_id,
)


class TestMitreValidation(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.catalog_path = Path(self.temp_dir.name) / "mitre_techniques.json"
        self.catalog_path.write_text(
            json.dumps(
                {
                    "techniques": [
                        {"id": "T1110", "name": "Brute Force", "tactics": ["Credential Access"]},
                        {"id": "T1059.001", "name": "PowerShell"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        self.catalog = load_techniques(self.catalog_path)

    def test_valid_technique_id_is_accepted(self):
        self.assertEqual(validate_technique_id("T1059.001", self.catalog), "valid")

    def test_real_parent_technique_id_is_accepted(self):
        self.assertEqual(validate_technique_id("T1110", self.catalog), "valid")

    def test_unknown_well_formed_id_is_invalid(self):
        self.assertEqual(validate_technique_id("T9999", self.catalog), "invalid")

    def test_malformed_id_is_rejected(self):
        self.assertEqual(validate_technique_id("T1059.1", self.catalog), "malformed")

    def test_invalid_ids_are_removed_and_flagged_in_output(self):
        result, findings = validate_mitre_references(
            "Review T1059.001 and T9999.", self.catalog_path
        )
        self.assertIn("T1059.001", result)
        self.assertNotIn("T9999", result)
        self.assertIn("omitted 1 ID(s) absent from the local catalog", result)
        self.assertEqual(findings, [("T1059.001", "valid"), ("T9999", "invalid")])

    def test_missing_catalog_marks_ids_unverified(self):
        absent = Path(self.temp_dir.name) / "missing.json"
        result, findings = validate_mitre_references("Review T1059.001.", absent)
        self.assertIn("T1059.001 (unverified)", result)
        self.assertIn("MITRE validation: unverified", result)
        self.assertEqual(findings, [("T1059.001", "unverified")])


if __name__ == "__main__":
    unittest.main()
