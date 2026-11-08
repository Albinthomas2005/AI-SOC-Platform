import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import app


TOKEN = "training-test-token"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}
COMPLETE_REPORT = "Summary: routine package update. Evidence: alert says update completed. Actions: reviewed supplied record. Unknowns: authorization details not yet verified."


class TrainingApiTests(unittest.TestCase):
    def setUp(self):
        import database
        import training

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db_patch = patch.object(database, "DB_PATH", Path(self.temp.name) / "training.db")
        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)
        self.catalog = Path(self.temp.name) / "mitre.json"
        self.catalog.write_text(json.dumps({"techniques": [
            {"id": "T1110.001", "name": "Password Guessing"},
        ]}), encoding="utf-8")
        self.catalog_patch = patch.object(training, "CATALOG_PATH", self.catalog)
        self.catalog_patch.start()
        self.addCleanup(self.catalog_patch.stop)
        self.env = patch.dict(os.environ, {"SOC_AI_INTERNAL_TOKEN": TOKEN})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.client = app.test_client()

    def submit(self, **overrides):
        payload = {
            "scenario_id": "ssh-brute-force",
            "verdict": "true_positive",
            "escalate": True,
            "mitre_ids": ["T1110.001"],
            "report_text": COMPLETE_REPORT,
            "time_spent": 90,
        }
        payload.update(overrides)
        return self.client.post("/training/attempts", json=payload, headers=HEADERS)

    def test_auth_required_for_all_training_resources(self):
        for path in ("/training/scenarios", "/training/scenarios/ssh-brute-force", "/training/scenarios/ssh-brute-force/hints?level=1"):
            self.assertEqual(self.client.get(path).status_code, 401)
        self.assertEqual(self.client.post("/training/attempts", json={}).status_code, 401)

    def test_answer_keys_absent_from_visible_responses(self):
        for response in (
            self.client.get("/training/scenarios", headers=HEADERS),
            self.client.get("/training/scenarios/ssh-brute-force", headers=HEADERS),
        ):
            body = json.dumps(response.get_json()).casefold()
            for forbidden in ("expected_verdict", "expected_escalate", "accepted_mitre_ids", "explanation", "answer_status"):
                self.assertNotIn(forbidden, body)

    def test_hints_are_ordered_and_free(self):
        response = self.client.get("/training/scenarios/ssh-brute-force/hints?level=2", headers=HEADERS)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["score_impact"], 0)
        self.assertEqual(len(response.get_json()["hints"]), 2)

    def test_all_correct_submission_scores_and_reveals_feedback(self):
        response = self.submit()
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.get_json()["score"]["total"], 100)
        self.assertTrue(response.get_json()["feedback"]["verdict"])
        import database
        stored = database.get_training_attempt(response.get_json()["attempt_id"])
        self.assertNotIn("answer", json.dumps(dict(stored)).casefold())
        self.assertNotIn("explanation", json.dumps(dict(stored)).casefold())

    def test_wrong_verdict_and_escalation_are_graded_deterministically(self):
        response = self.submit(verdict="benign", escalate=False)
        score = response.get_json()["score"]
        self.assertFalse(score["verdict"]["correct"])
        self.assertFalse(score["escalation"]["correct"])

    def test_invalid_mitre_ids_are_flagged(self):
        response = self.submit(mitre_ids=["T9999", "not-an-id"])
        mitre = response.get_json()["score"]["mitre"]
        self.assertCountEqual(mitre["invalid"], ["T9999", "not-an-id"])
        self.assertFalse(mitre["correct"])

    def test_missing_report_sections_reduce_completeness_score(self):
        response = self.submit(report_text="Only a summary.")
        self.assertFalse(response.get_json()["score"]["report"]["complete"])
        self.assertEqual(response.get_json()["score"]["report"]["points"], 0)


if __name__ == "__main__":
    unittest.main()
