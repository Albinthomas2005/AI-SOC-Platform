import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import app
from hunting import (
    ALLOWED_INDEX,
    HuntValidationError,
    validate_mitre_ids,
    validate_search_query,
)


TOKEN = "hunting-test-token"
HEADERS = {"Authorization": f"Bearer {TOKEN}", "X-SOC-User": "hunter-one"}
VALID_QUERY = {
    "index": ALLOWED_INDEX,
    "size": 100,
    "query": {"bool": {"must": [
        {"match": {"rule.description": "ssh authentication"}},
        {"range": {"@timestamp": {"gte": "now-24h"}}},
    ]}},
}


class HuntingApiTests(unittest.TestCase):
    def setUp(self):
        import database

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db_patch = patch.object(
            database, "DB_PATH", Path(self.temp.name) / "hunts.db"
        )
        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)
        self.env_patch = patch.dict(os.environ, {"SOC_AI_INTERNAL_TOKEN": TOKEN})
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        self.client = app.test_client()

    def test_query_validator_accepts_allowlisted_read_only_dsl(self):
        self.assertEqual(validate_search_query(VALID_QUERY), VALID_QUERY)
        exists_query = {
            "index": ALLOWED_INDEX, "size": 1,
            "query": {"exists": {"field": "rule.id"}},
        }
        self.assertEqual(validate_search_query(exists_query), exists_query)

    def test_query_validator_rejects_unsafe_indices_clauses_fields_and_sizes(self):
        invalid_queries = [
            {**VALID_QUERY, "index": "_all"},
            {**VALID_QUERY, "size": 1001},
            {**VALID_QUERY, "size": 0},
            {**VALID_QUERY, "script_fields": {"x": {"script": "1"}}},
            {**VALID_QUERY, "query": {"script": {"script": "ctx._source.x"}}},
            {**VALID_QUERY, "query": {"match": {"full_log": "secret"}}},
            {**VALID_QUERY, "query": {"bool": {"must": [{"delete": {"index": "x"}}]}}},
        ]
        for query in invalid_queries:
            with self.subTest(query=query), self.assertRaises(HuntValidationError):
                validate_search_query(query)

    def test_mitre_ids_are_validated_against_local_catalog(self):
        self.assertEqual(validate_mitre_ids(["T1110"])[0]["id"], "T1110")
        with self.assertRaisesRegex(HuntValidationError, "not in the local catalog"):
            validate_mitre_ids(["T9999"])
        with self.assertRaisesRegex(HuntValidationError, "malformed"):
            validate_mitre_ids(["T1110.1"])

    def test_proposal_is_validated_and_persisted_for_signed_in_user(self):
        proposal = {
            "hypothesis": "Repeated authentication attempts precede a success.",
            "query": VALID_QUERY,
            "mitre_ids": ["T1110"],
        }
        with patch("hunting.generate_hunt_proposal", return_value={
            "hypothesis": proposal["hypothesis"],
            "query": proposal["query"],
            "mitre": [{"id": "T1110", "name": "Brute Force"}],
        }) as generate:
            response = self.client.post(
                "/api/hunts/proposals",
                json={"question": "Find repeated authentication attempts."},
                headers=HEADERS,
            )
        self.assertEqual(response.status_code, 201, response.get_json())
        generate.assert_called_once()
        body = response.get_json()
        self.assertEqual(body["proposal"]["query"], VALID_QUERY)
        self.assertEqual(body["proposal"]["mitre"][0]["id"], "T1110")
        self.assertRegex(body["hunt_id"], r"^[0-9a-f]{32}$")

    def test_results_are_interpreted_sanitized_and_saved_as_report(self):
        proposal = {
            "hypothesis": "A successful login followed repeated failures.",
            "query": VALID_QUERY,
            "mitre": [{"id": "T1110", "name": "Brute Force"}],
        }
        with patch("hunting.generate_hunt_proposal", return_value=proposal):
            created = self.client.post(
                "/api/hunts/proposals", json={"question": "Review SSH failures."}, headers=HEADERS
            ).get_json()
        hunt_id = created["hunt_id"]
        hits = [{
            "_id": "alert-123",
            "_source": {
                "@timestamp": "2026-01-02T03:00:00Z",
                "rule": {"id": "5710", "description": "Authentication failed"},
                "data": {"srcip": "8.8.8.8", "password": "synthetic-secret"},
                "full_log": "synthetic raw log",
            },
        }]
        with patch("hunting.interpret_hunt_results", return_value="Finding cites alert-123") as interpret:
            saved = self.client.post(
                f"/api/hunts/{hunt_id}/results", json={"results": hits}, headers=HEADERS
            )
        self.assertEqual(saved.status_code, 200)
        self.assertEqual(saved.get_json()["result_count"], 1)
        interpreted_results = interpret.call_args.args[1]
        serialized = json.dumps(interpreted_results)
        for forbidden in ("synthetic-secret", "synthetic raw log", "8.8.8.8"):
            self.assertNotIn(forbidden, serialized)

        report = self.client.get(f"/api/hunts/{hunt_id}", headers=HEADERS)
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report.get_json()["report"]["interpretation"], "Finding cites alert-123")
        self.assertEqual(report.get_json()["report"]["user_id"], "hunter-one")
        other_user = self.client.get(
            f"/api/hunts/{hunt_id}", headers={**HEADERS, "X-SOC-User": "hunter-two"}
        )
        self.assertEqual(other_user.status_code, 404)

    def test_hunt_routes_require_internal_auth(self):
        unauthenticated = self.client.post(
            "/api/hunts/proposals", json={"question": "synthetic question"}
        )
        self.assertEqual(unauthenticated.status_code, 401)
        no_user = self.client.post(
            "/api/hunts/proposals",
            json={"question": "synthetic question"},
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        self.assertEqual(no_user.status_code, 400)


if __name__ == "__main__":
    unittest.main()
