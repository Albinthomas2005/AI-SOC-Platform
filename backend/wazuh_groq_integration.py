import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

PROJECT_DIR = Path(__file__).resolve().parent
load_dotenv(PROJECT_DIR / ".env")

sys.path.insert(0, str(PROJECT_DIR))
from gemini_service import explain_alert
from privacy_filter import sanitize_alert

PASSWORD_FILE = PROJECT_DIR / "secrets" / "opensearch_ai_password"
CA_FILE = str(PROJECT_DIR / "root-ca.pem")
INDEX_URL = "https://127.0.0.1:9200/soc-ai-explanations/_doc"


def save_explanation(alert, explanation):
    password = PASSWORD_FILE.read_text().strip()

    alert_id = (
        alert.get("id")
        or alert.get("alert_id")
        or "synthetic-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    )

    document = {
        "alert_id": str(alert_id),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "wazuh-groq-integration",
        "ai_model": os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
        "ai_explanation": explanation,
        "sanitized_alert": alert,
        "status": "analyzed"
    }

    import subprocess

    result = subprocess.run(
        [
            "curl", "--silent", "--show-error", "--fail-with-body",
            "--cacert", CA_FILE,
            "--user", "soc_ai_service:" + password,
            "-H", "Content-Type: application/json",
            "-X", "POST", INDEX_URL,
            "--data-binary", "@-"
        ],
        input=json.dumps(document),
        text=True,
        capture_output=True,
        timeout=30
    )

    if result.returncode != 0:
        print("Indexer save failed.")
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr)
        raise SystemExit(result.returncode)

    response = json.loads(result.stdout)
    print("Saved AI explanation to:", response.get("_index"))
    print("Document ID:", response.get("_id"))
    print("Result:", response.get("result"))


def main():
    if len(sys.argv) != 2:
        raise SystemExit(
            "Usage: python wazuh_groq_integration.py alert.json"
        )

    alert_path = Path(sys.argv[1]).expanduser()
    alert = json.loads(alert_path.read_text())

    if not isinstance(alert, dict):
        raise SystemExit("The alert JSON must be a single JSON object.")

    safe_alert = sanitize_alert(alert)
    print("Generating Groq explanation from sanitized alert...")
    explanation = explain_alert(safe_alert)

    if not isinstance(explanation, str) or not explanation.strip():
        raise SystemExit("Groq returned an empty explanation.")

    save_explanation(safe_alert, explanation)


if __name__ == "__main__":
    main()
