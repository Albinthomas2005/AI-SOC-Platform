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
from groq_service import DEFAULT_GROQ_MODEL, explain_alert
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
        "ai_model": os.getenv("GROQ_MODEL", DEFAULT_GROQ_MODEL),
        "ai_explanation": explanation,
        "sanitized_alert": alert,
        "status": "analyzed"
    }

    authorization = base64.b64encode(
        f"soc_ai_service:{password}".encode("utf-8")
    ).decode("ascii")
    request = urllib.request.Request(
        INDEX_URL,
        data=json.dumps(document).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Basic {authorization}",
        },
        method="POST",
    )
    ssl_context = ssl.create_default_context(cafile=CA_FILE)
    try:
        with urllib.request.urlopen(
            request, context=ssl_context, timeout=30
        ) as response:
            response_text = response.read().decode("utf-8")
    except urllib.error.URLError as error:
        print("Indexer save failed.")
        if isinstance(error, urllib.error.HTTPError):
            error_text = error.read().decode("utf-8", errors="replace")
            if error_text:
                print(error_text)
            if error.reason:
                print(error.reason)
        elif error.reason:
            print(error.reason)
        raise SystemExit(1) from None

    response_data = json.loads(response_text)
    print("Saved AI explanation to:", response_data.get("_index"))
    print("Document ID:", response_data.get("_id"))
    print("Result:", response_data.get("result"))


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
