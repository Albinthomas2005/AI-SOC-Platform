#!/usr/bin/env python3
"""Run a local, synthetic-alert evaluation against the AI analysis API."""

import argparse
import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = BACKEND_DIR.parent
SCENARIOS_FILE = REPOSITORY_ROOT / "datasets" / "simulated-alerts" / "scenarios.json"
REPORT_FILE = REPOSITORY_ROOT / "documentation" / "evaluation.md"


def read_internal_token(env_file=BACKEND_DIR / ".env"):
    """Read the internal token without writing it to stdout or logs."""
    try:
        lines = env_file.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ValueError("backend/.env is missing or unreadable") from error

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("SOC_AI_INTERNAL_TOKEN="):
            token = stripped.partition("=")[2].strip().strip("\"'")
            if token:
                return token
    raise ValueError("SOC_AI_INTERNAL_TOKEN is missing from backend/.env")


def evaluate_response(response, scenario):
    """Check an HTTP response against a scenario's content expectations."""
    try:
        status_code = response.status
        payload = json.loads(response.read().decode("utf-8"))
    except (AttributeError, UnicodeDecodeError, json.JSONDecodeError):
        status_code = getattr(response, "status", None)
        payload = {}

    analysis = payload.get("analysis", "") if isinstance(payload, dict) else ""
    usable_analysis = (
        status_code == 200
        and isinstance(payload, dict)
        and payload.get("ok") is True
        and isinstance(analysis, str)
    )
    normalized = analysis.casefold() if usable_analysis else ""
    checks = {
        "api": usable_analysis,
        "mitre": bool(scenario["expected_mitre"])
        and scenario["expected_mitre"].casefold() in normalized,
        "keywords": bool(scenario["must_mention"])
        and all(keyword.casefold() in normalized for keyword in scenario["must_mention"]),
        "claims": bool(usable_analysis)
        and all(phrase.casefold() not in normalized for phrase in scenario["must_not_claim"]),
    }
    checks["overall"] = all(checks.values())
    return checks


def load_scenarios(path=SCENARIOS_FILE):
    with path.open(encoding="utf-8") as source:
        scenarios = json.load(source)
    if not isinstance(scenarios, list) or len(scenarios) != 10:
        raise ValueError("Expected exactly 10 synthetic evaluation scenarios")
    return scenarios


def markdown_report(results):
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = [
        "# Synthetic AI Analysis Evaluation",
        "",
        f"Last run: {generated}",
        "",
        "These scenarios use synthetic, allowlisted Wazuh-style alerts. This report checks response text mechanically; it is not a clinical, security, or analyst-quality certification.",
        "",
        "| Scenario | API | MITRE | Keywords | Prohibited claims | Time (ms) | Overall |",
        "|---|---|---|---|---|---:|---|",
    ]
    for result in results:
        checks = result["checks"]
        format_check = lambda key: "PASS" if checks[key] else "FAIL"
        rows.append(
            "| {scenario} | {api} | {mitre} | {keywords} | {claims} | {duration:.0f} | {overall} |".format(
                scenario=result["scenario"],
                api=format_check("api"),
                mitre=format_check("mitre"),
                keywords=format_check("keywords"),
                claims=format_check("claims"),
                duration=result["duration_ms"],
                overall=format_check("overall"),
            )
        )
    rows.extend(
        [
            "",
            "## Limitations",
            "",
            "- All inputs are synthetic and do not establish performance on real Wazuh telemetry.",
            "- Keyword and phrase checks are literal, case-insensitive string checks; paraphrases can produce false failures, and a passing keyword check does not prove factual correctness.",
            "- The harness does not validate analyst usefulness, MITRE mapping quality, privacy leakage, hallucination beyond the listed phrases, or service availability outside this run.",
            "- Review every AI response manually. Do not use this harness as authorization for automated response actions.",
            "",
        ]
    )
    return "\n".join(rows)


def write_report(results, path=REPORT_FILE):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(markdown_report(results), encoding="utf-8")


def run_scenario(scenario, token, port):
    request_body = json.dumps({"alert": scenario["alert"]}).encode("utf-8")
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/ai/analyze-alert",
        data=request_body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            checks = evaluate_response(response, scenario)
    except (urllib.error.URLError, TimeoutError):
        checks = {
            "api": False,
            "mitre": False,
            "keywords": False,
            "claims": False,
            "overall": False,
        }
    return {
        "scenario": scenario["name"],
        "checks": checks,
        "duration_ms": (time.monotonic() - started) * 1000,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    try:
        token = read_internal_token()
        scenarios = load_scenarios()
    except ValueError as error:
        parser.error(str(error))

    results = [run_scenario(scenario, token, args.port) for scenario in scenarios]
    write_report(results)
    print(f"Wrote evaluation results for {len(results)} synthetic scenarios to documentation/evaluation.md")
    print(f"Passed: {sum(result['checks']['overall'] for result in results)}/{len(results)}")
    return 0 if all(result["checks"]["overall"] for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
