#!/usr/bin/env python3
"""Run a local, synthetic-alert evaluation against the AI analysis API."""

import argparse
import json
import re
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

    def keyword_present(keyword_or_synonyms):
        if isinstance(keyword_or_synonyms, str):
            return keyword_or_synonyms.casefold() in normalized
        if (
            isinstance(keyword_or_synonyms, list)
            and keyword_or_synonyms
            and all(isinstance(option, str) for option in keyword_or_synonyms)
        ):
            return any(option.casefold() in normalized for option in keyword_or_synonyms)
        return False

    expected_mitre = scenario.get("expected_mitre")
    checks = {
        "api": usable_analysis,
        "mitre": (
            expected_mitre.casefold() in normalized
            if expected_mitre
            else None
        ),
        "keywords": bool(scenario["must_mention"])
        and all(keyword_present(keyword) for keyword in scenario["must_mention"]),
        "claims": bool(usable_analysis)
        and all(phrase.casefold() not in normalized for phrase in scenario["must_not_claim"]),
    }
    applicable_checks = [checks["api"], checks["keywords"], checks["claims"]]
    if not scenario.get("mitre_in_input", False) and checks["mitre"] is not None:
        applicable_checks.append(checks["mitre"])
    checks["overall"] = all(applicable_checks)
    return checks


def load_scenarios(path=SCENARIOS_FILE):
    with path.open(encoding="utf-8") as source:
        scenarios = json.load(source)
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError("Expected at least one synthetic evaluation scenario")
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
        "| Scenario | MITRE in input | API | MITRE | Keywords | Prohibited claims | Time (ms) | Overall |",
        "|---|---|---|---|---|---:|---|",
    ]
    for result in results:
        checks = result["checks"]
        format_check = lambda key: (
            "N/A" if checks[key] is None else "PASS" if checks[key] else "FAIL"
        )
        mitre_context = "yes (not independent)" if result["mitre_in_input"] else "no"
        rows.append(
            "| {scenario} | {mitre_context} | {api} | {mitre} | {keywords} | {claims} | {duration:.0f} | {overall} |".format(
                scenario=result["scenario"],
                mitre_context=mitre_context,
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
            "## MITRE evidence context",
            "",
            "The MITRE check for scenarios with `mitre_in_input: true` is reported for visibility but excluded from the overall result: the expected technique was already present in the alert and is not independent evidence that the model inferred it. Scenarios without an expected technique show MITRE as N/A.",
            "",
            "Scenarios with MITRE supplied in the input:",
            "",
        ]
    )
    supplied = [result["scenario"] for result in results if result["mitre_in_input"]]
    rows.extend(f"- {scenario}" for scenario in supplied)
    if not supplied:
        rows.append("- None")
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


def run_scenario(scenario, token, port, save_responses_dir=None):
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
    response_body = None
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            response_body = response.read()
            checks = evaluate_response(
                _BufferedResponse(response.status, response_body), scenario
            )
    except (urllib.error.URLError, TimeoutError):
        checks = {
            "api": False,
            "mitre": False if scenario.get("expected_mitre") else None,
            "keywords": False,
            "claims": False,
            "overall": False,
        }
    if save_responses_dir is not None and response_body is not None:
        save_responses_dir.mkdir(parents=True, exist_ok=True)
        filename = re.sub(r"[^a-z0-9]+", "-", scenario["name"].casefold()).strip("-")
        (save_responses_dir / f"{filename}.json").write_bytes(response_body)
    return {
        "scenario": scenario["name"],
        "checks": checks,
        "mitre_in_input": bool(scenario.get("mitre_in_input", False)),
        "duration_ms": (time.monotonic() - started) * 1000,
    }


class _BufferedResponse:
    """Minimal response wrapper so a captured body can be checked and saved."""

    def __init__(self, status, body):
        self.status = status
        self._body = body

    def read(self):
        return self._body


def run_scenarios(scenarios, token, port, delay=0, save_responses_dir=None):
    results = []
    for index, scenario in enumerate(scenarios):
        if index and delay:
            time.sleep(delay)
        results.append(run_scenario(scenario, token, port, save_responses_dir))
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--save-responses", type=Path, metavar="DIR")
    parser.add_argument("--delay", type=float, default=0, metavar="SECONDS")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if args.delay < 0:
        parser.error("--delay must be non-negative")

    try:
        token = read_internal_token()
        scenarios = load_scenarios()
    except ValueError as error:
        parser.error(str(error))

    results = run_scenarios(
        scenarios,
        token,
        args.port,
        args.delay,
        args.save_responses,
    )
    write_report(results)
    print(f"Wrote evaluation results for {len(results)} synthetic scenarios to documentation/evaluation.md")
    print(f"Passed: {sum(result['checks']['overall'] for result in results)}/{len(results)}")
    return 0 if all(result["checks"]["overall"] for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
