"""Validate model-generated ATT&CK technique references against a local catalog."""

import json
import re
from pathlib import Path


CATALOG_PATH = Path(__file__).resolve().parents[1] / "data" / "mitre_techniques.json"
TECHNIQUE_ID = re.compile(r"T\d{4}(?:\.\d{3})?\Z")
TECHNIQUE_TOKEN = re.compile(r"\bT\d+(?:\.\d+)?\b", re.IGNORECASE)


def load_techniques(path=CATALOG_PATH):
    """Load `{\"techniques\": [{\"id\": ..., \"name\": ...}]}` from JSON."""
    with Path(path).open(encoding="utf-8") as source:
        document = json.load(source)
    techniques = document.get("techniques") if isinstance(document, dict) else None
    if not isinstance(techniques, list):
        raise ValueError("ATT&CK catalog must contain a techniques array")

    catalog = {}
    for entry in techniques:
        if not isinstance(entry, dict):
            raise ValueError("ATT&CK technique entries must be objects")
        technique_id = entry.get("id")
        name = entry.get("name")
        if (
            not isinstance(technique_id, str)
            or not TECHNIQUE_ID.fullmatch(technique_id)
            or not isinstance(name, str)
            or not name.strip()
        ):
            raise ValueError("ATT&CK entries require a valid id and non-empty name")
        catalog[technique_id] = name.strip()
    return catalog


def validate_technique_id(technique_id, catalog):
    """Return valid, invalid, malformed, or unverified for one technique ID."""
    if not isinstance(technique_id, str) or not TECHNIQUE_ID.fullmatch(technique_id):
        return "malformed"
    if catalog is None:
        return "unverified"
    return "valid" if technique_id in catalog else "invalid"


def validate_mitre_references(text, catalog_path=CATALOG_PATH):
    """Remove IDs absent from a catalog or visibly mark IDs when none is usable."""
    try:
        catalog = load_techniques(catalog_path)
        unavailable_reason = ""
    except FileNotFoundError:
        catalog = None
        unavailable_reason = f"catalog not found at {catalog_path}"
    except (OSError, json.JSONDecodeError, ValueError):
        catalog = None
        unavailable_reason = f"catalog unavailable or invalid at {catalog_path}"

    findings = []

    def replace(match):
        value = match.group(0)
        normalized = value.upper()
        status = validate_technique_id(normalized, catalog)
        findings.append((normalized, status))
        if status == "valid":
            return value
        if status == "invalid":
            return "[invalid MITRE ID removed]"
        if status == "malformed":
            return "[malformed MITRE ID removed]"
        return f"{value} (unverified)"

    validated = TECHNIQUE_TOKEN.sub(replace, text)
    if findings:
        if catalog is None:
            ids = ", ".join(dict.fromkeys(item for item, _ in findings))
            validated += (
                "\n\nMITRE validation: unverified because the local ATT&CK "
                f"catalog is unavailable ({unavailable_reason}). IDs: {ids}."
            )
        else:
            invalid_count = sum(status == "invalid" for _, status in findings)
            malformed_count = sum(status == "malformed" for _, status in findings)
            notes = []
            if invalid_count:
                notes.append(f"omitted {invalid_count} ID(s) absent from the local catalog")
            if malformed_count:
                notes.append(f"omitted {malformed_count} malformed ID(s)")
            if notes:
                validated += "\n\nMITRE validation: " + "; ".join(notes) + "."
    return validated, findings
