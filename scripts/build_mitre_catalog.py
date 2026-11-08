#!/usr/bin/env python3
"""Build the local Enterprise ATT&CK catalog from an official STIX bundle."""

import argparse
import json
import re
from pathlib import Path


ATTACK_ID = re.compile(r"T\d{4}(?:\.\d{3})?\Z")


def build_catalog(source_path):
    source_path = Path(source_path)
    bundle = json.loads(source_path.read_text(encoding="utf-8"))
    objects = bundle.get("objects") if isinstance(bundle, dict) else None
    if not isinstance(objects, list):
        raise ValueError("STIX document must contain an objects array")

    tactics = {
        obj["x_mitre_shortname"]: obj["name"]
        for obj in objects
        if obj.get("type") == "x-mitre-tactic"
        and not obj.get("revoked", False)
        and not obj.get("x_mitre_deprecated", False)
        and isinstance(obj.get("x_mitre_shortname"), str)
        and isinstance(obj.get("name"), str)
    }

    techniques = {}
    for obj in objects:
        if (obj.get("type") != "attack-pattern"
                or obj.get("revoked", False)
                or obj.get("x_mitre_deprecated", False)):
            continue
        references = [
            reference for reference in obj.get("external_references", [])
            if reference.get("source_name") == "mitre-attack"
            and isinstance(reference.get("external_id"), str)
            and ATTACK_ID.fullmatch(reference["external_id"])
        ]
        if not references:
            continue
        technique_id = references[0]["external_id"]
        name = obj.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        phases = {
            phase.get("phase_name")
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        }
        unknown_phases = phases - tactics.keys()
        if unknown_phases:
            raise ValueError(
                f"Unknown MITRE tactic phase(s) for {technique_id}: "
                f"{', '.join(sorted(unknown_phases))}"
            )
        entry = {
            "id": technique_id,
            "name": name.strip(),
            "tactics": sorted(tactics[phase] for phase in phases),
        }
        if technique_id in techniques and techniques[technique_id] != entry:
            raise ValueError(f"Conflicting STIX entries for {technique_id}")
        techniques[technique_id] = entry

    if not techniques:
        raise ValueError("No Enterprise ATT&CK techniques found in STIX bundle")
    return {
        "source": "MITRE Enterprise ATT&CK STIX 2.1",
        "source_bundle": source_path.name,
        "source_bundle_id": bundle.get("id"),
        "techniques": [techniques[key] for key in sorted(techniques)],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="local Enterprise ATT&CK STIX bundle")
    parser.add_argument("output", type=Path, help="generated catalog JSON path")
    args = parser.parse_args()
    catalog = build_catalog(args.source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(catalog, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {len(catalog['techniques'])} techniques to {args.output}")


if __name__ == "__main__":
    main()
