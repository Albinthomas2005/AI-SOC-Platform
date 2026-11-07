#!/usr/bin/env python3
"""Convert MITRE Enterprise ATT&CK STIX bundle to the backend catalog format."""

import json
import re
import sys
from pathlib import Path


TECHNIQUE_ID = re.compile(r"T\d{4}(?:\.\d{3})?\Z")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        raise SystemExit(f"Usage: {Path(sys.argv[0]).name} SOURCE.json DESTINATION.json")

    source, destination = map(Path, argv)
    bundle = json.loads(source.read_text(encoding="utf-8"))
    techniques = {}
    for item in bundle.get("objects", []):
        if (
            not isinstance(item, dict)
            or item.get("type") != "attack-pattern"
            or item.get("revoked") is True
            or item.get("x_mitre_deprecated") is True
        ):
            continue
        for reference in item.get("external_references", []):
            if reference.get("source_name") != "mitre-attack":
                continue
            technique_id = reference.get("external_id")
            name = item.get("name")
            if TECHNIQUE_ID.fullmatch(str(technique_id or "")) and isinstance(name, str):
                techniques[technique_id] = name

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(
            {
                "source": "MITRE Enterprise ATT&CK STIX 2.1",
                "techniques": [
                    {"id": technique_id, "name": techniques[technique_id]}
                    for technique_id in sorted(techniques)
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {len(techniques)} techniques to {destination}")


if __name__ == "__main__":
    main()
