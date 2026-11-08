# Local MITRE ATT&CK catalog

The backend loads `data/mitre_techniques.json` to validate generated
Enterprise ATT&CK technique IDs. IDs absent from the catalog are reported as
invalid; without a usable catalog, IDs are explicitly marked unverified.

The committed catalog is generated from the official Enterprise ATT&CK STIX
2.1 bundle. The source bundle is kept locally at
`data/raw/enterprise-attack.json` and is ignored by Git. To regenerate after
updating that local source file, run this command from the repository root:

```bash
python3 scripts/build_mitre_catalog.py \
  data/raw/enterprise-attack.json data/mitre_techniques.json
```

The script includes non-revoked, non-deprecated Enterprise `attack-pattern`
objects with a MITRE ATT&CK external ID, along with their names and tactic
names. IDs are taken directly from STIX external references; the builder does
not create or infer IDs. The generated format is:

```json
{
  "source": "MITRE Enterprise ATT&CK STIX 2.1",
  "source_bundle": "enterprise-attack.json",
  "source_bundle_id": "bundle--...",
  "techniques": [
    {"id": "T1059.001", "name": "PowerShell", "tactics": ["Execution"]}
  ]
}
```

Do not edit or add technique entries by hand. Re-run the builder from an
official bundle when updating the catalog. Keep the source bundle ID with the
generated catalog so its provenance can be traced.
