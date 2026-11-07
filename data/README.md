# Local MITRE ATT&CK catalog

The complete Enterprise ATT&CK catalog is not bundled because it was not
available offline for verification. The backend looks for
`data/mitre_techniques.json`; without it, generated technique IDs are retained
but explicitly marked unverified. With it, IDs absent from the catalog are
removed and reported as invalid.

To create the file from MITRE's official Enterprise ATT&CK STIX 2.1 bundle,
download the `enterprise-attack.json` bundle from the `enterprise-attack`
directory of MITRE's `attack-stix-data` repository, then convert it:

```bash
curl -L \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json \
  -o /tmp/enterprise-attack.json
cd /path/to/AI-SOC-Platform
python3 backend/scripts/convert_attack_stix.py \
  /tmp/enterprise-attack.json data/mitre_techniques.json
```

The converter keeps non-revoked, non-deprecated `attack-pattern` objects with
a MITRE ATT&CK external ID and writes this format:

```json
{
  "source": "MITRE Enterprise ATT&CK STIX 2.1",
  "techniques": [
    {"id": "T1059.001", "name": "PowerShell"}
  ]
}
```

Do not edit or add technique entries by hand. Re-run the converter from an
official bundle when updating the catalog. The generated catalog is local
data; review its provenance and keep its source bundle/version recorded.
