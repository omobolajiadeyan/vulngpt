# Sample Output

Command:

```bash
python3 vulngpt.py CVE-2021-44228 --offline
```

Expected high-level result:

```text
CVE-2021-44228  |  CRITICAL - CVSS 10.0
Rule-based analysis (set CLAUDE_API_KEY for AI analysis)

SUMMARY
  CVE-2021-44228 is a CRITICAL-severity vulnerability affecting software
  systems. It is exploitable remotely over the network, no authentication
  required, no user interaction needed.

EXPLOITATION LIKELIHOOD
  CRITICAL
  Priority    : P1  |  Confidence: HIGH

REMEDIATION STEPS
  1. Identify affected assets and confirm vulnerable product versions.
  2. Apply the vendor security update or upgrade to a fixed version.
  3. If patching is delayed, restrict access and apply vendor workarounds.
```

JSON export:

```bash
python3 vulngpt.py CVE-2021-44228 --offline --output report.json
```

The JSON report includes:

- `cve.id`
- `cve.score`
- `cve.severity`
- `cve.vector`
- `cve.cwes`
- `analysis.exploitation_likelihood`
- `analysis.triage_priority`
- `analysis.confidence`
- `analysis.remediation`
- `analysis.detection_guidance`
- `analysis.limitations`
