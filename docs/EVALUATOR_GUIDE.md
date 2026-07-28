# External Evaluator Guide

This guide is for an external professional who wants to understand VulnGPT
quickly, run it safely, and judge whether it does the job it claims to do.

## Product Promise

VulnGPT turns CVE metadata into an actionable triage report. It explains:

- what is affected
- how exploitation conditions look from CVSS and reference signals
- likely triage priority
- remediation steps
- detection guidance
- confidence and limitations

It can run without API keys using deterministic, rule-based analysis.

## Five-Minute Demo

Run the bundled Log4Shell fixture. This does not require network access.

```bash
python3 vulngpt.py CVE-2021-44228 --offline
```

Export machine-readable output:

```bash
python3 vulngpt.py CVE-2021-44228 --offline --json
python3 vulngpt.py CVE-2021-44228 --offline --output report.json
```

## Expected Outcome

The terminal report should show:

- CVE ID and severity
- technical breakdown
- exploitation likelihood
- triage priority
- remediation steps
- detection guidance
- references
- explicit limitations

For the bundled Log4Shell fixture, the expected triage result is:

| Field | Expected Value |
|---|---|
| CVE | `CVE-2021-44228` |
| Severity | `CRITICAL` |
| CVSS | `10.0` |
| Exploitation likelihood | `CRITICAL` |
| Priority | `P1` |
| Confidence | `HIGH` |

## Who This Is For

- security analysts who need a readable first-pass CVE triage note
- developers who need remediation direction from CVE metadata
- students and educators demonstrating vulnerability prioritization
- teams that want deterministic demos before adding optional AI narrative

## What This Is Not

VulnGPT does not know your asset inventory, exposure, compensating controls, or
business criticality. It does not replace:

- vendor advisories
- emergency change control
- asset-aware vulnerability management
- exploit validation
- human risk acceptance decisions

Use the report as a structured starting point, then adjust priority using your
environment.

## Optional AI Mode

If `CLAUDE_API_KEY` is set, VulnGPT can enrich the narrative. Do not send
private asset data, customer information, or sensitive environment details to
AI-assisted mode.
