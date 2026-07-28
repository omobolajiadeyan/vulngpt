# VulnGPT

VulnGPT is a CVE vulnerability triage assistant. It fetches CVE data from the National Vulnerability Database, parses CVSS/CWE/reference context, and generates an actionable report with exploitation likelihood, remediation steps, detection guidance, triage priority, confidence, and limitations.

It works without API keys through a deterministic rule-based fallback. Optional Claude/Anthropic analysis can be enabled for narrative enrichment, but the project is designed to remain demoable and testable offline.

## Why This Exists

CVE descriptions often explain what is vulnerable, but not what an analyst should do next. VulnGPT turns CVE metadata into a practical triage report:

- What is affected?
- How likely is exploitation based on CVSS and public reference signals?
- What priority should the issue receive?
- What should defenders monitor?
- What are the limitations of this conclusion?

## For External Reviewers

If you are evaluating this project, start here:

- [External Evaluator Guide](docs/EVALUATOR_GUIDE.md) - five-minute review path, expected outcome, and trust boundaries
- [Sample Output](docs/SAMPLE_OUTPUT.md) - what the offline demo should produce

Fastest safe demo:

```bash
python3 vulngpt.py CVE-2021-44228 --offline
python3 vulngpt.py CVE-2021-44228 --offline --output report.json
```

The bundled fixture keeps the demo deterministic and does not require network
access or API keys.

## Features

- Fetches CVE metadata from NVD
- Offline fixture mode for deterministic demos and tests
- Parses CVSS v3.1/v3.0, CWE, references, dates, and affected CPEs
- Rule-based exploitation likelihood and triage priority
- Optional Claude/Anthropic narrative analysis via `CLAUDE_API_KEY`
- JSON export for tickets, reports, or automation
- Zero runtime dependencies in deterministic mode
- Unit-tested NVD parsing, analysis, and CLI behavior

## Installation

```bash
git clone https://github.com/omobolajiadeyan/vulngpt.git
cd vulngpt
python --version  # Python 3.10+ required
```

Optional local install:

```bash
python -m pip install .
vulngpt CVE-2021-44228 --offline
```

## Usage

```bash
# Demo without network access, using the bundled Log4Shell fixture
python vulngpt.py CVE-2021-44228 --offline

# Fetch from NVD and use deterministic fallback analysis
python vulngpt.py CVE-2023-44487

# Export report to JSON
python vulngpt.py CVE-2021-44228 --offline --output report.json

# Raw JSON output
python vulngpt.py CVE-2021-44228 --offline --json
```

Optional AI-assisted narrative mode:

```bash
export CLAUDE_API_KEY=your-key-here
python vulngpt.py CVE-2021-44228
```

Rule-based mode is preferred for repeatable tests, demos, and CI. AI-assisted mode should not be used with private asset data or customer information.

## Example Output

```text
CVE-2021-44228  |  CRITICAL — CVSS 10.0
Rule-based analysis (set CLAUDE_API_KEY for AI analysis)

SUMMARY
  CVE-2021-44228 is a CRITICAL-severity vulnerability (CVSS 10.0)
  affecting software systems. It is exploitable remotely over the
  network, no authentication required, no user interaction needed.

EXPLOITATION LIKELIHOOD
  CRITICAL — CVSS base score of 10.0 with vector
  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H.
  Priority    : P1  |  Confidence: HIGH

REMEDIATION STEPS
  1. Identify affected assets and confirm whether vulnerable product versions are present.
  2. Apply the vendor security update or upgrade to a fixed version as soon as change control allows.
  3. If patching is delayed, restrict network access to the affected component and apply vendor workarounds.
```

## Triage Model

The deterministic fallback uses:

- CVSS base score and severity
- CVSS vector signals such as network attack, privileges required, and user interaction
- CWE values
- NVD reference tags such as vendor advisory, exploit, or third-party advisory
- Affected product identifiers when available

Priority mapping:

| Likelihood | Priority |
|---|---|
| `CRITICAL` | `P1` |
| `HIGH` | `P2` |
| `MEDIUM` | `P3` |
| `LOW` | `P4` |

Limitations:

- It does not know whether your environment is exposed.
- It does not replace vendor advisories or emergency change control.
- It does not currently ingest EPSS, CISA KEV, asset inventory, or SBOM context.

## Offline Fixtures

Bundled fixtures live in:

```text
data/fixtures/
```

Run with:

```bash
python vulngpt.py CVE-2021-44228 --offline
```

Use a custom fixture directory:

```bash
python vulngpt.py CVE-2021-44228 --offline --fixture-dir ./my-fixtures
```

## Architecture

```text
vulngpt/
├── vulngpt.py        # CLI entrypoint and report renderer
├── nvd.py            # NVD API client, fixture loader, and CVE parser
├── analyst.py        # Optional Claude analysis and deterministic fallback
├── data/fixtures/    # Offline CVE fixtures for demos and tests
├── tests/            # Unit tests for parser, analyst, and CLI behavior
└── .github/workflows # CI test workflow
```

## Verification

```bash
python -m unittest discover -s tests -v
python vulngpt.py CVE-2021-44228 --offline --json
```

## Roadmap

- [ ] EPSS probability support
- [ ] CISA KEV enrichment
- [ ] Batch analysis for CVE lists
- [ ] SBOM/package-name matching
- [ ] SARIF or ticket-friendly export format
- [ ] Local LLM/Ollama support for air-gapped environments

## Author

**Omobolaji Adeyan** - Cybersecurity Engineer  
GitHub: https://github.com/omobolajiadeyan · Website: https://omobolajiadeyan.com

## License

MIT License. See [LICENSE](LICENSE).
