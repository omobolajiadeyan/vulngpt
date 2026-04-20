# VulnGPT

An AI-powered vulnerability analyst that fetches CVE data from the National Vulnerability Database and uses Claude AI to generate plain-English security reports — including exploitation likelihood, real-world impact, remediation steps, and SOC detection guidance.

Built out of frustration with CVE descriptions that are technically accurate but practically useless. Most NVD entries tell you *what* is vulnerable but not *what to do about it*. VulnGPT bridges that gap.

## How It Works

1. Fetches the CVE from the NVD REST API
2. Sends the raw data to Claude AI with a structured analyst prompt
3. Claude returns a JSON report covering summary, technical breakdown, exploitation likelihood, impact, remediation, and detection guidance
4. Falls back to a rule-based analysis engine if no API key is configured

## Features

- AI-generated vulnerability reports in plain English
- Exploitation likelihood assessment (LOW / MEDIUM / HIGH / CRITICAL)
- Concrete, numbered remediation steps
- SOC detection guidance — what to look for in logs
- Structured JSON export for ticket/report integration
- Works without an API key (rule-based fallback)
- Zero third-party dependencies

## Installation

```bash
git clone https://github.com/oadeyan/vulngpt.git
cd vulngpt
python --version  # Python 3.10+ required
```

## Usage

```bash
# Analyze any CVE (rule-based, no API key needed)
python vulngpt.py CVE-2021-44228    # Log4Shell
python vulngpt.py CVE-2023-44487    # HTTP/2 Rapid Reset
python vulngpt.py CVE-2024-3400     # PAN-OS command injection

# Enable AI-powered analysis with Claude
export CLAUDE_API_KEY=your-key-here
python vulngpt.py CVE-2021-44228

# Export report to JSON
python vulngpt.py CVE-2021-44228 --output log4shell_report.json

# Raw JSON output
python vulngpt.py CVE-2021-44228 --json
```

Get a free Claude API key at: https://console.anthropic.com

## Example Output

```
 VULNGPT
 AI-powered vulnerability analyst | Powered by Claude AI

Fetching CVE-2021-44228 from NVD...
Analyzing with Claude AI...

═══════════════════════════════════════════════════════════════════
  CVE-2021-44228  |  CRITICAL — CVSS 10.0
  Powered by Claude AI
═══════════════════════════════════════════════════════════════════

SUMMARY
  Log4Shell is a critical remote code execution vulnerability in
  Apache Log4j 2, a widely used Java logging library. Any attacker
  who can control log messages can execute arbitrary code on the
  server with no authentication required.

TECHNICAL BREAKDOWN
  Affected   : Apache Log4j 2.0-beta9 through 2.14.1
  Capability : Remote code execution via JNDI injection
  Conditions : Exploitable remotely; no authentication required; no user interaction
  CWEs       : CWE-917, CWE-502
  Vector     : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

EXPLOITATION LIKELIHOOD
  CRITICAL  —  Publicly available exploits, actively exploited in the wild.

REMEDIATION STEPS
  1. Upgrade Log4j to version 2.17.1 or later immediately
  2. If upgrading is not possible, set log4j2.formatMsgNoLookups=true
  3. Block LDAP/RMI outbound traffic at the firewall as a workaround
  4. Scan your environment using tools like log4j-scanner
  5. Monitor for exploitation attempts in application logs
```

## Architecture

```
vulngpt/
├── vulngpt.py    # CLI entrypoint + report renderer
├── nvd.py        # NVD API client + CVE parser
├── analyst.py    # Claude AI analyst + rule-based fallback
└── README.md
```

## Roadmap

- [ ] Batch analysis of multiple CVEs
- [ ] PDF report generation
- [ ] Slack/Teams webhook integration for SOC alerting
- [ ] Local LLM support (Ollama) for air-gapped environments
- [ ] EPSS score integration for exploitation probability

## Author

**Omobolaji Adeyan** — Cybersecurity Portfolio Project  
[GitHub](https://github.com/oadeyan)
