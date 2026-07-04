# Security Policy

VulnGPT is a local vulnerability triage assistant. Its output is advisory and
must be validated against your actual asset exposure, compensating controls,
vendor advisories, and change-management requirements.

## Reporting Vulnerabilities

Please report security issues privately through GitHub security advisories or by
contacting Omobolaji Adeyan through the profile links at:

https://github.com/omobolajiadeyan

Do not open public issues for vulnerabilities that could expose users, API keys,
or private infrastructure details.

## Data Handling

Rule-based mode runs locally. Optional Claude/Anthropic analysis sends the CVE
summary payload to Anthropic. Do not send private asset inventory, internal host
names, tickets, or customer data through optional AI prompts.

## Supported Versions

The `main` branch is the only supported development line until tagged releases
are published.
