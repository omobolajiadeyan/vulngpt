"""
AI-powered vulnerability analysis using the Anthropic Claude API.
Falls back to a structured rule-based analysis if no API key is set.
"""

import os
import json
import urllib.request


CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"


ANALYSIS_PROMPT = """You are a senior cybersecurity analyst. Analyze the following CVE and produce a structured report.

CVE Data:
{cve_json}

Your report must include:

1. PLAIN ENGLISH SUMMARY
   Write 2-3 sentences explaining what this vulnerability is, as if explaining to a non-technical executive.

2. TECHNICAL BREAKDOWN
   - What component/software is affected
   - What the attacker can do (e.g., remote code execution, privilege escalation, data exfiltration)
   - What conditions are required to exploit it (e.g., authentication needed, network access required)

3. EXPLOITATION LIKELIHOOD
   Rate as: LOW / MEDIUM / HIGH / CRITICAL
   Justify your rating in one sentence.

4. REAL-WORLD IMPACT
   What could actually happen to an organisation if this is exploited?

5. REMEDIATION STEPS
   Provide 3-5 concrete, actionable steps to remediate or mitigate this vulnerability.

6. DETECTION GUIDANCE
   What should a SOC analyst look for in logs or network traffic to detect exploitation attempts?

Format your response as valid JSON matching this structure:
{{
  "summary": "...",
  "technical": {{
    "affected_component": "...",
    "attacker_capability": "...",
    "exploitation_conditions": "..."
  }},
  "exploitation_likelihood": "HIGH",
  "likelihood_justification": "...",
  "real_world_impact": "...",
  "remediation": ["step 1", "step 2", "step 3"],
  "detection_guidance": "..."
}}
"""


def analyze_with_claude(cve: dict, api_key: str) -> dict:
    """Send CVE to Claude API for AI-powered analysis."""
    prompt = ANALYSIS_PROMPT.format(cve_json=json.dumps(cve, indent=2))

    payload = {
        "model": "claude-opus-4-6",
        "max_tokens": 1500,
        "messages": [{"role": "user", "content": prompt}],
    }

    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }

    req = urllib.request.Request(
        CLAUDE_API_URL,
        data=json.dumps(payload).encode(),
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            response = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        raise RuntimeError(f"Claude API error {e.code}: {body}")

    raw_text = response["content"][0]["text"].strip()

    # Extract JSON from response
    start = raw_text.find("{")
    end = raw_text.rfind("}") + 1
    if start == -1 or end == 0:
        raise ValueError("Claude did not return valid JSON.")

    return json.loads(raw_text[start:end])


def analyze_fallback(cve: dict) -> dict:
    """
    Rule-based analysis when no Claude API key is available.
    Produces a structured report from CVE data alone.
    """
    score = cve.get("score", 0)
    try:
        score = float(score)
    except (ValueError, TypeError):
        score = 0.0

    severity = cve.get("severity", "N/A")
    vector = cve.get("vector", "")
    cwes = cve.get("cwes", [])
    description = cve.get("description", "")

    # Exploitation likelihood from CVSS score
    if score >= 9.0:
        likelihood = "CRITICAL"
    elif score >= 7.0:
        likelihood = "HIGH"
    elif score >= 4.0:
        likelihood = "MEDIUM"
    else:
        likelihood = "LOW"

    # Detect attack type from vector string
    network_attack = "AV:N" in vector
    no_auth = "PR:N" in vector
    no_interaction = "UI:N" in vector

    conditions = []
    if network_attack:
        conditions.append("exploitable remotely over the network")
    else:
        conditions.append("requires local access")
    if no_auth:
        conditions.append("no authentication required")
    else:
        conditions.append("some authentication required")
    if no_interaction:
        conditions.append("no user interaction needed")

    remediation = [
        f"Apply the latest security patch for the affected software immediately.",
        f"If no patch is available, restrict network access to the affected component.",
        f"Enable logging and monitoring for the affected service.",
        f"Review access controls and apply principle of least privilege.",
        f"Check vendor advisories for workarounds: {cve['references'][0] if cve.get('references') else 'N/A'}",
    ]

    return {
        "summary": (
            f"{cve['id']} is a {severity}-severity vulnerability (CVSS {score}) affecting software systems. "
            f"It is {', '.join(conditions)}. Organisations should prioritise patching immediately."
        ),
        "technical": {
            "affected_component": ", ".join(cve.get("affected_products", ["See CVE description"])[:3]) or "See CVE description",
            "attacker_capability": f"Exploitation may allow {', '.join(cwes) if cwes else 'unauthorized access or code execution'}.",
            "exploitation_conditions": "; ".join(conditions),
        },
        "exploitation_likelihood": likelihood,
        "likelihood_justification": f"CVSS base score of {score} with vector {vector}.",
        "real_world_impact": (
            f"If exploited, an attacker could compromise the affected system. "
            f"Depending on the environment, this could lead to data breach, service disruption, or lateral movement."
        ),
        "remediation": remediation,
        "detection_guidance": (
            f"Monitor logs for unusual access patterns to the affected component. "
            f"Look for unexpected process spawning, privilege escalation events, or anomalous network connections. "
            f"Check SIEM alerts for {cve['id']} signatures."
        ),
        "note": "Generated by rule-based fallback. Set CLAUDE_API_KEY for AI-powered analysis.",
    }


def analyze(cve: dict) -> dict:
    """Analyze a CVE — uses Claude AI if API key is set, otherwise falls back to rule-based."""
    api_key = os.environ.get("CLAUDE_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        return analyze_with_claude(cve, api_key)
    return analyze_fallback(cve)
