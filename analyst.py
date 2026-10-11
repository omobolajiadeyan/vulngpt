"""
Vulnerability analysis using an optional Anthropic Claude API call.
Falls back to a structured deterministic analysis if no API key is set.
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

3. EXPLOITABILITY AND ACTIVE EXPLOITATION
   - Give a CVSS-based heuristic exploitability rating: LOW / MEDIUM / HIGH / CRITICAL / UNKNOWN.
     This describes intrinsic indicators only; it is not a probability or evidence of attacks.
   - State active_exploitation_status as UNKNOWN. The supplied data contains no CISA KEV
     lookup or environment telemetry. Do not infer active exploitation from CVSS, CWE,
     reference tags, or a public proof of concept.
   - Explain the evidence and its limitations separately.

4. REAL-WORLD IMPACT
   What could actually happen to an organisation if this is exploited?

5. TRIAGE AND REMEDIATION
   - Recommend a baseline priority from CVSS severity, not a claim of observed exploitation
     or knowledge of the user's asset exposure.
   - Give 3-5 concrete steps: confirm affected assets and fixed versions, apply vendor
     guidance, and use proportionate mitigations if patching is delayed. Avoid asserting
     emergency action is required unless the supplied evidence supports it.

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
  "heuristic_exploitability": "HIGH",
  "active_exploitation_status": "UNKNOWN",
  "exploitability_basis": "...",
  "confidence": "MEDIUM",
  "confidence_basis": "...",
  "triage_priority": "P2",
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
    score = cve.get("score")
    try:
        score = float(score)
        if not 0 <= score <= 10:
            score = None
    except (ValueError, TypeError):
        score = None

    severity = cve.get("severity", "N/A")
    vector = cve.get("vector", "")
    cwes = cve.get("cwes", [])
    references = cve.get("reference_details", [])
    reference_tags = {tag.lower() for ref in references for tag in ref.get("tags", [])}

    network_attack = "AV:N" in vector
    no_auth = "PR:N" in vector
    no_interaction = "UI:N" in vector
    public_exploit_signal = "exploit" in reference_tags

    # CVSS describes intrinsic severity and exploitability, not observed attacks.
    if score is None:
        exploitability = "UNKNOWN"
        priority = "UNRATED"
    elif score >= 9.0:
        exploitability = "CRITICAL"
        priority = "P1"
    elif score >= 7.0:
        exploitability = "HIGH"
        priority = "P2"
    elif score >= 4.0:
        exploitability = "MEDIUM"
        priority = "P3"
    else:
        exploitability = "LOW"
        priority = "P4"

    conditions = []
    if vector == "N/A" or not vector:
        conditions.append("attack vector is not available in the CVE metadata")
    elif network_attack:
        conditions.append("exploitable remotely over the network")
    else:
        conditions.append("requires local access")
    if vector == "N/A" or not vector:
        conditions.append("authentication requirements are unknown")
    elif no_auth:
        conditions.append("no authentication required")
    else:
        conditions.append("some authentication required")
    if vector != "N/A" and vector and no_interaction:
        conditions.append("no user interaction needed")

    if score is not None and vector and vector != "N/A":
        confidence = "HIGH"
        confidence_basis = "CVSS score and vector are available; this is confidence in the metadata-based triage, not exploitation status."
    elif score is not None:
        confidence = "MEDIUM"
        confidence_basis = "CVSS score is available but the vector is missing; exploitation status and asset exposure are not assessed."
    else:
        confidence = "LOW"
        confidence_basis = "CVSS score is unavailable or invalid; severity, exploitation status, and asset exposure need validation."

    score_text = f"{score:.1f}" if score is not None else "unavailable"
    vector_text = vector if vector and vector != "N/A" else "unavailable"

    remediation = [
        "Inventory potentially affected assets and confirm product versions against the vendor advisory.",
        "Apply the vendor security update or upgrade affected instances to a fixed version, prioritizing by this CVSS-based baseline and local exposure.",
        "If patching is delayed, apply vendor-approved mitigations and restrict access to affected components where feasible.",
        "Review relevant service logs and threat intelligence for indicators; this report does not establish that exploitation is occurring.",
        f"Review vendor advisories and references: {cve['references'][0] if cve.get('references') else 'N/A'}",
    ]

    return {
        "summary": (
            f"{cve['id']} is a {severity}-severity vulnerability (CVSS {score_text}) affecting software systems. "
            f"Available CVSS vector indicators: {', '.join(conditions)}. These describe intrinsic conditions only; "
            "they do not establish active exploitation or whether your systems are affected."
        ),
        "technical": {
            "affected_component": ", ".join(cve.get("affected_products", ["See CVE description"])[:3]) or "See CVE description",
            "attacker_capability": f"Exploitation may allow {', '.join(cwes) if cwes else 'unauthorized access or code execution'}.",
            "exploitation_conditions": "; ".join(conditions),
        },
        "heuristic_exploitability": exploitability,
        "active_exploitation_status": "UNKNOWN",
        "active_exploitation_evidence": (
            "Not assessed: this tool does not query CISA KEV or environment telemetry. "
            "A CVSS vector or tagged public reference is not evidence of active exploitation."
        ),
        "public_exploit_reference_signal": public_exploit_signal,
        "exploitability_basis": (
            f"CVSS base score {score_text} and vector {vector_text}; network attack={network_attack if vector_text != 'unavailable' else 'unknown'}, "
            f"no privileges required={no_auth if vector_text != 'unavailable' else 'unknown'}, "
            f"no user interaction={no_interaction if vector_text != 'unavailable' else 'unknown'}. "
            f"Public exploit/advisory reference tag present={public_exploit_signal}; this is a reference signal, not proof of active attacks."
        ),
        "triage_priority": priority,
        "confidence": confidence,
        "confidence_basis": confidence_basis,
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
        "limitations": [
            "CVSS and public reference tags are indicators only; active exploitation has not been verified.",
            "This report does not know your asset exposure, affected product versions, compensating controls, or business criticality.",
            "No CISA KEV, EPSS, asset inventory, SBOM, or security telemetry is queried.",
        ],
        "note": "Generated by deterministic fallback. Set CLAUDE_API_KEY for optional AI-assisted narrative analysis.",
    }


def analyze(cve: dict) -> dict:
    """Analyze a CVE — uses Claude AI if API key is set, otherwise falls back to rule-based."""
    api_key = os.environ.get("CLAUDE_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        analysis = analyze_with_claude(cve, api_key)
        # Do not allow generated narrative to present CVSS indicators as evidence
        # of active exploitation or to overstate priority/confidence.
        baseline = analyze_fallback(cve)
        for field in (
            "heuristic_exploitability",
            "active_exploitation_status",
            "active_exploitation_evidence",
            "public_exploit_reference_signal",
            "exploitability_basis",
            "triage_priority",
            "confidence",
            "confidence_basis",
        ):
            analysis[field] = baseline[field]
        return analysis
    return analyze_fallback(cve)
