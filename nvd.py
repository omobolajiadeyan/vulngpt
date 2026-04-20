"""
NVD API client for fetching raw CVE data.
"""

import urllib.request
import urllib.parse
import json
import os


NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cve(cve_id: str) -> dict:
    """Fetch a single CVE by ID from the NVD API."""
    params = {"cveId": cve_id}
    url = f"{NVD_BASE}?{urllib.parse.urlencode(params)}"
    headers = {
        "User-Agent": "VulnGPT/1.0 (github.com/oadeyan/vulngpt)",
    }
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"NVD API error {e.code}: {e.reason}")
    except Exception as e:
        raise RuntimeError(f"Could not reach NVD: {e}")

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        raise ValueError(f"CVE '{cve_id}' not found in NVD.")
    return vulns[0].get("cve", {})


def parse_cve(raw: dict) -> dict:
    cve_id = raw.get("id", "N/A")

    descriptions = raw.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "No description available.",
    )

    metrics = raw.get("metrics", {})
    cvss_list = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
    score, severity, vector = "N/A", "N/A", "N/A"
    if cvss_list:
        cvss = cvss_list[0].get("cvssData", {})
        score = cvss.get("baseScore", "N/A")
        severity = cvss.get("baseSeverity", "N/A")
        vector = cvss.get("vectorString", "N/A")

    weaknesses = raw.get("weaknesses", [])
    cwes = []
    for w in weaknesses:
        for d in w.get("description", []):
            if d.get("lang") == "en":
                cwes.append(d.get("value", ""))

    refs = [r.get("url", "") for r in raw.get("references", [])[:5]]
    published = raw.get("published", "")[:10]
    modified = raw.get("lastModified", "")[:10]

    configs = raw.get("configurations", [])
    affected = []
    for config in configs:
        for node in config.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                if cpe.get("vulnerable"):
                    affected.append(cpe.get("criteria", ""))

    return {
        "id": cve_id,
        "description": description,
        "score": score,
        "severity": severity,
        "vector": vector,
        "cwes": cwes,
        "published": published,
        "modified": modified,
        "references": refs,
        "affected_products": affected[:10],
    }
