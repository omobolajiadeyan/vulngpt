#!/usr/bin/env python3
"""
VulnGPT — AI-powered vulnerability analyst.
Fetches CVE data from NVD and uses Claude AI to generate
actionable security reports in plain English.
Author: Omobolaji Adeyan
"""

import argparse
import json
import sys
import os
from nvd import fetch_cve, parse_cve
from analyst import analyze

RED    = "\033[91m"
ORANGE = "\033[38;5;208m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

SEVERITY_COLOR = {
    "CRITICAL": RED,
    "HIGH": ORANGE,
    "MEDIUM": YELLOW,
    "LOW": GREEN,
}

LIKELIHOOD_COLOR = {
    "CRITICAL": RED,
    "HIGH": ORANGE,
    "MEDIUM": YELLOW,
    "LOW": GREEN,
}


def print_banner():
    print(f"""
{RED}{BOLD}
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗ ██████╗ ██████╗ ████████╗
 ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝ ██╔══██╗╚══██╔══╝
 ██║   ██║██║   ██║██║     ██╔██╗ ██║██║  ███╗██████╔╝   ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██║   ██║██╔═══╝    ██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║╚██████╔╝██║        ██║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝        ╚═╝
{RESET}{GRAY}  AI-powered vulnerability analyst | Powered by Claude AI | github.com/oadeyan{RESET}
""")


def print_report(cve: dict, analysis: dict):
    sev_color = SEVERITY_COLOR.get(str(cve.get("severity", "")).upper(), GRAY)
    lik_color = LIKELIHOOD_COLOR.get(str(analysis.get("exploitation_likelihood", "")).upper(), GRAY)
    ai_powered = "note" not in analysis

    print(f"\n{'═'*65}")
    print(f"  {BOLD}{cve['id']}{RESET}  |  {sev_color}{cve['severity']} — CVSS {cve['score']}{RESET}")
    if ai_powered:
        print(f"  {CYAN}Powered by Claude AI{RESET}")
    else:
        print(f"  {GRAY}Rule-based analysis (set CLAUDE_API_KEY for AI analysis){RESET}")
    print(f"{'═'*65}")

    print(f"\n{BOLD}SUMMARY{RESET}")
    summary = analysis.get("summary", "N/A")
    words = summary.split()
    line = "  "
    for word in words:
        if len(line) + len(word) + 1 > 72:
            print(line)
            line = "  " + word + " "
        else:
            line += word + " "
    if line.strip():
        print(line)

    tech = analysis.get("technical", {})
    print(f"\n{BOLD}TECHNICAL BREAKDOWN{RESET}")
    print(f"  Affected   : {tech.get('affected_component', 'N/A')}")
    print(f"  Capability : {tech.get('attacker_capability', 'N/A')}")
    print(f"  Conditions : {tech.get('exploitation_conditions', 'N/A')}")
    if cve.get("cwes"):
        print(f"  CWEs       : {', '.join(cve['cwes'])}")
    print(f"  Vector     : {GRAY}{cve.get('vector', 'N/A')}{RESET}")

    print(f"\n{BOLD}EXPLOITATION LIKELIHOOD{RESET}")
    likelihood = analysis.get("exploitation_likelihood", "N/A")
    print(f"  {lik_color}{BOLD}{likelihood}{RESET}  —  {analysis.get('likelihood_justification', '')}")

    print(f"\n{BOLD}REAL-WORLD IMPACT{RESET}")
    impact = analysis.get("real_world_impact", "N/A")
    print(f"  {impact}")

    print(f"\n{BOLD}REMEDIATION STEPS{RESET}")
    for i, step in enumerate(analysis.get("remediation", []), 1):
        print(f"  {i}. {step}")

    print(f"\n{BOLD}DETECTION GUIDANCE{RESET}")
    print(f"  {analysis.get('detection_guidance', 'N/A')}")

    if cve.get("references"):
        print(f"\n{BOLD}REFERENCES{RESET}")
        for ref in cve["references"][:3]:
            print(f"  {GRAY}{ref}{RESET}")

    print(f"\n{'═'*65}\n")


def export_report(cve: dict, analysis: dict, output: str):
    data = {"cve": cve, "analysis": analysis}
    with open(output, "w") as f:
        json.dump(data, f, indent=2)
    print(f"{GREEN}Report saved to {output}{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="VulnGPT — AI-powered CVE vulnerability analyst",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vulngpt.py CVE-2021-44228           # Analyze Log4Shell
  python vulngpt.py CVE-2023-44487           # Analyze HTTP/2 Rapid Reset
  python vulngpt.py CVE-2024-3400 --output report.json

Set your Claude API key for AI-powered analysis:
  export CLAUDE_API_KEY=your-key-here
  python vulngpt.py CVE-2021-44228

Get a free API key at: https://console.anthropic.com
        """,
    )
    parser.add_argument("cve_id", help="CVE ID to analyze (e.g. CVE-2021-44228)")
    parser.add_argument("--output", "-o", help="Save report to JSON file")
    parser.add_argument("--json", action="store_true", help="Print raw JSON output")

    args = parser.parse_args()
    cve_id = args.cve_id.upper()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    print_banner()
    print(f"{CYAN}Fetching {cve_id} from NVD...{RESET}")

    try:
        raw = fetch_cve(cve_id)
        cve = parse_cve(raw)
    except (RuntimeError, ValueError) as e:
        print(f"{RED}Error: {e}{RESET}")
        sys.exit(1)

    ai_key = os.environ.get("CLAUDE_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
    if ai_key:
        print(f"{CYAN}Analyzing with Claude AI...{RESET}\n")
    else:
        print(f"{YELLOW}No CLAUDE_API_KEY set — using rule-based analysis.{RESET}\n")

    try:
        analysis = analyze(cve)
    except Exception as e:
        print(f"{RED}Analysis error: {e}{RESET}")
        sys.exit(1)

    if args.json:
        print(json.dumps({"cve": cve, "analysis": analysis}, indent=2))
    else:
        print_report(cve, analysis)

    if args.output:
        export_report(cve, analysis, args.output)


if __name__ == "__main__":
    main()
