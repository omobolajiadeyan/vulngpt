import unittest
from unittest.mock import patch

from analyst import analyze, analyze_fallback
from nvd import fetch_cve, parse_cve


class AnalystTests(unittest.TestCase):
    def test_fallback_separates_cvss_potential_from_active_exploitation(self):
        cve = parse_cve(fetch_cve("CVE-2021-44228", offline=True))
        analysis = analyze_fallback(cve)

        self.assertEqual(analysis["heuristic_exploitability"], "CRITICAL")
        self.assertEqual(analysis["active_exploitation_status"], "UNKNOWN")
        self.assertTrue(analysis["public_exploit_reference_signal"])
        self.assertIn("not proof of active attacks", analysis["exploitability_basis"])
        self.assertEqual(analysis["triage_priority"], "P1")
        self.assertEqual(analysis["confidence"], "HIGH")
        self.assertIn("not exploitation status", analysis["confidence_basis"])
        self.assertTrue(analysis["remediation"])
        self.assertTrue(analysis["limitations"])

    @patch.dict("os.environ", {"CLAUDE_API_KEY": "test-key"})
    @patch("analyst.analyze_with_claude")
    def test_ai_assessment_labels_are_replaced_with_local_evidence_baseline(self, mock_claude):
        cve = parse_cve(fetch_cve("CVE-2021-44228", offline=True))
        mock_claude.return_value = {
            "heuristic_exploitability": "LOW",
            "active_exploitation_status": "CONFIRMED",
            "triage_priority": "P4",
            "confidence": "LOW",
            "summary": "AI narrative",
        }

        analysis = analyze(cve)

        self.assertEqual(analysis["heuristic_exploitability"], "CRITICAL")
        self.assertEqual(analysis["active_exploitation_status"], "UNKNOWN")
        self.assertEqual(analysis["triage_priority"], "P1")
        self.assertEqual(analysis["confidence"], "HIGH")
        self.assertEqual(analysis["summary"], "AI narrative")

    def test_missing_cvss_data_does_not_claim_low_risk_or_local_access(self):
        analysis = analyze_fallback({
            "id": "CVE-2099-0001",
            "score": "N/A",
            "severity": "N/A",
            "vector": "N/A",
            "references": [],
        })

        self.assertEqual(analysis["heuristic_exploitability"], "UNKNOWN")
        self.assertEqual(analysis["active_exploitation_status"], "UNKNOWN")
        self.assertEqual(analysis["triage_priority"], "UNRATED")
        self.assertEqual(analysis["confidence"], "LOW")
        self.assertIn("attack vector is not available", analysis["technical"]["exploitation_conditions"])
        self.assertNotIn("requires local access", analysis["technical"]["exploitation_conditions"])


if __name__ == "__main__":
    unittest.main()
