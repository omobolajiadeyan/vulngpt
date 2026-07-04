import unittest

from analyst import analyze_fallback
from nvd import fetch_cve, parse_cve


class AnalystTests(unittest.TestCase):
    def test_fallback_prioritizes_remote_critical_cve(self):
        cve = parse_cve(fetch_cve("CVE-2021-44228", offline=True))
        analysis = analyze_fallback(cve)

        self.assertEqual(analysis["exploitation_likelihood"], "CRITICAL")
        self.assertEqual(analysis["triage_priority"], "P1")
        self.assertEqual(analysis["confidence"], "HIGH")
        self.assertTrue(analysis["remediation"])
        self.assertTrue(analysis["limitations"])


if __name__ == "__main__":
    unittest.main()
