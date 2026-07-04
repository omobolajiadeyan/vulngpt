import unittest

from nvd import fetch_cve, parse_cve


class NvdTests(unittest.TestCase):
    def test_offline_fixture_parses_log4shell(self):
        raw = fetch_cve("CVE-2021-44228", offline=True)
        cve = parse_cve(raw)

        self.assertEqual(cve["id"], "CVE-2021-44228")
        self.assertEqual(cve["severity"], "CRITICAL")
        self.assertEqual(cve["score"], 10.0)
        self.assertIn("CWE-917", cve["cwes"])
        self.assertTrue(cve["reference_details"])


if __name__ == "__main__":
    unittest.main()
