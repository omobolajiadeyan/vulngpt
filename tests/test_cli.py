import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CliTests(unittest.TestCase):
    def test_offline_json_output(self):
        result = subprocess.run(
            [sys.executable, "vulngpt.py", "CVE-2021-44228", "--offline", "--json"],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.lstrip().startswith("{"))
        payload = json.loads(result.stdout)
        self.assertEqual(payload["cve"]["id"], "CVE-2021-44228")
        self.assertEqual(payload["analysis"]["triage_priority"], "P1")

    def test_offline_export(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.json"
            result = subprocess.run(
                [sys.executable, "vulngpt.py", "CVE-2021-44228", "--offline", "--output", str(output)],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0)
            payload = json.loads(output.read_text())
            self.assertEqual(payload["cve"]["id"], "CVE-2021-44228")


if __name__ == "__main__":
    unittest.main()
