"""Tests for TXT, JSON and Markdown report generation."""

import json
import tempfile
import unittest
from pathlib import Path

from dsrlab import report

SYNTHETIC_TOKEN = "100000000000000001.ABCDEF." + ("DUMMMY" * 4 + "DDD")
SYNTHETIC_SECRET = "123456:" + ("EXAMPLEKEY" * 4)


def sample_analysis():
    return {
        "version": "1.0",
        "summary": {
            "endpoints": 1,
            "scenarios": 1,
            "findings": 2,
            "by_module": {"rest": 0, "oauth": 1, "gateway": 0, "permissions": 1, "lab": 0},
            "by_severity": {"critical": 1, "high": 0, "medium": 1, "low": 0},
        },
        "findings": [
            {
                "module": "oauth",
                "id": "oauth-pkce-disabled",
                "title": "PKCE disabled",
                "severity": "medium",
                "evidence": "pkce=false",
                "recommendation": "Enable PKCE",
            },
            {
                "module": "permissions",
                "id": "perm-admin-granted",
                "title": "Administrator bit granted",
                "severity": "critical",
                "evidence": "bits=8",
                "recommendation": "Remove ADMINISTRATOR",
            },
        ],
        "permission_bits": [
            {"role": "bot", "bits": 8, "names": ["ADMINISTRATOR"], "excessive": True}
        ],
        "scenario_results": [
            {
                "id": "ratelimit-001",
                "status": "reproduced",
                "severity": "medium",
                "notes": "mock 429",
            }
        ],
    }


class ReportTests(unittest.TestCase):
    def test_all_formats_include_required_sections(self):
        analysis = sample_analysis()
        for renderer in (report.render_txt, report.render_markdown, report.render_json):
            with self.subTest(renderer=renderer.__name__):
                text = renderer(analysis)
                self.assertIn(report.TITLE, text)
                for section in (
                    "Summary", "By module", "By severity", "Findings",
                    "Permission bits", "Scenario results", "Recommendations",
                    "Endpoints: 1", "Scenarios: 1", "Findings: 2",
                ):
                    self.assertIn(section, text)
                for column in report.FINDING_COLUMNS:
                    self.assertIn(column, text)
                self.assertIn("synthetic", text)
                self.assertIn("masked", text)

    def test_json_report_is_structured(self):
        data = json.loads(report.render_json(sample_analysis()))
        self.assertEqual(data["title"], report.TITLE)
        self.assertEqual(data["by_module"]["oauth"], 1)
        self.assertEqual(data["by_severity"]["critical"], 1)
        self.assertEqual(data["findings_table"]["columns"], report.FINDING_COLUMNS)
        self.assertEqual(len(data["findings_table"]["rows"]), 2)
        self.assertEqual(data["permission_bits"]["rows"][0][0], "bot")
        self.assertEqual(data["scenario_results"]["rows"][0][1], "reproduced")
        self.assertIn("Enable PKCE", data["recommendations"])

    def test_assert_no_secret_detects_both_shapes(self):
        with self.assertRaises(ValueError):
            report.assert_no_secret("token=" + SYNTHETIC_TOKEN)
        with self.assertRaises(ValueError):
            report.assert_no_secret("secret=" + SYNTHETIC_SECRET)
        report.assert_no_secret("pkce=false; evidence is masked")

    def test_renderers_refuse_secret_leaks(self):
        analysis = sample_analysis()
        analysis["findings"][0]["evidence"] = SYNTHETIC_TOKEN
        for renderer in (report.render_txt, report.render_markdown, report.render_json):
            with self.subTest(renderer=renderer.__name__):
                with self.assertRaises(ValueError):
                    renderer(analysis)

    def test_permission_bits_and_scenarios_are_rendered(self):
        for renderer in (report.render_txt, report.render_markdown, report.render_json):
            with self.subTest(renderer=renderer.__name__):
                text = renderer(sample_analysis())
                for expected in ("bot", "8", "ADMINISTRATOR", "yes", "ratelimit-001", "mock 429"):
                    self.assertIn(expected, text)

    def test_write_report_and_module_main(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            analysis_path = root / "analysis.json"
            analysis_path.write_text(json.dumps(sample_analysis()), encoding="utf-8")
            self.assertEqual(
                report.main([str(analysis_path), str(root / "single.md"), "--format", "md"]),
                0,
            )
            self.assertIn(report.TITLE, (root / "single.md").read_text(encoding="utf-8"))
            self.assertEqual(
                report.main([str(analysis_path), str(root / "all.md"), "--format", "all"]),
                0,
            )
            for suffix in (".txt", ".json", ".md"):
                output = root / ("all" + suffix)
                self.assertTrue(output.is_file())
                self.assertIn(report.TITLE, output.read_text(encoding="utf-8"))
            report.write_report(root / "direct.txt", report.render_txt(sample_analysis()))
            self.assertTrue((root / "direct.txt").is_file())


if __name__ == "__main__":
    unittest.main()
