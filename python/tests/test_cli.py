"""Tests for the dsrlab command line interface."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from dsrlab import cli, integration

VALID_COMMANDS = [
    ["scan", "corpus"],
    ["analyze", "bundle.json"],
    ["gateway"],
    ["permissions", "bundle.json"],
    ["oauth", "bundle.json"],
    ["exploit-lab", "bundle.json"],
    ["report", "analysis.json"],
    ["config", "show"],
    ["version"],
    ["help"],
]


def _available(finder) -> bool:
    try:
        return Path(finder()).is_file()
    except integration.ToolNotFoundError:
        return False


class CliTests(unittest.TestCase):
    def test_parser_accepts_every_command(self):
        parser = cli.build_parser()
        for arguments in VALID_COMMANDS:
            with self.subTest(command=arguments[0]):
                args = parser.parse_args(arguments)
                self.assertEqual(args.command, arguments[0])

    def test_parser_rejects_invalid_commands_and_arguments(self):
        parser = cli.build_parser()
        for arguments in (["nonsense"], ["scan"], ["config", "destroy"], ["report"]):
            with self.subTest(arguments=arguments):
                with self.assertRaises(SystemExit) as raised:
                    parser.parse_args(arguments)
                self.assertEqual(raised.exception.code, 2)

    def test_version_and_help(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(cli.main(["version"]), 0)
            self.assertEqual(cli.main(["help"]), 0)
        output = stdout.getvalue()
        self.assertIn("dsrlab 1.0.0", output)
        for command in cli.COMMANDS:
            self.assertIn(command, output)

    def test_main_returns_two_for_usage_errors(self):
        self.assertEqual(cli.main(["scan"]), 2)
        self.assertEqual(cli.main(["--definitely-not-an-option"]), 2)

    def test_config_init_show_validate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(cli.main(["config", "init", "--path", str(path)]), 0)
                self.assertEqual(cli.main(["config", "validate", "--path", str(path)]), 0)
                self.assertEqual(cli.main(["config", "show", "--path", str(path)]), 0)
            self.assertTrue(path.is_file())
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["version"], "1.0")
            self.assertIn('"discord_bot_token"', stdout.getvalue())
            self.assertIn("config valid", stdout.getvalue())

    def test_config_validate_invalid_returns_one(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text(json.dumps({"version": "1.0", "workers": -1}), encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(cli.main(["config", "validate", "--path", str(path)]), 1)
            self.assertIn("ERROR:", stderr.getvalue())

    def test_report_command_writes_selected_format(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            analysis_path = root / "analysis.json"
            analysis_path.write_text(
                json.dumps(
                    {
                        "summary": {"endpoints": 0, "scenarios": 0, "findings": 0},
                        "findings": [],
                        "permission_bits": [],
                        "scenario_results": [],
                    }
                ),
                encoding="utf-8",
            )
            output = root / "out.md"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(
                    cli.main(["report", str(analysis_path), "--format", "md", "--out", str(output)]),
                    0,
                )
            self.assertIn("Discord API Security Research Lab report", output.read_text(encoding="utf-8"))

    def test_runtime_errors_are_reported_with_status_one(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(cli.main(["analyze", "/no/such/bundle.json"]), 1)
        self.assertIn("ERROR:", stderr.getvalue())

    @unittest.skipUnless(
        _available(integration.find_mock) and _available(integration.find_core),
        "dsmock or dscore binary is not built",
    )
    def test_exploit_lab_uses_original_api_v10_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle.json"
            bundle.write_text(
                json.dumps(
                    {
                        "version": "1.0",
                        "endpoints": [],
                        "oauth": {},
                        "permissions": [],
                        "gateway": {},
                        "scenarios": [
                            {
                                "id": "ratelimit-001",
                                "type": "rate_limit",
                                "title": "429 handling",
                                "endpoint": "/api/v10/rate-limited",
                                "mock_response": 429,
                                "expected": "Retry-After processed",
                                "fix_check": "Retry-After header present",
                                "impact": "medium",
                                "fixed": False,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            config_path = Path(__file__).resolve().parents[1] / ".." / "configs" / "default.json"
            output = root / "LAB_RESULTS.json"
            with mock.patch.dict(os.environ, {"TGSEC_CORE": str(integration.find_core())}, clear=False):
                self.assertEqual(
                    cli.main(
                        [
                            "exploit-lab",
                            str(bundle),
                            "--config",
                            str(config_path.resolve()),
                            "--out",
                            str(output),
                        ]
                    ),
                    0,
                )
            results = json.loads(output.read_text(encoding="utf-8"))
            scenario = results["scenario_results"][0]
            self.assertEqual(scenario["status"], "reproduced")
            self.assertEqual(scenario["status_code"], 429)
            self.assertTrue(scenario["retry_after"])


if __name__ == "__main__":
    unittest.main()
