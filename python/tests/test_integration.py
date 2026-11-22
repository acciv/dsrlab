"""Tests for local tool discovery and integration adapters."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from dsrlab import integration, mockclient

SYNTHETIC_TOKEN = "100000000000000001.ABCDEF." + ("DUMMMY" * 4 + "DDD")


def _available(finder) -> bool:
    try:
        return Path(finder()).is_file()
    except (integration.ToolNotFoundError, OSError):
        return False


def _script(path: Path, body: str) -> Path:
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)
    return path


class IntegrationTests(unittest.TestCase):
    def test_find_tools_missing_has_install_hint(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(integration, "REPO_ROOT", Path(directory)), \
                 mock.patch.dict(os.environ, {}, clear=True), \
                 mock.patch.object(integration.shutil, "which", return_value=None):
                for finder in (integration.find_core, integration.find_scanner, integration.find_mock):
                    with self.subTest(finder=finder.__name__):
                        with self.assertRaisesRegex(integration.ToolNotFoundError, "Install"):
                            finder()

    def test_environment_overrides_win(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {
                "TGSEC_CORE": root / "core-binary",
                "TGSEC_DSTOKEN": root / "scanner-binary",
                "TGSEC_DSMOCK": root / "mock-binary",
            }
            for path in paths.values():
                path.touch()
            with mock.patch.dict(os.environ, {key: str(value) for key, value in paths.items()}, clear=True):
                self.assertEqual(integration.find_core(), paths["TGSEC_CORE"])
                self.assertEqual(integration.find_scanner(), paths["TGSEC_DSTOKEN"])
                self.assertEqual(integration.find_mock(), paths["TGSEC_DSMOCK"])

    def test_bad_environment_override_is_reported(self):
        with mock.patch.dict(os.environ, {"TGSEC_CORE": "/not/a/real/dscore"}, clear=True):
            with self.assertRaisesRegex(integration.ToolNotFoundError, "TGSEC_CORE"):
                integration.find_core()

    def test_validate_local_url(self):
        for url in (
            "http://127.0.0.1:8080/callback",
            "http://localhost/health",
            "ws://127.0.0.1:9000/gateway",
        ):
            with self.subTest(url=url):
                self.assertTrue(integration.validate_local_url(url))
        for url in (
            "https://discord.com/api/v10/users/@me",
            "http://127.0.0.2/",
            "ftp://127.0.0.1/file",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    integration.validate_local_url(url)

    def test_run_tools_with_fake_local_binaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            core = _script(
                root / "dscore",
                "if [ \"$1\" = analyze ]; then\n"
                "  printf '%s' '{\"version\":\"1.0\",\"summary\":{\"endpoints\":1},"
                "\"findings\":[],\"permission_bits\":[],\"scenario_results\":[]}'\n"
                "else\n"
                "  printf '%s' '{\"version\":\"1.0\",\"summary\":{\"findings\":0},"
                "\"findings\":[],\"permission_bits\":[],\"scenario_results\":[]}'\n"
                "fi\n",
            )
            scanner = _script(
                root / "dstoken",
                "out=''\n"
                "while [ $# -gt 0 ]; do\n"
                "  if [ \"$1\" = --out ]; then out=\"$2\"; shift 2; else shift; fi\n"
                "done\n"
                "printf '%s' '{\"scanned_files\":1,\"skipped_files\":0,\"findings\":[]}' > \"$out\"\n",
            )
            raw = root / "raw.json"
            token_analysis = root / "token-analysis.json"
            bundle_analysis = root / "analysis.json"
            raw_result = integration.run_token_scan(root, root / "config.json", raw, scanner=scanner)
            self.assertEqual(raw_result["scanned_files"], 1)
            token_result = integration.run_token_analysis(raw, root / "config.json", token_analysis, core=core)
            self.assertEqual(token_result["summary"]["findings"], 0)
            bundle_result = integration.run_analysis(root / "bundle.json", root / "config.json", bundle_analysis, core=core)
            self.assertEqual(bundle_result["summary"]["endpoints"], 1)
            self.assertEqual(json.loads(bundle_analysis.read_text(encoding="utf-8")), bundle_result)

    def test_mock_startup_failure_redacts_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = _script(Path(directory) / "dsmock", f"echo '{SYNTHETIC_TOKEN}' >&2\nexit 1\n")
            with self.assertRaises(RuntimeError) as raised:
                integration.start_mock(mock_bin=fake)
            message = str(raised.exception)
            self.assertIn("[REDACTED]", message)
            self.assertNotIn(SYNTHETIC_TOKEN, message)

    @unittest.skipUnless(_available(integration.find_mock), "dsmock binary is not built")
    def test_gateway_trace_with_real_mock(self):
        mock_process = integration.start_mock()
        try:
            trace = mockclient.collect_gateway_trace(mock_process.port)
        finally:
            mock_process.close()
        self.assertTrue(trace["connected"])
        self.assertTrue(trace["disconnected"])
        self.assertIn(10, trace["ops"])
        self.assertIn(11, trace["ops"])
        self.assertGreaterEqual(trace["heartbeat_acks"], 1)
        self.assertIn("READY", trace["events"])
        self.assertIn("MESSAGE_CREATE", trace["events"])

    @unittest.skipUnless(_available(integration.find_core), "dscore binary is not built")
    def test_analyze_with_real_core(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle.json"
            bundle.write_text(
                json.dumps(
                    {
                        "version": "1.0",
                        "endpoints": [
                            {
                                "method": "GET",
                                "path": "/api/v10/users/@me",
                                "auth": "bearer",
                                "rate_limit": "per-route",
                                "scopes": ["identify"],
                                "errors": [401],
                            }
                        ],
                        "oauth": {
                            "client_id": "100000000000000001",
                            "redirect_uris": ["http://localhost:8080/callback"],
                            "scopes": ["identify"],
                            "pkce": True,
                            "state": True,
                        },
                        "permissions": [{"role": "reader", "bits": 1024, "scope": "guild"}],
                        "gateway": {
                            "version": 10,
                            "heartbeat_interval": 41250,
                            "intents": ["GUILDS"],
                            "events": ["READY"],
                            "resume": True,
                        },
                        "scenarios": [],
                    }
                ),
                encoding="utf-8",
            )
            config_path = Path(__file__).resolve().parents[1] / ".." / "configs" / "default.json"
            analysis = integration.run_analysis(bundle, config_path.resolve(), root / "analysis.json")
            self.assertIn("summary", analysis)
            self.assertIn("findings", analysis)


if __name__ == "__main__":
    unittest.main()
