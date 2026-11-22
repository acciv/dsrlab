"""Tests for the configuration manager."""

import tempfile
import unittest
from pathlib import Path

from dsrlab import config


class ConfigTests(unittest.TestCase):
    def test_default_config_matches_shipped_values(self):
        cfg = config.default_config()
        self.assertEqual(cfg["version"], "1.0")
        self.assertEqual(cfg["max_file_bytes"], 2097152)
        self.assertEqual(cfg["max_line_bytes"], 16384)
        self.assertEqual(cfg["workers"], 0)
        self.assertEqual(len(cfg["patterns"]), 1)
        pattern = cfg["patterns"][0]
        self.assertEqual(pattern["id"], "discord_bot_token")
        self.assertEqual(pattern["value_group"], 3)
        self.assertEqual(pattern["expected_length"], 27)
        self.assertIn("DUMMY", cfg["false_positive_markers"])
        self.assertEqual(cfg["public_paths"], ["/gateway", "/oauth2/token"])
        self.assertEqual(
            cfg["gateway"],
            {"heartbeat_min": 1000, "heartbeat_max": 60000, "min_version": 10},
        )

    def test_default_config_is_a_fresh_copy(self):
        first = config.default_config()
        first["patterns"].append({"id": "extra"})
        second = config.default_config()
        self.assertEqual(len(second["patterns"]), 1)

    def test_write_and_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            cfg = config.default_config()
            config.write_config(path, cfg)
            text = path.read_text(encoding="utf-8")
            self.assertIn('  "version": "1.0"', text)
            self.assertNotIn("\\u", text)
            self.assertEqual(config.load_config(path), cfg)

    def test_validate_default_config(self):
        self.assertEqual(config.validate_config(config.default_config()), [])

    def test_validate_reports_all_invalid_fields(self):
        cfg = config.default_config()
        cfg["version"] = ""
        cfg["max_file_bytes"] = 0
        cfg["max_line_bytes"] = -1
        cfg["workers"] = -2
        cfg["patterns"][0]["value_group"] = 99
        cfg["false_positive_markers"] = "DUMMY"
        cfg["risk_levels"] = {"low": 50, "medium": 25, "high": 75, "critical": 90}
        cfg["public_paths"] = "/gateway"
        cfg["gateway"]["heartbeat_min"] = 70000
        errors = config.validate_config(cfg)
        for expected in (
            "version", "max_file_bytes", "max_line_bytes", "workers",
            "value_group", "false_positive_markers", "risk_levels",
            "public_paths", "heartbeat_min",
        ):
            self.assertTrue(any(expected in error for error in errors), msg=expected)
        self.assertTrue(config.validate_config({"version": "1.0"}))


if __name__ == "__main__":
    unittest.main()
