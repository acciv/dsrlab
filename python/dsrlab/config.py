"""Configuration management for the Discord API Security Research Lab.

``default_config`` is a literal copy of ``configs/default.json``; the Python
layer never reads that file implicitly.  Users may load, edit and validate
their own copies with the helpers below.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

VERSION = "1.0"


def default_config() -> dict:
    """Return a fresh copy of the shipped default configuration."""
    return {
        "version": "1.0",
        "exclude_dirs": [
            ".git",
            "target",
            "node_modules",
            "__pycache__",
            "dist",
            "build",
            "vendor",
            ".idea",
            ".vscode",
        ],
        "exclude_extensions": [
            ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".tar",
            ".so", ".dll", ".exe", ".bin", ".pyc",
        ],
        "max_file_bytes": 2097152,
        "max_line_bytes": 16384,
        "workers": 0,
        "patterns": [
            {
                "id": "discord_bot_token",
                "type": "discord_bot_token",
                "regex": r"([0-9]{17,20})\.([A-Za-z0-9_-]{6})\.([A-Za-z0-9_-]{27})",
                "value_group": 3,
                "risk_weight": 50,
                "expected_length": 27,
            }
        ],
        "false_positive_markers": [
            "DUMMY", "FAKE", "EXAMPLE", "SAMPLE", "REDACTED", "PLACEHOLDER", "TESTKEY",
        ],
        "risk_levels": {"low": 25, "medium": 50, "high": 75, "critical": 90},
        "public_paths": ["/gateway", "/oauth2/token"],
        "dangerous_scopes": [
            "guilds.join", "webhook.incoming", "applications.commands.update",
        ],
        "dangerous_permissions": [
            "ADMINISTRATOR", "BAN_MEMBERS", "KICK_MEMBERS", "MANAGE_GUILD",
            "MANAGE_CHANNELS", "MANAGE_ROLES", "MANAGE_WEBHOOKS", "MANAGE_MESSAGES",
        ],
        "gateway": {
            "heartbeat_min": 1000,
            "heartbeat_max": 60000,
            "min_version": 10,
        },
    }


def load_config(path: str | Path) -> dict:
    """Load a JSON configuration file."""
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("config must be a JSON object")
    return data


def write_config(path: str | Path, cfg: dict) -> None:
    """Write a configuration file with stable, human-friendly formatting."""
    destination = Path(path)
    if destination.parent != Path(""):
        destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as handle:
        json.dump(cfg, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _string_list(cfg: dict, key: str, errors: list[str], *, allow_empty: bool = True) -> None:
    value = cfg.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        errors.append(f"{key} must be a list of strings")
    elif not allow_empty and not value:
        errors.append(f"{key} must not be empty")


def validate_config(cfg: Any) -> list[str]:
    """Return a list of human-readable problems; an empty list means valid."""
    errors: list[str] = []
    if not isinstance(cfg, dict):
        return ["config must be an object"]

    version = cfg.get("version")
    if not isinstance(version, str) or not version.strip():
        errors.append("version must be a non-empty string")

    for key in ("max_file_bytes", "max_line_bytes"):
        value = cfg.get(key)
        if not _is_number(value) or value <= 0:
            errors.append(f"{key} must be a positive number")

    workers = cfg.get("workers")
    if not _is_number(workers) or workers < 0:
        errors.append("workers must be a number >= 0")
    elif int(workers) != workers:
        errors.append("workers must be an integer")

    patterns = cfg.get("patterns")
    if not isinstance(patterns, list) or not patterns:
        errors.append("patterns must be a non-empty list")
    else:
        for index, pattern in enumerate(patterns):
            prefix = f"patterns[{index}]"
            if not isinstance(pattern, dict):
                errors.append(f"{prefix} must be an object")
                continue
            for field in ("id", "type", "regex"):
                value = pattern.get(field)
                if not isinstance(value, str) or not value.strip():
                    errors.append(f"{prefix}.{field} must be a non-empty string")
            regex = pattern.get("regex")
            if isinstance(regex, str) and regex.strip():
                try:
                    compiled = re.compile(regex)
                    group = pattern.get("value_group")
                    if not isinstance(group, int) or isinstance(group, bool) or not 0 <= group <= compiled.groups:
                        errors.append(f"{prefix}.value_group must be an integer within the regex groups")
                except re.error as exc:
                    errors.append(f"{prefix}.regex is invalid: {exc}")
            weight = pattern.get("risk_weight")
            if not _is_number(weight) or weight < 0:
                errors.append(f"{prefix}.risk_weight must be a number >= 0")
            length = pattern.get("expected_length")
            if not _is_number(length) or length <= 0:
                errors.append(f"{prefix}.expected_length must be a positive number")
            ids = [p.get("id") for p in patterns if isinstance(p, dict)]
            if len(ids) != len(set(ids)):
                errors.append("patterns ids must be unique")

    _string_list(cfg, "false_positive_markers", errors)
    for key in ("public_paths", "dangerous_scopes", "dangerous_permissions"):
        _string_list(cfg, key, errors)

    risk_levels = cfg.get("risk_levels")
    ordered = ("low", "medium", "high", "critical")
    if not isinstance(risk_levels, dict):
        errors.append("risk_levels must be an object with low, medium, high and critical")
    else:
        values = []
        for level in ordered:
            value = risk_levels.get(level)
            if not _is_number(value) or value <= 0:
                errors.append(f"risk_levels.{level} must be a positive number")
            else:
                values.append(value)
        if len(values) == len(ordered) and any(a >= b for a, b in zip(values, values[1:])):
            errors.append("risk_levels must be ordered low < medium < high < critical")

    gateway = cfg.get("gateway")
    if not isinstance(gateway, dict):
        errors.append("gateway must be an object")
    else:
        minimum = gateway.get("heartbeat_min")
        maximum = gateway.get("heartbeat_max")
        version_number = gateway.get("min_version")
        if not _is_number(minimum) or minimum <= 0:
            errors.append("gateway.heartbeat_min must be a positive number")
        if not _is_number(maximum) or maximum <= 0:
            errors.append("gateway.heartbeat_max must be a positive number")
        if _is_number(minimum) and _is_number(maximum) and minimum >= maximum:
            errors.append("gateway.heartbeat_min must be less than gateway.heartbeat_max")
        if not _is_number(version_number) or version_number <= 0:
            errors.append("gateway.min_version must be a positive number")

    if "exclude_dirs" in cfg:
        _string_list(cfg, "exclude_dirs", errors)
    if "exclude_extensions" in cfg:
        _string_list(cfg, "exclude_extensions", errors)

    return errors
