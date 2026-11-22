"""Local logging with mandatory secret redaction.

Nothing that leaves this layer may contain a Discord token or a generic
``id:secret`` pair.  All output goes to stderr so stdout stays machine-readable.
"""

from __future__ import annotations

import re
import sys

DISCORD_TOKEN_RE = re.compile(
    r"\d{17,20}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}"
)
GENERIC_SECRET_RE = re.compile(r"\d{6,12}:[A-Za-z0-9_-]{30,50}")
REDACTED = "[REDACTED]"
_LEVELS = {"info", "warn", "error", "warning", "debug"}


def redact(message: object) -> str:
    """Mask Discord token and generic id:secret shapes in ``message``."""
    text = str(message)
    text = DISCORD_TOKEN_RE.sub(REDACTED, text)
    text = GENERIC_SECRET_RE.sub(REDACTED, text)
    return text


def log(level: str, message: object) -> None:
    """Write ``LEVEL: redacted message`` to stderr for known levels."""
    normalized = str(level).lower()
    if normalized not in _LEVELS:
        return
    label = "warning" if normalized == "warning" else normalized
    print(f"{label.upper()}: {redact(message)}", file=sys.stderr)
