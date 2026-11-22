"""Integration with the locally built Go and Rust helper binaries.

Every external tool is discovered from an environment override first and then
from well-known local build directories.  No tool is downloaded and no remote
service is contacted.
"""

from __future__ import annotations

import json
import os
import queue
import re
import shutil
import subprocess
import threading
from pathlib import Path
from urllib.parse import urlparse

from .logging import redact

REPO_ROOT = Path(__file__).resolve().parents[2]

TOOL_ENV = {
    "dscore": "TGSEC_CORE",
    "dstoken": "TGSEC_DSTOKEN",
    "dsmock": "TGSEC_DSMOCK",
}

TOOL_HINTS = {
    "dscore": "cargo build --manifest-path rust/crates/core/Cargo.toml",
    "dstoken": "cd go && go build -o bin/dstoken ./cmd/dstoken",
    "dsmock": "cd go && go build -o bin/dsmock ./cmd/dsmock",
}


class ToolNotFoundError(FileNotFoundError):
    """Raised when a required local helper binary cannot be discovered."""


def _candidates(name: str) -> list[Path]:
    root = Path(REPO_ROOT)
    return [
        root / "target" / "debug" / name,
        root / "rust" / "crates" / "core" / "target" / "debug" / name,
        root / "go" / "bin" / name,
        root / name,
    ]


def _not_found(name: str) -> ToolNotFoundError:
    env_var = TOOL_ENV.get(name, "TGSEC_" + name.upper())
    hint = TOOL_HINTS.get(name, "build the tool locally")
    return ToolNotFoundError(
        f"Tool '{name}' not found. Install or build it locally ({hint}), "
        f"or set {env_var} to the binary path."
    )


def _find(name: str, env_var: str) -> Path:
    override = os.environ.get(env_var)
    if override:
        candidate = Path(override).expanduser()
        if candidate.is_file():
            return candidate
        raise ToolNotFoundError(
            f"Tool '{name}' not found at {env_var}={override!r}. "
            f"Install or build it locally ({TOOL_HINTS.get(name, 'build the tool locally')}) "
            "and point the environment variable at the executable."
        )
    for candidate in _candidates(name):
        if candidate.is_file():
            return candidate
    located = shutil.which(name)
    if located:
        return Path(located)
    raise _not_found(name)


def find_core() -> Path:
    """Locate the Rust ``dscore`` binary."""
    return _find("dscore", "TGSEC_CORE")


def find_scanner() -> Path:
    """Locate the Go ``dstoken`` token scanner."""
    return _find("dstoken", "TGSEC_DSTOKEN")


def find_mock() -> Path:
    """Locate the local Go ``dsmock`` server."""
    return _find("dsmock", "TGSEC_DSMOCK")


def _run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ToolNotFoundError(f"Cannot execute {command[0]!r}: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "no diagnostic output").strip()
        raise RuntimeError(
            f"{Path(command[0]).name} exited with code {completed.returncode}: {redact(detail)}"
        )
    return completed


def _parse_json(text: str, source: str) -> dict:
    stripped = text.strip()
    if not stripped:
        raise RuntimeError(f"{source} produced no JSON output")
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        start, end = stripped.find("{"), stripped.rfind("}")
        if start == -1 or end <= start:
            raise RuntimeError(f"{source} output is not JSON: {redact(stripped[:200])}")
        try:
            parsed = json.loads(stripped[start : end + 1])
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"{source} output is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(f"{source} JSON output must be an object")
    return parsed


def run_token_scan(
    path: str | Path,
    config_path: str | Path,
    raw_out: str | Path,
    scanner: str | Path | None = None,
) -> dict:
    """Run ``dstoken`` over ``path`` and return the parsed RAW JSON document."""
    binary = Path(scanner) if scanner is not None else find_scanner()
    command = [
        str(binary),
        "--path", str(path),
        "--config", str(config_path),
        "--out", str(raw_out),
    ]
    _run(command, timeout=600)
    output = Path(raw_out)
    if not output.is_file():
        raise RuntimeError(f"dstoken did not create RAW output at {output}")
    try:
        data = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read RAW output {output}: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"RAW output {output} must be a JSON object")
    return data


def _write_analysis(analysis: dict, analyzed_out: str | Path) -> None:
    destination = Path(analyzed_out)
    if destination.parent != Path(""):
        destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as handle:
        json.dump(analysis, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def run_analysis(
    bundle_path: str | Path,
    config_path: str | Path,
    analyzed_out: str | Path,
    core: str | Path | None = None,
) -> dict:
    """Run ``dscore analyze`` and return/write the analysis JSON."""
    binary = Path(core) if core is not None else find_core()
    command = [str(binary), "analyze", str(bundle_path), str(config_path)]
    completed = _run(command, timeout=600)
    analysis = _parse_json(completed.stdout, "dscore analyze")
    _write_analysis(analysis, analyzed_out)
    return analysis


def run_token_analysis(
    raw_path: str | Path,
    config_path: str | Path,
    analyzed_out: str | Path,
    core: str | Path | None = None,
) -> dict:
    """Run ``dscore analyze-tokens`` and return/write the analysis JSON."""
    binary = Path(core) if core is not None else find_core()
    command = [str(binary), "analyze-tokens", str(raw_path), str(config_path)]
    completed = _run(command, timeout=600)
    analysis = _parse_json(completed.stdout, "dscore analyze-tokens")
    _write_analysis(analysis, analyzed_out)
    return analysis


def validate_local_url(url: str) -> bool:
    """Accept only loopback URLs; raise ``ValueError`` for everything else."""
    try:
        parsed = urlparse(str(url))
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid local URL {url!r}: {exc}") from exc
    if parsed.scheme.lower() not in {"http", "https", "ws", "wss"}:
        raise ValueError(f"unsupported URL scheme: {parsed.scheme!r}")
    if hostname not in {"127.0.0.1", "localhost"}:
        raise ValueError(f"external URLs are forbidden: {url!r}")
    if port is not None and not 0 <= port <= 65535:
        raise ValueError(f"invalid port in URL: {url!r}")
    return True


class MockProcess:
    """Handle for a locally running ``dsmock`` process."""

    def __init__(
        self,
        port: int,
        process: subprocess.Popen[str],
        stderr_thread: threading.Thread,
        stderr_lines: list[str],
    ) -> None:
        self.port = port
        self.process = process
        self._stderr_thread = stderr_thread
        self._stderr_lines = stderr_lines
        self._closed = False

    @property
    def stderr(self) -> str:
        """Redacted stderr collected from the mock process."""
        return redact("".join(self._stderr_lines))

    def close(self) -> None:
        """Terminate the mock server; safe to call more than once."""
        if self._closed:
            return
        self._closed = True
        process = self.process
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        self._stderr_thread.join(timeout=2)

    def __enter__(self) -> "MockProcess":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _terminate(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def start_mock(
    config_path: str | Path | None = None,
    mock_bin: str | Path | None = None,
    port: int = 0,
) -> MockProcess:
    """Start ``dsmock`` on loopback and read its ``PORT:<n>`` handshake line."""
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise ValueError("port must be an integer between 0 and 65535")
    binary = Path(mock_bin) if mock_bin is not None else find_mock()
    if not binary.is_file():
        raise ToolNotFoundError(f"dsmock binary not found at {binary}")
    command = [str(binary), "--port", str(port)]
    if config_path is not None:
        command.extend(["--config", str(config_path)])

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except OSError as exc:
        raise RuntimeError(f"cannot start dsmock: {redact(exc)}") from exc

    stderr_lines: list[str] = []
    stderr_lock = threading.Lock()

    def drain_stderr() -> None:
        assert process.stderr is not None
        for line in process.stderr:
            with stderr_lock:
                stderr_lines.append(line)

    stderr_thread = threading.Thread(target=drain_stderr, name="dsmock-stderr", daemon=True)
    stderr_thread.start()

    greeting: queue.Queue[str] = queue.Queue(maxsize=1)

    def read_greeting() -> None:
        assert process.stdout is not None
        try:
            greeting.put(process.stdout.readline())
        except (OSError, ValueError) as exc:
            greeting.put(f"ERROR:{exc}")

    greeting_thread = threading.Thread(target=read_greeting, name="dsmock-port", daemon=True)
    greeting_thread.start()

    def startup_failure(reason: str) -> RuntimeError:
        _terminate(process)
        stderr_thread.join(timeout=2)
        with stderr_lock:
            detail = "".join(stderr_lines[-10:]).strip()
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        suffix = f": {redact(detail)}" if detail else ""
        return RuntimeError(f"dsmock failed to start ({reason}){suffix}")

    try:
        line = greeting.get(timeout=10)
    except queue.Empty:
        raise startup_failure("no PORT line within 10 seconds")
    match = re.fullmatch(r"\s*PORT:(\d+)\s*", line)
    if not match:
        raise startup_failure(f"unexpected greeting {redact(line.strip())!r}")
    actual_port = int(match.group(1))
    if not 0 < actual_port <= 65535:
        raise startup_failure(f"invalid port {actual_port}")
    return MockProcess(actual_port, process, stderr_thread, stderr_lines)
