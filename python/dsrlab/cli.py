"""Command line interface for the Discord API Security Research Lab.

All tool invocations and network checks target the local machine only.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import tempfile
from pathlib import Path
from typing import Any, Iterator

from . import __version__
from .config import default_config, load_config, validate_config, write_config
from .integration import run_analysis, run_token_analysis, run_token_scan, start_mock
from .logging import log, redact
from .mockclient import collect_gateway_trace, http_request
from .report import load_analysis, render_json, render_markdown, render_txt, write_report

REPO_DEFAULT_CONFIG = Path(__file__).resolve().parents[2] / "configs" / "default.json"
COMMANDS = (
    "scan", "analyze", "gateway", "permissions", "oauth", "exploit-lab",
    "report", "config", "version", "help",
)


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser used by ``main``."""
    parser = argparse.ArgumentParser(
        prog="dsrlab",
        description="Discord API Security Research Lab (local-only tooling)",
    )
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")

    scan = commands.add_parser("scan", help="scan files with dstoken and analyse the RAW output")
    scan.add_argument("path", help="file or directory to scan")
    scan.add_argument("--config", help="path to a JSON config")
    scan.add_argument("--out", help=" Markdown report output (default token-report.md)")

    analyze = commands.add_parser("analyze", help="analyse a BUNDLE.json with dscore")
    analyze.add_argument("bundle")
    analyze.add_argument("--config")
    analyze.add_argument("--out")

    gateway = commands.add_parser("gateway", help="collect a local mock gateway trace")
    gateway.add_argument("--port", type=int, default=0)
    gateway.add_argument("--out", default="gateway-trace.json")

    permissions = commands.add_parser("permissions", help="show permission findings")
    permissions.add_argument("bundle")
    permissions.add_argument("--config")

    oauth = commands.add_parser("oauth", help="show OAuth2 findings")
    oauth.add_argument("bundle")
    oauth.add_argument("--config")

    lab = commands.add_parser("exploit-lab", help="replay local scenarios against dsmock")
    lab.add_argument("bundle")
    lab.add_argument("--config")
    lab.add_argument("--out", default="LAB_RESULTS.json")

    report_command = commands.add_parser("report", help="render an ANALYSIS.json report")
    report_command.add_argument("analysis")
    report_command.add_argument("--format", choices=("txt", "json", "md", "all"), default="md")
    report_command.add_argument("--out")

    config_command = commands.add_parser("config", help="show, initialise or validate configuration")
    config_command.add_argument("action", choices=("show", "init", "validate"))
    config_command.add_argument("--path")

    commands.add_parser("version", help="print the dsrlab version")
    commands.add_parser("help", help="print the command list")
    return parser


# Friendly aliases used by external callers and tests.
create_parser = build_parser
make_parser = build_parser


@contextlib.contextmanager
def _config_file(path: str | None) -> Iterator[Path]:
    """Yield a config path, creating a temporary default config if needed."""
    if path:
        yield Path(path)
        return
    if REPO_DEFAULT_CONFIG.is_file():
        yield REPO_DEFAULT_CONFIG
        return
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", encoding="utf-8", delete=False
    ) as handle:
        json.dump(default_config(), handle, indent=2, ensure_ascii=False)
        temporary = Path(handle.name)
    try:
        yield temporary
    finally:
        temporary.unlink(missing_ok=True)


def _write_json(path: str | Path, data: Any) -> Path:
    destination = Path(path)
    if destination.parent != Path(""):
        destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return destination


def _default_analysis_path(bundle: str) -> Path:
    source = Path(bundle)
    return source.with_name(source.stem + ".analysis.json")


def _summary_line(analysis: dict[str, Any]) -> str:
    summary = analysis.get("summary") if isinstance(analysis.get("summary"), dict) else {}
    return (
        f"endpoints={summary.get('endpoints', 0)} "
        f"scenarios={summary.get('scenarios', 0)} "
        f"findings={summary.get('findings', 0)}"
    )


def _cmd_scan(args: argparse.Namespace) -> int:
    with _config_file(args.config) as config_path:
        raw_path = Path("token-raw.json")
        analysis_path = Path("token-analysis.json")
        run_token_scan(args.path, config_path, raw_path)
        analysis = run_token_analysis(raw_path, config_path, analysis_path)
        out = Path(args.out) if args.out else Path("token-report.md")
        write_report(out, render_markdown(analysis))
    print(f"scan: {_summary_line(analysis)}")
    print(out)
    return 0


def _cmd_analyze(args: argparse.Namespace) -> int:
    with _config_file(args.config) as config_path:
        out = Path(args.out) if args.out else _default_analysis_path(args.bundle)
        analysis = run_analysis(args.bundle, config_path, out)
    print(f"analyze: {_summary_line(analysis)}")
    print(out)
    return 0


def _cmd_gateway(args: argparse.Namespace) -> int:
    mock = None
    try:
        mock = start_mock(port=args.port)
        trace = collect_gateway_trace(mock.port)
        out = _write_json(args.out, trace)
    finally:
        if mock is not None:
            mock.close()
    print(
        f"gateway: ops={len(trace['ops'])} events={len(trace['events'])} "
        f"heartbeat_acks={trace['heartbeat_acks']}"
    )
    print(out)
    return 0


def _print_module_findings(analysis: dict[str, Any], module: str) -> None:
    findings = analysis.get("findings")
    findings = findings if isinstance(findings, list) else []
    selected = [item for item in findings if isinstance(item, dict) and item.get("module") == module]
    if not selected:
        print(f"no {module} findings")
        return
    for finding in selected:
        print(redact(f"[{finding.get('severity', 'unknown')}] {finding.get('id', '')}: {finding.get('title', '')}"))
        print(redact(f"  evidence: {finding.get('evidence', '')}"))
        print(redact(f"  recommendation: {finding.get('recommendation', '')}"))


def _cmd_module(args: argparse.Namespace, module: str) -> int:
    with _config_file(args.config) as config_path:
        with tempfile.TemporaryDirectory(prefix="dsrlab-") as directory:
            analysis = run_analysis(args.bundle, config_path, Path(directory) / "analysis.json")
    _print_module_findings(analysis, module)
    return 0


def _run_scenario(port: int, scenario: Any) -> dict[str, Any]:
    if not isinstance(scenario, dict):
        return {"id": "", "status": "skipped", "notes": "invalid scenario entry"}
    # The local Go mock already serves routes under /api/v10: use the exact path.
    endpoint = str(scenario.get("endpoint") or "")
    path = endpoint
    if not path.startswith("/"):
        path = "/" + path
    scenario_id = scenario.get("id", "")
    fixed = bool(scenario.get("fixed"))
    expected = scenario.get("mock_response")
    notes: list[str] = []
    try:
        status, headers, _body = http_request(
            port,
            path,
            method=str(scenario.get("method") or "GET"),
            body=scenario.get("body"),
        )
    except Exception as exc:  # a scenario needing a different mock route is skipped
        return {
            "id": scenario_id,
            "status": "skipped",
            "notes": redact(f"local mock request failed: {exc}"),
        }

    matches = expected is None or status == int(expected)
    notes.append(f"mock status {status}" + (f" (expected {expected})" if expected is not None else ""))
    retry_after = headers.get("Retry-After")
    if status == 429 or expected == 429:
        if retry_after:
            notes.append(f"Retry-After: {redact(str(retry_after))}")
        else:
            matches = False
            notes.append("Retry-After missing on 429 response")
    if not matches:
        notes.append("expectation did not match")

    if fixed:
        label = "fixed"
    elif matches:
        label = "reproduced"
    else:
        label = "skipped"
    return {
        "id": scenario_id,
        "status": label,
        "endpoint": endpoint,
        "status_code": status,
        "expected": expected,
        "retry_after": redact(str(retry_after)) if retry_after else None,
        "notes": "; ".join(notes),
    }


def _cmd_exploit_lab(args: argparse.Namespace) -> int:
    mock = None
    with _config_file(args.config) as config_path:
        try:
            with Path(args.bundle).open("r", encoding="utf-8") as handle:
                bundle = json.load(handle)
            mock = start_mock(config_path=config_path)
            scenarios = bundle.get("scenarios", []) if isinstance(bundle, dict) else []
            results = [_run_scenario(mock.port, scenario) for scenario in scenarios]
            out = _write_json(
                args.out,
                {"version": "1.0", "scenario_results": results, "scenarios": results},
            )
            with tempfile.TemporaryDirectory(prefix="dsrlab-") as directory:
                analysis = run_analysis(args.bundle, config_path, Path(directory) / "analysis.json")
        finally:
            if mock is not None:
                mock.close()
    reported = analysis.get("scenario_results") if isinstance(analysis, dict) else None
    reported = reported if isinstance(reported, list) else results
    counts: dict[str, int] = {}
    for result in reported:
        if isinstance(result, dict):
            label = str(result.get("status", "skipped"))
            counts[label] = counts.get(label, 0) + 1
    print("exploit-lab: " + ", ".join(f"{key}={value}" for key, value in sorted(counts.items())))
    print(out)
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    renderers = {"txt": render_txt, "json": render_json, "md": render_markdown}
    if args.format == "all":
        base = Path(args.out).with_suffix("") if args.out else Path("report")
        for fmt, renderer in renderers.items():
            destination = base.with_suffix("." + fmt)
            write_report(destination, renderer(analysis))
            print(destination)
    else:
        destination = Path(args.out) if args.out else Path("report." + args.format)
        write_report(destination, renderers[args.format](analysis))
        print(destination)
    return 0


def _cmd_config(args: argparse.Namespace) -> int:
    if args.action == "show":
        cfg = load_config(args.path) if args.path else default_config()
        print(json.dumps(cfg, indent=2, ensure_ascii=False))
        return 0
    if args.action == "init":
        destination = Path(args.path) if args.path else Path("config.json")
        write_config(destination, default_config())
        print(destination)
        return 0
    cfg = load_config(args.path) if args.path else default_config()
    errors = validate_config(cfg)
    if errors:
        for error in errors:
            log("error", error)
        return 1
    print("config valid")
    return 0


def _dispatch(args: argparse.Namespace) -> int:
    command = args.command
    if command == "scan":
        return _cmd_scan(args)
    if command == "analyze":
        return _cmd_analyze(args)
    if command == "gateway":
        return _cmd_gateway(args)
    if command == "permissions":
        return _cmd_module(args, "permissions")
    if command == "oauth":
        return _cmd_module(args, "oauth")
    if command == "exploit-lab":
        return _cmd_exploit_lab(args)
    if command == "report":
        return _cmd_report(args)
    if command == "config":
        return _cmd_config(args)
    if command == "version":
        print(f"dsrlab {__version__}")
        return 0
    if command == "help":
        return _cmd_help()
    return 2


def _cmd_help() -> int:
    build_parser().print_help()
    print("commands: " + ", ".join(COMMANDS))
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run the CLI; return 0 on success, 1 on runtime errors, 2 on usage errors."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2
    command = getattr(args, "command", None)
    if command is None:
        parser.print_help()
        return 2
    try:
        return _dispatch(args)
    except (KeyboardInterrupt, SystemExit) as exc:
        log("error", f"interrupted: {exc}")
        return 1
    except Exception as exc:
        log("error", f"{type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
