"""Report generation for analysis JSON in TXT, Markdown and JSON formats."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable

from .logging import DISCORD_TOKEN_RE, GENERIC_SECRET_RE, REDACTED

TITLE = "Discord API Security Research Lab report"
NOTE = "Note: all data is synthetic and all secrets are masked."
FINDING_COLUMNS = ["Module", "ID", "Title", "Severity", "Evidence", "Recommendation"]
MODULES = ("rest", "oauth", "gateway", "permissions", "lab")
SEVERITIES = ("critical", "high", "medium", "low")


def load_analysis(path: str | Path) -> dict[str, Any]:
    """Load an ANALYSIS.json document."""
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("analysis must be a JSON object")
    return data


def assert_no_secret(text: str) -> None:
    """Raise ``ValueError`` if text contains a Discord token or id:secret pair."""
    if DISCORD_TOKEN_RE.search(text) or GENERIC_SECRET_RE.search(text):
        raise ValueError(f"report output contains a secret; use {REDACTED}")


def _cell(value: Any) -> str:
    return str(value if value is not None else "").replace("\r", " ").replace("\n", " ").replace("|", "\\|")


def _table(columns: Iterable[str], rows: Iterable[Iterable[Any]]) -> str:
    headers = [str(column) for column in columns]
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(_cell(item) for item in row) + " |")
    return "\n".join(lines)


def _summary(analysis: dict[str, Any]) -> dict[str, int]:
    summary = analysis.get("summary")
    summary = summary if isinstance(summary, dict) else {}
    findings = analysis.get("findings")
    findings = findings if isinstance(findings, list) else []
    scenarios = analysis.get("scenario_results")
    scenarios = scenarios if isinstance(scenarios, list) else []
    return {
        "endpoints": int(summary.get("endpoints", 0) or 0),
        "scenarios": int(summary.get("scenarios", len(scenarios)) or 0),
        "findings": int(summary.get("findings", len(findings)) or 0),
    }


def _counts(raw: Any, defaults: Iterable[str], *, reverse: bool = False) -> dict[str, int]:
    source = raw if isinstance(raw, dict) else {}
    keys = list(defaults)
    if not reverse:
        keys += [str(key) for key in source if str(key) not in keys]
    else:
        keys = [str(key) for key in source] + keys
        seen: set[str] = set()
        keys = [key for key in keys if not (key in seen or seen.add(key))]
    result: dict[str, int] = {}
    for key in keys:
        try:
            result[key] = int(source.get(key, 0) or 0)
        except (TypeError, ValueError):
            result[key] = 0
    return result


def _by_module(analysis: dict[str, Any]) -> dict[str, int]:
    summary = analysis.get("summary")
    source = summary.get("by_module") if isinstance(summary, dict) else None
    return _counts(source, MODULES)


def _by_severity(analysis: dict[str, Any]) -> dict[str, int]:
    summary = analysis.get("summary")
    source = summary.get("by_severity") if isinstance(summary, dict) else None
    return _counts(source, SEVERITIES, reverse=True)


def _findings(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    findings = analysis.get("findings")
    return [item for item in findings if isinstance(item, dict)] if isinstance(findings, list) else []


def _finding_rows(analysis: dict[str, Any]) -> list[list[str]]:
    rows = []
    for finding in _findings(analysis):
        rows.append(
            [
                finding.get("module", ""),
                finding.get("id", ""),
                finding.get("title", ""),
                finding.get("severity", ""),
                finding.get("evidence", ""),
                finding.get("recommendation", ""),
            ]
        )
    return rows


def _permission_rows(analysis: dict[str, Any]) -> list[list[str]]:
    rows = []
    entries = analysis.get("permission_bits")
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            names = entry.get("names")
            rows.append(
                [
                    entry.get("role", ""),
                    entry.get("bits", ""),
                    ", ".join(str(name) for name in names) if isinstance(names, list) else names or "",
                    "yes" if entry.get("excessive") else "no",
                ]
            )
    return rows


def _scenario_rows(analysis: dict[str, Any]) -> list[list[str]]:
    rows = []
    entries = analysis.get("scenario_results")
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict):
                rows.append(
                    [
                        entry.get("id", ""),
                        entry.get("status", ""),
                        entry.get("severity", ""),
                        entry.get("notes", ""),
                    ]
                )
    return rows


def _recommendations(analysis: dict[str, Any]) -> list[str]:
    recommendations: list[str] = []
    for finding in _findings(analysis):
        text = str(finding.get("recommendation") or "").strip()
        if text and text not in recommendations:
            recommendations.append(text)
    return recommendations or ["No recommendations: no findings were reported."]


def _sections(analysis: dict[str, Any]) -> dict[str, str]:
    summary = _summary(analysis)
    by_module = _by_module(analysis)
    by_severity = _by_severity(analysis)
    return {
        "summary": (
            f"Summary\nEndpoints: {summary['endpoints']}\n"
            f"Scenarios: {summary['scenarios']}\nFindings: {summary['findings']}"
        ),
        "by_module": "By module\n" + _table(["Module", "Count"], [[key, value] for key, value in by_module.items()]),
        "by_severity": "By severity\n" + _table(["Severity", "Count"], [[key, value] for key, value in by_severity.items()]),
        "findings": "Findings\n" + _table(FINDING_COLUMNS, _finding_rows(analysis)),
        "permission_bits": "Permission bits\n"
        + _table(["Role", "Bits", "Names", "Excessive"], _permission_rows(analysis)),
        "scenario_results": "Scenario results\n"
        + _table(["ID", "Status", "Severity", "Notes"], _scenario_rows(analysis)),
        "recommendations": "Recommendations\n"
        + "\n".join(f"{index}. {text}" for index, text in enumerate(_recommendations(analysis), 1)),
    }


def _ordered_sections(analysis: dict[str, Any]) -> str:
    sections = _sections(analysis)
    return "\n\n".join(
        [
            TITLE,
            sections["summary"],
            sections["by_module"],
            sections["by_severity"],
            sections["findings"],
            sections["permission_bits"],
            sections["scenario_results"],
            sections["recommendations"],
            NOTE,
        ]
    )


def _finish(content: str) -> str:
    assert_no_secret(content)
    return content


def render_txt(analysis: dict[str, Any]) -> str:
    """Render a plain-text report (pipe tables keep it easy to diff)."""
    return _finish(_ordered_sections(analysis) + "\n")


def render_markdown(analysis: dict[str, Any]) -> str:
    """Render a Markdown report."""
    lines = [
        f"# {TITLE}",
        "",
        "## Summary",
        "",
    ]
    summary = _summary(analysis)
    lines.extend(
        [
            f"- Endpoints: {summary['endpoints']}",
            f"- Scenarios: {summary['scenarios']}",
            f"- Findings: {summary['findings']}",
            "",
            "## By module",
            "",
            _table(["Module", "Count"], [[key, value] for key, value in _by_module(analysis).items()]),
            "",
            "## By severity",
            "",
            _table(["Severity", "Count"], [[key, value] for key, value in _by_severity(analysis).items()]),
            "",
            "## Findings",
            "",
            _table(FINDING_COLUMNS, _finding_rows(analysis)),
            "",
            "## Permission bits",
            "",
            _table(["Role", "Bits", "Names", "Excessive"], _permission_rows(analysis)),
            "",
            "## Scenario results",
            "",
            _table(["ID", "Status", "Severity", "Notes"], _scenario_rows(analysis)),
            "",
            "## Recommendations",
            "",
        ]
    )
    lines.extend(f"{index}. {text}" for index, text in enumerate(_recommendations(analysis), 1))
    lines.extend(["", NOTE, ""])
    return _finish("\n".join(lines))


def render_json(analysis: dict[str, Any]) -> str:
    """Render a machine-readable report that still contains every section."""
    sections = _sections(analysis)
    data = {
        "title": TITLE,
        "summary": _summary(analysis),
        "by_module": _by_module(analysis),
        "by_severity": _by_severity(analysis),
        "findings_table": {"columns": FINDING_COLUMNS, "rows": _finding_rows(analysis)},
        "findings": _findings(analysis),
        "permission_bits": {
            "columns": ["Role", "Bits", "Names", "Excessive"],
            "rows": _permission_rows(analysis),
        },
        "scenario_results": {
            "columns": ["ID", "Status", "Severity", "Notes"],
            "rows": _scenario_rows(analysis),
        },
        "recommendations": _recommendations(analysis),
        "note": NOTE,
        "sections": sections,
    }
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    return _finish(content)


def write_report(path: str | Path, content: str) -> None:
    """Write rendered report content to ``path``."""
    assert_no_secret(content)
    destination = Path(path)
    if destination.parent != Path(""):
        destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as handle:
        handle.write(content)


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``python -m dsrlab.report ANALYSIS OUT.md``."""
    parser = argparse.ArgumentParser(prog="python -m dsrlab.report")
    parser.add_argument("analysis", help="ANALYSIS.json produced by dscore")
    parser.add_argument("out", nargs="?", help="output report path")
    parser.add_argument("--format", choices=("txt", "json", "md", "all"), default="md")
    args = parser.parse_args(argv)
    renderers = {"txt": render_txt, "json": render_json, "md": render_markdown}
    analysis = load_analysis(args.analysis)
    if args.format == "all":
        base = Path(args.out).with_suffix("") if args.out else Path("report")
        for fmt, renderer in renderers.items():
            destination = base.with_suffix("." + fmt)
            write_report(destination, renderer(analysis))
            print(destination)
        return 0
    out = Path(args.out) if args.out else Path(f"report.{args.format}")
    write_report(out, renderers[args.format](analysis))
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
