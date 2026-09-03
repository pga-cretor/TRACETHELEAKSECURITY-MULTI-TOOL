from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path
from typing import Any

from .models import AssessmentResult, Report


def build_report(target: str, results: list[AssessmentResult]) -> Report:
    findings = [finding for result in results for finding in result.findings]
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    summary = (
        f"{len(results)} modulo/i eseguito/i; "
        f"{len(findings)} finding rilevato/i. "
        f"Severità: {', '.join(f'{key}={value}' for key, value in sorted(counts.items())) or 'nessuna'}."
    )
    return Report(
        target=target,
        modules=[result.module for result in results],
        results=results,
        executive_summary=summary,
    )


def render_report(report: Report, format_name: str) -> str:
    format_name = format_name.lower()
    if format_name == "json":
        return json.dumps(report.as_dict(), indent=2, ensure_ascii=False)
    if format_name == "csv":
        return _render_csv(report)
    if format_name == "html":
        return _render_html(report)
    raise ValueError(f"Formato non supportato: {format_name}")


def write_report(report: Report, format_name: str, destination: str | None) -> str:
    content = render_report(report, format_name)
    if destination:
        path = Path(destination).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return content


def _render_csv(report: Report) -> str:
    stream = io.StringIO()
    writer = csv.DictWriter(
        stream,
        fieldnames=["target", "module", "title", "severity", "description", "evidence", "recommendation", "cve"],
    )
    writer.writeheader()
    for result in report.results:
        for finding in result.findings:
            writer.writerow(
                {
                    "target": report.target,
                    "module": result.module,
                    **finding.as_dict(),
                }
            )
    return stream.getvalue()


def _render_html(report: Report) -> str:
    rows: list[str] = []
    for result in report.results:
        for finding in result.findings:
            rows.append(
                "<tr>"
                + "".join(
                    f"<td>{html.escape(str(value or ''))}</td>"
                    for value in [
                        result.module,
                        finding.title,
                        finding.severity,
                        finding.description,
                        finding.evidence,
                        finding.recommendation,
                    ]
                )
                + "</tr>"
            )
    return f"""<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TraceTheLeakSecurity Report</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem;color:#18212f}}
table{{border-collapse:collapse;width:100%;font-size:.9rem}}th,td{{border:1px solid #d7dee8;padding:.65rem;text-align:left;vertical-align:top}}
th{{background:#142b4a;color:white}}.summary{{background:#eef5fb;padding:1rem;border-left:4px solid #198754}}
</style>
</head>
<body><h1>TraceTheLeakSecurity Multi-Tool</h1>
<p><strong>Target:</strong> {html.escape(report.target)}</p>
<p><strong>Generated:</strong> {html.escape(report.generated_at)}</p>
<p class="summary">{html.escape(report.executive_summary)}</p>
<table><thead><tr><th>Module</th><th>Title</th><th>Severity</th><th>Description</th><th>Evidence</th><th>Recommendation</th></tr></thead>
<tbody>{"".join(rows) or "<tr><td colspan='6'>Nessun finding.</td></tr>"}</tbody></table>
</body></html>"""


def compact_terminal(result: AssessmentResult) -> str:
    lines = [f"[{result.module}] {result.target}"]
    if result.errors:
        lines.extend(f"  ERRORE: {error}" for error in result.errors)
    for finding in result.findings:
        lines.append(f"  {finding.severity.upper():8} {finding.title}")
    if result.data:
        lines.append(f"  dati: {json.dumps(result.data, ensure_ascii=False, default=str)[:800]}")
    return "\n".join(lines)
