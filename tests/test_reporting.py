import unittest

from trace_the_leak_security.models import AssessmentResult, Finding
from trace_the_leak_security.modules.web import _response_encoding, _redact_headers
from trace_the_leak_security.reporting import build_report, render_report


class ReportingTests(unittest.TestCase):
    def test_json_report_contains_finding(self) -> None:
        result = AssessmentResult(
            target="lab.local",
            module="test",
            findings=[
                Finding(
                    title="Example",
                    severity="low",
                    description="Description",
                    evidence="Evidence",
                    recommendation="Fix",
                )
            ],
        )
        report = build_report("lab.local", [result])
        rendered = render_report(report, "json")
        self.assertIn('"title": "Example"', rendered)
        self.assertIn("low=1", report.executive_summary)

    def test_html_escapes_evidence(self) -> None:
        result = AssessmentResult(
            target="lab.local",
            module="test",
            findings=[Finding("X", "info", "<script>alert(1)</script>")],
        )
        rendered = render_report(build_report("lab.local", [result]), "html")
        self.assertNotIn("<script>alert(1)</script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)

    def test_web_helpers_are_safe(self) -> None:
        self.assertEqual(_response_encoding("text/html"), "utf-8")
        self.assertEqual(_response_encoding("text/html; charset=iso-8859-1"), "iso-8859-1")
        self.assertEqual(_redact_headers({"set-cookie": "session=secret", "server": "lab"}), {
            "set-cookie": "[REDACTED]",
            "server": "lab",
        })


if __name__ == "__main__":
    unittest.main()
