from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    title: str
    severity: str
    description: str
    evidence: str = ""
    recommendation: str = ""
    cve: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AssessmentResult:
    target: str
    module: str
    started_at: str = field(default_factory=utc_now)
    completed_at: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def finish(self) -> "AssessmentResult":
        self.completed_at = utc_now()
        return self

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["findings"] = [finding.as_dict() for finding in self.findings]
        return result


@dataclass
class Report:
    target: str
    modules: list[str]
    results: list[AssessmentResult]
    generated_at: str = field(default_factory=utc_now)
    executive_summary: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": "TraceTheLeakSecurity Multi-Tool",
            "target": self.target,
            "generated_at": self.generated_at,
            "modules": self.modules,
            "executive_summary": self.executive_summary,
            "results": [result.as_dict() for result in self.results],
        }
