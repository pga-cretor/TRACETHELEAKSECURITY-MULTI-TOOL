from __future__ import annotations

import socket

from ..models import AssessmentResult, Finding


def enumerate_dns(host: str, addresses: list[str]) -> AssessmentResult:
    result = AssessmentResult(target=host, module="information-gathering.dns")
    try:
        canonical, aliases, resolved = socket.gethostbyname_ex(host)
        result.data = {
            "canonical_name": canonical,
            "aliases": sorted(set(aliases)),
            "a_records": sorted(set(resolved)),
            "resolved_addresses": sorted(set(addresses)),
        }
        if not aliases and canonical == host:
            result.findings.append(
                Finding(
                    title="No alias information returned",
                    severity="info",
                    description="The local resolver returned no CNAME/alias metadata.",
                    recommendation="Validate DNS records using the authoritative DNS platform.",
                )
            )
    except socket.gaierror as exc:
        result.errors.append(f"DNS resolution failed: {exc}")
    return result.finish()
