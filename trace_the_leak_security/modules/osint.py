from __future__ import annotations

import socket
import ssl

from ..config import RuntimeConfig
from ..models import AssessmentResult


def passive_domain_profile(host: str, config: RuntimeConfig) -> AssessmentResult:
    result = AssessmentResult(target=host, module="osint.passive-domain-profile")
    try:
        addresses = sorted({entry[4][0] for entry in socket.getaddrinfo(host, None)})
        result.data["resolved_addresses"] = addresses
    except socket.gaierror as exc:
        result.errors.append(f"DNS lookup failed: {exc}")

    if config.safe:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=config.timeout) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls_socket:
                    cert = tls_socket.getpeercert()
                    result.data["certificate"] = {
                        "subject": cert.get("subject"),
                        "issuer": cert.get("issuer"),
                        "subject_alt_names": cert.get("subjectAltName"),
                    }
        except (OSError, ssl.SSLError) as exc:
            result.data["certificate_error"] = str(exc)
    return result.finish()
