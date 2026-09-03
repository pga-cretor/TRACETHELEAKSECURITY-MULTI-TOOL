from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from ..config import RuntimeConfig
from ..models import AssessmentResult, Finding


SECURITY_HEADERS = {
    "strict-transport-security": (
        "high",
        "HSTS is missing.",
        "Enable HSTS after confirming all application subdomains support HTTPS.",
    ),
    "content-security-policy": (
        "medium",
        "Content-Security-Policy is missing.",
        "Define a restrictive CSP and roll it out with report-only monitoring first.",
    ),
    "x-content-type-options": (
        "low",
        "X-Content-Type-Options is missing.",
        "Set X-Content-Type-Options: nosniff.",
    ),
    "referrer-policy": (
        "low",
        "Referrer-Policy is missing.",
        "Set a restrictive Referrer-Policy appropriate to the application.",
    ),
    "permissions-policy": (
        "low",
        "Permissions-Policy is missing.",
        "Disable browser capabilities the application does not need.",
    ),
}


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.title = ""
        self._in_title = False
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag.lower() == "title":
            self._in_title = True
        if tag.lower() == "a" and attributes.get("href"):
            self.links.append(attributes["href"] or "")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data.strip()


def analyze_web(url: str, config: RuntimeConfig) -> AssessmentResult:
    result = AssessmentResult(target=url, module="web-security.analysis")
    parsed = urlparse(url if "://" in url else f"https://{url}")
    normalized_url = parsed.geturl()
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        result.errors.append("URL non valida: usa http:// o https:// con hostname.")
        return result.finish()

    body = b""
    headers: dict[str, str] = {}
    status: int | None = None
    try:
        request = Request(
            normalized_url,
            headers={"User-Agent": "TraceTheLeakSecurity/0.1 (authorized-assessment)"},
            method="GET",
        )
        with urlopen(request, timeout=config.timeout) as response:
            status = response.status
            headers = {key.lower(): value for key, value in response.headers.items()}
            body = response.read(config.max_body_bytes)
    except HTTPError as exc:
        status = exc.code
        headers = {key.lower(): value for key, value in exc.headers.items()}
        result.errors.append(f"HTTP {exc.code}: {exc.reason}")
    except (URLError, TimeoutError, OSError) as exc:
        result.errors.append(f"HTTP request failed: {exc}")

    parser = _LinkParser()
    if body:
        parser.feed(body.decode(_response_encoding(headers.get("content-type", "")), errors="replace"))
    missing_headers: list[str] = []
    for header, (severity, description, recommendation) in SECURITY_HEADERS.items():
        if header not in headers:
            missing_headers.append(header)
            result.findings.append(
                Finding(
                    title=f"Missing security header: {header}",
                    severity=severity,
                    description=description,
                    evidence=f"URL: {normalized_url}",
                    recommendation=recommendation,
                )
            )

    server = headers.get("server")
    if server:
        result.findings.append(
            Finding(
                title="Server header discloses implementation details",
                severity="info",
                description="The response includes a Server header that may help passive fingerprinting.",
                evidence=server,
                recommendation="Minimize version and implementation disclosure where practical.",
            )
        )

    same_host_links = []
    for link in parser.links[: config.max_requests]:
        candidate = urljoin(normalized_url, link)
        if urlparse(candidate).hostname == parsed.hostname:
            same_host_links.append(candidate)

    result.data = {
        "url": normalized_url,
        "status": status,
        "headers": _redact_headers(headers),
        "title": re.sub(r"\s+", " ", parser.title).strip(),
        "body_bytes_read": len(body),
        "same_host_links": sorted(set(same_host_links)),
        "missing_security_headers": missing_headers,
        "safe_mode": config.safe,
    }
    if parsed.scheme == "https":
        result.data["tls"] = _tls_metadata(parsed.hostname, parsed.port or 443, config.timeout)
    elif config.safe:
        result.findings.append(
            Finding(
                title="Target is using HTTP",
                severity="medium",
                description="The analyzed URL does not use transport encryption.",
                evidence=normalized_url,
                recommendation="Redirect to HTTPS and apply HSTS after validating the deployment.",
            )
        )
    return result.finish()


def _response_encoding(content_type: str) -> str:
    for part in content_type.split(";")[1:]:
        key, separator, value = part.strip().partition("=")
        if separator and key.lower() == "charset":
            return value.strip().strip("\"'") or "utf-8"
    return "utf-8"


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    sensitive = {"authorization", "proxy-authorization", "cookie", "set-cookie"}
    return {
        name: "[REDACTED]" if name.lower() in sensitive else value
        for name, value in headers.items()
    }


def _tls_metadata(host: str, port: int, timeout: float) -> dict[str, Any]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                certificate = tls_socket.getpeercert()
                expires = certificate.get("notAfter")
                expiration = None
                if expires:
                    expiration = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=timezone.utc
                    ).isoformat()
                return {
                    "protocol": tls_socket.version(),
                    "cipher": tls_socket.cipher(),
                    "subject": certificate.get("subject"),
                    "issuer": certificate.get("issuer"),
                    "expires_at": expiration,
                }
    except (OSError, ssl.SSLError, ValueError) as exc:
        return {"error": str(exc)}
