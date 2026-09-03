from __future__ import annotations

import socket

from ..config import RuntimeConfig
from ..models import AssessmentResult
from ..utils import throttled


COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
}


def scan_ports(host: str, ports: list[int], config: RuntimeConfig) -> AssessmentResult:
    result = AssessmentResult(target=host, module="network-security.port-scan")
    max_ports = 32 if config.safe else 128
    if len(ports) > max_ports:
        result.errors.append(
            f"Limite safe: richieste {len(ports)} porte, massimo consentito {max_ports}."
        )
        return result.finish()

    open_ports: list[dict[str, object]] = []
    for port in throttled(ports, config.rate_limit):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(config.timeout)
                status = sock.connect_ex((host, port))
            if status == 0:
                banner = ""
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as banner_socket:
                        banner_socket.settimeout(min(config.timeout, 0.5))
                        if banner_socket.connect_ex((host, port)) == 0:
                            banner = banner_socket.recv(256).decode("utf-8", errors="replace").strip()
                except OSError:
                    # Many services do not speak until the client sends a request.
                    pass
                open_ports.append(
                    {
                        "port": port,
                        "service_hint": COMMON_SERVICES.get(port, "unknown"),
                        "observed_banner": banner[:256],
                    }
                )
        except (OSError, ValueError) as exc:
            result.errors.append(f"{host}:{port}: {exc}")

    result.data = {
        "host": host,
        "requested_ports": ports,
        "open_ports": open_ports,
        "scanned_count": len(ports),
        "safe_mode": config.safe,
    }
    return result.finish()
