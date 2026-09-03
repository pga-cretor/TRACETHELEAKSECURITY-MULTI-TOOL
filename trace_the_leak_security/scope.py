from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse


class ScopeError(ValueError):
    """Raised when a target is outside the declared assessment scope."""


@dataclass
class ScopeGuard:
    allowlist: list[str]
    require_confirmation: bool = True
    lab_targets: list[str] = field(default_factory=lambda: ["127.0.0.1", "localhost", "::1"])

    def __post_init__(self) -> None:
        self._normalized = {self._normalize(item) for item in self.allowlist if item.strip()}
        self._lab_normalized = {self._normalize(item) for item in self.lab_targets if item.strip()}

    @staticmethod
    def _normalize(target: str) -> str:
        value = target.strip()
        parsed = urlparse(value if "://" in value else f"//{value}", scheme="https")
        host = parsed.hostname or value.split("/")[0].split(":")[0]
        return host.rstrip(".").lower()

    def check(self, target: str, confirmed: bool = False, lab_mode: bool = False) -> str:
        host = self._normalize(target)
        if not host:
            raise ScopeError("Target non valido.")
        if self.require_confirmation and not confirmed:
            raise ScopeError(
                "Conferma esplicita richiesta: usa --confirm-authorization "
                "solo per un target che possiedi o per cui hai autorizzazione."
            )
        if not self._normalized:
            raise ScopeError(
                "Allowlist vuota: configura [scope].allowlist o usa --allow "
                "con un target autorizzato."
            )
        if not self._matches_allowlist(host):
            raise ScopeError(f"Target fuori scope: {host}")
        if lab_mode and not self._matches(host, self._lab_normalized):
            raise ScopeError(
                f"Target non autorizzato per la modalità Lab/CTF: {host}. "
                "Aggiungilo esplicitamente a [lab].targets."
            )
        return host

    def _matches_allowlist(self, host: str) -> bool:
        return self._matches(host, self._normalized)

    def _matches(self, host: str, allowed_hosts: set[str]) -> bool:
        for allowed in allowed_hosts:
            if host == allowed or host.endswith(f".{allowed}"):
                return True
            try:
                if ipaddress.ip_address(host) == ipaddress.ip_address(allowed):
                    return True
            except ValueError:
                continue
        return False

    def resolve(self, host: str) -> list[str]:
        try:
            return sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
        except socket.gaierror as exc:
            raise ScopeError(f"Impossibile risolvere {host}: {exc}") from exc
