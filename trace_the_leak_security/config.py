from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_CONFIG_PATH = Path.home() / ".config" / "trace-the-leak-security" / "config.toml"


@dataclass
class ScopeConfig:
    allowlist: list[str] = field(default_factory=list)
    require_confirmation: bool = True


@dataclass
class RuntimeConfig:
    safe: bool = True
    lab_mode: bool = False
    lab_targets: list[str] = field(default_factory=lambda: ["127.0.0.1", "localhost", "::1"])
    timeout: float = 3.0
    max_requests: int = 20
    rate_limit: float = 1.0
    max_body_bytes: int = 1_048_576
    scope: ScopeConfig = field(default_factory=ScopeConfig)


def load_config(path: str | None = None) -> RuntimeConfig:
    config_path = Path(path).expanduser() if path else DEFAULT_CONFIG_PATH
    if not config_path.exists():
        return RuntimeConfig()

    with config_path.open("rb") as handle:
        raw: dict[str, Any] = tomllib.load(handle)

    runtime = raw.get("runtime", {})
    scope = raw.get("scope", {})
    lab = raw.get("lab", {})
    return RuntimeConfig(
        safe=bool(runtime.get("safe", True)),
        lab_mode=bool(lab.get("enabled", False)),
        lab_targets=[str(item) for item in lab.get("targets", ["127.0.0.1", "localhost", "::1"])],
        timeout=max(0.2, float(runtime.get("timeout", 3.0))),
        max_requests=max(1, int(runtime.get("max_requests", 20))),
        rate_limit=max(0.0, float(runtime.get("rate_limit", 1.0))),
        max_body_bytes=max(1024, int(runtime.get("max_body_bytes", 1_048_576))),
        scope=ScopeConfig(
            allowlist=[str(item) for item in scope.get("allowlist", [])],
            require_confirmation=bool(scope.get("require_confirmation", True)),
        ),
    )


def write_example_config(path: str) -> Path:
    destination = Path(path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        """# TraceTheLeakSecurity Multi-Tool configuration
[runtime]
safe = true
timeout = 3.0
max_requests = 20
rate_limit = 1.0
max_body_bytes = 1048576

[scope]
require_confirmation = true
allowlist = ["127.0.0.1", "localhost", "::1"]

[lab]
enabled = false
targets = ["127.0.0.1", "localhost", "::1"]
""",
        encoding="utf-8",
    )
    return destination


def merge_cli_overrides(config: RuntimeConfig, args: Any) -> RuntimeConfig:
    if getattr(args, "safe", False):
        config.safe = True
    if getattr(args, "timeout", None) is not None:
        config.timeout = max(0.2, float(args.timeout))
    if getattr(args, "max_requests", None) is not None:
        config.max_requests = max(1, int(args.max_requests))
    if getattr(args, "lab", False):
        config.lab_mode = True
        config.safe = True
    if getattr(args, "allow", None):
        config.scope.allowlist.extend(args.allow)
    if os.environ.get("TRACELEAK_SAFE") == "1":
        config.safe = True
    return config
