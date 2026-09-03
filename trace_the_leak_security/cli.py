from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .config import DEFAULT_CONFIG_PATH, load_config, merge_cli_overrides, write_example_config
from .models import AssessmentResult
from .modules.dns import enumerate_dns
from .modules.network import scan_ports
from .modules.osint import passive_domain_profile
from .modules.passwords import audit_hash
from .modules.vulnerability import passive_assessment
from .modules.web import analyze_web
from .reporting import build_report, compact_terminal, write_report
from .scope import ScopeError, ScopeGuard
from .utils import configure_logging, parse_ports
from .utils import LOGGER


BANNER = """╔══════════════════════════════════════════════════════════╗
║       TraceTheLeakSecurity Multi-Tool                   ║
║          Authorized Security Assessment Suite            ║
╚══════════════════════════════════════════════════════════╝"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="traceleak",
        description="Security assessment controllato per sistemi autorizzati, lab e CTF.",
        epilog="Non usare su sistemi senza autorizzazione esplicita.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", help=f"File TOML di configurazione (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--allow", action="append", help="Aggiunge un hostname/IP alla allowlist")
    parser.add_argument("--safe", action="store_true", help="Attiva limiti conservativi")
    parser.add_argument(
        "--lab",
        action="store_true",
        help="Modalità Lab/CTF: forza safe mode e accetta solo target lab dichiarati",
    )
    parser.add_argument("--timeout", type=float, help="Timeout di rete in secondi")
    parser.add_argument("--max-requests", type=int, help="Massimo numero di richieste controllate")
    parser.add_argument("-v", "--verbose", action="store_true", help="Log diagnostici")
    subparsers = parser.add_subparsers(dest="command", required=True)

    config_parser = subparsers.add_parser("config", help="Gestione configurazione")
    config_sub = config_parser.add_subparsers(dest="config_command", required=True)
    init_parser = config_sub.add_parser("init", help="Crea una configurazione di esempio")
    init_parser.add_argument("path", nargs="?", default=str(DEFAULT_CONFIG_PATH))

    info_parser = subparsers.add_parser("info", help="Information gathering")
    info_sub = info_parser.add_subparsers(dest="info_command", required=True)
    dns_parser = info_sub.add_parser("dns", help="Enumerazione DNS tramite resolver locale")
    _add_target_options(dns_parser)

    network_parser = subparsers.add_parser("network", help="Network security")
    network_sub = network_parser.add_subparsers(dest="network_command", required=True)
    scan_parser = network_sub.add_parser("scan", help="Controllo TCP mirato su porte dichiarate")
    _add_target_options(scan_parser)
    scan_parser.add_argument("--ports", default="22,80,443,8080")

    web_parser = subparsers.add_parser("web", help="Web security")
    web_sub = web_parser.add_subparsers(dest="web_command", required=True)
    analyze_parser = web_sub.add_parser("analyze", help="Analisi HTTP/TLS e security headers")
    _add_target_options(analyze_parser)

    osint_parser = subparsers.add_parser("osint", help="OSINT passivo")
    osint_sub = osint_parser.add_subparsers(dest="osint_command", required=True)
    domain_parser = osint_sub.add_parser("domain", help="Profilo passivo DNS/certificato")
    _add_target_options(domain_parser)

    vulnerability_parser = subparsers.add_parser(
        "vulnerability", help="Vulnerability assessment passivo e non distruttivo"
    )
    vulnerability_sub = vulnerability_parser.add_subparsers(dest="vulnerability_command", required=True)
    assess_parser = vulnerability_sub.add_parser(
        "assess", help="Controlli osservabili HTTP/TLS senza exploit o fuzzing"
    )
    _add_target_options(assess_parser)

    password_parser = subparsers.add_parser("password", help="Audit su hash e wordlist fornite dall'utente")
    password_sub = password_parser.add_subparsers(dest="password_command", required=True)
    audit_parser = password_sub.add_parser("audit", help="Confronta un hash con una wordlist locale")
    audit_parser.add_argument("--hash", required=True, dest="digest")
    audit_parser.add_argument("--algorithm", default="sha256", choices=["md5", "sha1", "sha224", "sha256", "sha384", "sha512"])
    audit_parser.add_argument("--wordlist", required=True)
    audit_parser.add_argument("--format", choices=["table", "json", "csv", "html"], default="table")
    audit_parser.add_argument("--output", help="Salva il report nel file indicato")

    return parser


def _add_target_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("target")
    parser.add_argument(
        "--confirm-authorization",
        action="store_true",
        help="Conferma di avere autorizzazione esplicita sul target",
    )
    parser.add_argument("--format", choices=["table", "json", "csv", "html"], default="table")
    parser.add_argument("--output", help="Salva il report nel file indicato")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)

    if args.command == "config":
        if args.config_command == "init":
            destination = write_example_config(args.path)
            print(f"Configurazione creata: {destination}")
            return 0
        parser.error("Sottocomando config non riconosciuto")

    config = merge_cli_overrides(load_config(args.config), args)
    LOGGER.info("Avvio modulo %s in modalità %s", args.command, "Lab/CTF" if config.lab_mode else "Safe")
    try:
        if args.command == "password":
            result = audit_hash(args.digest, args.algorithm, args.wordlist)
            return _emit_results([result], args)

        guard = ScopeGuard(config.scope.allowlist, config.scope.require_confirmation)
        host = guard.check(args.target, args.confirm_authorization, config.lab_mode)
        if args.command == "info":
            result = enumerate_dns(host, guard.resolve(host))
        elif args.command == "network":
            ports = parse_ports(args.ports)
            result = scan_ports(host, ports, config)
        elif args.command == "web":
            result = analyze_web(args.target, config)
        elif args.command == "osint":
            result = passive_domain_profile(host, config)
        elif args.command == "vulnerability":
            result = passive_assessment(args.target, config)
        else:
            parser.error(f"Comando non supportato: {args.command}")
        return _emit_results([result], args)
    except (ScopeError, ValueError) as exc:
        print(f"ERRORE DI SICUREZZA: {exc}", file=sys.stderr)
        return 2


def _emit_results(results: list[AssessmentResult], args: argparse.Namespace) -> int:
    report = build_report(results[0].target, results)
    output_format = getattr(args, "format", "table")
    output_path = getattr(args, "output", None)
    if output_format == "table":
        print(BANNER)
        for result in results:
            print(compact_terminal(result))
        if output_path:
            file_format = Path(output_path).suffix.lower().lstrip(".") or "json"
            if file_format not in {"json", "csv", "html"}:
                file_format = "json"
            write_report(report, file_format, output_path)
            print(f"\nReport salvato: {output_path}")
    else:
        content = write_report(report, output_format, output_path)
        if not output_path:
            print(content)
    return 1 if any(result.errors for result in results) else 0
