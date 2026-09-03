from __future__ import annotations

import hashlib
from pathlib import Path

from ..models import AssessmentResult, Finding


SUPPORTED_ALGORITHMS = {"md5", "sha1", "sha224", "sha256", "sha384", "sha512"}


def audit_hash(
    digest: str, algorithm: str, wordlist: str, max_candidates: int = 100_000
) -> AssessmentResult:
    result = AssessmentResult(target="user-provided-hash", module="password-security.audit")
    algorithm = algorithm.lower()
    digest = digest.strip().lower()
    if algorithm not in SUPPORTED_ALGORITHMS:
        result.errors.append(f"Algoritmo non supportato: {algorithm}")
        return result.finish()
    if not Path(wordlist).is_file():
        result.errors.append(f"Wordlist non trovata: {wordlist}")
        return result.finish()

    candidates = 0
    match: str | None = None
    try:
        with Path(wordlist).open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if candidates >= max_candidates:
                    result.errors.append(f"Limite candidati raggiunto: {max_candidates}")
                    break
                candidate = line.rstrip("\r\n")
                candidates += 1
                if hashlib.new(algorithm, candidate.encode()).hexdigest() == digest:
                    match = candidate
                    break
    except OSError as exc:
        result.errors.append(f"Impossibile leggere la wordlist: {exc}")

    result.data = {
        "algorithm": algorithm,
        "candidates_checked": candidates,
        "match_found": match is not None,
        "wordlist": str(Path(wordlist).resolve()),
        # Never include the recovered password in JSON/CSV/HTML reports.
    }
    if match is not None:
        result.findings.append(
            Finding(
                title="Hash matched a supplied wordlist candidate",
                severity="high",
                description="The provided hash was recovered using only the user-supplied wordlist.",
                evidence=f"Matched after {candidates} candidate(s); plaintext intentionally omitted.",
                recommendation="Replace the password, use a slow password hashing scheme, and enable MFA.",
            )
        )
    else:
        result.findings.append(
            Finding(
                title="No match in supplied wordlist",
                severity="info",
                description="No candidate in the supplied wordlist matched the hash.",
                evidence=f"Checked {candidates} candidate(s).",
                recommendation="This is not proof that the password is strong; use a calibrated password audit process.",
            )
        )
    return result.finish()
