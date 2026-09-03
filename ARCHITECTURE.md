# TraceTheLeakSecurity Multi-Tool — Architettura

## Obiettivo

Toolkit Python per security assessment autorizzati, laboratori locali, cyber-range e CTF.
Il progetto privilegia il comportamento verificabile e non distruttivo: ogni operazione di rete
richiede conferma esplicita e passa da una allowlist.

## Struttura

```text
trace-the-leak-security/
├── pyproject.toml
├── README.md
├── config.example.toml
├── ARCHITECTURE.md
├── trace_the_leak_security/
│   ├── cli.py                 # argparse, UX e dispatch
│   ├── config.py              # TOML e limiti runtime
│   ├── scope.py               # autorizzazione, allowlist, risoluzione
│   ├── models.py              # risultati, finding e report
│   ├── reporting.py           # terminale, JSON, CSV, HTML
│   └── modules/
│       ├── dns.py             # resolver locale e record A/alias
│       ├── network.py         # TCP connect su porte dichiarate
│       ├── web.py             # HTTP, headers, crawling same-host limitato, TLS
│       ├── vulnerability.py   # assessment web passivo senza exploit/fuzzing
│       ├── passwords.py       # audit hash contro wordlist locale
│       └── osint.py           # profilo DNS/certificato passivo
└── tests/
```

## Contratto dei moduli

Ogni modulo restituisce `AssessmentResult`, che contiene target, nome modulo, dati strutturati,
finding con severità/evidenza/raccomandazione e errori non fatali. Questo rende i moduli
componibili e consente di aggiungere futuri adapter senza cambiare il reporting.

## Controlli di sicurezza

- allowlist obbligatoria, con match esatto o sottodominio;
- `--confirm-authorization` obbligatorio per attività su target;
- modalità safe predefinita;
- timeout e rate limit tra tentativi;
- limite alle porte analizzabili e alle richieste/body web;
- nessuna scansione CIDR, exploit, brute force remoto, bypass, persistenza o esfiltrazione;
- il network module legge solo banner spontanei dopo la connessione, senza inviare payload;
- l'audit password accetta solo hash e wordlist forniti dall'utente;
- il plaintext recuperato non viene mai inserito nei report.
- `--lab` forza la modalità safe e richiede una seconda allowlist dedicata ai target Lab/CTF.

## Dipendenze

La prima versione usa esclusivamente la standard library di Python 3.11+.
Questo riduce la superficie di supply-chain e facilita l'uso in container, VM e lab isolati.

## Roadmap

1. Baseline corrente: scope, DNS, TCP mirato, HTTP/TLS, assessment passivo, audit hash locale, OSINT passivo e report.
2. Aggiungere test di configurazione per certificati/header e un formato SARIF opzionale.
3. Integrare adapter opt-in per tool locali legittimi (`dig`, `nmap`) solo con flag esplicito e limiti.
4. Aggiungere storage locale cifrato/append-only per campagne e confronto tra report.
5. Aggiungere una modalità Lab/CTF con fixture e target Docker/VM scelti dall'utente, mai target pubblici.
