# TraceTheLeakSecurity Multi-Tool

CLI modulare per assessment di sicurezza **autorizzati**, security lab, cyber-range e CTF.
Il tool non è progettato per attaccare sistemi reali senza consenso.

## Avvio rapido

```bash
cd trace-the-leak-security
python3 -m trace_the_leak_security config init ./config.toml
python3 -m trace_the_leak_security --config ./config.toml \
  --allow 127.0.0.1 info dns 127.0.0.1 --confirm-authorization
```

Il file di configurazione deve avere una allowlist. La conferma esplicita non viene dedotta
dalla presenza dell'host nella allowlist: va fornita a ogni comando di assessment.

## Comandi

```text
traceleak info dns TARGET --confirm-authorization
traceleak network scan TARGET --ports 22,80,443 --confirm-authorization
traceleak web analyze https://TARGET --format html --output report.html --confirm-authorization
traceleak osint domain TARGET --format json --confirm-authorization
traceleak vulnerability assess https://TARGET --confirm-authorization
traceleak password audit --hash HASH --algorithm sha256 --wordlist ./lab-wordlist.txt
```

`TARGET` deve essere nella allowlist. Gli assessment di rete e web hanno timeout, rate limit,
limiti di richieste e modalità safe. `password audit` opera esclusivamente su file locali
indicati dall'utente e non effettua tentativi su servizi.

### Modalità Lab/CTF

La modalità Lab/CTF forza i limiti safe e richiede che il target sia presente sia nella
allowlist generale sia in `[lab].targets`. Per default sono ammessi solo loopback e localhost:

```bash
python3 -m trace_the_leak_security --config ./config.toml --lab \
  --allow 127.0.0.1 network scan 127.0.0.1 --ports 8765 \
  --confirm-authorization
```

Per un cyber-range locale aggiungere alla sezione `[lab]` solo gli indirizzi dei sistemi
intenzionalmente vulnerabili e autorizzati.

## Formati

- `table`: output leggibile a terminale;
- `json`: dati completi machine-readable;
- `csv`: finding tabellari;
- `html`: report professionale standalone.

## Limitazioni note

- DNS avanzato (MX/NS/TXT) dipende dal resolver locale e non include una libreria DNS esterna;
- il port scan è TCP, mirato e richiede porte esplicite; registra solo eventuali banner
  spontanei e non invia probe di enumerazione attiva;
- il crawling web analizza solo link same-host presenti nella risposta iniziale e non esegue
  fuzzing né richieste a path inventati;
- i controlli CVE automatici non sono inclusi nella baseline per evitare correlazioni obsolete
  o non verificate; l'output identifica evidenze osservabili e raccomandazioni.

## Test

```bash
python3 -m unittest discover -s tests -v
```
