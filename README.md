# Advanced Security Suite

Interactive Python CLI built as a learning project during the *Junior System and CyberSecurity Analyst* course (Generation Italy). It groups password analysis, a TCP port scanner, basic web checks and local network monitoring behind a single menu.

> **Authorized use only.** Scan and test only systems you own or have written permission to test. Unauthorized scanning can be illegal (in Italy, e.g. art. 615-ter c.p.). The author accepts no liability for misuse.

## What it does

| Menu | Features |
|---|---|
| Password | Strength check against common patterns and a small leaked-password list, secure password generator (`secrets`) |
| Network scanner | Async TCP port scan, banner grabbing, TLS certificate and HTTP header info, export to txt/json/html/csv |
| Web security | Same-domain crawler, then per-parameter web tests: SQL injection (error-based, time-based, boolean-blind), reflected XSS and static DOM-based XSS detection; text report |
| Network monitor | Active connections and per-process network activity via `psutil` |

## How the web scanner works

Run *Web Security Tests > Full site scan*: it crawls the same-domain pages, collects GET links and forms, then tests every parameter. Results are trustworthy, not inflated:

- **One finding per vulnerable parameter** (with the count of confirming payloads), never one per payload or per keyword.
- **SQLi error-based** is differential — a DB error counts only if it appears with the payload but not in the clean baseline request.
- **SQLi time-based** requires a slow response reconfirmed by a second request (relative + absolute threshold).
- **SQLi boolean-blind** compares a TRUE and a FALSE condition against the baseline and needs at least two independent payload pairs to agree.
- **Reflected XSS** is flagged only when the payload is reflected **unescaped** (an app that HTML-encodes output is correctly not flagged).
- **DOM-based XSS** is a static check: it reports a user-controlled source (e.g. `location.hash`) reaching a dangerous sink (e.g. `document.write()`, `innerHTML`, `eval()`) in the same script; it does not execute JavaScript, so treat it as a lead to verify by hand.

## Known limitations

This is a learning project, not a professional scanner:

- No boolean-blind data extraction, no UNION column discovery, no authenticated crawling, no JavaScript execution. For real engagements use OWASP ZAP, Burp Suite or sqlmap.
- Some port-scan modes (`fast`, `smart`, `adaptive`, `specific service`) return simulated placeholder data.
- The file still contains unused code paths that are being cleaned up.
- No automated test suite yet: detection was validated manually against controlled local apps (vulnerable → found, HTML-escaping/static → nothing) and the port scanner against the authorized target scanme.nmap.org.

## Installation

Requires Python 3.10+.

```bash
git clone https://github.com/Kashim0-afk/Advanced-Security-Suite.git
cd Advanced-Security-Suite
pip install -r requirements.txt
python "Advanced Security Suite.py"
```

`scapy` needs Npcap on Windows and root privileges on Linux for ICMP features.

---

## Italiano

CLI Python interattiva, progetto di studio del corso *Junior System and CyberSecurity Analyst* (Generation Italy). Riunisce analisi password, port scanner TCP, scanner web con crawling e monitoraggio di rete locale in un unico menu.

> **Solo uso autorizzato.** Scansiona e testa solo sistemi tuoi o per cui hai un'autorizzazione scritta. La scansione non autorizzata può essere reato (es. art. 615-ter c.p.). L'autore non risponde di usi impropri.

**Scanner web** (*Web Security Tests > Scansione completa sito*): fa il crawling delle pagine dello stesso dominio, raccoglie link GET e form, poi testa ogni parametro. Risultati veri, non gonfiati: **una voce per parametro vulnerabile** (col numero di payload che l'hanno confermata). Copre SQL injection error-based (differenziale rispetto alla baseline), time-based (riconfermata), blind booleana (confronto condizione vera/falsa), XSS riflesso (solo se il payload torna **non codificato**) e DOM XSS statico (sorgente controllabile → sink pericoloso nello stesso script, da verificare a mano).

**Limiti noti:** niente estrazione dati via blind booleana, niente scoperta colonne UNION, niente crawling autenticato, nessuna esecuzione di JavaScript. Alcune modalità di port scan restituiscono dati simulati, resta del codice inutilizzato da ripulire, nessun test automatico (rilevamento validato a mano su app locali controllate e port scanner su scanme.nmap.org). Per lavori professionali usa OWASP ZAP, Burp o sqlmap.

**Installazione:** Python 3.10+, poi `pip install -r requirements.txt` e `python "Advanced Security Suite.py"`.

Sviluppato con il supporto dell'intelligenza artificiale per revisione e parte dell'implementazione.

## License

[MIT](LICENSE) © 2025 Matteo Zordan
