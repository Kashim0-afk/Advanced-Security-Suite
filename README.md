# Advanced Security Suite

Interactive Python CLI built as a learning project during the *Junior System and CyberSecurity Analyst* course (Generation Italy). It groups password analysis, a TCP port scanner, basic web checks and local network monitoring behind a single menu.

> **Authorized use only.** Scan and test only systems you own or have written permission to test. Unauthorized scanning can be illegal (in Italy, e.g. art. 615-ter c.p.). The author accepts no liability for misuse.

## What it does

| Menu | Features |
|---|---|
| Password | Strength check against common patterns and a small leaked-password list, secure password generator (`secrets`) |
| Network scanner | Async TCP port scan, banner grabbing, TLS certificate and HTTP header info, export to txt/json/html/csv |
| Web security | Basic SQL injection and reflected XSS probes (heuristic, keyword based) |
| Network monitor | Active connections and per-process network activity via `psutil` |

## Known limitations

This is a learning project, not a professional scanner:

- SQLi/XSS detection is heuristic and produces false positives and false negatives. Use dedicated tools (OWASP ZAP, Burp Suite, sqlmap) for real assessments.
- Some scan modes (`fast`, `smart`, `adaptive`, `specific service`) return simulated placeholder data.
- The file contains unused code paths that are being cleaned up.
- No automated tests yet.

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

CLI Python interattiva, progetto di studio del corso *Junior System and CyberSecurity Analyst* (Generation Italy). Riunisce analisi password, port scanner TCP, controlli web di base e monitoraggio di rete locale in un unico menu.

> **Solo uso autorizzato.** Scansiona e testa solo sistemi tuoi o per cui hai un'autorizzazione scritta. La scansione non autorizzata può essere reato (es. art. 615-ter c.p.). L'autore non risponde di usi impropri.

**Limiti noti:** rilevamento SQLi/XSS euristico (falsi positivi e negativi), alcune modalità di scansione restituiscono dati simulati, codice inutilizzato in fase di pulizia, nessun test automatico.

**Installazione:** Python 3.10+, poi `pip install -r requirements.txt` e `python "Advanced Security Suite.py"`.

Sviluppato con il supporto dell'intelligenza artificiale per revisione e parte dell'implementazione.

## License

[MIT](LICENSE) © 2025 Matteo Zordan
