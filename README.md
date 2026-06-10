# NMAP Scanner — PT Lab

Desktopová GUI aplikace (PySide6) pro **autorizované** bezpečnostní testování
v penetrační laboratoři. Orchestruje `nmap` a další nástroje, sbírá výsledky
do přehledné matice a generuje reporty.

> ⚠️ **Pouze pro autorizované testování.** Tento nástroj používej výhradně
> proti systémům, ke kterým máš písemné svolení (vlastní lab, klient se
> smlouvou, CTF). Skenování cizích sítí bez souhlasu je nezákonné.

## Funkce

- **Discovery & port scan** — fáze `online`, `tcp`, `udp`, `vuln`, `osscan`
  přes `nmap` (python-nmap), paralelně přes `QThreadPool`.
- **Stavová matice** — přehled stavu jednotlivých fází pro každou IP.
- **TLS / SSL audit** — lokálně přes `testssl.sh` a `openssl`, volitelně přes
  veřejné SSL Labs API.
- **Bezpečnostní hlavičky** — kontrola 6 klíčových HTTP hlaviček (HSTS, CSP,
  X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
- **Certifikáty** — detail, export, hromadný přehled.
- **ffuf** — fuzzing adresářů/souborů s vestavěnou správou wordlistů.
- **Screenshoty** webových služeb (QtWebEngine / Selenium).
- **Reporty** — export do Wordu (`.docx`), CSV a JSON.
- **Projekty** — ukládání/načítání stavu do `.nmapproj`, autosave.

## Požadavky

### Python balíčky
```bash
pip install -r requirements.txt
```

### Systémové nástroje
| Nástroj       | Účel                       | Instalace (macOS)          |
|---------------|----------------------------|----------------------------|
| `nmap`        | scan portů/služeb          | `brew install nmap`        |
| `ffuf`        | fuzzing adresářů           | `brew install ffuf`        |
| `testssl.sh`  | TLS audit interních IP     | `brew install testssl`     |
| `openssl`     | detaily certifikátů        | součást systému            |
| `chromedriver`| Selenium screenshoty       | `brew install chromedriver`|

## Spuštění
```bash
python nmap-scanner.py
```

## 🔒 Bezpečnost dat — DŮLEŽITÉ

Tento repozitář je **soukromý** a smí obsahovat **pouze zdrojový kód
a wordlisty**. Žádná data z testování (IP adresy, výsledky, screenshoty,
reporty, certifikáty, projekty klientů) se do gitu **nesmí** dostat.

O to se stará [`.gitignore`](.gitignore), který blokuje:

- `nmap_scan_results_*/`, `*.nmapproj`, `.nmap_scanner_autosave/`
- reporty a exporty: `*.docx`, `*.pdf`, `*.csv`, `*.json`, `*.xml`, `*.html`
- screenshoty: `*.png`, `*.jpg`, …
- dočasné soubory, logy, `.env`, klíče a certifikáty (`*.key`, `*.pem`, …)

**Před každým `git add` / `commit` zkontroluj `git status`** a ujisti se, že
se commitují jen zdrojové soubory a wordlisty. Aplikaci pouštěj raději mimo
adresář repozitáře, aby výstupy nevznikaly přímo v něm.

## Struktura
```
nmap-scanner.py     hlavní aplikace (PySide6 GUI)
wordlists/          slovníky pro ffuf (SecLists apod.)
requirements.txt    Python závislosti
.gitignore          ochrana proti úniku dat
```
