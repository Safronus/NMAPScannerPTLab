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

Doporučeno ve virtuálním prostředí (PySide6 zatím nemá wheels pro Python 3.14,
použij 3.12):
```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
`.venv/` je v `.gitignore`, do repozitáře se nedostane.

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

## Projektové složky (od 2.1.0)

Každý projekt má **vlastní složku** a všechna data skenu se ukládají dovnitř:

```
<projekt>/
  project.nmapproj      stav projektu (JSON)
  results/scan_<čas>/   výstupy nmap skenů
  screenshots/          screenshoty webových služeb
  reports/              exporty (docx/csv/json)
```

Výchozí základní složka je `~/NmapScannerProjects` (nastavení
`default_projects_dir`). Při „Uložit projekt" vybereš nadřazenou složku a
volba se zapamatuje. Pokud spustíš sken bez otevřeného projektu, složka se
automaticky založí pod výchozí základnou. Tím se data drží pohromadě a mimo
adresář repozitáře.

## Vývojové prostředí mimo iCloud

`.venv` je uložen mimo iCloud (`~/.venvs/NMAPScannerPTLab`), protože iCloud
velké/binární soubory odkládá a **neudrží symlinky**. Pouštěj přes:
```bash
~/.venvs/NMAPScannerPTLab/bin/python nmap-scanner.py
```
Robustnější řešení je přesunout celý repozitář mimo iCloud — pak půjde
i jednoduchý `.venv` v adresáři projektu a spolehlivě poběží GUI test.

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

Od verze 2.0.0 je aplikace rozdělena z jednoho 9100řádkového souboru do balíku:

```
nmap-scanner.py            tenký launcher (startovní kontroly + spuštění okna)
nmapscanner/               hlavní balík aplikace
  __init__.py              VERSION (jediný zdroj verze)
  utils.py                 parsování IP, barvy
  signals.py               WorkerSignals (Qt signály)
  core/scan_manager.py     orchestrace fází skenu
  workers/                 vlákna: scan, tls, certificate, security_headers, screenshot, ffuf
  widgets/                 LogConsole, StatusMatrix, CheckableComboBox
  dialogs/                 dialogy: startup, tls, headers, certificate, export, ffuf
  app.py                   NmapScannerApp (hlavní okno)
wordlists/                 slovníky pro ffuf (SecLists apod.)
requirements.txt           Python závislosti
CHANGELOG.md               historie verzí
.gitignore                 ochrana proti úniku dat
```

Verzování (od 2.0.0): velké zásahy → MAJOR, drobné úpravy a fixy → PATCH.
Každá změna chování má záznam v `CHANGELOG.md`.
