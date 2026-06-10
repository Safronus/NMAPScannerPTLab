# NMAP Scanner — PT Lab

Desktopová GUI aplikace (PySide6) pro **autorizované** bezpečnostní testování
v penetrační laboratoři. Orchestruje `nmap` a další nástroje, sbírá výsledky
do přehledné matice a generuje reporty.

> ⚠️ **Pouze pro autorizované testování.** Tento nástroj používej výhradně
> proti systémům, ke kterým máš písemné svolení (vlastní lab, klient se
> smlouvou, CTF). Skenování cizích sítí bez souhlasu je nezákonné.

## Funkce

- **Progresivní prioritní sken** — fáze `online`, `tcp`, `udp`, `vuln`,
  `osscan` přes `nmap`. Profil `Master` plánuje fáze podle **priority**
  (online → TCP → UDP → vuln → OS poslední) a porty pokrývá **progresivně**
  (nejdřív rychlé top porty, pak plný `-p-`, výsledky se slučují) — máš něco
  hned a vše po delším čase. Když selže ping, jede se s `-Pn`; timeout je jen
  pojistka (jeden klidnější pokus `-T3`), takže to nikdy nespadne. K dispozici
  i profily `Intensive/Medium/Light` a režim **Vlastní příkaz** (`{target}`).
  Skeny běží **paralelně** s prioritní frontou (hloubkové fáze startují hned po
  discovery cíle).
- **Živá vizualizace průběhu** — progress bary po fázích, panel „Živé úlohy"
  (co běží / co skončilo) a stavová matice pro každou IP.
- **Verzování běhů** — každé spuštění je samostatná verze výsledků; lze mezi
  nimi přepínat, **navázat** na zastavený běh (doskenuje jen chyby a nedoběhlé),
  spustit **retest** bez ztráty předchozích dat a **porovnat dvě verze** (nové/
  zmizelé porty, změny služeb/OS). Master seznam cílů + přepínání mezi projekty.
- **TLS / SSL audit** — tři enginy: lokální `nmap` (ssl-enum-ciphers, rychlý),
  `testssl.sh` (detailní, i pro interní IP) a Qualys SSL Labs API (jen veřejné
  domény). Klasifikace šifer (WEAK/INSECURE/SECURE) i celková známka jsou
  vyladěné podle Qualys SSL Labs (`core/tls_grading.py`, pokryto testem proti
  ground-truth sadě 47 šifer).
- **Bezpečnostní hlavičky** — kontrola 6 klíčových HTTP hlaviček (HSTS, CSP,
  X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
- **Certifikáty** — detail, export, hromadný přehled.
- **ffuf** — fuzzing adresářů/souborů s vestavěnou správou wordlistů.
- **Screenshoty** webových služeb přes **Selenium (headless Chrome)** — jeden
  znovupoužitý prohlížeč ve vlastním vlákně. chromedriver netřeba instalovat
  ručně (Selenium Manager ho vyřeší podle nainstalovaného Chrome).
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
| Google Chrome | Selenium screenshoty       | `brew install --cask google-chrome` (chromedriver řeší Selenium Manager) |

## Spuštění
```bash
python nmap-scanner.py
```

> 🔒 **Sudo:** nmap potřebuje root (SYN/UDP/OS sken). Když sudo žádá heslo,
> aplikace si o něj řekne v **dialogu** a předá ho nmap na stdin (`sudo -S`,
> heslo není vidět v `ps`). Heslo se drží **jen v RAM** (nikdy na disk) a jde
> ho kdykoli vymazat tlačítkem „Zapomenout sudo heslo". Pokud běžíš jako root
> nebo máš `NOPASSWD` sudo, na nic se neptá.

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

## Vývojové prostředí

Repozitář je uložen **mimo iCloud** (`~/GitHub Projects - Local/NMAPScannerPTLab`),
protože iCloud odkládá velké/binární soubory a neudrží symlinky (a může poškodit
`.git`). Virtuální prostředí `.venv` je v `~/.venvs/NMAPScannerPTLab` a do projektu
je vedeno symlinkem `.venv` (mimo iCloud už symlink drží). Spuštění:
```bash
.venv/bin/python nmap-scanner.py
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

Od verze 2.0.0 je aplikace rozdělena z jednoho 9100řádkového souboru do balíku:

```
nmap-scanner.py            tenký launcher (startovní kontroly + spuštění okna)
nmapscanner/               hlavní balík aplikace
  __init__.py              VERSION (jediný zdroj verze)
  utils.py                 parsování IP, barvy
  signals.py               WorkerSignals (Qt signály)
  core/scan_profiles.py    profily a žebříky variant skenu (bez Qt, testovatelné)
  core/scan_manager.py     adaptivní orchestrace fází (de-eskalace, pipeline, resume)
  core/run_history.py      historie běhů, verzování výsledků a diff (bez Qt, testovatelné)
  core/tls_grading.py      klasifikace TLS šifer + známka dle Qualys (bez Qt, testovatelné)
  workers/                 vlákna: scan, tls, certificate, security_headers, screenshot, ffuf
  widgets/                 LogConsole, StatusMatrix, LiveTaskPanel, PhaseProgressBars, …
  dialogs/                 dialogy: startup, tls, headers, certificate, export, ffuf, runs
  app.py                   NmapScannerApp (hlavní okno)
tests/                     headless testy (orchestrace skenu)
wordlists/                 slovníky pro ffuf (SecLists apod.)
requirements.txt           Python závislosti
CHANGELOG.md               historie verzí
.gitignore                 ochrana proti úniku dat
```

Headless testy (bez GUI a bez nmapu) se spouští jednotlivě, např.:
```bash
.venv/bin/python tests/test_scan_orchestration.py   # pipeline, de-eskalace, -Pn
.venv/bin/python tests/test_scan_resume.py          # navázání (resume)
.venv/bin/python tests/test_run_history.py          # verzování + diff
.venv/bin/python tests/test_project_versioning.py   # on-disk snapshoty verzí
.venv/bin/python tests/test_tls_grading.py          # TLS hodnocení dle Qualys
.venv/bin/python tests/test_sudo.py                 # sudo heslo jen na stdin (ne v ps)
.venv/bin/python tests/test_screenshot.py           # screenshot přes Selenium (skip bez Chrome)
```

Verzování (od 2.0.0): velké zásahy → MAJOR, drobné úpravy a fixy → PATCH.
Každá změna chování má záznam v `CHANGELOG.md`.
