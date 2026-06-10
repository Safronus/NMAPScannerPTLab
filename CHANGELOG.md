# Changelog

Formát vychází z [Keep a Changelog](https://keepachangelog.com/cs/),
verzování dle pravidel projektu (start na 2.0.0; velké zásahy = MAJOR,
drobnosti a fixy = PATCH).

## [2.1.0] - 2026-06-10

Projektové složky — všechna data skenu se ukládají do jedné složky projektu.

### Přidáno
- **Projektové složky:** každý projekt má vlastní složku s podsložkami
  `results/`, `screenshots/`, `reports/` a stavovým souborem
  `project.nmapproj`. Nový modul `nmapscanner/core/project.py`
  (`ProjectPaths`) centralizuje všechny výstupní cesty (bez závislosti na Qt,
  pokryto unit testy).
- Konfigurovatelná **výchozí základní složka** pro projekty
  (nastavení `default_projects_dir`, default `~/NmapScannerProjects`).
  Při uložení projektu se vybírá nadřazená složka a volba se zapamatuje.

### Změněno
- Výsledky skenu už nejdou do pracovního adresáře
  (`./nmap_scan_results_*`), ale do `<projekt>/results/scan_<čas>/`.
  Screenshoty (odvozené z téže cesty) tím rovněž padají do projektu.
- Autosave už netvoří soubory v `~/.nmap_scanner_autosave`, ale píše do
  projektové složky (případně nově založené pod výchozí základnou).
- „Uložit projekt" nyní zakládá projektovou složku místo samostatného
  `.nmapproj` souboru.

### Pozn.
- Vývojový `.venv` přesunut mimo iCloud (`~/.venvs/NMAPScannerPTLab`);
  symlink v iCloud složce iCloud bohužel odstraňuje — viz README.

## [2.0.0] - 2026-06-10

První verze po rozdělení monolitu. Beze změny chování aplikace —
čistě strukturální refaktor + dokumentace a ochrana dat.

### Změněno
- **Velký refaktor:** monolit `nmap-scanner.py` (9107 řádků) rozdělen do
  balíku `nmapscanner/` (23 modulů — `utils`, `signals`, `core/`,
  `workers/`, `widgets/`, `dialogs/`, `app`). `nmap-scanner.py` je nově
  tenký spouštěcí launcher.
- Sjednocené verzování — jediný zdroj pravdy `nmapscanner/__init__.py`
  (`VERSION = "2.0.0"`). Titulek okna je nově `NMAP Scanner PT Lab - v{VERSION}`
  (dříve natvrdo „Verze 19.0", zatímco kód hlásil 2.1.0).
- Odstraněny nepoužité importy napříč balíkem (autoflake).

### Přidáno
- `.gitignore`, který blokuje veškerá data z testování — do repozitáře
  smí jen zdrojový kód a wordlisty.
- `requirements.txt`, `README.md`, `CHANGELOG.md`.
- Lokální vývojové prostředí `.venv` (Python 3.12 + PySide6 6.11) pro
  reprodukovatelný běh a ověřování.

### Ověřeno
- `py_compile` všech modulů, `pyflakes` bez jediného nedefinovaného jména,
  čistý import všech 23 modulů (bez cyklických importů).
- Plný GUI start vyžaduje reálný displej; v tomto prostředí (iCloud + Qt)
  jej nelze headless ověřit — doporučeno přesunout repo mimo iCloud.
