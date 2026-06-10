# Changelog

Formát vychází z [Keep a Changelog](https://keepachangelog.com/cs/),
verzování dle pravidel projektu (start na 2.0.0; velké zásahy = MAJOR,
drobnosti a fixy = PATCH).

## [4.0.0] - 2026-06-10

Management projektu a **verzování běhů** — historie skenů, navázání (resume),
retest bez ztráty dat a porovnání verzí.

### Přidáno
- **Běh = verze:** každé spuštění skenu vytvoří novou verzi výsledků s metadaty
  (kdy začal/skončil, stav `běží/dokončeno/zastaveno`, profil, cíle, stav fází
  po cílech). Přepínač **„Běh/verze"** nad maticí umožňuje procházet a přepínat
  mezi verzemi (starší se zobrazují jen pro čtení).
- **Navázat (resume):** po zastavení skenu lze běh dokončit — úspěšné
  (cíl×fáze) se přeskočí, chyby a nedoběhlé se spustí znovu a výsledky se
  vmergují do téže verze (nezačíná se od píky). `vuln` se navíc zaměří na již
  nalezené otevřené porty.
- **Retest bez ztráty dat:** „Spustit nový běh" založí novou verzi; předchozí
  verze zůstávají zachované a procházatelné.
- **Porovnání verzí (diff):** dialog ukáže rozdíly mezi dvěma běhy — nové a
  zmizelé otevřené porty, změny služeb/verzí a změnu OS / online stavu.
- **Master seznam cílů** projektu — běhy u cílů zaznamenávají stav; přidané
  cíle se doplní do master seznamu, odebrané zůstanou v historii.
- **Správa běhů** (dialog): přejmenování, smazání verze a spuštění porovnání.
- **Přepínání mezi projekty** přímo z hlavního okna (tlačítko „Přepnout
  projekt…").
- Snapshoty verzí se ukládají vedle metadat do `results/<run_id>/snapshot.json`
  (projektový soubor zůstává malý). Nové moduly
  `nmapscanner/core/run_history.py` a `nmapscanner/dialogs/runs.py`; headless
  testy `tests/test_run_history.py`, `tests/test_scan_resume.py`,
  `tests/test_project_versioning.py`.

### Změněno
- Formát projektu `project.nmapproj` povýšen na **schema v3** (historie běhů
  místo jednoho inline `scan_results`). Staré projekty se při otevření
  automaticky **migrují** na jeden běh „Běh 1 (import)".
- `ScanManager.start_workflow` umí režim **resume** (přeskočí už hotové
  cíle×fáze a dopočítá progress jen ze zbývající práce).
- Tlačítko skenu se jmenuje „Spustit nový běh"; „Zastavit" označí běh jako
  `zastaveno` (jde navázat).

## [3.0.0] - 2026-06-10

Přepsané spouštění skenů — adaptivní vícestupňová detekce s paralelním během
a živou vizualizací průběhu. Nahrazuje dřívější přepínač intenzity Light/Intensive.

### Přidáno
- **Profily skenu** místo přepínače intenzity: `Master (adaptivní)`,
  `Intensive`, `Medium`, `Light` a `Vlastní příkaz`. Profil určuje startovní
  „příčku" v žebříku variant; výchozí je Master.
- **Vícestupňová adaptivní detekce (žebříky variant)** pro každou fázi
  (online / TCP / UDP / vuln / OS). Sken začne nejtvrdší variantou a při
  selhání/timeoutu se **automaticky zmírňuje** (méně portů, nižší
  version-intensity, mírnější timing), dokud něco neprojde. Když host
  neodpovídá na ping, zopakuje se příčka s `-Pn`. Cíl: zjistit co nejvíc,
  ale workflow nikdy nespadne.
- **Pipeline paralelismus:** jakmile doběhne discovery jednoho cíle, ihned se
  pro něj spustí hloubkové fáze — nečeká se na ostatní cíle. Souběh je omezen
  stropem vláken (výchozí 6). `vuln` se zaměří na otevřené porty nalezené v TCP.
- **Živá vizualizace průběhu:** souhrnné progress bary pro každou fázi, nový
  panel „Živé úlohy" (co běží — s běžícím časem — a co skončilo) a stavová
  matice.
- **Vlastní příkaz:** profil `Vlastní příkaz` spustí zadaný nmap příkaz
  (placeholder `{target}`) na každý cíl; XML výstup a `-Pn` fallback se doplní
  automaticky.
- Nový modul `nmapscanner/core/scan_profiles.py` (žebříky a profily, bez Qt,
  pokryto testem) a headless test `tests/test_scan_orchestration.py`.

### Změněno
- `ScanManager` přepsán na adaptivní orchestrátor řízený výsledky workerů
  (de-eskalace). Worker (`ScanWorker`) má timeout a hlásí strukturovaný stav
  (`ok` / `host_down` / `fail`).
- Start skenu se posílá do vlákna manažeru přes queued signál — všechny mutace
  stavu běží v jednom vlákně (odstraněna latentní race podmínka).
- Projekty i nastavení nově ukládají `scan_profile` a `custom_command`
  (dřívější `intensity_mode` a šablony po fázích už nejsou potřeba).

### Odstraněno
- Přepínač intenzity `Light/Intensive` a editovatelné šablony příkazů po fázích
  (nahrazeno profily + vlastním příkazem). Checkboxy pro povolení fází zůstávají.

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
