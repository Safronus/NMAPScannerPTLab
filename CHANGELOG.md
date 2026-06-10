# Changelog

Formát vychází z [Keep a Changelog](https://keepachangelog.com/cs/),
verzování dle pravidel projektu (start na 2.0.0; velké zásahy = MAJOR,
drobnosti a fixy = PATCH).

## [4.7.0] - 2026-06-10

Oprava spamu `_pythonToCppCopy` v terminálu.

### Opraveno
- Chyby `_pythonToCppCopy: Cannot copy-convert (int) to C++` padající do
  terminálu během skenu. Příčina: python-nmap vrací porty jako **int klíče**
  (`{22: {...}}`) a cross-thread (queued) signály nesoucí `dict` je PySide
  marshaloval na QVariantMap (vyžaduje str klíče) → varování pro každý port.
  Signály `task_outcome` a `scan_result` nově nesou `object` místo `dict`
  (Python dict se předá referencí, bez konverze). Data dorazí beze změny.
- Regresní test `tests/test_signal_marshal.py` (zachytává i C++ zápisy na fd 2).

## [4.6.0] - 2026-06-10

Drobnosti: adaptivní layout, vuln „bez nálezů", kontextový re-scan + timeline.

### Přidáno
- **Kontextový re-scan nad cílem v matici** (pravé tlačítko): re-scan TCP / UDP /
  Vuln / OS / screenshoty (HTTP/HTTPS porty) / vše. Výsledky se **merguje do
  aktuální verze** a událost se zapíše do **timeline** běhu — historie je vidět
  ve „Správa běhů → 📜 Timeline". Timeline zaznamenává i vytvoření běhu a navázání.
- Re-scan zaměřuje vuln na již nalezené otevřené porty (seed z aktuálních dat).

### Změněno / opraveno
- **Adaptivní layout** přepsán z pevných „bucketů" (na Retina/4K padal do
  nejmenšího → drobný font, úzké panely) na **proporční velikosti s normálním
  fontem**. Pravé souhrnné panely už nejsou tvrdě omezené — jdou roztáhnout
  splitterem; použitelné od FullHD po 4K.
- **Záložka Vuln:** když vuln sken nic nenajde (nebo nedoběhne), zobrazí se
  neutrální **„✓ Žádné zranitelnosti nenalezeny"** místo červeného ERROR; u
  skutečného selhání jemná šedá poznámka. Matice ukáže `hotovo`, ne `chyba`.
- Stavový řádek vlevo dole nově ukazuje i `Skenuji…/Navazuji…/Re-scan…` (dřív
  jen „Připraven").
- `ScanRun` má pole `timeline` (serializuje se do projektu); pokryto testem.

## [4.5.0] - 2026-06-10

Oprava screenshotů webových služeb — přechod na Selenium (headless Chrome).

### Opraveno
- **Screenshoty webu nyní fungují.** Dřívější způsob (`QWebEngineView.grab()`)
  na nezobrazeném off-screen view vracel prázdný/null obrázek (web obsah se
  renderuje v odděleném procesu a `grab()` ho nezachytí) — proto screenshoty
  nikdy nevznikly.
- Nový `ScreenshotManager` (`workers/screenshot.py`) řídí **headless Chrome přes
  Selenium** ve vlastním vlákně, drží **jeden** znovupoužitý prohlížeč (rychlejší
  než spouštět Chrome pro každý cíl) a zpracovává požadavky sériově. chromedriver
  se neinstaluje ručně — Selenium Manager (4.6+) ho vyřeší sám podle nainstalovaného
  Google Chrome / Chromium. Při nedostupnosti se ohlásí jasná hláška a další
  pokusy se přeskakují.
- Odstraněn rozbitý QtWebEngine způsob i nepoužitá Selenium varianta v `app.py`.
- Headless Chrome se korektně zavře při ukončení aplikace.
- Test `tests/test_screenshot.py` pořídí reálný screenshot offline `data:` URL a
  ověří nenulový PNG (přeskočí se, pokud Selenium/Chrome nejsou k dispozici).

## [4.4.0] - 2026-06-10

Sudo heslo pro nmap přes dialog v aplikaci — místo neviditelného čekání na
heslo v terminálu.

### Přidáno
- Když nmap potřebuje root (SYN/UDP/OS sken) a sudo žádá heslo, aplikace ho
  vyžádá v **modálním dialogu** (skrytý vstup) a předá ho nmap **na stdin**
  (`sudo -S`) — **nikdy ne na příkazovou řádku** (není vidět v `ps`).
- Preflight před spuštěním běhu: pokud appka běží jako root, nebo je sudo
  bez hesla (NOPASSWD/platná cache), na nic se neptá. Heslo se ověří
  (`sudo -S -v`) hned, takže se chybné heslo pozná okamžitě (max 3 pokusy).
- Heslo se drží **pouze v RAM** jako mazatelná `bytearray`, nikdy se neukládá
  na disk ani do nastavení. Tlačítko **„🔒 Zapomenout sudo heslo"** ho
  bezpečně vynuluje; vymaže se i při zavření aplikace.
- Worker běží v bajtovém režimu, ať se heslo drží jen jako `bytes` (nekopíruje
  se do nemazatelného `str`). Headless test `tests/test_sudo.py` ověřuje, že
  heslo jde jen na stdin (ne do argv) a že fungují tři režimy sudo.

### Poznámka
- Bezpečné mazání z RAM je v CPythonu **best-effort**: drženou `bytearray`
  přepíšeme nulami, ale vstup z dialogu vytvoří dočasný neměnný `str`, který
  nelze spolehlivě přepsat, a OS může paměť odložit do swapu. Jde o rozumné
  minimum, ne tvrdou záruku.

## [4.3.0] - 2026-06-10

Přepracovaná strategie Master běhu — progresivní pokrytí + priorita místo
de-eskalace řízené timeoutem.

### Změněno
- **Priorita fází přes prioritní frontu vláken:** online → TCP → UDP → vuln → OS.
  Fáze se stále překrývají (paralelně), ale důležitější se plánují dřív a
  **OS scan běží reálně až nakonec** (nejnižší priorita).
- **Progresivní pokrytí portů** místo „full → ubírat při chybě": TCP nejdřív
  `top 1000` (výsledky hned), pak `-p-` (vše); UDP `top 100` → `top 1000`.
  Výsledky stupňů se **slučují** (sjednocení portů) — uživatel má něco hned a
  vše po delším čase. Průběžné výsledky chodí do UI s příznakem `final=False`,
  matice/panel se finalizují až posledním stupněm.
- **`-Pn` je jednoznačně první zmírnění:** když ping nedetekuje online stav,
  jedou všechny hloubkové skeny s `-Pn`.
- **Timeout/chyba = jen pojistka:** při zaseknutí/chybě se zkusí jednou
  klidnější varianta (`-T3`) a pokračuje se dalším stupněm — nikdy se to
  nezablokuje. (Dřív byl timeout hlavním řídicím mechanismem, což nesedělo —
  nmap skoro vždy doběhne s návratovým kódem 0 i bez výsledků.)
- Profily nově volí hloubku progrese: Master/Intensive = plné (top→`-p-`),
  Medium = TCP plně + UDP jen rychlé, Light = jen rychlé top porty.
- Nový signál `WorkerSignals.scan_result` (s `final`) pro průběžné vs finální
  výsledky; `core/scan_profiles.py` a `core/scan_manager.py` přepsány na model
  stupňů + priorit. Headless testy aktualizovány.

## [4.1.0] - 2026-06-10

Audit TLS — vyladěné hodnocení šifer dle Qualys SSL Labs a oprava zbývajících
dvou enginů (Qualys API, testssl.sh).

### Přidáno
- Nový modul `nmapscanner/core/tls_grading.py` (bez Qt, testovatelný):
  `classify_cipher` (klasifikace WEAK/INSECURE/SECURE laděná **přesně dle Qualys
  SSL Labs**) a `calculate_grade` (celková známka A/B/C/F dle Qualys stropů).
- Headless test `tests/test_tls_grading.py` ověřuje klasifikaci proti
  ground-truth sadě 47 cipher suites z reálných výsledků Qualys.

### Opraveno / změněno
- **Lokální Nmap engine — hodnocení šifer** nyní odpovídá Qualysu. Hlavní opravy:
  3DES je `WEAK` (ne `INSECURE`), statická RSA (i s GCM/CCM) je `WEAK` (bez
  forward secrecy), CBC je `WEAK`, jednoduché DES/RC4 je `INSECURE`. Celková
  známka bere v potaz i šifry (WEAK → strop B, INSECURE → F), ne jen protokoly.
- **Qualys SSL Labs engine** opraven: cíl zadaný jako **IP** se přeloží reverzním
  DNS na doménu; interní/privátní IP se odmítne s jasnou hláškou (Qualys umí jen
  veřejné domény). Správný API flow (`startNew`, polling, ošetření rate-limitu a
  timeoutu). Zobrazuje se **oficiální Qualys známka** (A+/A/…/T) z API.
- **TestSSL.sh engine** opraven: robustnější parsování protokolů i cipher řádků
  z JSON, klasifikace šifer sjednocena přes stejnou Qualys-laděnou logiku
  (`classify_cipher`), s fallbackem na severity od testssl.

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
