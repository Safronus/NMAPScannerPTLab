# Changelog

Formát vychází z [Keep a Changelog](https://keepachangelog.com/cs/),
verzování dle pravidel projektu (start na 2.0.0; velké zásahy = MAJOR,
drobnosti a fixy = PATCH).

## [5.3.1] - 2026-06-10

### Opraveno
- **Pád při zavírání `RuntimeError: Signal source has been deleted`.** TLS workery
  (sslscan/sslyze/…) běžící na globálním poolu emitovaly signál do `WorkerSignals`,
  který se při zavírání aplikace už zničil. Všechny emity v `workers/tls.py` jsou
  teď přes `_safe_emit` (jako u scan workerů) → pád zmizí.
- **Zavírání aplikace „trvalo" bez zpětné vazby.** Přidán **progress dialog** při
  zavírání (Ukládám projekt → Ukončuji procesy → Zavírám vlákna), takže je vidět,
  že appka pracuje a nezamrzla.
- **Global pool čekal při zavírání na timeout TLS subprocess.** TLS enginy běží
  přes nový **killable Popen** (sdílený `TLS_PROCS` registr); `closeEvent` je při
  zavírání tvrdě ukončí, takže se nečeká na jejich timeout (až 180 s). Pokryto
  v `tests/test_tls_cancel.py`.

## [5.3.0] - 2026-06-10

### Přidáno
- **Automatický update po startu.** Launcher při spuštění zkontroluje GitHub,
  a když je novější verze, udělá `git pull --ff-only`, doinstaluje závislosti
  z `requirements.txt` a restartuje se na novou verzi — aby se nestávalo, že
  běží starý kód kvůli zapomenutému `git pull`. Bezpečně přeskočí bez sítě, se
  špinavým pracovním stromem, při rozejití větve nebo když `NMAPSCANNER_NO_UPDATE=1`.
  Ochrana proti restart-smyčce přes env proměnnou.
- **SSLyze nalezen i jako modul** (`python -m sslyze`), když není `sslyze`
  binárka na PATH (typické po `pip install` do venv). `sslyze` přidán do
  `requirements.txt` (auto-instalace při updatu).
- **Screenshoty — chytřejší hlášení a stav v záložce.** Hláška o selhání teď
  rozliší příčinu (síť: cíl tam neslouží web; práva: Plocha/iCloud blokuje zápis;
  Chrome/Selenium nedostupný) místo paušálního obviňování Plochy. Záložka
  **Screenshots** při prázdném stavu vysvětlí proč (poslední příčina) a poradí,
  jak screenshoty pořídit.

### Změněno
- **Vuln záložka už neukazuje benigní hlášky a chyby skriptů jako červené nálezy.**
  Nová klasifikace (`core/vuln_classify.py`) rozliší **potvrzený nález** od
  **chyby/timeoutu skriptu** a **čistého výsledku** („Couldn't find any…",
  „No reply… TIMEOUT", „ERROR: Script execution failed"). Počítají se jen
  potvrzené zranitelnosti; ostatní výstupy jsou ve sbaleném šedém uzlu „Výstupy
  skriptů (N) — bez potvrzených nálezů". Bez nálezů = zelené „bez nálezů".
  IP souhrn používá stejnou klasifikaci (pokryto `tests/test_vuln_classify.py`).

## [5.2.0] - 2026-06-10

### Přidáno
- **Inspektor TLS: dva nové enginy — `sslscan` a `SSLyze`** (vedle Nmap, Qualys,
  TestSSL). Oba lokální, fungují i na interní/bezdoménové IP:
  - `SslscanWorker` — parsuje XML (`sslscan --xml=-`): podporu protokolů a přijaté
    šifry (OpenSSL názvy → klasifikace přes `tls_grading`). Instalace
    `brew install sslscan`.
  - `SslyzeWorker` — spustí `sslyze --json_out=…` a z JSONu vytáhne protokoly a
    accepted cipher suites (IANA názvy). Instalace `pip install sslyze`.
  - Když nástroj chybí, engine vrátí jasnou chybu s návodem na instalaci.
  - Každý engine má jako dosud vlastní pod-řádek s historií; zrušitelnost
    (tlačítko Zastavit) i zavření dialogu fungují stejně.
- **Tlačítko „🧪 Prověřit VŠEMI enginy"** — spustí pro všechny cíle všech pět
  enginů naráz (každý do svého pod-řádku). Qualys u interních/bezdoménových cílů
  jen vrátí chybu, ostatní projdou.

### Změněno
- Spouštění enginů refaktorováno do `_start_engine(idx, tasks)`; enginy/workery/
  ikony jsou v jedné tabulce (`ENGINES`/`WORKERS`/`ICONS`) — přidání dalšího
  enginu = jeden řádek na stejný index.

## [5.1.4] - 2026-06-10

### Přidáno
- **Startup banner s verzí a cestou.** Launcher po startu vypíše
  `=== NMAP Scanner PT Lab vX.Y.Z ===` + absolutní cestu balíku a python. Snadno
  se tak pozná, **která kopie/verze** běží (časté zmatení: spuštění staré kopie
  mimo git repozitář → „opravy se neprojevily").
- **Ochrana proti ztrátě dat u nezapisovatelné složky.** Po načtení projektu se
  ověří zápis do jeho složky; když nejde (typicky projekt na **Ploše/iCloudu**
  blokované macOS TCC), aplikace **hned varuje** a nabídne **Uložit projekt
  jinam…** (přenese data z paměti do zapisovatelné složky). Stejnou nabídku dá i
  při selhání autosave. Dřív autosave jen tiše selhával a výsledky po zavření
  mizely. „Exportovat projekt" navíc zvládne i selhání cílového místa bez pádu.

## [5.1.3] - 2026-06-10

### Přidáno
- **Průběh a souhrn pořizování screenshotů.** Re-scan screenshotů (i screenshoty
  během skenu) teď hlásí živý průběh ve stavovém řádku
  (`📸 Screenshoty: 3/8 (✓ 2 · ✗ 1)…`) a po dokončení souhrn. Nový signál
  `screenshot_done` se emituje na **každé** cestě (úspěch, chyba i přeskočení),
  takže se čítač vždy dopočítá. Při chybách se v logu objeví počet a poslední
  chyba + tip (na Ploše/iCloudu macOS blokuje zápis). Dřív nešlo poznat, jestli
  pořizování proběhlo.

### Opraveno
- Re-scan screenshotů **nespadne**, když nejde vytvořit cílovou složku (macOS
  TCC na Ploše/iCloudu) — chyba se zaloguje a pokus pokračuje (reálný stav pak
  nahlásí ScreenshotManager). 

## [5.1.2] - 2026-06-10

### Opraveno
- **Zavření Inspektoru TLS / certifikátů / hlaviček zamrzlo aplikaci** (dlouhé
  „kolečko"). Každý dialog si vytvářel **vlastní** `QThreadPool`, jehož destruktor
  při zavření volá `waitForDone()` a **blokuje GUI vlákno**, dokud nedoběhne
  worker (Qualys/testssl/openssl/HTTP). Dialogy nově používají **globální pool**
  — zavření je okamžité, rozběhnuté kontroly doběhnou na pozadí (TLS je navíc ruší).
- **Autosave spamoval chyby u projektu na Ploše/iCloudu.** macOS (ochrana
  soukromí, TCC) blokuje zápis do takové složky → `EPERM` při každém pokusu po
  zavření dialogu. Nově se autosave po prvním selhání práv pro danou cestu
  **vypne**, vysvětlí to **jednou** (návod: exportovat projekt mimo Plochu/iCloud,
  nebo povolit přístup v Nastavení → Soukromí → Soubory a složky) a dál už
  nezahlcuje log ani nezdržuje GUI. Data v aplikaci zůstávají; po exportu/uložení
  jinam se ukládání samo obnoví.

## [5.1.1] - 2026-06-10

### Opraveno
- **Kontextový re-scan resetoval progress bary všech fází, ne jen dotčených.**
  Při re-scanu (např. jen UDP) se ostatní (už hotové) fáze zašedly na „—" a
  zmizel jejich průběh. Nově se resetují **jen re-scanované fáze**
  (`PhaseProgressBars.reset_phases`), ostatní si nechají svůj dosavadní stav.

## [5.1.0] - 2026-06-10

### Přidáno
- **Multiselect kontextových re-scanů v matici „Průběh fází".** Matice nově
  podporuje rozšířený výběr (Ctrl/Cmd-klik = přidat cíl, Shift-klik = rozsah).
  Pravý klik nad výběrem nabídne re-scan (TCP/UDP/Vuln/OS/vše/screenshoty) pro
  **všechny vybrané cíle najednou** — spustí se jako jeden běh, který merguje do
  aktuální verze a zapíše se do timeline. Pravý klik mimo výběr funguje jako dřív
  (jen ten jeden řádek). Popisky menu ukazují buď jméno cíle, nebo „N cílů".

## [5.0.5] - 2026-06-10

### Změněno
- **Export PDF v Inspektoru TLS má verzovaný název.** Místo statického
  `SSL_TLS_Audit_Report.pdf` se předvyplní
  `<projekt>_TLS_Audit_<YYYYMMDD_HHMMSS>.pdf` (název dle projektu + časové
  razítko). Když je projekt uložený, ukládací dialog míří rovnou do jeho složky
  `reports/`; bez projektu jen do aktuálního adresáře. Název lze před uložením
  pochopitelně přepsat.

## [5.0.4] - 2026-06-10

### Opraveno
- **Inspektor TLS: po doběhnutí testu zase nešlo zvolit jiný — odstraněno
  zamykání UI úplně.** Zámek byl „všechno nebo nic" přes celou dávku: dokud
  nedoběhl *poslední* worker (a TestSSL/Qualys na pomalém cíli běží i 1–2 min,
  nebo doběhne až na timeout), zůstala spouštěcí tlačítka zamčená — jeden pomalý
  cíl tak držel celé UI. Protože každý engine píše do **vlastního pod-řádku per
  cíl**, není co zamykat: tlačítka i engine combo jsou nově **vždy ovladatelné**,
  další test (i jiný engine) lze spustit kdykoli a souběžně. Jediný indikátor
  aktivity je tlačítko **Zastavit**, které ruší **všechny** rozběhnuté dávky.

## [5.0.3] - 2026-06-10

### Opraveno
- **Inspektor TLS se „zasekl" při běhu Qualysu a nešlo přepnout engine.** Qualys
  SSL Labs API se polluje klidně i pár minut na cíl; po celou tu dobu bylo UI
  zamčené, řádek ukazoval zavádějící „0× prověřeno" a engine combo bylo
  `disabled`. Nově:
  - **Engine combo zůstává vždy ovladatelné** (přepnutí se projeví u dalšího
    prověření) — uživatel není během běhu uvězněný.
  - **Průběžný řádek ukazuje skutečný stav** („🌐 Qualys — probíhá hloubkový
    audit (1–3 min)…") místo „0× prověřeno", takže je vidět, že běh žije.
  - Přidáno tlačítko **⏹ Zastavit** — zruší probíhající dávku. Workery se ukončí
    při nejbližší kontrole (Qualys čeká mezi dotazy a kontroluje zrušení po 1 s).
  - **Zavření dialogu** rovněž zruší běžící dávku (Qualys/TestSSL už nepolluje
    API na pozadí). Zrušený pokus se **neukládá** do výsledků projektu.
- Pokryto headless testem `tests/test_tls_cancel.py` (zrušitelnost workerů,
  Qualys končí stavem „Zrušeno" bez síťového dotazu, okamžitá reakce na stop).

## [5.0.2] - 2026-06-10

### Přidáno
- **Cesta k projektu je vidět v aplikaci.** Pod názvem projektu je řádek
  `📁 …/project.nmapproj` (plná cesta i v tooltipu, jde označit/zkopírovat myší).
  Když projekt ještě není uložen, řádek to říká („založí se při spuštění skenu").
  Aktualizuje se při přepnutí běhu, autosave, uložení i exportu.

### Opraveno
- **Nedokončená fáze (např. UDP) se po uložení/načtení tvářila jako „hotovo".**
  Při přerušení běhu se uložila částečná data fáze a po načtení je matice podle
  jejich pouhé přítomnosti označila za hotové. Nově `_display_run` data jen
  naplní do stromů (`final=False`) a stav buněk matice nastaví **autoritativně**
  podle skutečného stavu fází běhu (`phase_status`) — přerušená fáze zůstane
  „čeká"/nedoběhlá, ne „hotovo".

## [5.0.1] - 2026-06-10

### Opraveno
- **Progress bary fází se neobnovily při načtení projektu** (ukazovaly 0/0 i u
  doběhlého/rozpracovaného běhu). Nově se dopočítají z uloženého stavu běhu
  (kolik cílů má danou fázi hotovou).
- **FullHD layout:** pravé souhrnné panely byly moc široké a matice stísněná
  (pravý blok byl širší než matice). Zúženy levý i pravé panely, **střední
  panel (matice) = zbytek šířky** a má přednost i při roztahování okna. Panely
  jdou i dál ručně roztáhnout splitterem nebo skrýt tlačítky Souhrn IP/Porty/Služby.

## [5.0.0] - 2026-06-10

Nový projektový formát (schema v4) — robustní, atomický, self-describing,
rozšiřitelný. Verzování, historie a timeline zůstávají; ukládání je odolné.

### Přidáno
- Nový modul `nmapscanner/core/project_store.py` (bez Qt, pokrytý testem):
  - **Atomický zápis** všech souborů (temp + `os.replace` + `fsync`) — pád
    uprostřed ukládání už nepoškodí projekt ani jeho verze.
  - **Self-describing** soubory: `schema`, `format`, `updated_at`.
  - **Oddělení metadat a dat**: `project.nmapproj` drží jen metadata projektu a
    běhů; data každého běhu jsou v `results/<run_id>/data.json` pod klíčem
    `results` (libovolné typy: nmap fáze, tls_audit, certificates,
    security_headers, ffuf, screenshots…) — snadno rozšiřitelné.
  - **Migrace** ze schema v3 (run_history + snapshot.json) i z úplně starého
    formátu (scan_results inline) → jeden běh. Ověřeno i na reálném projektu.

### Změněno
- Veškeré ukládání/načítání projektu v `app.py` jde přes `ProjectStore`
  (autosave, export, „uložit při zavření", načtení). Data verzí se čtou z
  `data.json`, s fallbackem na starší `snapshot.json`.
- Zpětná kompatibilita formátu není garantovaná (dle zadání), ale staré projekty
  se při otevření automaticky **migrují** — o data nepřijdeš.

## [4.9.0] - 2026-06-10

TLS Inspektor — oddělení enginů do pod-řádků + historie prověřování.

### Změněno
- **TLS okno: výsledky per engine.** Pod každým cílem:portem je teď samostatný
  řádek pro **Nmap / Qualys / TestSSL** — každý se svou známkou, protokoly,
  šiframi a počtem „Nx prověřeno". Spuštění jednoho enginu už **nepřepíše**
  výsledky druhého; aktualizuje se jen jeho řádek (se záznamem historie).
- „Prověřit neprověřené" se vztahuje k vybranému enginu (prověří jen cíle, které
  tím enginem ještě prověřené nebyly).
- Workery hlásí svůj engine; uložení v projektu je `tls_audit[ip:port][engine]`
  vč. historie (starý formát se při načtení zmigruje). PDF export i filtry
  upraveny na nový model.

## [4.8.0] - 2026-06-10

Oprava pádu při zavírání během skenu, spolehlivější ukládání projektu, funkční
TestSSL engine a lepší startup dialog.

### Opraveno
- **Pád / zamrznutí při zavření aplikace, když běžel sken.** UDP sken se mohl
  zaseknout na `subprocess` (až do timeoutu 20 min), thread pool při ukončení
  čekal a worker padal na `RuntimeError: Signal source has been deleted`. Nově:
  nmap procesy jdou tvrdě zabít (`ProcessRegistry`), emise signálů jsou odolné
  vůči zničenému objektu, a `closeEvent` procesy nejdřív ukončí a počká s
  timeoutem. (Regresní test `tests/test_shutdown.py`.)
- **Projekt se neobjevoval ve startup dialogu** — autosave ho nepřidával do
  „posledních projektů". Nově každý autosave projekt zaregistruje.
- **Výsledky auditů (TLS/cert/headers/ffuf) se neukládaly do projektu** — nově
  se po zavření audit dialogu projekt automaticky uloží (je-li otevřený).
- **TestSSL.sh engine teď funguje.** testssl vrací cipher názvy v OpenSSL stylu
  (`ECDHE-ECDSA-AES256-GCM-SHA384`), můj parser čekal IANA → bral celý řádek a
  klasifikoval špatně. Opraveno parsování i `classify_cipher` (rozumí oběma
  stylům). Ověřeno reálně proti veřejné IP.

### Změněno
- **Startup dialog** přepsán: ukazuje **názvy projektů** (z `.nmapproj`) a počet
  běhů/cílů místo dlouhých názvů složek; seznam + Otevřít/Import/Nový.
- **Qualys**: pro veřejnou IP zkusí reverzní DNS (PTR) na doménu (pak funguje,
  např. 1.1.1.1 → one.one.one.one). IP bez PTR Qualys odmítá (HTTP 441) — nově
  s jasnou hláškou „použij doménu nebo TestSSL".
- Doinstalovány nástroje `testssl` a `ffuf` (na vyžádání).
- `classify_cipher` ověřuje i OpenSSL-styl názvy (rozšířený test).

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
