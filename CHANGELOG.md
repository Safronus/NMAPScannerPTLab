# Changelog

Formát vychází z [Keep a Changelog](https://keepachangelog.com/cs/),
verzování dle pravidel projektu (start na 2.0.0; velké zásahy = MAJOR,
drobnosti a fixy = PATCH).

## [5.16.8] - 2026-09-19

### Opraveno / Změněno (Vulners ověření klíče)
- Ověření Vulners klíče nově běží přes **audit endpoint** (v4, doporučeno
  dokumentací a zároveň endpoint, který appka reálně používá) s fallbackem na
  search; HTTP 200 na kterémkoli = klíč platný.
- **Klíč se před odesláním čistí** od mezer, nezlomitelných/neviditelných znaků
  a uvozovek (časté při copy-paste na Windows).
- Chybová hláška ukazuje **konkrétní důvod od Vulners** (např. „Unknown api key")
  a radí zkontrolovat přesnost klíče a aktivaci trialu.

## [5.16.7] - 2026-09-19

### Přidáno
- **Aktualizace aplikace z GitHubu (konec ručního přenášení ZIPu).** Přenosná
  kopie (Windows) se umí aktualizovat sama:
  - **V aplikaci** — Správce aktualizací → záložka „Aplikace": „Zkontrolovat
    aktualizaci" porovná lokální verzi s GitHubem, „Stáhnout a nainstalovat
    aktualizaci" stáhne ZIP hlavní větve a přepíše programové soubory
    (zachová `.venv` i nastavení). Běží na pozadí.
  - **`update_windows.bat`** (+ `update_windows.ps1`) — dvojklik mimo běžící
    aplikaci: zjistí verzi a je-li novější, stáhne a přepíše soubory.
  - Vývojová kopie (git) má dál tlačítka git fetch/pull; přenosná kopie ta
    stažení z GitHubu.

## [5.16.6] - 2026-09-19

### Změněno / Opraveno (Správce aktualizací — chytřejší na Windows)
- **ffuf hlásil „chybí", i když je nainstalovaný přes winget.** Detekce nově
  pozná balíček i mimo PATH (přes `winget list`) a označí ho „✅ nainstalováno
  (restartuj app)" — běžící proces má totiž ještě starou PATH.
- **Nástroje bez Windows balíku** (testssl.sh, sslscan, searchsploit) se už
  nenabízejí k instalaci naslepo: stav „— není pro tuto platformu" a neaktivní
  tlačítko „ℹ Nedostupné" s vysvětlením (WSL / ruční instalace).
- **Rozumnější akce u nainstalovaných nástrojů:** místo „Aktualizovat" je
  „↻ Přeinstalovat" s vysvětlením, že winget/brew aktualizuje jen když existuje
  novější verze (jinak nahlásí, že je aktuální).
- Po instalaci se do výstupu vypíše připomínka restartovat aplikaci, aby se
  načetla nová PATH.

## [5.16.5] - 2026-09-19

### Opraveno
- **Světlé téma na Windows → nečitelné prvky.** Aplikace je navržena pro tmavé
  pozadí (macOS dark); na systému ve světlém režimu (typicky Windows) se teď
  **vynutí konzistentní tmavé téma** (Fusion + tmavá paleta), takže vypadá stejně
  a čitelně jako na macOS. Když je systém už tmavý, nechá nativní vzhled.
  Vypnout lze proměnnou `NMAPSCANNER_LIGHT=1`. (`nmapscanner/core/theme.py`)

## [5.16.4] - 2026-09-19

### Změněno / Opraveno
- **Winget instalace přímo z aplikace na Windows** — příkazy dostaly
  `--accept-source-agreements --accept-package-agreements`, aby instalace/aktualizace
  z tlačítka ve Správci aktualizací proběhla neinteraktivně (jen případné UAC).
- **Text hlavičky Správce aktualizací je platformový** — na Windows už nemluví o
  brew/sudo, ale o wingetu a UAC (a připomíná, že Python knihovny řeší
  `install_windows.bat`, ne winget/brew).

## [5.16.3] - 2026-09-19

### Opraveno
- **Správce aktualizací na Windows nabízel `brew`** (fallback), který na Windows
  neexistuje. Nově ukazuje **winget** příkazy: `winget install -e --id
  Insecure.Nmap` / `ffuf.ffuf` / `ZAP.ZAP`; SSLyze přes pip; ostatní odkaz na
  homepage. macOS/Linux beze změny (brew/apt). `README_WINDOWS.txt` doplněn o
  jasné upozornění, že brew na Windows není a používá se winget.

## [5.16.2] - 2026-09-19

### Přidáno
- **Automatické generování portů při každé změně verze.** Nové pravidlo:
  jakmile commit změní `VERSION` v `nmapscanner/__init__.py`, git hook
  (`.githooks/post-commit`) sám přegeneruje přenosné porty pro **Windows i
  macOS**.
  - `make_ports.command` — jednotný build: Windows balík
    (`windows-package/NMAPScannerPTLab-<verze>-Windows.zip`) + macOS
    `NMAPScannerPTLab.app`. Lze spustit i ručně.
  - Hook se aktivuje přes `git config core.hooksPath .githooks` (dělá to
    `install_macos.command`).

## [5.16.1] - 2026-09-19

### Přidáno
- **macOS spouštěče na dvojklik (bez terminálu).**
  - `NMAPScannerPTLab.app` — spouštěcí `.app` (dvojklik ve Finderu, žádný
    terminál); doplní PATH o brew/MacPorts (aby se našel nmap) a spustí aplikaci
    z `.venv`. Generuje ho `make_macos_app.command` (ikona z `assets/icon.png`).
  - `install_macos.command` — vytvoří `.venv`, nainstaluje závislosti a rovnou
    vyrobí `.app`.
  - `run_macos.command` — spuštění z Finderu jako alternativa k `.app`.
  Generovaný `.app` je v `.gitignore` (skript na jeho výrobu je v repu, obdoba
  Windows `build_exe_windows.bat`).

## [5.16.0] - 2026-09-19

### Přidáno
- **Podpora Windows.** Aplikace už na Windows nevyžaduje `sudo` (to je macOS/Linux
  koncept):
  - Na Windows se `sudo` vůbec nepoužívá. Privilegia řeší spuštění „Spustit jako
    správce“. Při startu skenu bez práv správce se zobrazí info a nabídka
    pokračovat v neprivilegovaném režimu.
  - Bez práv správce se SYN sken (`-sS`) automaticky převede na TCP connect
    (`-sT`), který správce nevyžaduje (UDP `-sU` a detekce OS `-O` bez správce
    fungovat nemohou).
  - Tlačítko „Zapomenout sudo heslo“ je na Windows skryté.
- **`build_exe_windows.bat`** — skript, který aplikaci na Windows zabalí
  PyInstallerem do samostatného `.exe` (`dist\NMAPScannerPTLab\`), včetně assetů,
  klasifikační databáze a složky `wordlists` vedle exe. Zmražený běh navíc
  nastaví pracovní adresář vedle `.exe` a přeskočí auto-update.

## [5.15.2] - 2026-06-12

### Opraveno
- **Ověření Vulners klíče vracelo HTTP 403.** Vulners v3/v4 vyžaduje API klíč
  v hlavičce `X-Api-Key` a metodu POST — původní volání posílalo `apiKey` v URL
  přes GET, což API odmítá. Ověření nyní volá POST `…/api/v3/search/lucene/`
  s hlavičkou `X-Api-Key` a hlásí konkrétní příčinu (401/403/429/síť).
- **Vyhledávání CVE dle verze přes Vulners** převedeno na správný endpoint
  `POST …/api/v4/audit/software` (CPE + `X-Api-Key`), s odolným parsováním CVSS.

## [5.15.1] - 2026-06-12

### Přidáno
- **Kopírování API klíčů do schránky** ve Správci knihovny klasifikací —
  tlačítko „⧉ Kopírovat" u pole NVD i Vulners klíče (pole jsou maskovaná
  heslem, takže ruční výběr nešel). Po zkopírování krátké potvrzení v tooltipu.

## [5.15.0] - 2026-06-12

### Přidáno
- **Soft-lock nad projektovou složkou.** Při otevření projektu, který právě
  (nebo nedávno) používá někdo jiný z jiného místa, se zobrazí **varování**
  s identitou druhého uživatele (uživatel@stroj, PID, čas poslední aktivity).
  Nejde o tvrdé zamčení — práci to nezablokuje, jen upozorní na riziko
  souběžných úprav, které se mohou přepsat.
  - Do složky se zapisuje malý soubor `.nmapproj.lock` s identitou a časem.
  - **Heartbeat** každých 60 s značí aktivitu; po výpadku/pádu zámek do 3 minut
    „zestárne" a přestane varovat (považuje se za opuštěný).
  - Zámek se uvolní při přepnutí projektu i při zavření aplikace; cizí zámek se
    nikdy nepřepíše ani nemaže. Vše best-effort (I/O chyba nikdy nezablokuje práci).

## [5.14.3] - 2026-06-12

### Přidáno
- **Ověření Vulners API klíče** ve Správci knihovny klasifikací — stejně jako u
  NVD: indikátor stavu (○ nezadán / ● neověřeno / ✅ platný / ❌ neplatný) a
  tlačítko **Otestovat** (ověří klíč reálným dotazem na Vulners, na pozadí).

### Změněno
- **Dotaz na uložení API klíčů při zavírání Správce knihovny** se zobrazí jen
  když opravdu došlo ke změně klíče (NVD/Vulners) — bez změn se okno zavře bez
  ptaní. Funguje pro Zavřít, Esc i křížek; chrání před ztrátou napsaného klíče.

## [5.14.2] - 2026-06-12

### Opraveno
- **Sloupec „Doporučení" ve Správci knihovny klasifikací se ořezával na 90 znaků**
  — i po rozšíření okna nebyl vidět celý text. Nově se zobrazuje plné doporučení
  se zalamováním, plný text je i v tooltipu a sloupec „Klíč / pravidlo" je ručně
  zúžitelný (nežere šířku).

### Změněno
- **Souhrn počtu klasifikací** je přehlednější: celkový počet pravidel, počet
  oblastí a rozpad podle závažnosti (CRITICAL/HIGH/MEDIUM/LOW/INFO).

## [5.14.1] - 2026-06-12

### Přidáno
- **Indikátor platnosti NVD API klíče** ve Správci knihovny klasifikací. Vedle
  pole pro klíč je stav (○ nezadán / ● neověřeno / ✅ platný / ❌ neplatný) a
  tlačítko **Otestovat**, které klíč ověří reálným dotazem na NVD (na pozadí,
  nemrazí UI). Detail výsledku je v tooltipu i hlášce.

## [5.14.0] - 2026-06-12

### Přidáno
- **Klasifikace zranitelností podle verze služby (real-time z internetu).** Při
  obohacení se pro každou detekovanou službu (produkt + verze) vyhledají známá
  CVE i bez nmap vuln skriptu:
  - **NVD CPE match** — přesná shoda verze přes CPE 2.3 (mapa ~35 produktů:
    nginx, Apache, Tomcat, OpenSSH, OpenSSL, MySQL/MariaDB, PHP, WordPress…),
    bez klíče (rychlejší s NVD klíčem).
  - **Vulners** (volitelně, vyžaduje API klíč) — doplňkový zdroj jako fallback.
  - Nálezy jdou do nové oblasti **„Známé CVE dle verze"** (OWASP A06 — zranitelné
    a zastaralé komponenty), s CVSS, popisem, odkazem na NVD a — díky 5.13.5 —
    štítky existence exploitu (CISA KEV / EPSS) a navýšením závažnosti.
  - Zapínatelné ve Správci knihovny klasifikací; výsledky cachované (TTL 3 dny),
    omezené na top 12 CVE/službu dle CVSS (bez tichého ořezu — počet se loguje).
- **Vulners API klíč** v nastavení (vedle NVD klíče), ukládá se lokálně mimo git.

## [5.13.8] - 2026-06-12

### Přidáno
- **Automatické obohacení po skenu** (volitelné, přepínač ve Správci knihovny
  klasifikací). Po dokončení skenu aplikace sama stáhne CVE z NVD, zjistí
  End-of-Life software a existenci exploitů pro nalezené cíle. Běží na pozadí,
  výchozí stav vypnuto.

## [5.13.7] - 2026-06-12

### Přidáno
- **Správce aktualizací** (nové tlačítko ⬆️ v toolbaru) — tři záložky:
  - **Nástroje** — detekce nainstalované verze nmap, ffuf, OWASP ZAP,
    testssl.sh, sslscan, SSLyze a searchsploit (ExploitDB) + tlačítko
    Instalovat/Aktualizovat (brew/apt/pip dle platformy) s živým výstupem,
    nebo zkopírování příkazu. Nic se nespouští automaticky.
  - **Datové zdroje** — obnova online cache klasifikace: stažení aktuálního
    katalogu CISA KEV a vyprázdnění cache EOL / NVD / EPSS (nové zranitelnosti
    a konce podpory se tak natáhnou čerstvé při dalším obohacení).
  - **Aplikace & knihovna** — kontrola novější verze aplikace i referenční
    knihovny klasifikací přes git (fetch/pull) a počet pravidel knihovny.

## [5.13.6] - 2026-06-12

### Přidáno
- **Vyžádání NVD API klíče, když chybí.** Při prvním obohacení bez nastaveného
  klíče se zobrazí jednorázový dialog s odkazem na bezplatnou registraci a
  možností „Uložit a pokračovat" nebo „Pokračovat bez klíče" + „Příště se neptat".
  Klíč se ukládá persistentně jen lokálně na daném PC (QSettings →
  `~/Library/Preferences` na macOS), nikdy se nezapisuje do projektu ani do gitu.

## [5.13.5] - 2026-06-12

### Přidáno
- **Detekce existujících exploitů u nálezů.** Obohacení nově u každého CVE zjistí,
  zda pro něj existuje exploit — aplikace ho nikdy nepoužívá, jen informuje:
  - **CISA KEV** — je-li CVE v katalogu aktivně zneužívaných zranitelností,
    nález dostane štítek „🔴 AKTIVNĚ ZNEUŽÍVÁNO (CISA KEV)" a závažnost se zvedne
    min. na HIGH (u ransomware kampaní na CRITICAL).
  - **EPSS** (FIRST) — pravděpodobnost zneužití v dalších 30 dnech; u nálezu se
    zobrazí % a percentil.
  - **ExploitDB** přes lokální `searchsploit` (je-li nainstalován) — počet
    dostupných exploitů. Volitelné, degraduje bez nástroje.
  - Veřejný exploit / vysoká EPSS → štítek „🟠 EXPLOIT K DISPOZICI" a navýšení
    závažnosti na HIGH; doporučení dostane prefix „PRIORITNĚ opravit".
  - Vše cachované v `~/.nmapscanner/` (KEV 1 den, EPSS 3 dny), síť degraduje při výpadku.

## [5.13.4] - 2026-06-11

### Přidáno
- **NVD API klíč v nastavení** (správce knihovny klasifikací). Volitelné pole
  pro NVD API klíč — s klíčem je obohacení CVE z NVD rychlejší a bez rate-limitu.
  Ukládá se do nastavení a používá při obohacování. Bez klíče funguje také
  (pomaleji).

## [5.13.3] - 2026-06-11

### Změněno
- **Rozšířené EOL mapování (82 produktů).** Detekce konce podpory pokrývá nově
  výrazně víc produktů: Apache HTTP Server, Tomcat, Caddy, Traefik, HAProxy,
  Squid, MariaDB/MySQL/PostgreSQL/MongoDB/Redis/Memcached, Elasticsearch/Kibana,
  RabbitMQ/Kafka/ActiveMQ/ZooKeeper, MSSQL, PHP/Node.js/Python/Ruby/Perl,
  WordPress/Drupal/Joomla/TYPO3/Magento/Moodle/Nextcloud/phpMyAdmin, Grafana,
  Keycloak, Jenkins, GitLab, Confluence/Jira, ColdFusion, F5 BIG-IP, PAN-OS,
  FortiOS, Windows Server, Ubuntu/Debian/CentOS/RHEL, Docker, Kubernetes ad.
  Mapování bere nejspecifičtější shodu (phpMyAdmin ≠ PHP). Jen slugy ověřené na
  endoflife.date.

## [5.13.2] - 2026-06-11

### Změněno
- **Sjednocené generování reportu — jedno tlačítko, výběr formátů.** Místo dvou
  tlačítek je teď v dialogu **„Formát: ☑ PDF ☑ DOCX"** (oba zaškrtnuté defaultně)
  a jedno tlačítko **„Vytvořit report"**. Obsah a všechny volby jsou **sdílené**
  (DOCX nikdy nebude jiný než PDF) — vygeneruje se vybraný formát/formáty naráz,
  oba se zaregistrují do manažeru reportů.

## [5.13.1] - 2026-06-11

### Přidáno
- **Report do Wordu (.docx) vedle PDF.** V dialogu reportu nové tlačítko
  **„📝 Vytvořit DOCX"** — stejný obsah a struktura jako PDF (titulka, Executive
  summary s barevnými počty, metodika OWASP/CVSS, cíle, nástroje, nálezy dle typu
  testu → cíl → závažnost s barevnými buňkami rizika, detail HIGH/CRITICAL s
  dopadem/doporučením/komentářem, shrnutí/závěr), hlavička s názvem laboratoře a
  patička „SENSITIVE DATA" + čísla stran. Technický i manažerský, CZ/EN. Per-nález
  úpravy se promítají i do DOCX. Soubor se registruje do manažeru reportů.
  `core/report_docx.py` (python-docx).

## [5.13.0] - 2026-06-11

### Přidáno
- **Obohacení klasifikace z internetu (CVE z NVD + End-of-Life).** Nová kontextová
  akce nad cíli **„🌐 Obohatit z internetu (CVE z NVD + EOL)"**:
  - **NVD** — pro nalezené CVE (z nmap vuln i ZAP) stáhne **CVSS skóre** a podle
    něj nastaví závažnost (přesněji než heuristika) + popis.
  - **End-of-Life** — pro detekované produkty+verze (nmap `-sV`) zjistí přes
    endoflife.date, zda je **verze po konci podpory**; neudržovaný software se
    klasifikuje jako kritický nález (A03 Supply Chain — žádné bezpečnostní opravy).
    Mapování běžných produktů (nginx, Apache, OpenSSH, PHP, MySQL, Tomcat, …).
  - Výsledky se ukládají do projektu (`scan_results['enrichment']`) a **cachují**
    do `~/.nmapscanner/` (CVE natrvalo, EOL s TTL 14 dní). Síť běží na pozadí
    s progresem; offline degraduje. `core/enrichment.py`, `workers/enrichment.py`,
    pokryto `tests/test_enrichment.py`.
  - Nová oblast nálezů **„Konec podpory (EOL)"** v reportu i panelu; EOL pravidlo
    (severity/OWASP/doporučení/dopad) je editovatelné v knihovně.

## [5.12.7] - 2026-06-11

### Změněno
- **Barvy závažnosti dle zadání:** CRITICAL = fialová, HIGH = červená,
  MEDIUM = tmavě žlutá, LOW = zelená, INFO = modrá. Promítá se do PDF reportu,
  panelu Souhrn IP i správce knihovny (centrální `SEVERITY_COLOR`).

## [5.12.6] - 2026-06-11

### Opraveno
- **Nečitelné názvy kategorií ve správci knihovny v tmavém režimu** (tmavá na tmavém).
  Nadpisy kategorií jsou nově v akcentní červené se zvýrazněným pozadím — čitelné
  v tmavém i světlém režimu.

### Přidáno
- **Správce knihovny ukazuje VŠECHNA pravidla (91).** Dříve chyběly kategorie
  **Služby (klíčová slova)** a **Cesty/soubory (ffuf)** — byly interně seznamy a
  nešly editovat. Převedeny na editovatelné záznamy; nyní je v manažeru 7 kategorií
  (Porty 35, Služby 12, TLS známky 4, Hlavičky 6, Certifikáty 3, ffuf 27, CVE 4).
  Záhlaví ukazuje celkový počet.
- **Přidávání vlastních pravidel** ve správci (tlačítko **➕ Přidat pravidlo**) —
  výběr kategorie + klíč (port/služba/hlavička/cesta/CVE/…) a editace severity,
  OWASP, doporučení a dopadu (CZ/EN). Ukládá se do uživatelské knihovny.

## [5.12.5] - 2026-06-11

### Přidáno
- **Kontextová akce „🔎 Reklasifikovat nálezy" nad cíli v matici.** Bez nového
  skenu znovu klasifikuje vybrané cíle dle aktuální knihovny (po její editaci ve
  správci) a překreslí panel Souhrn IP. Funguje i pro **již dokončené běhy**
  (klasifikace je odvozená z dat běhu), takže lze reklasifikovat i staré výsledky.
  Hláška ukáže počty nálezů (CRITICAL/HIGH).

## [5.12.4] - 2026-06-11

### Přidáno
- **Klikací CVE odkazy (NVD + MITRE).** Nálezy obsahující CVE (z nmap vuln skriptů
  i ZAP) mají v PDF reportu i v editačním dialogu nálezu klikací odkazy na
  detail NVD (`nvd.nist.gov/vuln/detail/…`) a MITRE (`cve.org/CVERecord`).

## [5.12.3] - 2026-06-11

### Změněno
- **Organizace nálezů v technickém reportu dle typu testu → cíl → závažnost.**
  Hlavní část „5. Výsledky testů" je nově členěná na podsekce dle druhu testu
  (5.1 Otevřené porty, 5.2 Identifikace služeb, 5.3 Zranitelnosti, 5.4 TLS audit,
  5.5 Hlavičky, 5.6 ffuf, 5.7 Webserver, ZAP), uvnitř dle cíle (IP) a seřazené
  dle závažnosti; u každého typu testu jsou detailní karty HIGH/CRITICAL nálezů.
  Obsah (TOC) tyto podsekce automaticky zahrnuje.

## [5.12.2] - 2026-06-11

### Přidáno
- **Tlačítko „📚 Správce knihovny klasifikací" v hlavní liště.** Penetrační testeři
  mají přímý přístup k prohlížení a editaci pravidel knihovny (severity / OWASP /
  doporučení / dopad pro porty, TLS, hlavičky, certifikáty, CVE). Po editaci se
  překreslí klasifikace v panelu Souhrn IP.

## [5.12.1] - 2026-06-11

### Přidáno
- **Per-nález úpravy přímo v dialogu reportu.** Záložka s nálezy je teď plnohodnotný
  editor — **dvojklik na nález** otevře úpravu závažnosti, OWASP, názvu, **dopadu,
  doporučení a komentáře** pro daný report (uloží se jako override do projektu a
  projeví se v PDF). Tabulka ukazuje závažnost (barevně) i OWASP a reflektuje
  úpravy; komentář lze psát i přímo do sloupce. Tlačítko **⚙ Správce knihovny**
  otevře globální editaci pravidel. Overrides se při ukládání konfigurace
  zachovávají (nepřepíšou se).

## [5.12.0] - 2026-06-11

### Přidáno
- **Klasifikované nálezy přímo v panelu „Souhrn vybrané IP".** Po kliknutí na cíl
  v matici se automaticky z referenční knihovny vyhodnotí nálezy přiřazené k tomu
  cíli (porty, služby, TLS, hlavičky, ffuf, zranitelnosti, ZAP) — sekce
  **„🔎 Nálezy (klasifikace)"** se severitou, OWASP a CVSS pásmem; v tooltipu dopad
  a doporučení.
- **Editace nálezu pro daný případ + proklik na správce.** Dvojklik na nález
  otevře dialog, kde lze pro tento případ upravit závažnost, OWASP, název,
  **dopad, doporučení a komentář** (uloží se do projektu jako override a promítne
  se i do PDF reportu), nebo otevřít **globální správce knihovny**.
- **Správce knihovny klasifikací** (`dialogs/classification.py`) — prohlížení a
  editace pravidel (porty / TLS známky / hlavičky / certifikáty / CVE): severita,
  OWASP, doporučení a dopad (CZ/EN). Změny se ukládají do uživatelské knihovny
  (`~/.nmapscanner/classification_library.json`), reset na výchozí.
- Per-případ úpravy (`report_config.overrides`) se aplikují v panelu IP i v reportu.

## [5.11.1] - 2026-06-11

### Přidáno
- **Dopady (impact) v knihovně klasifikací.** Každý nález má nově i **dopad** —
  generický dle závažnosti (`impact_by_severity` v knihovně, editovatelné) +
  konkrétní dopady u klíčových pravidel (Telnet, SMB, Docker API, DB, Redis,
  .git/.env, slabé TLS, chybějící HSTS, Log4Shell). Zobrazuje se v kartě nálezu
  v PDF reportu (sekce „Dopad").

## [5.11.0] - 2026-06-11

### Přidáno
- **Referenční knihovna klasifikací.** Severity, OWASP kategorie a hlavně
  **doporučení** pro nálezy nově pocházejí z editovatelné knihovny pravidel:
  `nmapscanner/data/classification_library.json` (výchozí, verzovaná v repu) +
  uživatelské override `~/.nmapscanner/classification_library.json`
  (deep-merge, uživatel vyhrává). Loader `core/classification_library.py`.
  - Pokrývá: **otevřené porty** (Telnet/SMB/DB/RDP/VNC/Redis/Mongo/… s konkrétními
    doporučeními a vazbou na VPN/expozici), **identifikaci služeb**, **TLS známky
    A/B/C/F** (vč. odkazu na Mozilla SSL config a doporučených cipher suites),
    **certifikáty**, **bezpečnostní hlavičky** (doporučené hodnoty dle OWASP
    Secure Headers — HSTS/CSP/X-Frame-Options/…), **ffuf cesty/kódy** (.git/.env/
    zálohy/default loginy/admin/RDWeb/actuator/…), **CVE mapu** (Log4Shell,
    EternalBlue, BlueKeep, Heartbleed) + klikací odkazy na NVD/MITRE.
  - Zdroje: OWASP Top 10:2025, OWASP Secure Headers, Mozilla Server Side TLS,
    NVD/CVSS v4.0. Pokryto v `tests/test_classification_library.py`.
- Klasifikátor `report_classify` nově čerpá severity/OWASP/doporučení z knihovny;
  z nmap/ZAP výstupů se vytahuje CVE ID a podle něj klasifikuje + přidá odkaz NVD.

> Navazuje: správce knihovny v appce, per-nález override v dialogu, organizace
> nálezů dle typu testu (v dalších verzích).

## [5.10.2] - 2026-06-11

### Opraveno
- **Komentáře a texty v dialogu reportu se nepamatovaly.** Konfigurace (typ,
  jazyk, sekce, volby, metadata, **volné texty i komentáře k nálezům**) se
  ukládala jen při generování/náhledu PDF — když uživatel napsal komentáře a
  zavřel dialog bez generování, ztratily se. Nově se **ukládá do projektu i při
  zavření dialogu** (signál `finished`).
- **Komentáře přežijí re-scan.** Klíč komentáře už nezávisí na pořadovém `id`
  nálezu (F-001…), ale na obsahu (cíl + oblast + OWASP + název), takže se
  po opětovném skenu znovu napárují na správný nález.
- **Přepnutí záložky nezahodí rozepsané komentáře** a záložka „Komentáře" se při
  přepnutí vždy naplní aktuálními nálezy.

## [5.10.1] - 2026-06-11

### Změněno
- **Výrazná hlavička a patička reportu ve stylu webu laboratoře.** Místo strohého
  textu na bílé jsou teď **tmavě navy pruhy** (`#00102E` z webu PT Lab) s červeným
  akcentem, bílým textem a čistou značkou PT Lab (kruh). Hlavička: značka + název
  a adresa laboratoře + „N stran"; patička: „CITLIVÁ DATA / SENSITIVE DATA" +
  čísla stran. Titulka zbavena nadbytečného červeného proužku (akcent dělá pruh).

## [5.10.0] - 2026-06-11

### Změněno
- **Moderní redesign PDF reportu.** Bezpatkové písmo, výraznější titulní strana
  (červený akcent PT Lab, výrazný klient/rozsah, „DŮVĚRNÉ / CONFIDENTIAL"
  razítko), nadpisy s červeným akcentem. Hlavička/patička v bezpatkovém fontu.

### Přidáno
- **Generovaný obsah (TOC) s čísly stran.** Stránka „Obsah" za titulkou
  s číslovanými kapitolami/podkapitolami, tečkovými leadery a čísly stran.
  Dvouprůchodově: vyrenderuje se tělo, z textu stran se dohledají strany kapitol
  (odolné vůči ligaturám přes NFKC), vygeneruje se Obsah a vloží za titulku.
- **Executive summary box** na začátku — verdikt podle nejvyšší závažnosti
  a velké barevné počty CRITICAL/HIGH/MEDIUM/LOW/INFO.
- **Nálezy jako kombinace** — souhrnná tabulka per IP + **karty pro HIGH/CRITICAL**
  (barevný pruh dle závažnosti, chipy OWASP/CWE, důkaz, doporučení, komentář).
- **Nové přepínače v dialogu reportu** (Executive summary, Obsah/TOC) — obsah
  reportu je plně ovladatelný z dialogu.

## [5.9.3] - 2026-06-11

### Opraveno
- **Rozbitá hlavička/patička v PDF reportu.** Opakující se hlavička (logo +
  adresa) se přes `position: fixed` v QtWebEngine renderovala nespolehlivě —
  na titulce chyběla, na dalších stranách **překrývala text**; navíc `printToPdf`
  ignoroval CSS okraje a sázel obsah až ke kraji. Nově:
  - okraje se nastavují přes **QPageLayout** (QtWebEngine ignoruje CSS `@page
    margin`), takže obsah respektuje okraje;
  - hlavička (**logo PT Lab + adresa laboratoře + „N stran"**) a patička
    (**„CITLIVÁ DATA / SENSITIVE DATA" + čísla stran „i / N"**) se dokreslují
    **post-processingem** (`core/report_pdf.py`, reportlab + pypdf) identicky na
    každou stranu — včetně titulky a se správnou diakritikou (registrace serif
    TTF fontu, macOS i Linux).
- Nové závislosti `reportlab` a `pypdf` v `requirements.txt` (auto-instalace při
  aktualizaci).

## [5.9.2] - 2026-06-11

### Přidáno
- **Všechny exporty se evidují v manažeru reportů.** Dílčí exporty se nově po
  uložení zapisují do projektového registru a objeví se v manažeru 🗂 seskupené
  dle zdroje: **ffuf** (TXT/JSON), **certifikáty** (CSV/TXT), **TLS** (PDF),
  **bezpečnostní hlavičky** (PDF), **zranitelnosti** (Word), **porty/služby/
  hostnames** (TXT) a **OWASP ZAP** (nové tlačítko „Uložit alerty (JSON)").
  Registr drží absolutní cestu, takže funguje i pro soubory uložené mimo
  složku `reports/`.

## [5.9.1] - 2026-06-11

### Přidáno
- **Manažer reportů (tlačítko 🗂).** Nové okno s přehledem všech reportů
  vytvořených v projektu, **seskupené podle zdroje** (Souhrnné PDF, ffuf, TLS,
  certifikáty, hlavičky, Word, OWASP ZAP …). Umožní report otevřít, ukázat ve
  složce nebo smazat; chybějící soubory se z evidence automaticky proberou.

## [5.9.0] - 2026-06-11

### Přidáno
- **Report: výběr typu (technický / manažerský) a jazyka (CZ / EN).** Dialog má
  nově záložky **Report / Texty / Komentáře**. Manažerský report vynechá
  technikálie (jen metodiky, cíle, souhrnná tabulka nálezů + počty INFO/LOW/
  MEDIUM/HIGH/CRITICAL a souhrnné doporučení).
- **Editovatelná předgenerovaná pole.** Úvod/omezení, rozsah/náplň, shrnutí,
  závěr a souhrnné doporučení jsou předvyplněné generovaným textem a dají se
  přepsat; metadata (název, projekt, klient, autoři, zaměření); volitelné
  **komentáře k jednotlivým nálezům** (tabulka). Vše se ukládá do projektu
  (`scan_results['report_config']`) a obnoví při dalším otevření.
- **Sekce „Použité nástroje" s verzemi** — automatická detekce verzí (nmap, ffuf,
  sslscan, SSLyze, OpenSSL, OWASP ZAP, …) v `core/report_tools.py`.
- **Registr reportů v projektu** (`core/report_store.py`) — vytvořené PDF se
  ukládají do projektové složky `reports/` s timestampovaným názvem a zapisují
  do `manifest.json` (základ pro manažer reportů).

## [5.8.2] - 2026-06-11

### Přidáno
- **ffuf běží na pozadí.** Okno Directory Fuzzing je nově **nemodální** — během
  skenování můžeš normálně používat aplikaci a dělat jiné testy. Tlačítko
  **„⬇ Na pozadí"** okno skryje a skeny běží dál; znovu ho otevřeš tlačítkem
  ffuf (📂) v liště (vynese stávající okno dopředu). Při zavření okna během
  skenu se appka zeptá: *nechat běžet na pozadí / zastavit a zavřít / zrušit*.
  Výsledky se průběžně synchronizují do projektu (autosave) i při běhu na pozadí;
  při ukončení aplikace se skeny korektně zastaví.

## [5.8.1] - 2026-06-11

### Přidáno
- **ffuf: zrušení jednotlivého skenu + zbývající requesty a čas.** Každý řádek
  průběhu má nově tlačítko **✕** pro zrušení právě tohoto cíle (ostatní paralelní
  skeny běží dál; uvolněný slot zabere další cíl z fronty). V řádku navíc přibyl
  údaj **„zbývá N req"** a přesnější ETA — užitečné, když je cíl pomalý/filtrovaný
  (např. 2 req/s a 1000 h do konce → vidíš to a sken zrušíš).
- **Kontextová akce „Otevřít v prohlížeči" nad cíli — rozšířená.** Pravý klik na
  cíl v matici → podnabídka se **všemi otevřenými porty**; u jednoznačných se
  nabídne HTTP/HTTPS dle služby, u neznámých portů obě varianty (http i https),
  ať lze zkusit web na libovolném portu. Otevírá se v systémovém prohlížeči.

## [5.8.0] - 2026-06-11

### Změněno
- **PDF report přepracován do oficiálního stylu PT Lab** (dle reálného reportu
  laboratoře): bílé pozadí, patkové písmo, opakující se hlavička s logem PT Lab
  a adresou laboratoře na každé straně, červená patička „CITLIVÁ DATA / SENSITIVE
  DATA", modré hlavičky tabulek a barevně kódované buňky rizika. Obsahuje úvod,
  rozepsané OWASP Top 10:2025, barevnou stupnici INFO/LOW/MEDIUM/HIGH/CRITICAL
  (pásma CVSS v4.0), soupis cílů, použité nástroje, hlavní část nálezů per IP
  (tabulky IP|Porty|Služba|Zranitelnost|Riziko) + doporučení, souhrn a závěr.
  Dvojjazyčně (CZ/EN). `core/report_html.py` (technický report; manažerská
  varianta a editovatelná pole přijdou v navazujících verzích).

## [5.7.2] - 2026-06-10

### Přidáno (základy pro nové reporty)
- **Dvojjazyčný klasifikátor nálezů (CZ/EN).** `core/report_classify.py` nově
  generuje tituly, popisy i doporučení nálezů v češtině i angličtině
  (`build_findings(..., lang="cs"|"en")`). Rizikové tabulky jsou bilingvní.
  Pokryto v `tests/test_report_classify.py` (24 testů).
- **Oficiální logo PT Lab** (`assets/ptlab_logo.png`) staženo z webu laboratoře
  + `core/report_assets.py` pro embed jako data URI (self-contained PDF).
- Barvy stupnice závažnosti sjednoceny do palety PT Lab reportů (INFO/LOW/MEDIUM/
  HIGH/CRITICAL).

> Pozn.: jde o interní základy; nové technické a manažerské PDF reporty ve stylu
> PT Lab přijdou v navazujících verzích.

## [5.7.1] - 2026-06-10

### Opraveno
- **ZAP daemon: API odmítalo požadavky klienta (`host header zap not permitted`).**
  Klient `zapv2` chodí přes proxy s magickým hostem `http://zap/`; původní
  konfigurace `api.addrs.addr.name=127.0.0.1` ho zakázala. Nově povoleno regexem
  (listener je vázán jen na 127.0.0.1, takže zvenčí nedostupné). Ověřeno živě —
  daemon naběhne a API odpoví (verze 2.17.0).
- **ZAP daemon: kolize „home directory already in use" s GUI instancí ZAP.**
  Daemon nově běží ve vlastním `-dir` (dočasný home), takže nekoliduje s otevřeným
  ZAP. Pokryto v `tests/test_zap_runner.py`.

## [5.7.0] - 2026-06-10

### Přidáno
- **Integrace OWASP ZAP — aktivní web sken (tlačítko 🕷️).** Nové podokno spustí
  lokální ZAP daemon (nebo využije běžící), pro vybrané webové cíle proběhne
  **Spider + Active Scan** se sledováním postupu a alerty se zobrazí ve stromu
  seskupené dle rizika (High/Medium/Low/Info). Výsledky se ukládají do
  `scan_results['zap']`, persistují s projektem a **zapojí do PDF reportu**.
  - `core/zap_runner.py` — detekce ZAP binárky (PATH, `/Applications/ZAP.app`,
    snap, `ZAP_PATH`) + sestavení daemon příkazu; pokud ZAP chybí, podokno
    poradí s instalací. `workers/zap.py` — řízení daemonu, spider/ascan polling,
    sběr alertů, korektní zastavení.
  - **Mapování alertů do klasifikace** (`build_zap`): ZAP riziko → INFO/LOW/
    MEDIUM/HIGH, OWASP z tagu alertu (`OWASP_*_A0x`) s fallbackem dle názvu;
    deduplikace dle (název+URL+parametr). Pokryto v `tests/test_report_classify.py`.
  - Python klient `zaproxy` přidán do `requirements.txt` (auto-instalace při
    aktualizaci). Samotný ZAP (Java) se instaluje zvlášť: `brew install --cask zap`.

## [5.6.0] - 2026-06-10

### Přidáno
- **Souhrnný PDF report (tlačítko 📊).** Nové tlačítko v liště akcí vytvoří
  souhrnný report z celého běhu. Dialog umožní vybrat, co zahrnout (defaultně
  vše, co má data): otevřené porty, identifikace služeb, zranitelnosti (nmap),
  TLS audit, bezpečnostní hlavičky, ffuf, webserver. Volby: min. závažnost,
  seskupení (dle závažnosti / oblasti), důkazy, doporučení, metodika, grafy.
  Report se renderuje do PDF přes QtWebEngine ve stylu **PT Lab** (tmavě modré
  záhlaví + červený akcent).
  - **Klasifikace závažnosti INFO/LOW/MEDIUM/HIGH/CRITICAL** zarovnaná na pásma
    **CVSS v4.0** a mapovaná na **OWASP Top 10:2025** (A01–A10). Logika v
    `core/report_classify.py` (bez Qt, pokryto `tests/test_report_classify.py`):
    rizikové porty (Telnet/SMB/DB/RDP/VNC…), zveřejnění verzí, potvrzené nmap
    zranitelnosti (CVE→A03), TLS známka A/B/C/F→A04, chybějící hlavičky→A02,
    citlivé cesty z ffuf (.git/.env/zálohy→A02/A01), detekce webserveru.
  - HTML generátor v `core/report_html.py`; náhled v prohlížeči i přímý export PDF.
- **Kontextová akce „Otevřít v prohlížeči" nad cíli.** Pravý klik na cíl v matici
  „Průběh fází" → výběr webového portu (HTTP/HTTPS) → otevře se v systémovém
  prohlížeči (cross-platform přes `QDesktopServices`).

## [5.5.0] - 2026-06-10

### Přidáno
- **Paralelní directory fuzzing (ffuf).** Okno „Directory Fuzzing" umí skenovat
  více cílů najednou — nový přepínač **Paralelně (1–4)**. Každý běžící cíl má
  **vlastní progress řádek** (procenta, hotovo/celkem, req/sec, ETA) ve scroll
  panelu; jakmile cíl doběhne, uvolněný slot automaticky zabere další z fronty.
  Celkový postup hlídá spodní lišta „Cíle: x/y".
- **Pamatování posledního nastavení skenu (ffuf).** Vybrané slovníky, match
  codes, přípony, „sledovat přesměrování" i počet paralelních skenů se ukládají
  přes `QSettings("UTB","NmapScannerApp")` a obnoví při dalším otevření okna
  (uloží se při spuštění skenu i při zavření okna).

## [5.4.2] - 2026-06-10

### Opraveno
- **Runtime ikona `assets/icon.png` chyběla v repozitáři** — bezpečnostní
  `.gitignore` blokuje všechna `*.png` (screenshoty z testování), takže se
  ikona nedostala do commitu 5.4.1 a na čerstvém klonu by se nezobrazila.
  Přidána úzká výjimka `!assets/icon.png`.

## [5.4.1] - 2026-06-10

### Přidáno
- **Ikona aplikace.** Kombinace radaru a obvodových tras (PCB): červený radarový
  disk s bílými trasami a pady (objevené uzly sítě) na tmavě modrém macOS
  squircle podkladu + terminálová lišta `>_ 22 80 443` (otevřené porty).
  Zdroj `assets/icon.svg`, vyrenderované
  `assets/icon.png` (runtime, všechny OS) a `assets/icon.icns` (macOS bundle).
  Regenerace: `python3 assets/render_icon.py`. Launcher nastavuje
  `setWindowIcon` → ikona v Docku (macOS) i na taskbaru (Linux).

## [5.4.0] - 2026-06-10

### Přidáno
- **Detektor webového serveru (IIS / Apache / nginx / Tomcat / …).** Nová
  kontextová akce v matici „Průběh fází" (pravý klik na cíl → **🌐 Detekovat web
  server**, funguje i pro výběr více cílů). Aktivně stáhne HTTP hlavičky
  (`Server`, `X-Powered-By`, `X-AspNet-Version`) webových portů a zkombinuje je s
  nmap `-sV` detekcí. Výsledek se zobrazí v **souhrnu IP** (sekce „Webový server")
  a **uloží do projektu** (`scan_results['webserver']`, persistuje s verzí).
  - Klasifikace bez Qt (`core/webserver_detect.py`): rozezná IIS, Apache, nginx,
    Tomcat (Apache-Coyote), OpenResty, LiteSpeed, Caddy, Jetty, Kestrel,
    Cloudflare aj. (pokryto `tests/test_webserver_detect.py`).
  - Souhrn IP nově ukazuje web server i **pasivně** (z nmap `product`), i bez
    spuštění aktivní detekce.

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
