====================================================================
  NMAP Scanner PT Lab  -  spusteni na Windows
====================================================================

Prenosna kopie aplikace. Zkopiruj slozku na Windows PC (napr. pres
USB) a postupuj podle kroku nize.

POUZE PRO AUTORIZOVANE TESTOVANI.

--------------------------------------------------------------------
 RYCHLY START (doporuceno - spusteni ze zdrojaku)
--------------------------------------------------------------------

1) Nainstaluj PYTHON pro Windows (jednorazove)
   - https://www.python.org/downloads/windows/  (verze 3.11+)
   - DULEZITE: pri instalaci ZASKRTNI "Add Python to PATH".

2) Nainstaluj NMAP pro Windows (POVINNE - jadro aplikace)
   - https://nmap.org/download.html
   - Behem instalace nech zaskrtnute i "Npcap".

3) Dvojklik:  install_windows.bat
   - Vytvori .venv a doinstaluje Python knihovny. Muze trvat par minut.

4) Spusteni aplikace:  run_windows.bat
   - PRO PLNE SKENY spust pres pravy klik -> "Spustit jako spravce".
     (SYN -sS, UDP -sU a detekce OS -O vyzaduji spravce + Npcap.)
   - Bez prav spravce aplikace funguje take, ale nmap pouzije
     TCP connect sken (-sT) - pomalejsi, bez UDP/OS.

Priste uz staci jen krok 4.

--------------------------------------------------------------------
 AKTUALIZACE APLIKACE (uz nemusis prenaset ZIP rucne)
--------------------------------------------------------------------
   Dve moznosti, obe stahnou nejnovejsi verzi primo z GitHubu:

   A) Z aplikace: tlacitko Spravce aktualizaci -> zalozka "Aplikace"
      -> "Zkontrolovat aktualizaci" / "Stahnout a nainstalovat
      aktualizaci". Zachova .venv i nastaveni. Po dokonceni appku
      restartuj.

   B) Dvojklik na  update_windows.bat  (mimo bezici aplikaci).
      Zjisti verzi, a je-li novejsi, stahne a prepise soubory.

   Obe varianty nechavaji .venv a tva nastaveni (klice, volby) na
   miste - meni jen programove soubory.

--------------------------------------------------------------------
 OPRAVNENI (Windows) - misto sudo
--------------------------------------------------------------------
   Na Windows se sudo nepouziva. Privilegia se resi spustenim jako
   spravce (pravy klik na run_windows.bat -> "Spustit jako spravce").
   Kdyz spravce neni, aplikace se zepta a muze pokracovat v
   neprivilegovanem rezimu (TCP connect sken).

--------------------------------------------------------------------
 SYSTEMOVE NASTROJE - POZOR: brew NENI pro Windows!
--------------------------------------------------------------------
   Homebrew (brew) funguje jen na macOS/Linux. Na Windows pouzij
   WINGET (je soucasti Windows 10/11) nebo primy instalator.

   Nejrychleji pres winget (v PowerShellu/cmd):
     winget install -e --id Insecure.Nmap     (POVINNE, jadro aplikace)
     winget install -e --id ffuf.ffuf         (volitelne)
     winget install -e --id ZAP.ZAP           (volitelne, vyzaduje Javu 17+)

   Nebo primymi instalatory:
     * Nmap        https://nmap.org/download.html   (nech zaskrtnuty Npcap)
     * ffuf        https://github.com/ffuf/ffuf/releases  (ffuf.exe do PATH)
     * OWASP ZAP   https://www.zaproxy.org/download/  (Java 17+, napr.
                   Eclipse Temurin z https://adoptium.net )
     * testssl / sslscan  - na Windows nejsnaze pres WSL

   POZN.: Python knihovny (PySide6 atd.) NEinstaluje winget ani brew -
   ty resi install_windows.bat pres pip. Detekce verzi a aktualizace
   nastroju je i primo v aplikaci (tlacitko Spravce aktualizaci).

--------------------------------------------------------------------
 API KLICE (volitelne, zrychli obohacovani zranitelnosti)
--------------------------------------------------------------------
   NVD (NIST) a Vulners klice se zadavaji v aplikaci:
   "Spravce knihovny klasifikaci" -> pole dole. Ukladaji se lokalne.

--------------------------------------------------------------------
 SAMOSTATNE .EXE (volitelne, bez Pythonu)
--------------------------------------------------------------------
   Po kroku 3 spust:  build_exe_windows.bat
   Vysledek:  dist\NMAPScannerPTLab\NMAPScannerPTLab.exe
   Celou slozku dist\NMAPScannerPTLab lze prekopirovat a spoustet
   bez Pythonu. Nmap je stale potreba nainstalovat zvlast.
   Pozn.: QtWebEngine (screenshoty webu) je narocny na zabaleni -
   kdyby exe zlobilo, pouzij spolehlivy run_windows.bat.

--------------------------------------------------------------------
 RESENI PROBLEMU
--------------------------------------------------------------------
 * "Python nenalezen" -> preinstaluj Python (Add to PATH) / restart PC.
 * "nmap nenalezen" -> nainstaluj Nmap (krok 2) a restartuj aplikaci.
 * SmartScreen u .bat -> "Dalsi informace" -> "Presto spustit".
 * ZAP hlasi chybejici Javu -> nainstaluj Javu 17+ (Adoptium Temurin).
====================================================================
