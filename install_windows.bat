@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
echo ==================================================
echo   NMAP Scanner PT Lab - instalace (Windows)
echo ==================================================
echo.

REM --- 1) Najit Python (py launcher nebo python) ---
set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY (
    where python >nul 2>nul && set "PY=python"
)
if not defined PY (
    echo [CHYBA] Python nenalezen.
    echo   Nainstaluj Python 3.11+ z https://www.python.org/downloads/windows/
    echo   Pri instalaci ZASKRTNI "Add Python to PATH".
    echo.
    pause
    exit /b 1
)
echo Pouzivam Python:
%PY% --version
echo.

REM --- 2) Vytvorit virtualni prostredi .venv ---
if not exist ".venv\Scripts\python.exe" (
    echo Vytvarim virtualni prostredi .venv ...
    %PY% -m venv .venv
    if errorlevel 1 (
        echo [CHYBA] Nepodarilo se vytvorit .venv
        pause
        exit /b 1
    )
)

REM --- 3) Instalace zavislosti ---
echo Aktualizuji pip ...
".venv\Scripts\python.exe" -m pip install --upgrade pip
echo.
echo Instaluji Python zavislosti (PySide6 je velky, muze to trvat par minut) ...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo [CHYBA] Instalace zavislosti selhala. Zkontroluj pripojeni k internetu.
    pause
    exit /b 1
)

echo.
echo ==================================================
echo   [HOTOVO] Instalace dokoncena.
echo   Aplikaci spustis souborem:  run_windows.bat
echo   (Pro plne skeny spust pres pravy klik - "Spustit jako spravce".)
echo ==================================================
echo.
echo POZOR - krome Pythonu jeste doinstaluj systemove nastroje:
echo   * Nmap (POVINNE)  https://nmap.org/download.html  (nech zaskrtnuty Npcap)
echo   * ffuf (volitelne) https://github.com/ffuf/ffuf/releases
echo   * OWASP ZAP (volitelne) https://www.zaproxy.org/download/  (vyzaduje Javu 17+)
echo   Podrobnosti viz README_WINDOWS.txt
echo.
pause
