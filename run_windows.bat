@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo [CHYBA] Chybi virtualni prostredi .venv
    echo         Spust nejprve:  install_windows.bat
    echo.
    pause
    exit /b 1
)
REM Spustit aplikaci. Bez auto-update (kopie nema git repozitar).
REM TIP: pro plne skeny (SYN/UDP/OS) spust tento soubor pres
REM      pravy klik -> "Spustit jako spravce".
set NMAPSCANNER_NO_UPDATE=1
".venv\Scripts\python.exe" nmap-scanner.py
if errorlevel 1 (
    echo.
    echo [Aplikace skoncila s chybou - vypis vyse.]
    pause
)
