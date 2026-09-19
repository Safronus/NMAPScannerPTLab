@echo off
setlocal
cd /d "%~dp0"
REM ====================================================================
REM  Zabaleni NMAP Scanner PT Lab do samostatneho .exe (Windows)
REM  Vysledek: dist\NMAPScannerPTLab\NMAPScannerPTLab.exe  (nevyzaduje Python)
REM
REM  Pouziti:
REM    1) nejprve  install_windows.bat  (vytvori .venv se zavislostmi)
REM    2) pak tento skript
REM  Pozn.: Nmap se stejne instaluje zvlast. Pro plne skeny (SYN/UDP/OS)
REM  spoustej vyslednou aplikaci pres "Spustit jako spravce".
REM ====================================================================

if not exist ".venv\Scripts\python.exe" (
    echo [CHYBA] Chybi .venv - spust nejprve install_windows.bat
    pause
    exit /b 1
)

set "PYW=.venv\Scripts\python.exe"

echo Instaluji PyInstaller ...
"%PYW%" -m pip install --upgrade pyinstaller
if errorlevel 1 (
    echo [CHYBA] Instalace PyInstalleru selhala.
    pause
    exit /b 1
)

REM Ikona pro .exe jen pokud existuje .ico (PyInstaller neumi .png jako ikonu exe)
set "ICON="
if exist "assets\icon.ico" set "ICON=--icon assets\icon.ico"

echo.
echo Sestavuji aplikaci (onedir, muze trvat nekolik minut) ...
"%PYW%" -m PyInstaller --noconfirm --clean ^
  --name "NMAPScannerPTLab" ^
  --windowed ^
  %ICON% ^
  --add-data "assets;assets" ^
  --add-data "nmapscanner\data;nmapscanner\data" ^
  --collect-all PySide6 ^
  --collect-all sslyze ^
  --hidden-import nmap ^
  nmap-scanner.py
if errorlevel 1 (
    echo [CHYBA] Sestaveni selhalo - vypis vyse.
    pause
    exit /b 1
)

REM Wordlists aplikace hleda/uklada vedle .exe (zapisovatelne) -> zkopirovat tam.
echo Kopiruji slozku wordlists vedle .exe ...
xcopy /E /I /Y "wordlists" "dist\NMAPScannerPTLab\wordlists" >nul

echo.
echo ====================================================================
echo  [HOTOVO]
echo  Aplikace: dist\NMAPScannerPTLab\NMAPScannerPTLab.exe
echo  Celou slozku  dist\NMAPScannerPTLab  lze prekopirovat na jine PC
echo  a spoustet bez instalace Pythonu (Nmap je stale potreba zvlast).
echo ====================================================================
pause
