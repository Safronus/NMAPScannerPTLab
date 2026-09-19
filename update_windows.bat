@echo off
REM Aktualizace aplikace z GitHubu (dvojklik). Zavri nejdriv bezici aplikaci.
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0update_windows.ps1"
