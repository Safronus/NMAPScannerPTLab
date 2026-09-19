#!/bin/bash
# Spusteni aplikace na macOS (dvojklik v Finderu). Alternativa k NMAPScannerPTLab.app.
cd "$(dirname "$0")" || exit 1
if [ ! -x ".venv/bin/python" ]; then
  echo "[CHYBA] Chybi .venv - spust nejprve install_macos.command"
  read -n1 -r -p "Stiskni klavesu pro zavreni..."; exit 1
fi
export PATH="/opt/homebrew/bin:/usr/local/bin:/opt/local/bin:$PATH"
export NMAPSCANNER_NO_UPDATE=1
exec ./.venv/bin/python nmap-scanner.py
