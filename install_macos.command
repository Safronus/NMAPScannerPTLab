#!/bin/bash
# Instalace na macOS: vytvori .venv a nainstaluje Python zavislosti. Dvojklik v Finderu.
cd "$(dirname "$0")" || exit 1
echo "=================================================="
echo "  NMAP Scanner PT Lab - instalace (macOS)"
echo "=================================================="
if ! command -v python3 >/dev/null 2>&1; then
  echo "[CHYBA] python3 nenalezen. Nainstaluj Python 3.11+ (python.org, brew install python,"
  echo "        nebo sudo port install python312)."
  read -n1 -r -p "Stiskni klavesu pro zavreni..."; exit 1
fi
echo "Python: $(python3 --version)"
echo "Vytvarim .venv a instaluji zavislosti (PySide6 je velky, chvili to trva)..."
python3 -m venv .venv || { echo "[CHYBA] venv"; read -n1 -r -p "..."; exit 1; }
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install -r requirements.txt || { echo "[CHYBA] zavislosti"; read -n1 -r -p "..."; exit 1; }
# Aktivovat git hook: pri zmene verze se automaticky pregeneruji porty (Win + macOS)
git rev-parse --git-dir >/dev/null 2>&1 && git config core.hooksPath .githooks 2>/dev/null
# Vyrobit spousteci .app (dvojklik bez terminalu)
[ -x ./make_macos_app.command ] && ./make_macos_app.command
echo ""
echo "[HOTOVO] Spustit aplikaci: dvojklik na  NMAPScannerPTLab.app"
echo "         (nebo run_macos.command)"
echo "POZOR: nmap nainstaluj zvlast:  brew install nmap   (nebo: sudo port install nmap)"
read -n1 -r -p "Stiskni klavesu pro zavreni..."
