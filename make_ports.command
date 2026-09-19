#!/bin/bash
# Vyrobi prenosne PORTY aplikace pro Windows i macOS z aktualniho stavu (git HEAD).
# - Windows: windows-package/NMAPScannerPTLab-<verze>-Windows/  + stejnojmenny .zip
# - macOS:   NMAPScannerPTLab.app  (dvojklik, bez terminalu)
#
# Spousti se rucne (dvojklik / ./make_ports.command), NEBO automaticky pres
# git hook .githooks/post-commit VZDY pri zmene verze aplikace.
set -e
cd "$(dirname "$0")"
ROOT="$(pwd)"
VER="$(grep -oE '"[0-9]+\.[0-9]+\.[0-9]+"' nmapscanner/__init__.py | tr -d '"' | head -1)"
echo "=================================================="
echo "  Generuji porty pro verzi $VER"
echo "=================================================="

# --- Windows port (cisty git archive -> slozka + zip) ---
PKG="NMAPScannerPTLab-${VER}-Windows"
rm -rf windows-package
mkdir -p windows-package
git archive HEAD --prefix="$PKG/" | tar -x -C windows-package
find "windows-package/$PKG" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
( cd windows-package && zip -r -q -X "${PKG}.zip" "$PKG" -x "*/__pycache__/*" -x "*.DS_Store" )
echo "  [Windows] windows-package/${PKG}.zip"

# --- macOS .app ---
if [ -x ./make_macos_app.command ]; then
  ./make_macos_app.command >/dev/null
  echo "  [macOS]   NMAPScannerPTLab.app"
fi

echo "== Hotovo (verze $VER) =="
