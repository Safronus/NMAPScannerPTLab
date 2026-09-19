#!/bin/bash
# Vytvori NMAPScannerPTLab.app - spousteci .app pro macOS (dvojklik, bez terminalu).
# .app spousti aplikaci z ./.venv; koren projektu najde vedle sebe.
set -e
cd "$(dirname "$0")"
ROOT="$(pwd)"
APP="NMAPScannerPTLab.app"
VER="$(grep -oE '"[0-9]+\.[0-9]+\.[0-9]+"' nmapscanner/__init__.py | tr -d '"' | head -1)"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# --- Ikona: assets/icon.png -> app.icns ---
if [ -f assets/icon.png ]; then
  ICONSET="$(mktemp -d)/icon.iconset"; mkdir -p "$ICONSET"
  for s in 16 32 64 128 256 512; do
    sips -z $s $s assets/icon.png --out "$ICONSET/icon_${s}x${s}.png" >/dev/null 2>&1 || true
    d=$((s*2)); sips -z $d $d assets/icon.png --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null 2>&1 || true
  done
  iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/app.icns" 2>/dev/null || true
fi

# --- Spustitelny skript ---
cat > "$APP/Contents/MacOS/launch" <<'LAUNCH'
#!/bin/bash
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
cd "$ROOT" || exit 1
# GUI aplikace z Finderu nededi PATH shellu -> pridat obvykla umisteni nastroju.
export PATH="/opt/homebrew/bin:/usr/local/bin:/opt/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
PY="$ROOT/.venv/bin/python"
if [ ! -x "$PY" ]; then
  osascript -e 'display alert "NMAP Scanner PT Lab" message "Chybi .venv. Spust nejprve install_macos.command."' >/dev/null 2>&1
  exit 1
fi
export NMAPSCANNER_NO_UPDATE=1
exec "$PY" "$ROOT/nmap-scanner.py"
LAUNCH
chmod +x "$APP/Contents/MacOS/launch"

# --- Info.plist ---
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>NMAP Scanner PT Lab</string>
  <key>CFBundleDisplayName</key><string>NMAP Scanner PT Lab</string>
  <key>CFBundleIdentifier</key><string>cz.utb.fai.nmapscannerptlab</string>
  <key>CFBundleVersion</key><string>${VER}</string>
  <key>CFBundleShortVersionString</key><string>${VER}</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleExecutable</key><string>launch</string>
  <key>CFBundleIconFile</key><string>app.icns</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

# Obnovit ikonu v Finderu
touch "$APP"
echo "[HOTOVO] Vytvoreno $APP  (dvojklik = spusteni bez terminalu)."
