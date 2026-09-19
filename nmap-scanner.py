#!/usr/bin/env python3
"""
NMAP Scanner PT Lab - spouštěcí bod aplikace.

Aplikace je rozdělena do balíku ``nmapscanner/`` (refaktor monolitu).
Tento soubor jen provede startovní kontroly a spustí hlavní okno.

Spuštění (z kořene projektu, aby se našly wordlisty v ./wordlists):
    python nmap-scanner.py
"""
import os

# Musí být nastaveno PŘED jakýmkoli importem QtWebEngine (jinak pády Chromia na macOS).
os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu --disable-software-rasterizer")

import sys
import subprocess


def _startup_checks():
    """Ověří dostupnost Python modulu nmap a binárky nmap."""
    try:
        import nmap  # noqa: F401
        print("Python nmap modul OK")
    except ImportError:
        print("CHYBA: Python modul 'nmap' (python-nmap) není nainstalován.")

    try:
        result = subprocess.run(["nmap", "--version"], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout:
            print("Nmap binárka OK:", result.stdout.splitlines()[0])
        else:
            print("Nmap binárka CHYBA")
    except FileNotFoundError:
        print("Nmap binárka CHYBA: 'nmap' nenalezen v PATH")


def _auto_update():
    """Po startu zkusí stáhnout novější verzi z GitHubu (fast-forward), doinstalovat
    závislosti z ``requirements.txt`` a restartovat se na novou verzi — aby člověk
    nezapomněl na ``git pull`` a nespouštěl starý kód.

    Bezpečně přeskočí, když: je vypnuto (``NMAPSCANNER_NO_UPDATE=1``), už proběhl
    restart (ochrana proti smyčce), není to git repo / chybí git, strom je špinavý
    (lokální změny), není síť, nebo se větev rozešla s originem (nelze fast-forward).
    """
    if os.environ.get("NMAPSCANNER_NO_UPDATE") == "1":
        return
    if os.environ.get("NMAPSCANNER_RESTARTED") == "1":
        return  # už jsme se jednou restartovali na novou verzi → neopakovat
    import shutil
    repo = os.path.dirname(os.path.abspath(__file__))
    if not os.path.isdir(os.path.join(repo, ".git")):
        return
    git = shutil.which("git")
    if not git:
        return

    def _git(*args, timeout=25):
        return subprocess.run([git, "-C", repo, *args],
                              capture_output=True, text=True, timeout=timeout)
    try:
        # Špinavý pracovní strom → nehrabat (nepřijít o lokální změny).
        st = _git("status", "--porcelain")
        if st.returncode != 0 or st.stdout.strip():
            return
        if _git("fetch", "--quiet").returncode != 0:
            return  # offline / bez přístupu → tiše přeskočit
        branch = (_git("rev-parse", "--abbrev-ref", "HEAD").stdout or "").strip() or "main"
        local = (_git("rev-parse", "HEAD").stdout or "").strip()
        remote = (_git("rev-parse", f"origin/{branch}").stdout or "").strip()
        if not remote or local == remote:
            return  # aktuální
        base = (_git("merge-base", "HEAD", f"origin/{branch}").stdout or "").strip()
        if base != local:
            print("⚠️  Lokální větev se rozešla s origin — auto-update přeskočen "
                  "(vyřeš ručně: git pull).")
            return
        print(f"⬇️  Na GitHubu je novější verze ({remote[:8]}), aktualizuji…")
        pull = _git("pull", "--ff-only", "--quiet", timeout=90)
        if pull.returncode != 0:
            print("⚠️  git pull selhal:", (pull.stderr or "").strip()[:200])
            return
        # Doinstalovat/aktualizovat závislosti z nové verze (sslyze atd.).
        req = os.path.join(repo, "requirements.txt")
        if os.path.exists(req):
            print("📦  Instaluji/aktualizuji Python závislosti (requirements.txt)…")
            subprocess.run([sys.executable, "-m", "pip", "install", "-q", "-r", req],
                           timeout=600)
        print("🔄  Restartuji aplikaci na novou verzi…\n")
        os.environ["NMAPSCANNER_RESTARTED"] = "1"
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except subprocess.TimeoutExpired:
        print("⚠️  Auto-update přeskočen (časový limit gitu/pip).")
    except Exception as e:
        print(f"⚠️  Auto-update přeskočen: {str(e)[:160]}")


def _print_banner():
    """Vypíše verzi a ABSOLUTNÍ cestu běžícího kódu — ať je jednoznačné, která
    kopie/verze běží (časté zmatení: spuštění staré kopie mimo git repozitář)."""
    import nmapscanner
    pkg = os.path.dirname(os.path.abspath(nmapscanner.__file__))
    print(f"=== NMAP Scanner PT Lab v{nmapscanner.VERSION} ===")
    print(f"  balík:  {pkg}")
    print(f"  python: {sys.executable}")


def main():
    # Zmražený běh (PyInstaller .exe): pracovní adresář nastavit vedle .exe, aby
    # se našla/ukládala složka „wordlists“; auto-update (git) přeskočit.
    if getattr(sys, "frozen", False):
        try:
            os.chdir(os.path.dirname(sys.executable))
        except Exception:
            pass
        os.environ.setdefault("NMAPSCANNER_NO_UPDATE", "1")
    _auto_update()   # případný git pull + doinstalace závislostí + restart na novou verzi
    _startup_checks()
    _print_banner()
    # Pořadí importů je důležité: QtWebEngine (uvnitř nmapscanner.app) se musí
    # naimportovat PŘED vytvořením QApplication.
    from nmapscanner.app import NmapScannerApp
    from PySide6.QtGui import QIcon
    from PySide6.QtWidgets import QApplication

    app = QApplication(sys.argv)
    # Konzistentní tmavý vzhled (na světlém systému, typicky Windows, vynutí tmavé
    # téma — aplikace je navržena pro tmavé pozadí). Vypnout: NMAPSCANNER_LIGHT=1.
    try:
        from nmapscanner.core.theme import apply_theme
        apply_theme(app)
    except Exception:
        pass
    icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "icon.png")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))  # okna + Dock (macOS) / taskbar (Linux)
    window = NmapScannerApp()
    window.showMaximized()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
