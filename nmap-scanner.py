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


def _print_banner():
    """Vypíše verzi a ABSOLUTNÍ cestu běžícího kódu — ať je jednoznačné, která
    kopie/verze běží (časté zmatení: spuštění staré kopie mimo git repozitář)."""
    import nmapscanner
    pkg = os.path.dirname(os.path.abspath(nmapscanner.__file__))
    print(f"=== NMAP Scanner PT Lab v{nmapscanner.VERSION} ===")
    print(f"  balík:  {pkg}")
    print(f"  python: {sys.executable}")


def main():
    _startup_checks()
    _print_banner()
    # Pořadí importů je důležité: QtWebEngine (uvnitř nmapscanner.app) se musí
    # naimportovat PŘED vytvořením QApplication.
    from nmapscanner.app import NmapScannerApp
    from PySide6.QtWidgets import QApplication

    app = QApplication(sys.argv)
    window = NmapScannerApp()
    window.showMaximized()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
