#!/usr/bin/env python3
"""Vyrenderuje assets/icon.svg do PNG sad a macOS .icns.

Použití:  python3 assets/render_icon.py
Vyžaduje: PySide6 (QtSvg) a na macOS `iconutil` (součást systému).
"""
import subprocess
import sys
from pathlib import Path

from PySide6.QtCore import QRectF
from PySide6.QtGui import QGuiApplication, QImage, QPainter, QColor
from PySide6.QtSvg import QSvgRenderer

ASSETS = Path(__file__).resolve().parent
SVG = ASSETS / "icon.svg"

# (název v .iconset, velikost v px)
ICONSET = [
    ("icon_16x16.png", 16), ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32), ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128), ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256), ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512), ("icon_512x512@2x.png", 1024),
]


def render(renderer: QSvgRenderer, size: int, dest: Path) -> None:
    img = QImage(size, size, QImage.Format_ARGB32)
    img.fill(QColor(0, 0, 0, 0))
    painter = QPainter(img)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setRenderHint(QPainter.SmoothPixmapTransform)
    renderer.render(painter, QRectF(0, 0, size, size))
    painter.end()
    img.save(str(dest))


def main() -> int:
    app = QGuiApplication(sys.argv)  # noqa: F841 — QtSvg potřebuje GUI aplikaci
    renderer = QSvgRenderer(str(SVG))
    if not renderer.isValid():
        print(f"CHYBA: nelze načíst {SVG}", file=sys.stderr)
        return 1

    iconset = ASSETS / "icon.iconset"
    iconset.mkdir(exist_ok=True)
    for name, size in ICONSET:
        render(renderer, size, iconset / name)

    # samostatné PNG pro runtime (setWindowIcon) — funguje na všech OS
    render(renderer, 512, ASSETS / "icon.png")

    if sys.platform == "darwin":
        subprocess.run(
            ["iconutil", "-c", "icns", str(iconset), "-o", str(ASSETS / "icon.icns")],
            check=True,
        )
        print(f"OK: {ASSETS / 'icon.icns'}")
    print(f"OK: {ASSETS / 'icon.png'} + {iconset}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
