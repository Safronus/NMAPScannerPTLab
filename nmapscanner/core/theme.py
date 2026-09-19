"""Konzistentní tmavé téma aplikace.

Aplikace byla navržena pro tmavé pozadí (macOS dark). Na systému ve **světlém**
režimu (typicky Windows) by hardcodované barvy laděné na tmavé pozadí nebyly
čitelné — proto tam vynutíme vlastní tmavé téma (Fusion + tmavá paleta). Když je
systém už tmavý (macOS dark), necháme nativní vzhled.

Vypnout jde proměnnou prostředí ``NMAPSCANNER_LIGHT=1``.
"""

import os

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPalette


def is_dark_scheme(app):
    """True, pokud systém běží v tmavém režimu (nebo to tak vypadá dle palety)."""
    try:
        scheme = app.styleHints().colorScheme()
        if scheme == Qt.ColorScheme.Dark:
            return True
        if scheme == Qt.ColorScheme.Light:
            return False
    except Exception:
        pass
    # Fallback: podle jasu barvy okna ze systémové palety.
    return app.palette().color(QPalette.Window).lightness() <= 128


def _apply_dark_palette(app):
    app.setStyle("Fusion")
    text = QColor(228, 230, 233)
    disabled = QColor(128, 130, 134)
    highlight = QColor(46, 117, 182)   # PT Lab modrá akcent
    p = QPalette()
    p.setColor(QPalette.Window, QColor(32, 34, 38))
    p.setColor(QPalette.WindowText, text)
    p.setColor(QPalette.Base, QColor(24, 26, 29))
    p.setColor(QPalette.AlternateBase, QColor(40, 42, 47))
    p.setColor(QPalette.ToolTipBase, QColor(42, 44, 49))
    p.setColor(QPalette.ToolTipText, text)
    p.setColor(QPalette.Text, text)
    p.setColor(QPalette.Button, QColor(46, 48, 53))
    p.setColor(QPalette.ButtonText, text)
    p.setColor(QPalette.BrightText, QColor(231, 76, 60))
    p.setColor(QPalette.Link, highlight)
    p.setColor(QPalette.Highlight, highlight)
    p.setColor(QPalette.HighlightedText, Qt.white)
    try:
        p.setColor(QPalette.PlaceholderText, disabled)
    except Exception:
        pass
    for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
        p.setColor(QPalette.Disabled, role, disabled)
    p.setColor(QPalette.Disabled, QPalette.Highlight, QColor(60, 62, 66))
    p.setColor(QPalette.Disabled, QPalette.HighlightedText, disabled)
    app.setPalette(p)
    # Tooltipy a orámování polí čitelné na tmavém základu.
    app.setStyleSheet((app.styleSheet() or "") + """
        QToolTip { color:#E4E6E9; background-color:#2A2C31; border:1px solid #4A4C51; }
    """)


def apply_theme(app):
    """Zajistí čitelný tmavý vzhled na všech platformách. Volat po vytvoření
    QApplication a před oknem. Na tmavém systému nechá nativní vzhled."""
    if os.environ.get("NMAPSCANNER_LIGHT") == "1":
        return
    if not is_dark_scheme(app):
        _apply_dark_palette(app)
