"""NMAP Scanner PT Lab - modularni balik (refaktor monolitu)."""
import os
# Musi byt nastaveno PRED importem QtWebEngine kdekoli v baliku.
os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu --disable-software-rasterizer")

VERSION = "5.7.0"
