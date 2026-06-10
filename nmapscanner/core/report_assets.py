"""Načtení statických assetů reportu (logo PT Lab) jako data URI pro HTML/PDF.

Embed do HTML zajistí, že vytištěné PDF je self-contained (nezávislé na cestě).
"""

import base64
import os

_ASSETS = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "assets")


def _data_uri(path, mime="image/png"):
    try:
        with open(path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode("ascii")
        return f"data:{mime};base64,{b64}"
    except Exception:
        return ""


def ptlab_logo_uri():
    """Data URI loga PT Lab (kruh s textem). Prázdný řetězec, když chybí."""
    return _data_uri(os.path.join(_ASSETS, "ptlab_logo.png"))


def ptlab_mark_uri():
    """Data URI samotné značky PT Lab (bez textu)."""
    p = os.path.join(_ASSETS, "ptlab_mark.png")
    if os.path.exists(p):
        return _data_uri(p)
    return ptlab_logo_uri()
