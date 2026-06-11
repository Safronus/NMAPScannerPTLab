"""Post-processing PDF reportu: razítko hlavičky + patičky + čísel stran.

QtWebEngine `printToPdf` neumí spolehlivé opakující se hlavičky/patičky ani čísla
stran (CSS `position: fixed` se napříč stranami chová nestabilně a překrývá
obsah). Proto report renderujeme s prázdnými okraji a hlavičku (logo PT Lab +
adresa laboratoře + „N stran"), patičku („CITLIVÁ DATA…" + „i / N") dokreslíme
sem — na **každou stranu** identicky. Bez Qt.

Vyžaduje ``reportlab`` a ``pypdf`` (v requirements.txt).
"""

import io
import os

_ASSETS = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "assets")

MM = 2.834645  # 1 mm v bodech
RED = (0.886, 0.137, 0.102)

# Kandidáti serif TTF fontů (macOS → Linux → fallback uvnitř reportlab)
_FONT_CANDIDATES = {
    "regular": [
        "/System/Library/Fonts/Supplemental/Times New Roman.ttf",
        "/Library/Fonts/Times New Roman.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSerif-Regular.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSerif.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSerif.ttf",
    ],
    "bold": [
        "/System/Library/Fonts/Supplemental/Times New Roman Bold.ttf",
        "/Library/Fonts/Times New Roman Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSerif-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSerif-Bold.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSerifBold.ttf",
    ],
    "bolditalic": [
        "/System/Library/Fonts/Supplemental/Times New Roman Bold Italic.ttf",
        "/Library/Fonts/Times New Roman Bold Italic.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSerif-BoldItalic.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSerif-BoldItalic.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSerifBoldItalic.ttf",
    ],
}

_FONTS = None  # cache: {"regular": name, "bold": name, "bolditalic": name}


def _register_fonts():
    global _FONTS
    if _FONTS is not None:
        return _FONTS
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    builtin = {"regular": "Times-Roman", "bold": "Times-Bold", "bolditalic": "Times-BoldItalic"}
    names = {}
    for style, paths in _FONT_CANDIDATES.items():
        font_name = builtin[style]
        for p in paths:
            if os.path.exists(p):
                reg_name = f"PTSerif-{style}"
                try:
                    pdfmetrics.registerFont(TTFont(reg_name, p))
                    font_name = reg_name
                    break
                except Exception:
                    continue
        names[style] = font_name
    # bolditalic fallback na bold, když nenalezen vlastní
    if names["bolditalic"] == "Times-BoldItalic" and names["bold"] != "Times-Bold":
        names["bolditalic"] = names["bold"]
    _FONTS = names
    return names


# Texty hlavičky/patičky (CZ/EN)
_TXT = {
    "addr": (
        ["Penetration Testing Laboratory",
         "Univerzita Tomáše Bati ve Zlíně, Fakulta aplikované informatiky",
         "Nad Stráněmi 4511, 760 05 Zlín, Czech Republic"],
        ["Penetration Testing Laboratory",
         "Tomas Bata University in Zlin, Faculty of Applied Informatics",
         "Nad Stranemi 4511, 760 05 Zlin, Czech Republic"],
    ),
    "pages": ("{n} stran", "{n} pages"),
    "sensitive": ("! CITLIVÁ DATA – POUZE PRO AUTORIZOVANÉ POUŽITÍ !",
                  "! SENSITIVE DATA – FOR AUTHORIZED USE ONLY !"),
}


def _overlay_page(canvas, w, h, page_no, total, lang, logo):
    fonts = _FONTS
    i = 1 if lang == "en" else 0
    left = 16 * MM
    right = w - 16 * MM

    # --- Hlavička: logo + adresa + „N stran" ---
    logo_h = 13 * MM
    if logo:
        try:
            iw, ih = logo.getSize()
            logo_w = logo_h * iw / ih
            canvas.drawImage(logo, left, h - 11 * MM - logo_h, width=logo_w, height=logo_h,
                             preserveAspectRatio=True, mask="auto")
        except Exception:
            logo_w = 0
    else:
        logo_w = 0

    addr = _TXT["addr"][i]
    canvas.setFillColorRGB(0, 0, 0)
    canvas.setFont(fonts["bolditalic"], 8.5)
    tx = left + logo_w + 4 * MM
    ty = h - 13 * MM
    for line in addr:
        canvas.drawString(tx, ty, line)
        ty -= 3.4 * MM

    canvas.setFont(fonts["bolditalic"], 9)
    canvas.drawRightString(right, h - 13 * MM, _TXT["pages"][i].format(n=total))

    # --- Patička: SENSITIVE (červeně, na střed) + „i / N" vpravo ---
    canvas.setFont(fonts["bold"], 9)
    canvas.setFillColorRGB(*RED)
    canvas.drawCentredString(w / 2.0, 11 * MM, _TXT["sensitive"][i])
    canvas.setFillColorRGB(0, 0, 0)
    canvas.setFont(fonts["regular"], 9)
    canvas.drawRightString(right, 11 * MM, f"{page_no} / {total}")


def stamp_report(in_pdf, out_pdf, lang="cs"):
    """Na každou stranu ``in_pdf`` dokreslí hlavičku/patičku a uloží do ``out_pdf``.

    Vrací cestu k výslednému PDF. Když razítkování selže (chybí knihovny apod.),
    vyhodí výjimku — volající si pak nechá původní (nerazítkovaný) soubor.
    """
    from reportlab.pdfgen import canvas as rl_canvas
    from reportlab.lib.utils import ImageReader
    from pypdf import PdfReader, PdfWriter

    _register_fonts()
    logo_path = os.path.join(_ASSETS, "ptlab_logo.png")
    logo = ImageReader(logo_path) if os.path.exists(logo_path) else None

    reader = PdfReader(in_pdf)
    total = len(reader.pages)
    writer = PdfWriter()

    for idx, page in enumerate(reader.pages, start=1):
        w = float(page.mediabox.width)
        h = float(page.mediabox.height)
        buf = io.BytesIO()
        c = rl_canvas.Canvas(buf, pagesize=(w, h))
        _overlay_page(c, w, h, idx, total, lang, logo)
        c.save()
        buf.seek(0)
        overlay = PdfReader(buf).pages[0]
        page.merge_page(overlay)
        writer.add_page(page)

    with open(out_pdf, "wb") as f:
        writer.write(f)
    return out_pdf
