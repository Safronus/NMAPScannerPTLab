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

# Kandidáti bezpatkových (sans) TTF fontů — moderní vzhled (macOS → Linux → fallback)
_FONT_CANDIDATES = {
    "regular": [
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/Library/Fonts/Arial.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
    ],
    "bold": [
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
        "/Library/Fonts/Arial Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf",
    ],
    "bolditalic": [
        "/System/Library/Fonts/Supplemental/Arial Bold Italic.ttf",
        "/Library/Fonts/Arial Bold Italic.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-BoldItalic.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-BoldOblique.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSansBoldOblique.ttf",
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
                reg_name = f"PTFont-{style}"
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
    tx = left + logo_w + 4 * MM
    ty = h - 13 * MM
    # 1. řádek tučně (název laboratoře), zbytek normálně
    canvas.setFillColorRGB(0, 0, 0)
    for k, line in enumerate(addr):
        canvas.setFont(fonts["bold"] if k == 0 else fonts["regular"], 8.3)
        canvas.drawString(tx, ty, line)
        ty -= 3.4 * MM

    canvas.setFont(fonts["bold"], 9)
    canvas.setFillColorRGB(0.42, 0.45, 0.5)  # šedá
    canvas.drawRightString(right, h - 13 * MM, _TXT["pages"][i].format(n=total))

    # --- Patička: SENSITIVE (červeně, na střed) + „i / N" vpravo ---
    canvas.setFont(fonts["bold"], 9)
    canvas.setFillColorRGB(*RED)
    canvas.drawCentredString(w / 2.0, 11 * MM, _TXT["sensitive"][i])
    canvas.setFillColorRGB(0, 0, 0)
    canvas.setFont(fonts["regular"], 9)
    canvas.drawRightString(right, 11 * MM, f"{page_no} / {total}")


def _render_toc_page(toc_title, entries, w, h, lang):
    """Vyrenderuje jednu stránku Obsahu (reportlab) → PDF bytes.

    ``entries`` = ``[(title, level, page_no)]``. Tečkový leader mezi názvem a číslem.
    """
    import io
    from reportlab.pdfgen import canvas as rl_canvas
    from reportlab.pdfbase.pdfmetrics import stringWidth

    _register_fonts()
    fonts = _FONTS
    buf = io.BytesIO()
    c = rl_canvas.Canvas(buf, pagesize=(w, h))
    left = 16 * MM
    right = w - 16 * MM

    c.setFillColorRGB(0.086, 0.137, 0.247)  # navy
    c.setFont(fonts["bold"], 18)
    c.drawString(left, h - 36 * MM, toc_title)
    c.setStrokeColorRGB(0.886, 0.137, 0.102)
    c.setLineWidth(2)
    c.line(left, h - 39 * MM, left + 24 * MM, h - 39 * MM)

    y = h - 50 * MM
    for title, level, page_no in entries:
        indent = 8 * MM if level else 0
        size = 10.5 if level else 11.5
        font = fonts["regular"] if level else fonts["bold"]
        c.setFont(font, size)
        c.setFillColorRGB(0.13, 0.16, 0.19)
        tx = left + indent
        c.drawString(tx, y, title)
        pno = str(page_no)
        c.setFont(fonts["regular"], size)
        pw = stringWidth(pno, fonts["regular"], size)
        c.drawRightString(right, y, pno)
        # tečkový leader
        tw = stringWidth(title, font, size)
        dot_start = tx + tw + 2 * MM
        dot_end = right - pw - 2 * MM
        if dot_end > dot_start:
            c.setFillColorRGB(0.6, 0.63, 0.67)
            c.setFont(fonts["regular"], size)
            dots = "." * max(0, int((dot_end - dot_start) / stringWidth(".", fonts["regular"], size)))
            c.drawString(dot_start, y, dots)
        y -= 7.2 * MM
        if y < 30 * MM:
            break  # ochrana — TOC se vejde na jednu stranu

    c.save()
    buf.seek(0)
    return buf.read()


def assemble_with_toc(in_pdf, out_pdf, lang, headings, toc_title):
    """Vloží za titulku (stranu 1) vygenerovaný Obsah a uloží do ``out_pdf``.

    Strany kapitol dohledá z textu stran ``in_pdf``. Čísla stran v obsahu počítají
    s vloženou stranou Obsahu (+1 pro obsahové strany). Vrací ``out_pdf``.
    """
    from pypdf import PdfReader, PdfWriter

    import unicodedata
    reader = PdfReader(in_pdf)
    # Porovnání jen přes alfanumerické znaky + NFKC (rozloží ligatury jako „ﬁ"→"fi",
    # které Chromium do PDF vkládá) → odolné vůči mezerám, závorkám i ligaturám.
    norm = lambda s: "".join(
        ch.lower() for ch in unicodedata.normalize("NFKC", s or "") if ch.isalnum())

    page_of = {}
    for pidx, page in enumerate(reader.pages, start=1):
        try:
            txt = norm(page.extract_text())
        except Exception:
            txt = ""
        for title, _lvl in headings:
            if title not in page_of and norm(title) in txt:
                page_of[title] = pidx

    # +1 protože za titulku vkládáme stranu Obsahu (posune obsahové strany)
    entries = [(title, lvl, page_of[title] + 1) for title, lvl in headings if title in page_of]

    w = float(reader.pages[0].mediabox.width)
    h = float(reader.pages[0].mediabox.height)
    toc_bytes = _render_toc_page(toc_title, entries, w, h, lang)
    import io
    toc_reader = PdfReader(io.BytesIO(toc_bytes))

    writer = PdfWriter()
    writer.add_page(reader.pages[0])        # titulka
    writer.add_page(toc_reader.pages[0])    # obsah
    for p in reader.pages[1:]:              # zbytek
        writer.add_page(p)
    with open(out_pdf, "wb") as f:
        writer.write(f)
    return out_pdf


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
