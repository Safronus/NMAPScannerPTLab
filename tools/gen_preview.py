#!/usr/bin/env python3
"""Vygeneruje náhled reportu do .preview/preview.html (base64 obrázky stran).

Použití:  python3 tools/gen_preview.py [cesta_k.pdf]
Default PDF: /tmp/band_final.pdf. Strany renderuje přes `pdftoppm` (poppler).
Náhled je self-contained (obrázky vložené base64) → funguje i v preview panelu,
který neservíruje sousední soubory.
"""
import base64
import glob
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PREVIEW_DIR = os.path.join(ROOT, ".preview")


def main():
    pdf = sys.argv[1] if len(sys.argv) > 1 else "/tmp/band_final.pdf"
    if not os.path.exists(pdf):
        print(f"PDF nenalezeno: {pdf}", file=sys.stderr)
        return 1
    os.makedirs(PREVIEW_DIR, exist_ok=True)
    for old in glob.glob(os.path.join(PREVIEW_DIR, "page-*.jpg")):
        os.remove(old)

    subprocess.run(["pdftoppm", "-jpeg", "-jpegopt", "quality=62", "-r", "96",
                    pdf, os.path.join(PREVIEW_DIR, "page")], check=True)
    pages = sorted(glob.glob(os.path.join(PREVIEW_DIR, "page-*.jpg")))
    n = len(pages)

    imgs = []
    for i, p in enumerate(pages, 1):
        with open(p, "rb") as f:
            b64 = base64.b64encode(f.read()).decode("ascii")
        imgs.append(
            f'<div class="page"><img src="data:image/jpeg;base64,{b64}" '
            f'alt="strana {i}"><div class="num">{i} / {n}</div></div>')
        os.remove(p)  # už je v HTML, na disku netřeba

    html = f"""<!DOCTYPE html><html lang="cs"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Náhled reportu — PT Lab</title><style>
 *{{box-sizing:border-box}} body{{margin:0;background:#2a2f3a;
   font-family:'Helvetica Neue',Arial,sans-serif}}
 .bar{{position:sticky;top:0;z-index:5;display:flex;gap:12px;align-items:center;
   padding:8px 14px;background:#00102e;color:#fff;border-bottom:3px solid #e2231a;font-size:13px}}
 .bar .muted{{color:#9aa6bd}}
 .pages{{display:flex;flex-direction:column;align-items:center;gap:18px;padding:18px 12px 40px}}
 .page{{width:100%;max-width:840px}}
 .page img{{width:100%;display:block;border-radius:4px;background:#fff;
   box-shadow:0 4px 18px rgba(0,0,0,.45)}}
 .num{{color:#b8c0cf;font-size:11px;margin:6px 2px 0;text-align:right}}
</style></head><body>
 <div class="bar"><b>Náhled PDF reportu</b>
   <span class="muted">PT Lab · {n} stran</span>
   <span class="muted" style="margin-left:auto">aktualizuje se při přegenerování</span></div>
 <div class="pages">{''.join(imgs)}</div>
</body></html>"""

    out = os.path.join(PREVIEW_DIR, "preview.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"OK: {out} ({n} stran, {os.path.getsize(out)//1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
