"""Generování HTML souhrnného reportu (bez Qt → testovatelné).

Styl je laděný do vzhledu **PT Lab** (Penetration Testing Laboratory, FAI UTB):
tmavě modré záhlaví s červeným akcentem, čistá bílá sazba, barevné odznaky
závažnosti. HTML je připravené pro tisk do PDF (A4) přes QtWebEngine.
"""

import html as _html

from .report_classify import (
    SEVERITIES, SEVERITY_COLOR, CVSS_BAND, OWASP_2025, SECTION_TITLES,
)

# Barvy PT Lab tématu
NAVY = "#16233f"
NAVY_DARK = "#0e1830"
RED = "#d92e27"
INK = "#1f2733"
MUTED = "#6b7686"


def _esc(s):
    return _html.escape(str(s if s is not None else ""))


def _nl2br(s):
    return _esc(s).replace("\n", "<br>")


def _sev_badge(sev):
    return (f'<span class="badge" style="background:{SEVERITY_COLOR[sev]}">'
            f'{_esc(sev)}</span>')


def _owasp_badge(code):
    if not code:
        return ""
    return f'<span class="owasp">{_esc(code)}</span>'


def _css():
    bars = "\n".join(
        f".sev-{s.lower()}{{background:{SEVERITY_COLOR[s]}}}" for s in SEVERITIES
    )
    return f"""
    @page {{ size: A4; margin: 16mm 14mm 18mm 14mm; }}
    * {{ box-sizing: border-box; }}
    body {{ font-family: 'Helvetica Neue', Arial, 'Segoe UI', sans-serif;
            color: {INK}; font-size: 12px; line-height: 1.5; margin: 0; }}
    h1,h2,h3 {{ margin: 0 0 6px 0; }}
    a {{ color: {RED}; text-decoration: none; }}

    .cover {{ background: linear-gradient(135deg, {NAVY} 0%, {NAVY_DARK} 100%);
              color: #fff; padding: 38px 34px; border-bottom: 5px solid {RED}; }}
    .cover .brand {{ font-size: 13px; letter-spacing: 2px; text-transform: uppercase;
                     color: #aeb8cc; }}
    .cover .brand b {{ color: {RED}; }}
    .cover h1 {{ font-size: 30px; margin-top: 10px; }}
    .cover .sub {{ color: #c7d0e0; font-size: 13px; margin-top: 4px; }}
    .cover .slogan {{ margin-top: 18px; font-style: italic; color: #8e9bb5;
                      font-size: 12px; }}
    .meta-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 6px 26px;
                  margin-top: 22px; font-size: 12px; }}
    .meta-grid .k {{ color: #9aa6bd; }}
    .meta-grid .v {{ color: #fff; font-weight: 600; }}

    .wrap {{ padding: 22px 30px; }}
    .section {{ margin: 26px 0; }}
    .section > h2 {{ color: {NAVY}; font-size: 18px; border-bottom: 2px solid {RED};
                     padding-bottom: 5px; }}
    .lead {{ color: {MUTED}; margin: 4px 0 14px; }}

    .cards {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px;
              margin: 14px 0; }}
    .card {{ border-radius: 8px; color: #fff; padding: 12px 10px; text-align: center; }}
    .card .n {{ font-size: 26px; font-weight: 700; line-height: 1; }}
    .card .l {{ font-size: 11px; text-transform: uppercase; letter-spacing: 1px;
                margin-top: 4px; opacity: .95; }}
    {bars}

    table {{ border-collapse: collapse; width: 100%; font-size: 11.5px; }}
    th, td {{ border: 1px solid #e3e7ee; padding: 6px 8px; text-align: left;
              vertical-align: top; }}
    th {{ background: {NAVY}; color: #fff; font-weight: 600; }}
    tr:nth-child(even) td {{ background: #f7f9fc; }}

    .badge {{ display: inline-block; color: #fff; font-weight: 700; font-size: 10px;
              padding: 2px 8px; border-radius: 10px; letter-spacing: .5px; }}
    .owasp {{ display: inline-block; background: {NAVY}; color: #fff; font-size: 10px;
              padding: 2px 7px; border-radius: 4px; font-weight: 600; }}

    .finding {{ border: 1px solid #e3e7ee; border-left: 5px solid {MUTED};
                border-radius: 6px; padding: 10px 12px; margin: 10px 0;
                page-break-inside: avoid; }}
    .finding h3 {{ font-size: 13.5px; color: {NAVY}; }}
    .finding .row {{ margin: 3px 0; }}
    .finding .lbl {{ color: {MUTED}; font-size: 10.5px; text-transform: uppercase;
                     letter-spacing: .5px; }}
    .finding pre {{ background: #0e1830; color: #d6e0f5; padding: 8px 10px;
                    border-radius: 5px; font-size: 10.5px; white-space: pre-wrap;
                    word-break: break-word; overflow-wrap: anywhere; margin: 4px 0 0; }}
    .rec {{ background: #fff7f0; border: 1px solid #ffd9bf; border-radius: 5px;
            padding: 6px 9px; margin-top: 6px; }}

    .barline {{ display: flex; align-items: center; gap: 8px; margin: 4px 0; }}
    .barline .name {{ width: 90px; font-size: 11px; }}
    .barline .track {{ flex: 1; background: #eef1f6; border-radius: 4px; height: 14px; }}
    .barline .fill {{ height: 14px; border-radius: 4px; }}
    .barline .cnt {{ width: 30px; text-align: right; font-weight: 700; font-size: 11px; }}

    .foot {{ color: {MUTED}; font-size: 10px; text-align: center; margin-top: 26px;
             border-top: 1px solid #e3e7ee; padding-top: 8px; }}
    .pb {{ page-break-before: always; }}
    """


def _cover(meta, result):
    rows = [
        ("Projekt", meta.get("project_name", "—")),
        ("Klient / rozsah", meta.get("client", "—")),
        ("Zpracoval", meta.get("author", "—")),
        ("Datum", meta.get("date", "—")),
        ("Běh / verze dat", meta.get("run_info", "—")),
        ("Nástroj", meta.get("tool", "NMAP Scanner — PT Lab")),
    ]
    grid = "".join(
        f'<div class="k">{_esc(k)}</div><div class="v">{_esc(v)}</div>' for k, v in rows
    )
    return f"""
    <div class="cover">
      <div class="brand">PT&nbsp;<b>Lab</b> · Penetration Testing Laboratory</div>
      <h1>{_esc(meta.get('title', 'Zpráva z penetračního testu'))}</h1>
      <div class="sub">Fakulta aplikované informatiky · Univerzita Tomáše Bati ve Zlíně</div>
      <div class="meta-grid">{grid}</div>
      <div class="slogan">„You'll be hacked soon."</div>
    </div>"""


def _summary_cards(summary):
    cards = ""
    for s in SEVERITIES:
        cards += (f'<div class="card sev-{s.lower()}">'
                  f'<div class="n">{summary.get(s, 0)}</div>'
                  f'<div class="l">{_esc(s)}</div></div>')
    return f'<div class="cards">{cards}</div>'


def _severity_bars(summary, total):
    total = max(total, 1)
    lines = ""
    for s in SEVERITIES:
        n = summary.get(s, 0)
        pct = int(round(n / total * 100))
        lines += (
            f'<div class="barline"><div class="name">{_sev_badge(s)}</div>'
            f'<div class="track"><div class="fill" '
            f'style="width:{pct}%;background:{SEVERITY_COLOR[s]}"></div></div>'
            f'<div class="cnt">{n}</div></div>'
        )
    return lines


def _methodology():
    cvss_rows = "".join(
        f"<tr><td>{_sev_badge(s)}</td><td>{_esc(CVSS_BAND[s])}</td>"
        f"<td>{_esc(_CVSS_NOTE[s])}</td></tr>" for s in SEVERITIES
    )
    owasp_rows = "".join(
        f"<tr><td>{_owasp_badge(code)}</td><td>{_esc(name)}</td></tr>"
        for code, name in OWASP_2025.items()
    )
    return f"""
    <div class="section pb">
      <h2>Metodika</h2>
      <p class="lead">Závažnost nálezů je zarovnaná na kvalitativní pásma
      <b>CVSS v4.0</b>. Nálezy jsou kategorizovány dle <b>OWASP Top 10:2025</b>
      (aktuální vydání metodiky). Jde o orientační ohodnocení útočné plochy
      z pohledu síťového a webového skenu, nikoliv o per-CVE výpočet CVSS vektoru.</p>

      <h3 style="color:{NAVY};margin-top:14px;">Stupnice závažnosti (CVSS v4.0)</h3>
      <table><tr><th>Úroveň</th><th>CVSS skóre</th><th>Význam</th></tr>
      {cvss_rows}</table>

      <h3 style="color:{NAVY};margin-top:16px;">OWASP Top 10:2025</h3>
      <table><tr><th>Kategorie</th><th>Název</th></tr>{owasp_rows}</table>
    </div>"""


_CVSS_NOTE = {
    "CRITICAL": "Kritické — okamžitá náprava (RCE, únik dat, plný kompromis).",
    "HIGH": "Vysoké — náprava s vysokou prioritou.",
    "MEDIUM": "Střední — náprava v plánovaném cyklu.",
    "LOW": "Nízké — drobné nedostatky / hardening.",
    "INFO": "Informativní — bez přímého dopadu (kontext, útočná plocha).",
}


def _owasp_table(owasp):
    if not owasp:
        return ""
    rows = ""
    for code in sorted(owasp.keys()):
        info = owasp[code]
        rows += (f"<tr><td>{_owasp_badge(code)}</td>"
                 f"<td>{_esc(info['name'])}</td>"
                 f"<td>{_sev_badge(info['worst'])}</td>"
                 f"<td style='text-align:center'>{info['count']}</td></tr>")
    return f"""
    <div class="section">
      <h2>Pokrytí OWASP Top 10:2025</h2>
      <table><tr><th>Kat.</th><th>Název</th><th>Nejvyšší závažnost</th>
      <th>Počet nálezů</th></tr>{rows}</table>
    </div>"""


def _finding_block(f, options):
    sev = f["severity"]
    parts = [
        f'<div class="finding" style="border-left-color:{SEVERITY_COLOR[sev]}">',
        f'<h3>{_esc(f["id"])} — {_esc(f["title"])}</h3>',
        f'<div class="row">{_sev_badge(sev)} &nbsp; {_owasp_badge(f.get("owasp"))} '
        f'&nbsp; <span class="lbl">{_esc(f.get("owasp_name", ""))}</span></div>',
        f'<div class="row"><span class="lbl">Cíl</span> &nbsp; '
        f'<b>{_esc(f["target"])}</b> &nbsp; · &nbsp; '
        f'<span class="lbl">{_esc(f["category"])}</span></div>',
        f'<div class="row">{_esc(f["description"])}</div>',
    ]
    if options.get("include_evidence", True) and f.get("evidence"):
        parts.append(f'<div class="row"><span class="lbl">Důkaz</span>'
                     f'<pre>{_nl2br(f["evidence"])}</pre></div>')
    if options.get("include_recommendations", True) and f.get("recommendation"):
        parts.append(f'<div class="rec"><span class="lbl">Doporučení</span><br>'
                     f'{_esc(f["recommendation"])}</div>')
    parts.append("</div>")
    return "".join(parts)


def _findings_section(findings, options):
    if not findings:
        return ('<div class="section"><h2>Nálezy</h2>'
                '<p class="lead">Žádné nálezy odpovídající zvoleným filtrům.</p></div>')

    group_by = options.get("group_by", "severity")
    blocks = ""
    if group_by == "category":
        # seskupit podle kategorie
        seen = []
        for f in findings:
            if f["category"] not in seen:
                seen.append(f["category"])
        for cat in seen:
            blocks += f'<h3 style="color:{RED};margin-top:16px;">{_esc(cat)}</h3>'
            for f in [x for x in findings if x["category"] == cat]:
                blocks += _finding_block(f, options)
    else:
        # findings už jsou seřazené dle závažnosti
        cur = None
        for f in findings:
            if f["severity"] != cur:
                cur = f["severity"]
                blocks += (f'<h3 style="margin-top:16px;">{_sev_badge(cur)} '
                           f'<span style="color:{NAVY}">nálezy</span></h3>')
            blocks += _finding_block(f, options)

    return f'<div class="section pb"><h2>Nálezy ({len(findings)})</h2>{blocks}</div>'


def build_html(meta, result, options=None):
    """Sestaví kompletní HTML reportu.

    * ``meta`` — metadata (title, project_name, client, author, date, run_info, tool).
    * ``result`` — výstup ``build_findings`` (findings/summary/owasp/sections/total).
    * ``options`` — co zahrnout (include_evidence, include_recommendations,
      include_methodology, include_charts, group_by).
    """
    options = options or {}
    summary = result.get("summary", {})
    total = result.get("total", 0)

    sec_rows = "".join(
        f"<tr><td>{_esc(SECTION_TITLES.get(k, k))}</td>"
        f"<td style='text-align:center'>{v}</td></tr>"
        for k, v in sorted(result.get("sections", {}).items())
    )

    charts = ""
    if options.get("include_charts", True):
        charts = (f'<h3 style="color:{NAVY};margin-top:14px;">Rozložení závažnosti</h3>'
                  f'{_severity_bars(summary, total)}')

    overview = f"""
    <div class="section">
      <h2>Shrnutí</h2>
      <p class="lead">Report agreguje výsledky celého běhu skenu a klasifikuje je
      dle závažnosti (CVSS v4.0) a OWASP Top 10:2025. Celkem nálezů:
      <b>{total}</b>.</p>
      {_summary_cards(summary)}
      {charts}
      {('<h3 style="color:%s;margin-top:16px;">Nálezy podle oblasti</h3>'
        '<table><tr><th>Oblast</th><th>Počet</th></tr>%s</table>'
        % (NAVY, sec_rows)) if sec_rows else ''}
    </div>"""

    methodology = _methodology() if options.get("include_methodology", True) else ""

    html_doc = f"""<!DOCTYPE html><html lang="cs"><head><meta charset="utf-8">
    <title>{_esc(meta.get('title', 'Report'))}</title><style>{_css()}</style></head>
    <body>
      {_cover(meta, result)}
      <div class="wrap">
        {overview}
        {_owasp_table(result.get('owasp', {}))}
        {_findings_section(result.get('findings', []), options)}
        {methodology}
        <div class="foot">Vygenerováno nástrojem {_esc(meta.get('tool', 'NMAP Scanner — PT Lab'))}
        · {_esc(meta.get('date', ''))} · Pouze pro autorizované testování.</div>
      </div>
    </body></html>"""
    return html_doc
