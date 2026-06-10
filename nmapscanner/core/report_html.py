"""Generování HTML reportu ve stylu **PT Lab** (Penetration Testing Laboratory).

Vychází ze vzhledu oficiálních PT Lab reportů: bílé pozadí, patkové (serif) písmo,
opakující se hlavička s logem a adresou laboratoře, červená patička
„SENSITIVE DATA", modré hlavičky tabulek a barevně kódované buňky rizika.

Dva typy reportu — **technical** (podrobný technický) a **management**
(manažerský bez technikálií) — a dva jazyky (**cs/en**). Bez Qt → testovatelné;
tisk do PDF zajišťuje QtWebEngine ve volajícím dialogu.
"""

import html as _html

from .report_classify import (
    SEVERITIES, SEVERITY_COLOR, CVSS_BAND, OWASP_2025, section_title,
)
from .report_assets import ptlab_logo_uri

# Barvy PT Lab tématu
RED = "#E2231A"
BLUE = "#4472C4"      # hlavičky tabulek
BLUE_DARK = "#2E5496"
HEAD_MAROON = "#8B2E2E"
INK = "#1a1a1a"
MUTED = "#666666"


def _esc(s):
    return _html.escape(str(s if s is not None else ""))


def _nl2br(s):
    return _esc(s).replace("\n", "<br>")


def T(key, lang):
    return _L.get(key, (key, key))[1 if lang == "en" else 0]


# --- i18n texty scaffoldingu ----------------------------------------------
_L = {
    "report": ("Pentest Report", "Pentest Report"),
    "technical_sub": ("Technická zpráva", "Technical report"),
    "management_sub": ("Manažerská zpráva", "Management report"),
    "lab_line1": ("Penetration Testing Laboratory", "Penetration Testing Laboratory"),
    "lab_line2": ("Univerzita Tomáše Bati ve Zlíně, Fakulta aplikované informatiky",
                  "Tomas Bata University in Zlin, Faculty of Applied Informatics"),
    "lab_line3": ("Nad Stráněmi 4511, 760 05 Zlín, Czech Republic",
                  "Nad Stranemi 4511, 760 05 Zlin, Czech Republic"),
    "sensitive": ("! CITLIVÁ DATA – POUZE PRO AUTORIZOVANÉ POUŽITÍ !",
                  "! SENSITIVE DATA – FOR AUTHORIZED USE ONLY !"),
    "engagement": ("Penetrační test: infrastruktura", "Penetration testing: infrastructure"),
    "prepared_by": ("Zpracoval", "Prepared by"),
    "client": ("Klient / rozsah", "Client / scope"),
    "date": ("Datum", "Date"),
    "project": ("Projekt", "Project"),
    "tool": ("Nástroj", "Tool"),

    "h_limitation": ("1. Omezení reportu", "1. Report limitation"),
    "limitation_default": (
        "Tento report nepokrývá veškeré existující zranitelnosti IT infrastruktury, "
        "ale zaměřuje se pouze na testy odsouhlasené zadavatelem. Report rovněž "
        "nezaručuje bezpečnost systémů vůči zranitelnostem objeveným po provedení testů.",
        "This report does not cover all existing vulnerabilities of the IT infrastructure, "
        "but focuses only on the tests agreed with the client. The report also does not "
        "guarantee the security of systems against vulnerabilities discovered after the tests."),
    "h_owasp": ("1.1. Testované zranitelnosti (OWASP Top 10:2025)",
                "1.1. Vulnerabilities tested (OWASP Top 10:2025)"),
    "owasp_intro": (
        "Následující kategorie odpovídají metodice OWASP Top 10:2025, podle které byla "
        "infrastruktura testována.",
        "The following categories follow the OWASP Top 10:2025 methodology used to test "
        "the infrastructure."),
    "h_scale": ("1.2. Použitá klasifikační stupnice", "1.2. Vulnerability classification scale used"),
    "scale_intro": (
        "Závažnost nálezů je zarovnaná na kvalitativní pásma CVSS v4.0.",
        "Finding severity is aligned with the CVSS v4.0 qualitative bands."),
    "col_risk": ("Riziko", "Risk"),
    "col_name": ("Název", "Name"),
    "col_desc": ("Popis", "Description"),
    "col_score": ("CVSS skóre", "CVSS score"),
    "col_cat": ("Kategorie", "Category"),
    "col_ip": ("IP", "IP"),
    "col_ports": ("Porty", "Ports"),
    "col_service": ("Služba", "Service"),
    "col_vuln": ("Zranitelnost", "Vulnerability"),
    "col_count": ("Počet", "Count"),
    "col_tool": ("Nástroj", "Tool"),
    "col_version": ("Verze", "Version"),
    "col_purpose": ("Účel", "Purpose"),

    "h_objectives": ("2. Specifikace cílů", "2. Specification of objectives"),
    "scope_default": (
        "Náplní testu bylo ověřit odolnost poskytnuté infrastruktury a detekovat "
        "zranitelná místa na serverech.",
        "The purpose of the test was to verify the resilience of the provided "
        "infrastructure and to detect vulnerable spots on the servers."),
    "h_targets": ("2.1. Testované IP adresy", "2.1. Tested IP addresses"),
    "targets_intro": ("K testování byly poskytnuty následující cílové IP adresy:",
                      "The following destination IP addresses were provided for testing:"),
    "h_tools": ("2.2. Použité nástroje", "2.2. Tools used"),
    "tools_intro": ("Při testování byly použity následující nástroje:",
                    "The following tools were used during the testing:"),
    "h_results": ("3. Výsledky testů – nalezené zranitelnosti",
                  "3. Test results – discovered vulnerabilities"),
    "results_intro": ("Tato sekce obsahuje výstupy a doporučení pro nálezy zjištěné při testech.",
                      "This section contains outputs and recommendations for findings detected in the tests."),
    "h_overview": ("Souhrn nálezů", "Findings summary"),
    "overview_intro": ("Celkový počet nálezů dle závažnosti a oblasti:",
                       "Total number of findings by severity and area:"),
    "h_findings_table": ("Seznam nálezů (dle IP / portů / služeb / zranitelností)",
                         "List of findings (by IP / ports / services / vulnerabilities)"),
    "h_summary": ("Shrnutí", "Summary"),
    "summary_default": (
        "Cílem testu bylo zjistit odolnost infrastruktury zadavatele a detekovat zranitelná "
        "místa na serverech. Infrastruktura byla testována dle metodiky OWASP a aktuálního "
        "seznamu TOP 10:2025. Pro stanovení závažnosti byl použit systém CVSS se stupnicí 0–10.",
        "The aim of the test was to determine the resilience of the client's infrastructure "
        "and to detect vulnerable spots on the servers. The infrastructure was tested per the "
        "OWASP methodology and the current TOP 10:2025 list. The CVSS system with a 0–10 scale "
        "was used to determine severity."),
    "h_conclusion": ("Závěr", "Conclusion"),
    "conclusion_default": (
        "Je zásadní zaměřit se především na nálezy s vysokou závažností. Po nápravě "
        "doporučujeme provést opětovné ověření.",
        "It is essential to focus primarily on high-severity findings. After remediation we "
        "recommend a re-test for verification."),
    "h_recommendation": ("Souhrnné doporučení", "Overall recommendation"),
    "recommendation_default": (
        "Doporučujeme prioritně řešit nálezy se závažností HIGH a CRITICAL, následně MEDIUM, "
        "a postupně i LOW. Informativní nálezy slouží jako kontext.",
        "We recommend addressing HIGH and CRITICAL findings first, then MEDIUM, and gradually "
        "LOW. Informational findings serve as context."),
    "sev_counts": ("Počty dle závažnosti", "Counts by severity"),
    "no_findings": ("Žádné nálezy odpovídající zvoleným filtrům.",
                    "No findings matching the selected filters."),
    "comment": ("Komentář", "Comment"),
    "recommendation": ("Doporučení", "Recommendation"),
    "evidence": ("Důkaz", "Evidence"),
    "generated_by": ("Vygenerováno nástrojem", "Generated by"),
}

# Rozepsané OWASP kategorie (krátký popis CZ/EN)
OWASP_DESC = {
    "A01": ("Nedostatečné řízení přístupu — uživatelé se dostanou k datům/funkcím nad rámec oprávnění.",
            "Broken Access Control — users reach data/functions beyond their permissions."),
    "A02": ("Chybná konfigurace zabezpečení — výchozí nastavení, zbytečné služby, odhalené detaily.",
            "Security Misconfiguration — default settings, unnecessary services, exposed details."),
    "A03": ("Selhání dodavatelského řetězce SW — zastaralé/zranitelné komponenty a závislosti.",
            "Software Supply Chain Failures — outdated/vulnerable components and dependencies."),
    "A04": ("Kryptografická selhání — slabé/chybějící šifrování, špatná správa certifikátů.",
            "Cryptographic Failures — weak/missing encryption, poor certificate management."),
    "A05": ("Injektáž — SQLi, XSS, příkazová injektáž a podobné vstupní útoky.",
            "Injection — SQLi, XSS, command injection and similar input attacks."),
    "A06": ("Nezabezpečený návrh — chybějící bezpečnostní kontroly už na úrovni návrhu.",
            "Insecure Design — missing security controls at the design level."),
    "A07": ("Selhání autentizace — slabá hesla, brute-force, špatná správa relací.",
            "Authentication Failures — weak passwords, brute-force, poor session management."),
    "A08": ("Selhání integrity SW a dat — neověřené aktualizace, deserializace, CI/CD.",
            "Software and Data Integrity Failures — unverified updates, deserialization, CI/CD."),
    "A09": ("Selhání logování a alertů — nedostatečné záznamy a detekce incidentů.",
            "Security Logging and Alerting Failures — insufficient logging and incident detection."),
    "A10": ("Špatné zacházení s výjimečnými stavy — chybové stavy odhalující informace či vedoucí k selhání.",
            "Mishandling of Exceptional Conditions — error states leaking info or causing failures."),
}

CVSS_NOTE = {
    "CRITICAL": ("Kritické — okamžitá náprava (RCE, únik dat, plný kompromis).",
                 "Critical — immediate remediation (RCE, data breach, full compromise)."),
    "HIGH": ("Vysoké — náprava s vysokou prioritou.", "High — remediate with high priority."),
    "MEDIUM": ("Střední — náprava v plánovaném cyklu.", "Medium — remediate in a planned cycle."),
    "LOW": ("Nízké — drobné nedostatky / hardening.", "Low — minor issues / hardening."),
    "INFO": ("Informativní — bez přímého dopadu (kontext, útočná plocha).",
             "Informational — no direct impact (context, attack surface)."),
}

SEV_LABEL = {  # zkratka v tabulce stupnice
    "CRITICAL": "C.", "HIGH": "H.", "MEDIUM": "M.", "LOW": "L.", "INFO": "I.",
}


# ===========================================================================
#  CSS + opakující se hlavička/patička
# ===========================================================================
def _css():
    sev_bg = "\n".join(
        f".risk-{s.lower()}{{background:{SEVERITY_COLOR[s]};color:#fff;}}" for s in SEVERITIES
    )
    return f"""
    @page {{ size: A4; margin: 34mm 16mm 22mm 16mm; }}
    * {{ box-sizing: border-box; }}
    body {{ font-family: 'Times New Roman', Georgia, serif; color: {INK};
            font-size: 12.5px; line-height: 1.5; margin: 0; }}
    h1,h2,h3 {{ margin: 0 0 6px 0; }}
    p {{ text-align: justify; margin: 6px 0; }}
    a {{ color: {BLUE_DARK}; text-decoration: none; }}
    ul {{ margin: 6px 0; padding-left: 22px; }}

    /* Opakující se hlavička — QtWebEngine kotví fixed prvky obráceně, proto
       logo+adresa přes 'bottom' (vykreslí se NAHOŘE v horním okraji strany). */
    .run-header {{ position: fixed; bottom: -20mm; left: 0; right: 0; height: 20mm;
                   display: flex; align-items: center; gap: 10px; }}
    .run-header img {{ height: 17mm; }}
    .run-header .addr {{ font-style: italic; font-weight: bold; font-size: 11px;
                         line-height: 1.25; }}
    /* Opakující se patička — přes 'top' (vykreslí se DOLE ve spodním okraji). */
    .run-footer {{ position: fixed; top: -14mm; left: 0; right: 0; height: 12mm;
                   text-align: center; }}
    .run-footer .sens {{ color: {RED}; font-weight: bold; font-size: 11px; }}

    .section {{ margin: 16px 0; }}
    h1.title {{ text-align: center; font-size: 30px; margin-top: 70mm; }}
    .subtitle {{ text-align: center; font-size: 16px; color: {INK}; margin-bottom: 40mm; }}
    .authors {{ text-align: center; font-size: 15px; line-height: 1.8; }}
    .cover-foot {{ margin-top: 50mm; border-top: 1px solid #000; padding-top: 6px;
                   display: flex; justify-content: space-between; font-size: 12px; }}

    h2 {{ color: {INK}; font-size: 16px; font-weight: bold; margin-top: 14px; }}
    h3 {{ color: {BLUE_DARK}; font-size: 13.5px; margin-top: 12px; }}
    .lead {{ color: {MUTED}; }}

    table {{ border-collapse: collapse; width: 100%; font-size: 11.5px; margin: 8px 0; }}
    th, td {{ border: 1px solid #b9c2d0; padding: 5px 7px; text-align: left; vertical-align: top; }}
    th {{ background: {BLUE}; color: #fff; font-weight: bold; }}
    .scale th {{ background: {HEAD_MAROON}; }}

    .risk-cell {{ text-align: center; font-weight: bold; width: 64px; }}
    {sev_bg}
    .chip {{ display: inline-block; color:#fff; font-weight:bold; font-size:10px;
             padding:1px 7px; border-radius:9px; }}
    .owasp {{ display:inline-block; background:{BLUE_DARK}; color:#fff; font-size:10px;
              padding:1px 6px; border-radius:3px; font-weight:bold; }}

    .cards {{ display:flex; gap:8px; margin:10px 0; }}
    .card {{ flex:1; color:#fff; border-radius:6px; padding:8px; text-align:center; }}
    .card .n {{ font-size:22px; font-weight:bold; }}
    .card .l {{ font-size:10px; text-transform:uppercase; }}

    .rec {{ background:#fff7f0; border:1px solid #ffd9bf; border-radius:5px; padding:5px 8px; margin:4px 0; }}
    .cmt {{ background:#eef4ff; border:1px solid #bcd0f0; border-radius:5px; padding:5px 8px; margin:4px 0; }}
    pre {{ background:#f4f5f7; border:1px solid #e0e3e8; padding:6px 8px; border-radius:4px;
           font-size:10.5px; white-space:pre-wrap; word-break:break-word; overflow-wrap:anywhere; }}
    .pb {{ page-break-before: always; }}
    .avoid {{ page-break-inside: avoid; }}
    """


def _running_frame(lang):
    logo = ptlab_logo_uri()
    img = f'<img src="{logo}">' if logo else ""
    addr = (f'<div class="addr">{_esc(T("lab_line1", lang))}<br>'
            f'{_esc(T("lab_line2", lang))}<br>{_esc(T("lab_line3", lang))}</div>')
    header = f'<div class="run-header">{img}{addr}</div>'
    footer = (f'<div class="run-footer"><span class="sens">'
              f'{_esc(T("sensitive", lang))}</span></div>')
    return header + footer


# ===========================================================================
#  Sekce
# ===========================================================================
def _cover(meta, options, lang):
    sub = T("management_sub" if options.get("report_type") == "management" else "technical_sub", lang)
    authors = _esc(meta.get("author", "")) or "&nbsp;"
    return f"""
    <div class="section avoid">
      <h1 class="title">{_esc(T('report', lang))}</h1>
      <div class="subtitle">{_esc(sub)}</div>
      <div class="authors">{authors}</div>
      <div class="cover-foot">
        <div>{_esc(meta.get('date', ''))}</div>
        <div>{_esc(meta.get('engagement') or T('engagement', lang))}</div>
      </div>
    </div>"""


def _scale_table(lang):
    rows = ""
    for s in SEVERITIES:
        rows += (
            f'<tr><td class="risk-cell risk-{s.lower()}">{SEV_LABEL[s]} {_esc(s)}</td>'
            f'<td><b>{_esc(s)}</b></td>'
            f'<td>{_esc(CVSS_BAND[s])}</td>'
            f'<td>{_esc(CVSS_NOTE[s][1 if lang=="en" else 0])}</td></tr>'
        )
    return f"""
    <div class="section">
      <h2>{_esc(T('h_scale', lang))}</h2>
      <p class="lead">{_esc(T('scale_intro', lang))}</p>
      <table class="scale">
        <tr><th>{_esc(T('col_risk', lang))}</th><th>{_esc(T('col_name', lang))}</th>
        <th>{_esc(T('col_score', lang))}</th><th>{_esc(T('col_desc', lang))}</th></tr>
        {rows}
      </table>
    </div>"""


def _owasp_methodology(result, lang):
    used = set(result.get("owasp", {}).keys())
    rows = ""
    for code, name in OWASP_2025.items():
        mark = " ✓" if code in used else ""
        rows += (f'<tr><td><span class="owasp">{code}</span></td>'
                 f'<td><b>{_esc(name)}{mark}</b><br>'
                 f'<span class="lead">{_esc(OWASP_DESC[code][1 if lang=="en" else 0])}</span></td></tr>')
    return f"""
    <div class="section">
      <h2>{_esc(T('h_owasp', lang))}</h2>
      <p class="lead">{_esc(T('owasp_intro', lang))}</p>
      <table><tr><th style="width:60px">{_esc(T('col_cat', lang))}</th>
      <th>{_esc(OWASP_2025.get('A01') and T('col_name', lang))}</th></tr>{rows}</table>
    </div>"""


def _targets(scan_results, lang):
    tcp = scan_results.get("tcp", {}) or {}
    ips = sorted(tcp.keys())
    items = "".join(f"<li>{_esc(ip)}</li>" for ip in ips) or "<li>—</li>"
    return f"""
    <div class="section">
      <h2>{_esc(T('h_targets', lang))}</h2>
      <p>{_esc(T('targets_intro', lang))}</p>
      <ul>{items}</ul>
    </div>"""


def _tools_table(options, lang):
    tools = options.get("tools") or []
    if not tools:
        return ""
    rows = ""
    for t in tools:
        rows += (f"<tr><td>{_esc(t.get('name',''))}</td>"
                 f"<td>{_esc(t.get('version','—'))}</td>"
                 f"<td>{_esc(t.get('purpose',''))}</td></tr>")
    return f"""
    <div class="section">
      <h2>{_esc(T('h_tools', lang))}</h2>
      <p>{_esc(T('tools_intro', lang))}</p>
      <table><tr><th>{_esc(T('col_tool', lang))}</th><th>{_esc(T('col_version', lang))}</th>
      <th>{_esc(T('col_purpose', lang))}</th></tr>{rows}</table>
    </div>"""


def _summary_cards(summary, lang):
    cards = ""
    for s in SEVERITIES:
        cards += (f'<div class="card risk-{s.lower()}"><div class="n">{summary.get(s,0)}</div>'
                  f'<div class="l">{_esc(s)}</div></div>')
    return f'<div class="cards">{cards}</div>'


def _ip_of(target):
    # target je "ip" nebo "ip:port" nebo "scheme://ip:port"
    t = target
    if "://" in t:
        t = t.split("://", 1)[1]
    return t.split(":")[0].split("/")[0]


def _port_of(target):
    t = target
    if "://" in t:
        t = t.split("://", 1)[1]
    if ":" in t:
        return t.split(":")[1].split("/")[0]
    return ""


def _findings_by_ip_table(findings, lang, with_detail=True, options=None):
    """Hlavní technická část: per-IP tabulky IP|Porty|Služba|Zranitelnost|Riziko."""
    options = options or {}
    if not findings:
        return f'<p class="lead">{_esc(T("no_findings", lang))}</p>'

    # seskupit dle IP
    by_ip = {}
    for f in findings:
        by_ip.setdefault(_ip_of(f["target"]), []).append(f)

    comments = options.get("comments", {}) or {}
    blocks = ""
    for ip in sorted(by_ip.keys()):
        items = by_ip[ip]
        rows = ""
        for f in items:
            sev = f["severity"]
            port = _port_of(f["target"]) or "—"
            owasp = f.get("owasp", "")
            vuln = (f'<span class="owasp">{_esc(owasp)}</span> ' if owasp else "") + _esc(f["title"])
            rows += (
                f'<tr><td>{_esc(port)}</td>'
                f'<td>{_esc(f["category"])}</td>'
                f'<td>{vuln}</td>'
                f'<td class="risk-cell risk-{sev.lower()}">{SEV_LABEL[sev]}</td></tr>'
            )
        blocks += f'<h3>{_esc(ip)}</h3><table class="avoid">' \
                  f'<tr><th style="width:70px">{_esc(T("col_ports", lang))}</th>' \
                  f'<th style="width:130px">{_esc(T("col_service", lang))}</th>' \
                  f'<th>{_esc(T("col_vuln", lang))}</th>' \
                  f'<th style="width:54px">{_esc(T("col_risk", lang))}</th></tr>{rows}</table>'

        if with_detail:
            for f in items:
                cid = f["id"]
                detail = f'<div class="avoid" style="margin:6px 0 12px;">'
                detail += (f'<b>{_esc(f["id"])} — {_esc(f["title"])}</b> '
                           f'<span class="chip" style="background:{SEVERITY_COLOR[f["severity"]]}">'
                           f'{_esc(f["severity"])}</span><br>')
                detail += f'<span>{_esc(f["description"])}</span>'
                if options.get("include_evidence", True) and f.get("evidence"):
                    detail += f'<pre>{_nl2br(f["evidence"])}</pre>'
                if options.get("include_recommendations", True) and f.get("recommendation"):
                    detail += (f'<div class="rec"><b>{_esc(T("recommendation", lang))}:</b> '
                               f'{_esc(f["recommendation"])}</div>')
                if comments.get(cid):
                    detail += (f'<div class="cmt"><b>{_esc(T("comment", lang))}:</b> '
                               f'{_nl2br(comments[cid])}</div>')
                detail += "</div>"
                blocks += detail
    return blocks


def _findings_summary_table(findings, lang):
    """Kompaktní seznam nálezů: IP | Port | Služba | Zranitelnost | Riziko."""
    if not findings:
        return f'<p class="lead">{_esc(T("no_findings", lang))}</p>'
    rows = ""
    for f in findings:
        sev = f["severity"]
        owasp_html = f'<span class="owasp">{_esc(f["owasp"])}</span> ' if f.get("owasp") else ""
        rows += (
            f'<tr><td>{_esc(_ip_of(f["target"]))}</td>'
            f'<td>{_esc(_port_of(f["target"]) or "—")}</td>'
            f'<td>{_esc(f["category"])}</td>'
            f'<td>{owasp_html}{_esc(f["title"])}</td>'
            f'<td class="risk-cell risk-{sev.lower()}">{SEV_LABEL[sev]}</td></tr>'
        )
    return f"""
    <table><tr><th>{_esc(T('col_ip', lang))}</th><th>{_esc(T('col_ports', lang))}</th>
    <th>{_esc(T('col_service', lang))}</th><th>{_esc(T('col_vuln', lang))}</th>
    <th style="width:54px">{_esc(T('col_risk', lang))}</th></tr>{rows}</table>"""


def _counts_list(findings, lang):
    """Souhrnný seznam dle závažnosti (jako v referenčním reportu)."""
    by_sev = {s: [] for s in SEVERITIES}
    for f in findings:
        by_sev[f["severity"]].append(f)
    out = ""
    for s in SEVERITIES:
        items = by_sev[s]
        if not items:
            continue
        lis = "".join(f"<li>{_esc(f['title'])} <span class='lead'>({_esc(_ip_of(f['target']))})</span></li>"
                      for f in items[:30])
        out += (f'<p><span class="chip" style="background:{SEVERITY_COLOR[s]}">{_esc(s)}</span> '
                f'({len(items)})</p><ul>{lis}</ul>')
    return out


def _free_text(title, body):
    return (f'<div class="section"><h2>{_esc(title)}</h2>'
            f'<p>{_nl2br(body)}</p></div>')


# ===========================================================================
#  Sestavení reportu
# ===========================================================================
def build_report(meta, result, options=None):
    options = options or {}
    lang = result.get("lang", options.get("lang", "cs"))
    rtype = options.get("report_type", "technical")
    findings = result.get("findings", [])
    summary = result.get("summary", {})
    scan_results = options.get("scan_results", {}) or {}

    human = options.get("human", {}) or {}
    intro = human.get("intro") or T("limitation_default", lang)
    scope = human.get("scope") or T("scope_default", lang)
    conclusion = human.get("conclusion") or T("conclusion_default", lang)
    summary_txt = human.get("summary") or T("summary_default", lang)
    recommendation = human.get("recommendation") or T("recommendation_default", lang)

    # Souhrn nálezů (karty + počty + seznam)
    overview = f"""
    <div class="section">
      <h2>{_esc(T('h_overview', lang))}</h2>
      <p>{_esc(T('overview_intro', lang))}</p>
      {_summary_cards(summary, lang)}
    </div>"""

    findings_summary = f"""
    <div class="section">
      <h2>{_esc(T('h_findings_table', lang))}</h2>
      {_findings_summary_table(findings, lang)}
      <h3>{_esc(T('sev_counts', lang))}</h3>
      {_counts_list(findings, lang)}
    </div>"""

    if rtype == "management":
        body = "".join([
            _free_text(T("h_objectives", lang), scope),
            _targets(scan_results, lang),
            _owasp_methodology(result, lang),
            _scale_table(lang),
            overview,
            findings_summary,
            _free_text(T("h_recommendation", lang), recommendation),
        ])
    else:  # technical
        main = f"""
        <div class="section pb">
          <h2>{_esc(T('h_results', lang))}</h2>
          <p>{_esc(T('results_intro', lang))}</p>
          {_findings_by_ip_table(findings, lang, with_detail=True, options=options)}
        </div>"""
        body = "".join([
            _free_text(T("h_limitation", lang), intro),
            _owasp_methodology(result, lang),
            _scale_table(lang),
            _free_text(T("h_objectives", lang), scope),
            _targets(scan_results, lang),
            _tools_table(options, lang),
            overview,
            main,
            findings_summary,
            _free_text(T("h_summary", lang), summary_txt),
            _free_text(T("h_conclusion", lang), conclusion),
        ])

    foot = (f'<div class="section" style="margin-top:18px;color:{MUTED};font-size:10px;'
            f'border-top:1px solid #ddd;padding-top:6px;">'
            f'{_esc(T("generated_by", lang))} {_esc(meta.get("tool","NMAP Scanner — PT Lab"))} · '
            f'{_esc(meta.get("date",""))}</div>')

    return f"""<!DOCTYPE html><html lang="{lang}"><head><meta charset="utf-8">
    <title>{_esc(meta.get('title', T('report', lang)))}</title><style>{_css()}</style></head>
    <body>
      {_running_frame(lang)}
      {_cover(meta, options, lang)}
      <div class="pb"></div>
      {body}
      {foot}
    </body></html>"""


# Zpětná kompatibilita se starým voláním (5.6.0 dialog)
def build_html(meta, result, options=None):
    options = dict(options or {})
    options.setdefault("report_type", "technical")
    return build_report(meta, result, options)
