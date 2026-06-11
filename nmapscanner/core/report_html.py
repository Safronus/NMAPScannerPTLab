"""Generování HTML reportu — moderní vzhled s akcenty PT Lab.

Bezpatkové písmo, výrazná titulní strana (červený akcent + „Confidential"),
Executive summary box, OWASP/CVSS metodika, nálezy jako kombinace souhrnné
tabulky per IP + karet pro HIGH/CRITICAL. Dva typy (technical/management) a dva
jazyky (cs/en). Bez Qt → testovatelné.

Opakující se hlavička (logo + adresa + „N stran"), patička („SENSITIVE DATA" +
čísla stran) a volitelný obsah (TOC) se dokreslují post-processingem
(``core/report_pdf.py``) — QtWebEngine je v HTML přes ``position: fixed``
renderuje nespolehlivě. Okraje řídí QPageLayout v ``printToPdf``.
"""

import html as _html

from .report_classify import (
    SEVERITIES, SEVERITY_RANK, SEVERITY_COLOR, CVSS_BAND, OWASP_2025, section_title,
    ALL_SECTIONS,
)

# Paleta PT Lab (moderní)
RED = "#E2231A"
RED_DARK = "#B3160F"
NAVY = "#16233f"
INK = "#222831"
MUTED = "#6b7280"
LINE = "#e5e7eb"
BG_SOFT = "#f7f8fa"


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
    "confidential": ("DŮVĚRNÉ", "CONFIDENTIAL"),
    "engagement": ("Penetrační test infrastruktury", "Penetration testing of infrastructure"),
    "prepared_by": ("Zpracoval", "Prepared by"),
    "client": ("Klient / rozsah", "Client / scope"),
    "date": ("Datum", "Date"),
    "project": ("Projekt", "Project"),
    "version": ("Verze dat", "Data version"),

    "h_exec": ("Shrnutí pro vedení", "Executive summary"),
    "exec_intro": ("Stručný přehled výsledků testu a celkového rizika.",
                   "A brief overview of the test results and overall risk."),
    "verdict_crit": ("Byly zjištěny kritické nálezy vyžadující okamžitou nápravu.",
                     "Critical findings requiring immediate remediation were identified."),
    "verdict_high": ("Byly zjištěny nálezy vysoké závažnosti k prioritní nápravě.",
                     "High-severity findings requiring priority remediation were identified."),
    "verdict_med": ("Byly zjištěny nálezy střední závažnosti k nápravě.",
                    "Medium-severity findings to remediate were identified."),
    "verdict_low": ("Byly zjištěny pouze drobné / informativní nálezy.",
                    "Only minor / informational findings were identified."),
    "verdict_none": ("Nebyly zjištěny žádné nálezy odpovídající filtrům.",
                     "No findings matching the filters were identified."),
    "found_total": ("Celkem nálezů", "Total findings"),

    "h_limitation": ("1. Omezení reportu", "1. Report limitation"),
    "limitation_default": (
        "Tento report nepokrývá veškeré existující zranitelnosti IT infrastruktury, "
        "ale zaměřuje se pouze na testy odsouhlasené zadavatelem. Report rovněž "
        "nezaručuje bezpečnost systémů vůči zranitelnostem objeveným po provedení testů.",
        "This report does not cover all existing vulnerabilities of the IT infrastructure, "
        "but focuses only on the tests agreed with the client. The report also does not "
        "guarantee the security of systems against vulnerabilities discovered after the tests."),
    "h_owasp": ("2. Testované zranitelnosti (OWASP Top 10:2025)",
                "2. Vulnerabilities tested (OWASP Top 10:2025)"),
    "owasp_intro": (
        "Následující kategorie odpovídají metodice OWASP Top 10:2025, podle které byla "
        "infrastruktura testována (✓ = kategorie s nálezem).",
        "The following categories follow the OWASP Top 10:2025 methodology used to test "
        "the infrastructure (✓ = category with a finding)."),
    "h_scale": ("3. Klasifikační stupnice (CVSS v4.0)", "3. Classification scale (CVSS v4.0)"),
    "scale_intro": ("Závažnost nálezů je zarovnaná na kvalitativní pásma CVSS v4.0.",
                    "Finding severity is aligned with the CVSS v4.0 qualitative bands."),
    "col_risk": ("Riziko", "Risk"), "col_name": ("Název", "Name"),
    "col_desc": ("Popis", "Description"), "col_score": ("CVSS", "CVSS"),
    "col_cat": ("Kat.", "Cat."), "col_ip": ("IP", "IP"), "col_ports": ("Port", "Port"),
    "col_service": ("Oblast", "Area"), "col_vuln": ("Nález", "Finding"),
    "col_count": ("Počet", "Count"), "col_tool": ("Nástroj", "Tool"),
    "col_version": ("Verze", "Version"), "col_purpose": ("Účel", "Purpose"),

    "h_objectives": ("4. Specifikace cílů", "4. Specification of objectives"),
    "scope_default": (
        "Náplní testu bylo ověřit odolnost poskytnuté infrastruktury a detekovat "
        "zranitelná místa na serverech.",
        "The purpose of the test was to verify the resilience of the provided "
        "infrastructure and to detect vulnerable spots on the servers."),
    "h_targets": ("4.1. Testované IP adresy", "4.1. Tested IP addresses"),
    "targets_intro": ("K testování byly poskytnuty následující cílové IP adresy:",
                      "The following destination IP addresses were provided for testing:"),
    "h_tools": ("4.2. Použité nástroje", "4.2. Tools used"),
    "tools_intro": ("Při testování byly použity následující nástroje:",
                    "The following tools were used during the testing:"),
    "h_results": ("5. Výsledky testů – nalezené zranitelnosti",
                  "5. Test results – discovered vulnerabilities"),
    "results_intro": ("Tato sekce obsahuje souhrn nálezů a detail nálezů vysoké závažnosti.",
                      "This section contains a summary of findings and detail of high-severity findings."),
    "h_results_table": ("5.1. Souhrn nálezů dle cílů", "5.1. Findings summary by target"),
    "h_results_detail": ("5.2. Detail nálezů (HIGH / CRITICAL)",
                         "5.2. Finding detail (HIGH / CRITICAL)"),
    "detail_note": ("Detailně jsou rozepsány nálezy vysoké a kritické závažnosti; "
                    "ostatní nálezy jsou v souhrnné tabulce výše.",
                    "High and critical findings are detailed below; other findings are in "
                    "the summary table above."),
    "h_findings_table": ("Seznam nálezů (IP / port / oblast / nález)",
                         "List of findings (IP / port / area / finding)"),
    "h_summary": ("6. Shrnutí", "6. Summary"),
    "summary_default": (
        "Cílem testu bylo zjistit odolnost infrastruktury zadavatele a detekovat zranitelná "
        "místa na serverech. Infrastruktura byla testována dle metodiky OWASP a aktuálního "
        "seznamu TOP 10:2025. Pro stanovení závažnosti byl použit systém CVSS v4.0.",
        "The aim of the test was to determine the resilience of the client's infrastructure "
        "and to detect vulnerable spots on the servers. The infrastructure was tested per the "
        "OWASP methodology and the current TOP 10:2025 list. CVSS v4.0 was used for severity."),
    "h_conclusion": ("7. Závěr", "7. Conclusion"),
    "conclusion_default": (
        "Je zásadní zaměřit se především na nálezy s vysokou závažností. Po nápravě "
        "doporučujeme provést opětovné ověření (re-test).",
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
    "comment": ("Komentář", "Comment"), "recommendation": ("Doporučení", "Recommendation"),
    "impact": ("Dopad", "Impact"),
    "evidence": ("Důkaz", "Evidence"), "generated_by": ("Vygenerováno nástrojem", "Generated by"),
    "by_area": ("Nálezy podle oblasti", "Findings by area"),
}

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

SEV_LABEL = {"CRITICAL": "C", "HIGH": "H", "MEDIUM": "M", "LOW": "L", "INFO": "I"}


# ===========================================================================
#  CSS (moderní, bezpatkové)
# ===========================================================================
def _css():
    sev_bg = "\n".join(
        f".sev-{s.lower()}{{background:{SEVERITY_COLOR[s]};color:#fff;}}" for s in SEVERITIES
    )
    return f"""
    @page {{ size: A4; margin: 0; }}
    * {{ box-sizing: border-box; }}
    body {{ font-family: 'Helvetica Neue', Arial, 'Segoe UI', system-ui, sans-serif;
            color: {INK}; font-size: 11.5px; line-height: 1.55; margin: 0; }}
    h1,h2,h3,h4 {{ margin: 0 0 6px 0; }}
    p {{ margin: 6px 0; }}
    ul {{ margin: 6px 0; padding-left: 20px; }}
    a {{ color: {RED_DARK}; text-decoration: none; }}

    /* Titulní strana */
    .cover {{ position: relative; }}
    .cover .kicker {{ margin-top: 58mm; color: {RED}; font-weight: 700; letter-spacing: 3px;
                      text-transform: uppercase; font-size: 12px; }}
    .cover h1 {{ font-size: 40px; font-weight: 800; color: {NAVY}; margin: 6px 0 2px; }}
    .cover .rule {{ width: 70px; height: 4px; background: {RED}; margin: 14px 0 22px; }}
    .cover .info {{ font-size: 13px; }}
    .cover .info .k {{ color: {MUTED}; width: 130px; display: inline-block; vertical-align: top; }}
    .cover .info .v {{ color: {INK}; font-weight: 600; }}
    .cover .info div {{ margin: 5px 0; }}
    .cover .conf {{ display: inline-block; margin-top: 28px; border: 2px solid {RED};
                    color: {RED}; font-weight: 800; letter-spacing: 2px; padding: 6px 14px;
                    border-radius: 4px; transform: rotate(-3deg); }}

    .section {{ margin: 16px 0; }}
    h2 {{ color: {NAVY}; font-size: 16px; font-weight: 800; border-left: 5px solid {RED};
          padding-left: 9px; margin-top: 18px; }}
    h3 {{ color: {NAVY}; font-size: 13px; font-weight: 700; margin-top: 12px; }}
    .lead {{ color: {MUTED}; }}

    table {{ border-collapse: collapse; width: 100%; font-size: 11px; margin: 8px 0; }}
    th, td {{ border: 1px solid {LINE}; padding: 5px 8px; text-align: left; vertical-align: top; }}
    th {{ background: {NAVY}; color: #fff; font-weight: 600; }}
    tr:nth-child(even) td {{ background: {BG_SOFT}; }}
    .scale th {{ background: {RED_DARK}; }}

    .risk-cell {{ text-align: center; font-weight: 800; width: 42px; }}
    {sev_bg}
    .chip {{ display:inline-block; color:#fff; font-weight:700; font-size:9.5px;
             padding:1px 8px; border-radius:10px; letter-spacing:.3px; }}
    .owasp {{ display:inline-block; background:{NAVY}; color:#fff; font-size:9.5px;
              padding:1px 6px; border-radius:3px; font-weight:700; }}
    .cwe {{ display:inline-block; background:#eef1f6; color:{NAVY}; font-size:9.5px;
            padding:1px 6px; border-radius:3px; font-weight:700; }}

    /* Executive summary */
    .exec {{ border: 1px solid {LINE}; border-top: 4px solid {RED}; border-radius: 8px;
             padding: 14px 16px; background: #fff; margin: 10px 0 4px; }}
    .exec h2 {{ border: none; padding: 0; margin: 0 0 6px; }}
    .exec .verdict {{ font-size: 13px; font-weight: 600; color: {INK}; margin: 8px 0 12px; }}

    .cards {{ display:flex; gap:8px; margin:10px 0; }}
    .scard {{ flex:1; color:#fff; border-radius:8px; padding:10px 8px; text-align:center; }}
    .scard .n {{ font-size:24px; font-weight:800; line-height:1; }}
    .scard .l {{ font-size:9.5px; text-transform:uppercase; letter-spacing:.6px; margin-top:4px; }}

    /* Karta nálezu */
    .fcard {{ border:1px solid {LINE}; border-left:6px solid {MUTED}; border-radius:8px;
              padding:11px 13px; margin:10px 0; page-break-inside:avoid; }}
    .fcard .top {{ display:flex; justify-content:space-between; align-items:center; gap:8px; }}
    .fcard .ttl {{ font-weight:800; color:{NAVY}; font-size:12.5px; }}
    .fcard .meta {{ margin:5px 0; }}
    .fcard .lbl {{ color:{MUTED}; font-size:10px; text-transform:uppercase; letter-spacing:.5px; }}
    pre {{ background:#0f172a; color:#dbe5f5; padding:8px 10px; border-radius:6px;
           font-size:10px; white-space:pre-wrap; word-break:break-word; overflow-wrap:anywhere;
           margin:5px 0 0; font-family:'SF Mono',Menlo,Consolas,monospace; }}
    .rec {{ background:#fff5f3; border:1px solid #ffd6cc; border-radius:6px; padding:6px 9px; margin-top:6px; }}
    .cmt {{ background:#eef4ff; border:1px solid #cfe0fb; border-radius:6px; padding:6px 9px; margin-top:6px; }}

    .heat {{ display:grid; grid-template-columns:repeat(5,1fr); gap:6px; margin:8px 0; }}
    .pb {{ page-break-before: always; }}
    .avoid {{ page-break-inside: avoid; }}
    """


# ===========================================================================
#  Pomocné
# ===========================================================================
def _ip_of(target):
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


def _sev_chip(sev):
    return f'<span class="chip" style="background:{SEVERITY_COLOR[sev]}">{_esc(sev)}</span>'


def _owasp_chip(code):
    return f'<span class="owasp">{_esc(code)}</span>' if code else ""


# ===========================================================================
#  Sekce
# ===========================================================================
def _cover(meta, options, lang):
    rtype = options.get("report_type", "technical")
    sub = T("management_sub" if rtype == "management" else "technical_sub", lang)
    rows = [
        (T("client", lang), meta.get("client", "—")),
        (T("project", lang), meta.get("project_name", "—")),
        (T("prepared_by", lang), meta.get("author", "—")),
        (T("date", lang), meta.get("date", "—")),
    ]
    if meta.get("run_info") and meta["run_info"] != "—":
        rows.append((T("version", lang), meta["run_info"]))
    info = "".join(f'<div><span class="k">{_esc(k)}</span>'
                   f'<span class="v">{_esc(v)}</span></div>' for k, v in rows)
    return f"""
    <div class="cover">
      <div class="kicker">{_esc(sub)}</div>
      <h1>{_esc(meta.get('title', T('report', lang)))}</h1>
      <div class="rule"></div>
      <div class="info">{info}</div>
      <div class="conf">{_esc(T('confidential', lang))}</div>
    </div>"""


def _severity_cards(summary):
    cards = ""
    for s in SEVERITIES:
        cards += (f'<div class="scard sev-{s.lower()}"><div class="n">{summary.get(s,0)}</div>'
                  f'<div class="l">{_esc(s)}</div></div>')
    return f'<div class="cards">{cards}</div>'


def _verdict(summary, lang):
    if summary.get("CRITICAL", 0) > 0:
        return T("verdict_crit", lang)
    if summary.get("HIGH", 0) > 0:
        return T("verdict_high", lang)
    if summary.get("MEDIUM", 0) > 0:
        return T("verdict_med", lang)
    if any(summary.get(s, 0) for s in ("LOW", "INFO")):
        return T("verdict_low", lang)
    return T("verdict_none", lang)


def _exec_summary(result, lang):
    summary = result.get("summary", {})
    total = result.get("total", 0)
    return f"""
    <div class="exec avoid">
      <h2>{_esc(T('h_exec', lang))}</h2>
      <div class="lead">{_esc(T('exec_intro', lang))}</div>
      <div class="verdict">{_esc(T('found_total', lang))}: <b>{total}</b>. {_esc(_verdict(summary, lang))}</div>
      {_severity_cards(summary)}
    </div>"""


def _scale_table(lang):
    rows = ""
    for s in SEVERITIES:
        rows += (f'<tr><td class="risk-cell sev-{s.lower()}">{SEV_LABEL[s]}</td>'
                 f'<td><b>{_esc(s)}</b></td><td>{_esc(CVSS_BAND[s])}</td>'
                 f'<td>{_esc(CVSS_NOTE[s][1 if lang=="en" else 0])}</td></tr>')
    return f"""<div class="section"><h2>{_esc(T('h_scale', lang))}</h2>
      <p class="lead">{_esc(T('scale_intro', lang))}</p>
      <table class="scale"><tr><th>{_esc(T('col_risk', lang))}</th><th>{_esc(T('col_name', lang))}</th>
      <th>{_esc(T('col_score', lang))}</th><th>{_esc(T('col_desc', lang))}</th></tr>{rows}</table></div>"""


def _owasp_methodology(result, lang):
    used = set(result.get("owasp", {}).keys())
    rows = ""
    for code, name in OWASP_2025.items():
        mark = ' <span class="chip" style="background:%s">✓</span>' % RED if code in used else ""
        rows += (f'<tr><td><span class="owasp">{code}</span></td>'
                 f'<td><b>{_esc(name)}</b>{mark}<br>'
                 f'<span class="lead">{_esc(OWASP_DESC[code][1 if lang=="en" else 0])}</span></td></tr>')
    return f"""<div class="section"><h2>{_esc(T('h_owasp', lang))}</h2>
      <p class="lead">{_esc(T('owasp_intro', lang))}</p>
      <table><tr><th style="width:46px">{_esc(T('col_cat', lang))}</th>
      <th>{_esc(T('col_name', lang))}</th></tr>{rows}</table></div>"""


def _targets(scan_results, lang):
    ips = sorted((scan_results.get("tcp", {}) or {}).keys())
    items = "".join(f"<li>{_esc(ip)}</li>" for ip in ips) or "<li>—</li>"
    return f"""<div class="section"><h3>{_esc(T('h_targets', lang))}</h3>
      <p>{_esc(T('targets_intro', lang))}</p><ul>{items}</ul></div>"""


def _tools_table(options, lang):
    tools = options.get("tools") or []
    if not tools:
        return ""
    rows = "".join(f"<tr><td>{_esc(t.get('name',''))}</td><td>{_esc(t.get('version','—'))}</td>"
                   f"<td>{_esc(t.get('purpose',''))}</td></tr>" for t in tools)
    return f"""<div class="section"><h3>{_esc(T('h_tools', lang))}</h3>
      <p>{_esc(T('tools_intro', lang))}</p>
      <table><tr><th>{_esc(T('col_tool', lang))}</th><th>{_esc(T('col_version', lang))}</th>
      <th>{_esc(T('col_purpose', lang))}</th></tr>{rows}</table></div>"""


def _findings_summary_table(findings, lang):
    if not findings:
        return f'<p class="lead">{_esc(T("no_findings", lang))}</p>'
    rows = ""
    for f in findings:
        sev = f["severity"]
        rows += (f'<tr><td>{_esc(_ip_of(f["target"]))}</td>'
                 f'<td>{_esc(_port_of(f["target"]) or "—")}</td>'
                 f'<td>{_esc(f["category"])}</td>'
                 f'<td>{_owasp_chip(f.get("owasp"))} {_esc(f["title"])}</td>'
                 f'<td class="risk-cell sev-{sev.lower()}">{SEV_LABEL[sev]}</td></tr>')
    return f"""<table><tr><th>{_esc(T('col_ip', lang))}</th><th>{_esc(T('col_ports', lang))}</th>
      <th>{_esc(T('col_service', lang))}</th><th>{_esc(T('col_vuln', lang))}</th>
      <th style="width:42px">{_esc(T('col_risk', lang))}</th></tr>{rows}</table>"""


def _finding_card(f, lang, options, comments):
    sev = f["severity"]
    cwe = ""
    ev = f.get("evidence", "")
    for line in ev.splitlines():
        if line.strip().upper().startswith("CWE-"):
            cwe = f'<span class="cwe">{_esc(line.strip())}</span>'
            break
    parts = [
        f'<div class="fcard" style="border-left-color:{SEVERITY_COLOR[sev]}">',
        '<div class="top">',
        f'<span class="ttl">{_esc(f["id"])} — {_esc(f["title"])}</span>',
        f'<span>{_sev_chip(sev)}</span></div>',
        f'<div class="meta">{_owasp_chip(f.get("owasp"))} '
        f'<span class="lbl">{_esc(f.get("owasp_name",""))}</span> {cwe} '
        f'&nbsp;·&nbsp; <span class="lbl">{_esc(f["category"])}</span> '
        f'&nbsp;·&nbsp; <b>{_esc(f["target"])}</b></div>',
        f'<div>{_esc(f["description"])}</div>',
    ]
    if f.get("impact"):
        parts.append(f'<div class="meta"><span class="lbl">{_esc(T("impact", lang))}:</span> '
                     f'{_esc(f["impact"])}</div>')
    if options.get("include_evidence", True) and ev:
        parts.append(f'<pre>{_nl2br(ev)}</pre>')
    if options.get("include_recommendations", True) and f.get("recommendation"):
        parts.append(f'<div class="rec"><span class="lbl">{_esc(T("recommendation", lang))}</span><br>'
                     f'{_esc(f["recommendation"])}</div>')
    cmt = f.get("comment") or comments.get(f["id"])
    if cmt:
        parts.append(f'<div class="cmt"><span class="lbl">{_esc(T("comment", lang))}</span><br>'
                     f'{_nl2br(cmt)}</div>')
    parts.append("</div>")
    return "".join(parts)


def results_subsections(result, lang):
    """Podsekce výsledků dle typu testu (jen ty, co mají nález) — pořadí + nadpisy
    „5.N <Oblast>". Sdílené reportem i obsahem (TOC)."""
    by_section = {}
    for f in result.get("findings", []):
        by_section.setdefault(f.get("section", ""), []).append(f)
    out = []
    n = 0
    for sec in ALL_SECTIONS:
        if by_section.get(sec):
            n += 1
            out.append((sec, f"5.{n}. {section_title(sec, lang)}", by_section[sec]))
    return out


def _section_ip_table(items, lang):
    """Kompaktní tabulka nálezů pro jeden cíl v rámci typu testu: Port | Nález | Riziko."""
    rows = ""
    for f in sorted(items, key=lambda x: SEVERITY_RANK[x["severity"]]):
        sev = f["severity"]
        owasp_html = f'<span class="owasp">{_esc(f["owasp"])}</span> ' if f.get("owasp") else ""
        rows += (f'<tr><td>{_esc(_port_of(f["target"]) or "—")}</td>'
                 f'<td>{owasp_html}{_esc(f["title"])}</td>'
                 f'<td class="risk-cell sev-{sev.lower()}">{SEV_LABEL[sev]}</td></tr>')
    return (f'<table><tr><th style="width:60px">{_esc(T("col_ports", lang))}</th>'
            f'<th>{_esc(T("col_vuln", lang))}</th>'
            f'<th style="width:42px">{_esc(T("col_risk", lang))}</th></tr>{rows}</table>')


def _technical_results(result, lang, options):
    findings = result.get("findings", [])
    comments = options.get("comments", {}) or {}
    if not findings:
        return (f'<div class="section pb"><h2>{_esc(T("h_results", lang))}</h2>'
                f'<p class="lead">{_esc(T("no_findings", lang))}</p></div>')

    blocks = ""
    for sec, heading, secf in results_subsections(result, lang):
        blocks += f'<h3>{_esc(heading)}</h3>'
        # uvnitř typu testu: dle cíle (IP), seřazené dle závažnosti
        by_ip = {}
        for f in secf:
            by_ip.setdefault(_ip_of(f["target"]), []).append(f)
        for ip in sorted(by_ip.keys()):
            blocks += (f'<h4 style="color:{NAVY};font-size:12px;margin:8px 0 2px;">{_esc(ip)}</h4>'
                       f'{_section_ip_table(by_ip[ip], lang)}')
        # detailní karty pro HIGH/CRITICAL v tomto typu testu
        cards = [_finding_card(f, lang, options, comments)
                 for f in sorted(secf, key=lambda x: SEVERITY_RANK[x["severity"]])
                 if f["severity"] in ("CRITICAL", "HIGH")]
        if cards:
            blocks += "".join(cards)

    return (f'<div class="section pb"><h2>{_esc(T("h_results", lang))}</h2>'
            f'<p class="lead">{_esc(T("results_intro", lang))} {_esc(T("detail_note", lang))}</p>'
            f'{blocks}</div>')


def _counts_list(findings, lang):
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
        out += f'<p>{_sev_chip(s)} ({len(items)})</p><ul>{lis}</ul>'
    return out


def _free_text(title, body):
    return f'<div class="section"><h2>{_esc(title)}</h2><p>{_nl2br(body)}</p></div>'


# ===========================================================================
#  Sestavení
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

    inc_exec = options.get("include_exec", True)
    inc_method = options.get("include_methodology", True)
    inc_charts = options.get("include_charts", True)

    exec_box = _exec_summary(result, lang) if inc_exec else ""

    findings_summary = ""
    if inc_charts:
        sec_rows = "".join(
            f"<tr><td>{_esc(section_title(k, lang)) if False else _esc(k)}</td>"
            f"<td style='text-align:center'>{v}</td></tr>"
            for k, v in sorted(result.get("sections", {}).items()))
        by_area = (f'<h3>{_esc(T("by_area", lang))}</h3>'
                   f'<table><tr><th>{_esc(T("col_service", lang))}</th>'
                   f'<th style="width:60px">{_esc(T("col_count", lang))}</th></tr>{sec_rows}</table>'
                   ) if sec_rows else ""
    else:
        by_area = ""

    findings_table_block = (
        f'<div class="section"><h2>{_esc(T("h_findings_table", lang))}</h2>'
        f'{_findings_summary_table(findings, lang)}'
        f'<h3>{_esc(T("sev_counts", lang))}</h3>{_counts_list(findings, lang)}{by_area}</div>')

    if rtype == "management":
        body = "".join([
            exec_box,
            _free_text(T("h_objectives", lang), scope),
            _targets(scan_results, lang),
            (_owasp_methodology(result, lang) + _scale_table(lang)) if inc_method else "",
            findings_table_block,
            _free_text(T("h_recommendation", lang), recommendation),
        ])
    else:
        body = "".join([
            exec_box,
            _free_text(T("h_limitation", lang), intro),
            (_owasp_methodology(result, lang) + _scale_table(lang)) if inc_method else "",
            _free_text(T("h_objectives", lang), scope),
            _targets(scan_results, lang),
            _tools_table(options, lang),
            _technical_results(result, lang, options),
            findings_table_block,
            _free_text(T("h_summary", lang), summary_txt),
            _free_text(T("h_conclusion", lang), conclusion),
        ])

    foot = (f'<div class="section" style="margin-top:18px;color:{MUTED};font-size:9.5px;'
            f'border-top:1px solid {LINE};padding-top:6px;">'
            f'{_esc(T("generated_by", lang))} {_esc(meta.get("tool","NMAP Scanner — PT Lab"))} · '
            f'{_esc(meta.get("date",""))}</div>')

    return f"""<!DOCTYPE html><html lang="{lang}"><head><meta charset="utf-8">
    <title>{_esc(meta.get('title', T('report', lang)))}</title><style>{_css()}</style></head>
    <body>
      {_cover(meta, options, lang)}
      <div class="pb"></div>
      {body}
      {foot}
    </body></html>"""


def toc_headings(result, options, lang):
    """Seznam nadpisů pro obsah (TOC) ve stejném pořadí, jak je emituje build_report.

    Vrací ``[(title, level)]`` (level 0 = kapitola, 1 = podkapitola). Post-processing
    pak v textu stran dohledá, na které straně nadpis je.
    """
    options = options or {}
    rtype = options.get("report_type", "technical")
    inc_exec = options.get("include_exec", True)
    inc_method = options.get("include_methodology", True)
    has_detail = any(f["severity"] in ("CRITICAL", "HIGH") for f in result.get("findings", []))

    h = []
    if inc_exec:
        h.append((T("h_exec", lang), 0))
    if rtype == "management":
        h.append((T("h_objectives", lang), 0))
        h.append((T("h_targets", lang), 1))
        if inc_method:
            h.append((T("h_owasp", lang), 0))
            h.append((T("h_scale", lang), 0))
        h.append((T("h_findings_table", lang), 0))
        h.append((T("h_recommendation", lang), 0))
    else:
        h.append((T("h_limitation", lang), 0))
        if inc_method:
            h.append((T("h_owasp", lang), 0))
            h.append((T("h_scale", lang), 0))
        h.append((T("h_objectives", lang), 0))
        h.append((T("h_targets", lang), 1))
        if options.get("tools"):
            h.append((T("h_tools", lang), 1))
        h.append((T("h_results", lang), 0))
        for _sec, heading, _items in results_subsections(result, lang):
            h.append((heading, 1))
        h.append((T("h_findings_table", lang), 0))
        h.append((T("h_summary", lang), 0))
        h.append((T("h_conclusion", lang), 0))
    return h


def toc_title(lang):
    return ("Obsah", "Table of contents")[1 if lang == "en" else 0]


def build_html(meta, result, options=None):
    options = dict(options or {})
    options.setdefault("report_type", "technical")
    return build_report(meta, result, options)
