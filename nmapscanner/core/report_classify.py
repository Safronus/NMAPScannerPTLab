"""Klasifikace výsledků skenu do nálezů se závažností + mapování na OWASP/CVSS.

Čistá logika **bez Qt**, aby šla samostatně testovat (``tests/test_report_classify.py``).
Z agregovaného ``scan_results`` (viz ``app.py``) vyrobí seznam nálezů, kde každý
nález má:

* **závažnost** dle stupnice INFO / LOW / MEDIUM / HIGH / CRITICAL, zarovnané na
  kvalitativní pásma **CVSS v4.0** (None 0.0 · Low 0.1–3.9 · Medium 4.0–6.9 ·
  High 7.0–8.9 · Critical 9.0–10.0),
* **kategorii OWASP Top 10:2025** (A01–A10) — aktuální vydání metodiky.

Texty nálezů jsou **dvojjazyčné (CZ/EN)** — ``build_findings(..., lang="cs"|"en")``.
Klasifikace je záměrně **konzervativní a transparentní**: jde o orientační
ohodnocení útočné plochy z pohledu síťového/web skenu, ne o per-CVE CVSS vektor.
"""

from urllib.parse import urlparse

from .tls_grading import calculate_grade
from .vuln_classify import classify_vuln_output
from . import classification_library as lib

# --- Stupnice závažnosti (pořadí = priorita) -------------------------------
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # 0 = nejvyšší

SEVERITY_COLOR = {
    "CRITICAL": "#7030A0",   # fialová
    "HIGH": "#C00000",       # červená
    "MEDIUM": "#BF9000",     # tmavě žlutá
    "LOW": "#1F9E4F",        # zelená
    "INFO": "#2E75B6",       # modrá
}

# Orientační pásma CVSS v4.0 pro každou úroveň (text do metodiky)
CVSS_BAND = {
    "CRITICAL": "9.0–10.0",
    "HIGH": "7.0–8.9",
    "MEDIUM": "4.0–6.9",
    "LOW": "0.1–3.9",
    "INFO": "0.0",
}

# --- OWASP Top 10:2025 (oficiální anglické názvy) --------------------------
OWASP_2025 = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging and Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}


def _t(val, lang):
    """Resolve dvojjazyčné hodnoty: (cs, en) tuple → text dle lang; jinak val."""
    if isinstance(val, (tuple, list)) and len(val) == 2:
        return val[1] if lang == "en" else val[0]
    return val


def worst(severities):
    """Nejvyšší závažnost ze seznamu (nebo 'INFO', když je prázdný)."""
    best = "INFO"
    for s in severities:
        if SEVERITY_RANK.get(s, 99) < SEVERITY_RANK[best]:
            best = s
    return best


# ===========================================================================
#  Kategorie (CZ/EN) a názvy sekcí
# ===========================================================================
CATEGORY = {
    "ports": ("Otevřené porty", "Open ports"),
    "services": ("Identifikace služeb", "Service identification"),
    "vulns": ("Zranitelnosti (nmap)", "Vulnerabilities (nmap)"),
    "tls": ("TLS audit", "TLS audit"),
    "headers": ("Bezpečnostní hlavičky", "Security headers"),
    "ffuf": ("Directory fuzzing (ffuf)", "Directory fuzzing (ffuf)"),
    "webserver": ("Webserver", "Web server"),
    "zap": ("OWASP ZAP", "OWASP ZAP"),
}

# Pozn.: severity + OWASP + doporučení nově pocházejí z referenční knihovny
# (core/classification_library.py + data/classification_library.json), která je
# editovatelná. Níže zůstaly jen popisné/odvozené konstanty, pokud jsou potřeba.

# ===========================================================================
#  Stavitelé nálezů
# ===========================================================================
def _mk(idx, title, severity, owasp, category, target, description,
        lang, evidence="", recommendation="", impact=""):
    imp = _t(impact, lang) or lib.impact_for_severity(severity, lang)
    return {
        "id": f"F-{idx:03d}",
        "title": _t(title, lang),
        "severity": severity,
        "owasp": owasp,
        "owasp_name": OWASP_2025.get(owasp, "") if owasp else "",
        "category": _t(category, lang),
        "target": target,
        "description": _t(description, lang),
        "evidence": evidence,
        "recommendation": _t(recommendation, lang),
        "impact": imp,
    }


import re as _re
_CVE_RE = _re.compile(r"CVE-\d{4}-\d{4,7}", _re.IGNORECASE)


def _first_cve(text):
    m = _CVE_RE.search(text or "")
    return m.group(0).upper() if m else ""


def _iter_open_ports(scan_results, proto):
    phase = scan_results.get(proto, {}) or {}
    for ip, ip_data in phase.items():
        if not isinstance(ip_data, dict):
            continue
        ports = ip_data.get(proto, {}) or {}
        for port, info in ports.items():
            if not isinstance(info, dict) or info.get("state") != "open":
                continue
            try:
                pnum = int(port)
            except (TypeError, ValueError):
                continue
            yield ip, pnum, info


def build_ports(scan_results, start_idx=1, lang="cs"):
    out = []
    idx = start_idx
    for proto in ("tcp", "udp"):
        for ip, pnum, info in _iter_open_ports(scan_results, proto):
            name = (info.get("name") or "").lower()
            # Klasifikace z referenční knihovny: port → služba (klíč) → default
            rule = lib.port_rule(pnum, lang) or lib.service_keyword_rule(name, lang) \
                or lib.port_default(lang)
            sev, owasp, rec = rule["severity"], rule["owasp"], rule["recommendation"]
            label = rule.get("name") or name
            product = " ".join(x for x in [info.get("product", ""), info.get("version", "")] if x).strip()
            ev = f"{proto.upper()} {pnum} ({name or '?'})"
            if product:
                ev += f" — {product}"
            if info.get("extrainfo"):
                ev += f" [{info['extrainfo']}]"
            title = (f"Otevřený port {pnum}/{proto} — {name or 'neznámá služba'}",
                     f"Open port {pnum}/{proto} — {name or 'unknown service'}")
            full_desc = (f"Otevřená služba: {label}.", f"Open service: {label}.")
            out.append(_mk(idx, title, sev, owasp, CATEGORY["ports"], f"{ip}:{pnum}",
                           full_desc, lang, evidence=ev, recommendation=rec,
                           impact=rule.get("impact", "")))
            idx += 1
    return out, idx


def build_services(scan_results, start_idx=1, lang="cs"):
    out = []
    idx = start_idx
    for proto in ("tcp", "udp"):
        for ip, pnum, info in _iter_open_ports(scan_results, proto):
            product = info.get("product", "").strip()
            version = info.get("version", "").strip()
            if not product and not version:
                continue
            banner = " ".join(x for x in [product, version] if x).strip()
            rule = lib.service_version_rule(bool(version), lang)
            title = (f"Zveřejnění verze služby — {banner}",
                     f"Service version disclosure — {banner}")
            desc = ("Služba prozrazuje produkt a verzi, což usnadňuje útočníkovi "
                    "vyhledání známých zranitelností.",
                    "The service discloses product and version, which helps an attacker "
                    "look up known vulnerabilities.")
            ev = (f"{proto.upper()} {pnum}: {banner}"
                  + (f" {info.get('extrainfo')}" if info.get("extrainfo") else ""))
            out.append(_mk(idx, title, rule["severity"], rule["owasp"], CATEGORY["services"],
                           f"{ip}:{pnum}", desc, lang, evidence=ev,
                           recommendation=rule["recommendation"]))
            idx += 1
    return out, idx


def build_vulns(scan_results, start_idx=1, lang="cs"):
    out = []
    idx = start_idx
    vuln = scan_results.get("vuln", {}) or {}
    for ip, ip_data in vuln.items():
        if not isinstance(ip_data, dict):
            continue
        for proto in ("tcp", "udp"):
            ports = ip_data.get(proto, {}) or {}
            for port, info in ports.items():
                scripts = (info or {}).get("script", {}) or {}
                for sname, output in scripts.items():
                    if classify_vuln_output(output) != "finding":
                        continue
                    up = (output or "").upper()
                    has_cve = "CVE" in up
                    cve_id = _first_cve(output)
                    # Klasifikace z knihovny (vuln rule), případně konkrétní CVE
                    rule = lib.vuln_rule(has_cve, lang)
                    sev, owasp, rec = rule["severity"], rule["owasp"], rule["recommendation"]
                    cve_rule = lib.cve_rule(cve_id, lang) if cve_id else None
                    if cve_rule:
                        sev, owasp, rec = cve_rule["severity"], cve_rule["owasp"], cve_rule["recommendation"]
                    elif any(k in up for k in ("REMOTE CODE EXECUTION", " RCE", "CRITICAL", "UNAUTHENTICATED")):
                        sev = "CRITICAL"
                    snippet = (output or "").strip()
                    if len(snippet) > 600:
                        snippet = snippet[:600] + " …"
                    title = (f"Potvrzená zranitelnost: {sname}", f"Confirmed vulnerability: {sname}")
                    if has_cve:
                        desc = ("Nmap vuln skript potvrdil zranitelnost služby. Souvisí se "
                                "známou CVE / zastaralou komponentou.",
                                "An nmap vuln script confirmed a service vulnerability, related "
                                "to a known CVE / outdated component.")
                    else:
                        desc = ("Nmap vuln skript potvrdil zranitelnost služby. Vyžaduje ruční "
                                "ověření a opravu.",
                                "An nmap vuln script confirmed a service vulnerability. Requires "
                                "manual verification and remediation.")
                    ev = f"{sname}\n{snippet}"
                    if cve_id:
                        ev += f"\nNVD: {lib.cve_link('nvd', cve_id)}"
                    out.append(_mk(idx, title, sev, owasp, CATEGORY["vulns"], f"{ip}:{port}",
                                   desc, lang, evidence=ev, recommendation=rec))
                    idx += 1
    return out, idx


def _best_tls_grade(engines_dict):
    worst_grade = None
    worst_color = "#95A5A6"
    detail = {}
    order = {"F": 0, "C": 1, "B": 2, "A": 3, "ERR": 4}
    for engine, data in (engines_dict or {}).items():
        if not isinstance(data, dict):
            continue
        protocols = data.get("protocols") or {}
        cipher_tree = data.get("cipher_tree") or {}
        if not any(protocols.values()):
            continue
        grade, color = calculate_grade(protocols, cipher_tree)
        if worst_grade is None or order.get(grade, 9) < order.get(worst_grade, 9):
            worst_grade, worst_color = grade, color
            detail = {"engine": engine, "protocols": protocols}
    return worst_grade, worst_color, detail


def build_tls(scan_results, start_idx=1, lang="cs"):
    out = []
    idx = start_idx
    grade_desc = {
        "F": ("Kriticky slabé TLS — SSLv2/SSLv3, nebezpečné šifry nebo chybí TLS 1.2/1.3.",
              "Critically weak TLS — SSLv2/SSLv3, insecure ciphers, or missing TLS 1.2/1.3."),
        "C": ("Slabé TLS — podporován zastaralý SSLv3.",
              "Weak TLS — obsolete SSLv3 supported."),
        "B": ("TLS s rezervami — zastaralé protokoly (TLS 1.0/1.1) nebo slabé šifry "
              "(CBC/3DES/bez forward secrecy).",
              "TLS with reservations — obsolete protocols (TLS 1.0/1.1) or weak ciphers "
              "(CBC/3DES/no forward secrecy)."),
        "A": ("TLS konfigurace je v pořádku (moderní protokoly a silné šifry).",
              "TLS configuration is fine (modern protocols and strong ciphers)."),
    }
    tls_audit = scan_results.get("tls_audit", {}) or {}
    for key, engines in tls_audit.items():
        if isinstance(engines, dict) and "protocols" in engines:
            engines = {engines.get("engine", "Nmap"): engines}
        grade, color, detail = _best_tls_grade(engines)
        if grade is None:
            continue
        rule = lib.tls_grade_rule(grade, lang) or {"severity": "INFO", "owasp": "A04",
                                                    "recommendation": ""}
        protos = detail.get("protocols", {})
        enabled = [p for p, v in protos.items() if v]
        title = (f"TLS hodnocení {grade} — {key}", f"TLS grade {grade} — {key}")
        ev = (f"Engine: {detail.get('engine', '?')}; "
              + ("protokoly: " if lang != "en" else "protocols: ")
              + (", ".join(enabled) if enabled else "—"))
        out.append(_mk(idx, title, rule["severity"], rule["owasp"], CATEGORY["tls"], key,
                       grade_desc.get(grade, ("TLS audit.", "TLS audit.")), lang,
                       evidence=ev, recommendation=rule["recommendation"],
                       impact=rule.get("impact", "")))
        idx += 1

    certs = scan_results.get("certificates", {}) or {}
    for key, data in certs.items():
        if not isinstance(data, dict):
            continue
        status = (data.get("status") or "").lower()
        days = data.get("days")
        kind = None
        why = None
        if "expir" in status or (isinstance(days, int) and days < 0):
            kind = "expired"
            why = ("Certifikát je prošlý.", "The certificate has expired.")
        elif isinstance(days, int) and days <= 15:
            kind = "expiring"
            why = (f"Certifikát brzy vyprší (za {days} dní).",
                   f"The certificate expires soon (in {days} days).")
        if kind:
            rule = lib.certificate_rule(kind, lang) or {"severity": "MEDIUM", "owasp": "A04",
                                                        "recommendation": ""}
            title = (f"Stav certifikátu — {key}", f"Certificate status — {key}")
            out.append(_mk(idx, title, rule["severity"], rule["owasp"], CATEGORY["tls"], key,
                           why, lang,
                           evidence=f"CN={data.get('cn', '?')}, "
                                    + ("vyprší " if lang != "en" else "expires ")
                                    + str(data.get("expiry", "?")),
                           recommendation=rule["recommendation"]))
            idx += 1
    return out, idx


def build_headers(scan_results, start_idx=1, lang="cs"):
    out = []
    idx = start_idx
    headers = scan_results.get("security_headers", {}) or {}
    for key, data in headers.items():
        if not isinstance(data, dict):
            continue
        hdrs = data.get("headers", {}) or {}
        missing = [h for h, v in hdrs.items() if str(v).upper() in ("CHYBÍ", "MISSING", "")]
        if not missing:
            continue
        # Pravidla z knihovny pro každou chybějící hlavičku
        rules = {h: lib.header_rule(h, lang) for h in missing}
        severities = [r["severity"] for r in rules.values() if r]
        sev = worst(severities) if severities else "LOW"
        # Agregovaný nález chybějících hlaviček = Security Misconfiguration (A02)
        owasp = "A02"
        details = []
        recs = []
        for h in missing:
            r = rules.get(h)
            if r:
                details.append(f"• {h}: " + (r.get("recommendation") or ""))
                recs.append(r.get("recommendation") or "")
        title = (f"Chybějící bezpečnostní hlavičky ({len(missing)}) — {key}",
                 f"Missing security headers ({len(missing)}) — {key}")
        desc = ("Web nevrací část doporučených bezpečnostních HTTP hlaviček, což snižuje "
                "obranu prohlížeče proti běžným útokům.",
                "The site is missing some recommended security HTTP headers, reducing the "
                "browser's defenses against common attacks.")
        ev_lead = "Chybí: " if lang != "en" else "Missing: "
        recommendation = "\n".join(r for r in recs if r) or _t(
            ("Doplnit chybějící bezpečnostní hlavičky.", "Add the missing security headers."), lang)
        out.append(_mk(idx, title, sev, owasp, CATEGORY["headers"], key, desc, lang,
                       evidence=ev_lead + ", ".join(missing) + "\n" + "\n".join(details),
                       recommendation=recommendation))
        idx += 1
    return out, idx


def build_ffuf(scan_results, start_idx=1, lang="cs"):
    out = []
    idx = start_idx
    results = scan_results.get("ffuf", []) or []
    found_codes = {200, 201, 204, 301, 302, 307, 401, 403, 405, 500}
    per_target_generic = {}

    for data in results:
        if not isinstance(data, dict):
            continue
        if data.get("_meta") == "empty_scan":
            continue
        status = data.get("status", 0)
        try:
            status = int(status)
        except (TypeError, ValueError):
            status = 0
        if status not in found_codes:
            continue
        url = data.get("url", "")
        try:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            path = parsed.path or "/"
        except Exception:
            base, path = url, url
        plow = (path or "").lower()

        rule, matched_kw = lib.ffuf_rule(path, lang)
        if rule:
            sev, owasp = rule["severity"], rule["owasp"]
            # downgrade dle status kódu (401/403 = existuje, ale chráněno) — kromě .git/.env
            dg = lib.ffuf_status_downgrade(status)
            if dg and matched_kw not in (".git", ".env"):
                i = min(SEVERITY_RANK[sev] + dg, len(SEVERITIES) - 1)
                sev = SEVERITIES[i]
            label = rule.get("name") or path
            title = (f"Citlivá cesta: {path} (HTTP {status})",
                     f"Sensitive path: {path} (HTTP {status})")
            full_desc = (f"{label}.", f"{label}.")
            ev = (f"{url} → HTTP {status}, "
                  + ("délka " if lang != "en" else "length ") + str(data.get("length", "?")))
            out.append(_mk(idx, title, sev, owasp, CATEGORY["ffuf"], base, full_desc, lang,
                           evidence=ev, recommendation=rule["recommendation"],
                           impact=rule.get("impact", "")))
            idx += 1
        else:
            per_target_generic[base] = per_target_generic.get(base, 0) + 1

    for base, count in per_target_generic.items():
        title = (f"Directory fuzzing: {count} přístupných cest — {base}",
                 f"Directory fuzzing: {count} accessible paths — {base}")
        desc = ("ffuf objevil přístupné cesty/soubory. Samy o sobě nemusí být zranitelností, "
                "ale rozšiřují útočnou plochu (forced browsing).",
                "ffuf discovered accessible paths/files. Not necessarily a vulnerability by "
                "themselves, but they expand the attack surface (forced browsing).")
        ev = (f"{count} " + ("cest s odpovědí 2xx/3xx/40x" if lang != "en"
                             else "paths responding 2xx/3xx/40x"))
        rec_gen = ("Projít nalezené cesty, odstranit nepotřebné, citlivé chránit "
                   "autentizací/autorizací.",
                   "Review discovered paths, remove unnecessary ones, protect sensitive "
                   "ones with authentication/authorization.")
        out.append(_mk(idx, title, "INFO", "A01", CATEGORY["ffuf"], base, desc, lang,
                       evidence=ev, recommendation=rec_gen))
        idx += 1
    return out, idx


# --- ZAP -------------------------------------------------------------------
ZAP_RISK_SEVERITY = {
    "high": "HIGH", "medium": "MEDIUM", "low": "LOW",
    "informational": "INFO", "info": "INFO",
}

ZAP_KEYWORD_OWASP = [
    ("sql injection", "A05"), ("injection", "A05"), ("cross site scripting", "A05"),
    ("xss", "A05"), ("path traversal", "A01"), ("directory browsing", "A01"),
    ("remote code", "A05"), ("authentication", "A07"), ("session", "A07"),
    ("csrf", "A01"), ("cross-domain", "A02"), ("content security policy", "A02"),
    ("hsts", "A04"), ("strict-transport", "A04"), ("cookie", "A02"),
    ("x-frame", "A02"), ("x-content-type", "A02"), ("cors", "A02"),
    ("ssl", "A04"), ("tls", "A04"), ("cipher", "A04"),
    ("information disclosure", "A02"), ("vulnerable", "A03"), ("outdated", "A03"),
    ("deserialization", "A08"),
]


def _zap_owasp(alert):
    tags = alert.get("tags") or {}
    if isinstance(tags, dict):
        keys = list(tags.keys())
    elif isinstance(tags, (list, tuple)):
        keys = list(tags)
    else:
        keys = []
    for k in keys:
        ku = str(k).upper()
        if "OWASP" in ku and "_A" in ku:
            tail = ku.split("_A")[-1]
            num = "".join(ch for ch in tail[:2] if ch.isdigit())
            if num:
                code = f"A{int(num):02d}"
                if code in OWASP_2025:
                    return code
    name = (alert.get("alert") or alert.get("name") or "").lower()
    for kw, code in ZAP_KEYWORD_OWASP:
        if kw in name:
            return code
    return "A06"


def build_zap(scan_results, start_idx=1, lang="cs"):
    out = []
    idx = start_idx
    zap = scan_results.get("zap", {}) or {}
    if isinstance(zap, dict) and "alerts" in zap and isinstance(zap["alerts"], dict):
        per_target = zap["alerts"]
    elif isinstance(zap, dict):
        per_target = zap
    else:
        per_target = {}

    fallback_rec = ("Ověřit a opravit dle doporučení OWASP ZAP.",
                    "Verify and remediate per the OWASP ZAP recommendation.")
    seen = set()
    for target, alerts in per_target.items():
        for a in (alerts or []):
            if not isinstance(a, dict):
                continue
            name = a.get("alert") or a.get("name") or "ZAP alert"
            url = a.get("url", target)
            param = a.get("param", "")
            key = (name, url, param)
            if key in seen:
                continue
            seen.add(key)

            risk = (a.get("risk") or "").strip().lower()
            sev = ZAP_RISK_SEVERITY.get(risk, "INFO")
            owasp = _zap_owasp(a)
            desc = (a.get("description") or "").strip()
            if len(desc) > 500:
                desc = desc[:500] + " …"
            ev = a.get("evidence") or ""
            cwe = a.get("cweid")
            evidence = f"URL: {url}"
            if param:
                evidence += ("\nParametr: " if lang != "en" else "\nParameter: ") + str(param)
            if ev:
                evidence += ("\nDůkaz: " if lang != "en" else "\nEvidence: ") + str(ev)
            if cwe and str(cwe) not in ("-1", "0", ""):
                evidence += f"\nCWE-{cwe}"
            conf = a.get("confidence")
            if conf:
                evidence += ("\nDůvěra: " if lang != "en" else "\nConfidence: ") + str(conf)

            default_desc = ("Alert nahlášený nástrojem OWASP ZAP.",
                            "Alert reported by OWASP ZAP.")
            out.append(_mk(idx, f"ZAP: {name}", sev, owasp, CATEGORY["zap"], target,
                           desc or default_desc, lang, evidence=evidence,
                           recommendation=(a.get("solution") or "").strip() or fallback_rec))
            idx += 1
    return out, idx


def build_webserver(scan_results, start_idx=1, lang="cs"):
    out = []
    idx = start_idx
    ws = scan_results.get("webserver", {}) or {}
    for ip, info in ws.items():
        records = []
        if isinstance(info, dict) and "family" in info:
            records.append((ip, info))
        elif isinstance(info, dict):
            for port, rec in info.items():
                if isinstance(rec, dict):
                    records.append((f"{ip}:{port}", rec))
        for target, rec in records:
            family = rec.get("family", "neznámý")
            detail = (rec.get("detail") or rec.get("server") or "").strip()
            if family == "neznámý" and not detail:
                continue
            has_version = any(ch.isdigit() for ch in detail)
            rule = lib.webserver_rule(has_version, lang)
            title = (f"Webserver: {family}" + (f" ({detail})" if detail else ""),
                     f"Web server: {family}" + (f" ({detail})" if detail else ""))
            if has_version:
                desc = ("Webový server prozrazuje svůj typ a verzi, což usnadňuje cílení útoků.",
                        "The web server discloses its type and version, which helps targeting attacks.")
            else:
                desc = ("Webový server prozrazuje svůj typ, což usnadňuje cílení útoků.",
                        "The web server discloses its type, which helps targeting attacks.")
            out.append(_mk(idx, title, rule["severity"], rule["owasp"], CATEGORY["webserver"],
                           target, desc, lang,
                           evidence=f"{family} | {detail or '—'} "
                                    + (f"(zdroj: {rec.get('source', '?')})" if lang != "en"
                                       else f"(source: {rec.get('source', '?')})"),
                           recommendation=rule["recommendation"]))
            idx += 1
    return out, idx


# Mapování názvu sekce -> stavitel
SECTION_BUILDERS = {
    "ports": build_ports,
    "services": build_services,
    "vulns": build_vulns,
    "tls": build_tls,
    "headers": build_headers,
    "ffuf": build_ffuf,
    "webserver": build_webserver,
    "zap": build_zap,
}

ALL_SECTIONS = ["ports", "services", "vulns", "tls", "headers", "ffuf", "webserver", "zap"]


def section_title(key, lang="cs"):
    return _t(CATEGORY.get(key, (key, key)), lang)


# Zpětná kompatibilita: SECTION_TITLES = české názvy
SECTION_TITLES = {k: v[0] for k, v in CATEGORY.items()}


def _filter_scan_results_for_ip(scan_results, ip):
    """Vyřízne ze scan_results jen data pro jednu IP (pro klasifikaci jednoho cíle)."""
    out = {}
    for phase in ("tcp", "udp", "vuln", "osscan", "online"):
        d = scan_results.get(phase, {}) or {}
        if ip in d:
            out[phase] = {ip: d[ip]}
    # klíčované "ip:port"
    for phase in ("tls_audit", "security_headers", "certificates"):
        d = scan_results.get(phase, {}) or {}
        sub = {k: v for k, v in d.items() if str(k).split(":")[0] == ip}
        if sub:
            out[phase] = sub
    # webserver: klíč ip
    ws = scan_results.get("webserver", {}) or {}
    if ip in ws:
        out["webserver"] = {ip: ws[ip]}
    # ffuf: list, url obsahuje ip
    ffuf = scan_results.get("ffuf", []) or []
    fsub = [x for x in ffuf if isinstance(x, dict) and ip in (x.get("url", "") or "")]
    if fsub:
        out["ffuf"] = fsub
    # zap: klíčováno target url obsahující ip
    zap = scan_results.get("zap", {}) or {}
    if isinstance(zap, dict):
        zsub = {k: v for k, v in zap.items() if ip in str(k)}
        if zsub:
            out["zap"] = zsub
    return out


def override_key(f):
    """Stabilní klíč nálezu pro per-případ úpravy (nezávislý na pořadovém id)."""
    return f"{f.get('target','')}|{f.get('section','')}|{f.get('owasp','')}|{f.get('title','')}"


def apply_overrides(result, overrides, lang="cs"):
    """Aplikuje per-případ úpravy (severity/owasp/recommendation/impact/title/
    description/comment) na nálezy a přepočítá souhrny. ``overrides`` keyed dle
    ``override_key``. Vrací ten samý dict (upravený na místě)."""
    if not overrides:
        return result
    for f in result.get("findings", []):
        ov = overrides.get(override_key(f))
        if not ov:
            continue
        for fld in ("severity", "owasp", "recommendation", "impact", "title", "description"):
            if ov.get(fld):
                f[fld] = ov[fld]
        if ov.get("comment"):
            f["comment"] = ov["comment"]
        if f.get("owasp"):
            f["owasp_name"] = OWASP_2025.get(f["owasp"], "")

    findings = result["findings"]
    findings.sort(key=lambda f: (SEVERITY_RANK[f["severity"]], f["category"], f["target"]))
    summary = {s: 0 for s in SEVERITIES}
    for f in findings:
        summary[f["severity"]] += 1
    owasp = {}
    for f in findings:
        a = f.get("owasp")
        if not a:
            continue
        owasp.setdefault(a, {"name": OWASP_2025.get(a, ""), "count": 0, "severities": []})
        owasp[a]["count"] += 1
        owasp[a]["severities"].append(f["severity"])
    for a in owasp:
        owasp[a]["worst"] = worst(owasp[a]["severities"])
    result["summary"] = summary
    result["owasp"] = owasp
    return result


def findings_for_ip(scan_results, ip, sections=None, min_severity="INFO", lang="cs",
                    overrides=None):
    """Klasifikované nálezy pro jeden cíl (IP) — pro náhled v panelu Souhrn IP."""
    res = build_findings(_filter_scan_results_for_ip(scan_results, ip),
                         sections=sections, min_severity=min_severity, lang=lang)
    if overrides:
        apply_overrides(res, overrides, lang)
    return res


def build_findings(scan_results, sections=None, min_severity="INFO", lang="cs"):
    """Vyrobí nálezy ze ``scan_results`` pro zvolené sekce a jazyk (cs/en).

    Vrací dict: ``{'findings', 'summary', 'owasp', 'sections', 'total', 'lang'}``.
    """
    if sections is None:
        sections = list(ALL_SECTIONS)
    sections = [s for s in sections if s in SECTION_BUILDERS]

    findings = []
    idx = 1
    for s in sections:
        part, idx = SECTION_BUILDERS[s](scan_results, idx, lang)
        for f in part:
            f["section"] = s  # jazykově nezávislý klíč sekce (pro skupiny/komentáře)
        findings.extend(part)

    cap = SEVERITY_RANK.get(min_severity, SEVERITY_RANK["INFO"])
    findings = [f for f in findings if SEVERITY_RANK[f["severity"]] <= cap]

    findings.sort(key=lambda f: (SEVERITY_RANK[f["severity"]], f["category"], f["target"]))

    summary = {s: 0 for s in SEVERITIES}
    for f in findings:
        summary[f["severity"]] += 1

    owasp = {}
    for f in findings:
        a = f.get("owasp")
        if not a:
            continue
        owasp.setdefault(a, {"name": OWASP_2025.get(a, ""), "count": 0, "severities": []})
        owasp[a]["count"] += 1
        owasp[a]["severities"].append(f["severity"])
    for a in owasp:
        owasp[a]["worst"] = worst(owasp[a]["severities"])

    sec_counts = {}
    for f in findings:
        sec_counts[f["category"]] = sec_counts.get(f["category"], 0) + 1

    return {
        "findings": findings,
        "summary": summary,
        "owasp": owasp,
        "sections": sec_counts,
        "total": len(findings),
        "lang": lang,
    }
