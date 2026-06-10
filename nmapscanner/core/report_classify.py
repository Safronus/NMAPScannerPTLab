"""Klasifikace výsledků skenu do nálezů se závažností + mapování na OWASP/CVSS.

Čistá logika **bez Qt**, aby šla samostatně testovat (``tests/test_report_classify.py``).
Z agregovaného ``scan_results`` (viz ``app.py``) vyrobí seznam nálezů, kde každý
nález má:

* **závažnost** dle stupnice INFO / LOW / MEDIUM / HIGH / CRITICAL, zarovnané na
  kvalitativní pásma **CVSS v4.0** (None 0.0 · Low 0.1–3.9 · Medium 4.0–6.9 ·
  High 7.0–8.9 · Critical 9.0–10.0),
* **kategorii OWASP Top 10:2025** (A01–A10) — aktuální vydání metodiky.

Klasifikace je záměrně **konzervativní a transparentní**: jde o orientační
ohodnocení útočné plochy z pohledu síťového/web skenu, ne o per-CVE CVSS vektor
(na ten sken nemá dost vstupů). Každý nález nese zdůvodnění i doporučení.
"""

from urllib.parse import urlparse

from .tls_grading import calculate_grade
from .vuln_classify import classify_vuln_output

# --- Stupnice závažnosti (pořadí = priorita) -------------------------------
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # 0 = nejvyšší

SEVERITY_COLOR = {
    "CRITICAL": "#7b1113",
    "HIGH": "#c0392b",
    "MEDIUM": "#e67e22",
    "LOW": "#f1c40f",
    "INFO": "#2980b9",
}

# Orientační pásma CVSS v4.0 pro každou úroveň (text do metodiky)
CVSS_BAND = {
    "CRITICAL": "9.0–10.0",
    "HIGH": "7.0–8.9",
    "MEDIUM": "4.0–6.9",
    "LOW": "0.1–3.9",
    "INFO": "0.0",
}

# --- OWASP Top 10:2025 -----------------------------------------------------
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


def worst(severities):
    """Nejvyšší závažnost ze seznamu (nebo 'INFO', když je prázdný)."""
    best = "INFO"
    for s in severities:
        if SEVERITY_RANK.get(s, 99) < SEVERITY_RANK[best]:
            best = s
    return best


# ===========================================================================
#  Tabulky rizik
# ===========================================================================

# port -> (závažnost, owasp, popis). Default pro neznámý otevřený port níže.
PORT_RISK = {
    21: ("MEDIUM", "A04", "FTP — přenos přihlašovacích údajů i dat v otevřené podobě"),
    23: ("HIGH", "A04", "Telnet — vzdálená správa bez šifrování (hesla v plaintextu)"),
    25: ("INFO", "A02", "SMTP — poštovní přenos"),
    69: ("MEDIUM", "A02", "TFTP — přenos souborů bez autentizace"),
    110: ("LOW", "A04", "POP3 — pošta v otevřené podobě"),
    111: ("LOW", "A02", "rpcbind/portmapper — mapování RPC služeb"),
    135: ("MEDIUM", "A02", "MSRPC — endpoint mapper Windows"),
    137: ("MEDIUM", "A02", "NetBIOS Name Service"),
    139: ("MEDIUM", "A01", "NetBIOS/SMB — sdílení souborů"),
    143: ("LOW", "A04", "IMAP — pošta v otevřené podobě"),
    161: ("MEDIUM", "A02", "SNMP — často výchozí community string (public/private)"),
    389: ("LOW", "A02", "LDAP — adresářová služba"),
    445: ("HIGH", "A01", "SMB — sdílení souborů (EternalBlue, ransomware vektor)"),
    512: ("HIGH", "A04", "rexec — vzdálené spuštění bez šifrování"),
    513: ("HIGH", "A04", "rlogin — vzdálené přihlášení bez šifrování"),
    514: ("HIGH", "A04", "rsh — vzdálený shell bez šifrování"),
    873: ("MEDIUM", "A01", "rsync — synchronizace souborů (často bez autentizace)"),
    1433: ("HIGH", "A01", "MSSQL — databáze přístupná ze sítě"),
    1521: ("HIGH", "A01", "Oracle DB — databáze přístupná ze sítě"),
    2049: ("MEDIUM", "A01", "NFS — síťový souborový systém"),
    2375: ("CRITICAL", "A02", "Docker API bez TLS — plná kontrola nad hostitelem"),
    3306: ("HIGH", "A01", "MySQL/MariaDB — databáze přístupná ze sítě"),
    3389: ("MEDIUM", "A07", "RDP — vzdálená plocha (brute-force, BlueKeep)"),
    5432: ("HIGH", "A01", "PostgreSQL — databáze přístupná ze sítě"),
    5900: ("HIGH", "A07", "VNC — vzdálená plocha (často slabá/žádná autentizace)"),
    5985: ("MEDIUM", "A02", "WinRM (HTTP) — vzdálená správa Windows"),
    6379: ("HIGH", "A01", "Redis — ve výchozím stavu bez autentizace"),
    9200: ("HIGH", "A01", "Elasticsearch — často bez autentizace"),
    11211: ("HIGH", "A01", "Memcached — bez autentizace, riziko DDoS amplifikace"),
    27017: ("HIGH", "A01", "MongoDB — často bez autentizace"),
    22: ("LOW", "A02", "SSH — vzdálená správa (omezit na management síť)"),
    80: ("INFO", "A02", "HTTP — webová služba"),
    443: ("INFO", "A02", "HTTPS — webová služba"),
    8080: ("INFO", "A02", "HTTP (alt) — webová služba"),
    8443: ("INFO", "A02", "HTTPS (alt) — webová služba"),
    8000: ("INFO", "A02", "HTTP (alt) — webová služba"),
    8888: ("INFO", "A02", "HTTP (alt) — webová služba"),
}

# Override podle názvu služby (nmap -sV), když port není v tabulce
SERVICE_KEYWORD_RISK = [
    ("telnet", ("HIGH", "A04", "Telnet — vzdálená správa bez šifrování")),
    ("ftp", ("MEDIUM", "A04", "FTP — přenos v otevřené podobě")),
    ("vnc", ("HIGH", "A07", "VNC — vzdálená plocha (slabá autentizace)")),
    ("rdp", ("MEDIUM", "A07", "RDP — vzdálená plocha")),
    ("ms-wbt", ("MEDIUM", "A07", "RDP — vzdálená plocha")),
    ("mysql", ("HIGH", "A01", "MySQL — databáze přístupná ze sítě")),
    ("postgres", ("HIGH", "A01", "PostgreSQL — databáze přístupná ze sítě")),
    ("mongodb", ("HIGH", "A01", "MongoDB — databáze přístupná ze sítě")),
    ("redis", ("HIGH", "A01", "Redis — často bez autentizace")),
    ("microsoft-ds", ("HIGH", "A01", "SMB — sdílení souborů")),
    ("netbios", ("MEDIUM", "A02", "NetBIOS")),
    ("snmp", ("MEDIUM", "A02", "SNMP — často výchozí community string")),
    ("ldap", ("LOW", "A02", "LDAP — adresářová služba")),
    ("rlogin", ("HIGH", "A04", "rlogin — bez šifrování")),
    ("rsh", ("HIGH", "A04", "rsh — bez šifrování")),
]

# Citlivé cesty z ffuf (substring v path, lowercase) -> (závažnost, owasp, popis)
FFUF_SENSITIVE = [
    (".git", ("CRITICAL", "A02", "Expozice gitového repozitáře — zdrojový kód, historie, tajemství")),
    (".env", ("CRITICAL", "A02", "Expozice .env — přístupové údaje a klíče v otevřené podobě")),
    (".svn", ("HIGH", "A02", "Expozice SVN metadat — únik zdrojového kódu")),
    ("phpmyadmin", ("HIGH", "A01", "phpMyAdmin — administrace databáze přístupná")),
    ("/backup", ("HIGH", "A02", "Zálohy přístupné přes web")),
    ("actuator", ("HIGH", "A02", "Spring Boot Actuator — citlivé interní endpointy")),
    ("server-status", ("MEDIUM", "A02", "Apache server-status — interní informace o serveru")),
    ("server-info", ("MEDIUM", "A02", "Apache server-info — konfigurace serveru")),
    (".htaccess", ("MEDIUM", "A02", "Konfigurační soubor .htaccess přístupný")),
    (".sql", ("HIGH", "A02", "SQL dump přístupný přes web")),
    (".bak", ("MEDIUM", "A02", "Záložní soubor přístupný")),
    (".old", ("MEDIUM", "A02", "Záložní soubor (.old) přístupný")),
    (".zip", ("MEDIUM", "A02", "Archiv přístupný přes web")),
    (".tar.gz", ("MEDIUM", "A02", "Archiv přístupný přes web")),
    ("wp-admin", ("MEDIUM", "A01", "WordPress administrace")),
    ("wp-login", ("MEDIUM", "A07", "WordPress přihlášení — brute-force vektor")),
    ("/admin", ("MEDIUM", "A01", "Administrační rozhraní")),
    ("/login", ("LOW", "A07", "Přihlašovací stránka")),
    ("/config", ("MEDIUM", "A02", "Konfigurační adresář/soubor")),
    (".ds_store", ("LOW", "A02", ".DS_Store — odhalení struktury adresářů")),
    ("robots.txt", ("INFO", "A02", "robots.txt — naznačuje skryté cesty")),
    (".well-known", ("INFO", "A02", ".well-known")),
]

# Bezpečnostní hlavičky -> (závažnost při chybění, owasp, popis)
HEADER_RISK = {
    "Strict-Transport-Security": ("MEDIUM", "A04", "Chybí HSTS — riziko downgrade na HTTP / SSL stripping"),
    "Content-Security-Policy": ("MEDIUM", "A02", "Chybí CSP — slabší ochrana proti XSS a injektáži obsahu"),
    "X-Frame-Options": ("MEDIUM", "A02", "Chybí X-Frame-Options — riziko clickjackingu"),
    "X-Content-Type-Options": ("LOW", "A02", "Chybí X-Content-Type-Options — MIME sniffing"),
    "Referrer-Policy": ("LOW", "A02", "Chybí Referrer-Policy — únik referreru"),
    "Permissions-Policy": ("LOW", "A02", "Chybí Permissions-Policy — bez omezení API prohlížeče"),
}


# ===========================================================================
#  Stavitelé nálezů pro jednotlivé kategorie
# ===========================================================================

def _mk(idx, title, severity, owasp, category, target, description,
        evidence="", recommendation=""):
    return {
        "id": f"F-{idx:03d}",
        "title": title,
        "severity": severity,
        "owasp": owasp,
        "owasp_name": OWASP_2025.get(owasp, "") if owasp else "",
        "category": category,
        "target": target,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def _iter_open_ports(scan_results, proto):
    """Yielduje (ip, port_int, info) pro otevřené porty daného protokolu (tcp/udp)."""
    phase = scan_results.get(proto, {}) or {}
    for ip, ip_data in phase.items():
        if not isinstance(ip_data, dict):
            continue
        ports = ip_data.get(proto, {}) or {}
        for port, info in ports.items():
            if not isinstance(info, dict):
                continue
            if info.get("state") != "open":
                continue
            try:
                pnum = int(port)
            except (TypeError, ValueError):
                continue
            yield ip, pnum, info


def build_ports(scan_results, start_idx=1):
    """Nálezy z otevřených portů (TCP+UDP) — útočná plocha."""
    out = []
    idx = start_idx
    for proto in ("tcp", "udp"):
        for ip, pnum, info in _iter_open_ports(scan_results, proto):
            name = (info.get("name") or "").lower()
            risk = PORT_RISK.get(pnum)
            if risk is None:
                risk = ("INFO", "A02", "Otevřený port — součást útočné plochy")
                for kw, kw_risk in SERVICE_KEYWORD_RISK:
                    if kw in name:
                        risk = kw_risk
                        break
            sev, owasp, desc = risk
            product = " ".join(
                x for x in [info.get("product", ""), info.get("version", "")] if x
            ).strip()
            ev = f"{proto.upper()} {pnum} ({name or '?'})"
            if product:
                ev += f" — {product}"
            if info.get("extrainfo"):
                ev += f" [{info['extrainfo']}]"
            out.append(_mk(
                idx, f"Otevřený port {pnum}/{proto} — {name or 'neznámá služba'}",
                sev, owasp, "Otevřené porty", f"{ip}:{pnum}",
                desc + ".",
                evidence=ev,
                recommendation="Ověřit nutnost služby; nepotřebné porty zavřít nebo "
                               "omezit firewallem na management síť.",
            ))
            idx += 1
    return out, idx


def build_services(scan_results, start_idx=1):
    """Nálezy ze zveřejnění verzí služeb (information disclosure)."""
    out = []
    idx = start_idx
    for proto in ("tcp", "udp"):
        for ip, pnum, info in _iter_open_ports(scan_results, proto):
            product = info.get("product", "").strip()
            version = info.get("version", "").strip()
            if not product and not version:
                continue
            banner = " ".join(x for x in [product, version] if x).strip()
            sev = "LOW" if version else "INFO"
            out.append(_mk(
                idx, f"Zveřejnění verze služby — {banner}",
                sev, "A02", "Identifikace služeb", f"{ip}:{pnum}",
                "Služba prozrazuje produkt a verzi, což usnadňuje útočníkovi "
                "vyhledání známých zranitelností.",
                evidence=f"{proto.upper()} {pnum}: {banner}"
                         + (f" {info.get('extrainfo')}" if info.get("extrainfo") else ""),
                recommendation="Skrýt/upravit bannery a hlavičky verzí; udržovat "
                               "software aktualizovaný.",
            ))
            idx += 1
    return out, idx


def build_vulns(scan_results, start_idx=1):
    """Nálezy z nmap vuln skriptů (jen potvrzené 'finding')."""
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
                    sev = "HIGH"
                    if any(k in up for k in ("REMOTE CODE EXECUTION", " RCE", "CRITICAL",
                                             "UNAUTHENTICATED")):
                        sev = "CRITICAL"
                    has_cve = "CVE" in up
                    owasp = "A03" if has_cve else "A06"
                    snippet = (output or "").strip()
                    if len(snippet) > 600:
                        snippet = snippet[:600] + " …"
                    out.append(_mk(
                        idx, f"Potvrzená zranitelnost: {sname}",
                        sev, owasp, "Zranitelnosti (nmap)", f"{ip}:{port}",
                        "Nmap vuln skript potvrdil zranitelnost služby. "
                        + ("Souvisí se známou CVE / zastaralou komponentou."
                           if has_cve else "Vyžaduje ruční ověření a opravu."),
                        evidence=f"{sname}\n{snippet}",
                        recommendation="Aktualizovat/patchovat dotčenou komponentu; "
                                       "ověřit exploitovatelnost a dopad.",
                    ))
                    idx += 1
    return out, idx


def _best_tls_grade(engines_dict):
    """Z per-engine dictu (Nmap/SSLyze/…) vrátí (nejhorší_grade, color, detail_engine)."""
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


def build_tls(scan_results, start_idx=1):
    """Nálezy z TLS auditu (na základě známky A/B/C/F) + certifikáty."""
    out = []
    idx = start_idx
    grade_sev = {"F": "HIGH", "C": "MEDIUM", "B": "LOW", "A": "INFO"}
    grade_desc = {
        "F": "Kriticky slabé TLS — SSLv2/SSLv3, nebezpečné šifry nebo chybí TLS 1.2/1.3.",
        "C": "Slabé TLS — podporován zastaralý SSLv3.",
        "B": "TLS s rezervami — zastaralé protokoly (TLS 1.0/1.1) nebo slabé šifry (CBC/3DES/bez forward secrecy).",
        "A": "TLS konfigurace je v pořádku (moderní protokoly a silné šifry).",
    }
    tls_audit = scan_results.get("tls_audit", {}) or {}
    for key, engines in tls_audit.items():
        # engines je per-engine dict; starší formát může být plochý
        if isinstance(engines, dict) and "protocols" in engines:
            engines = {engines.get("engine", "Nmap"): engines}
        grade, color, detail = _best_tls_grade(engines)
        if grade is None:
            continue
        sev = grade_sev.get(grade, "INFO")
        protos = detail.get("protocols", {})
        enabled = [p for p, v in protos.items() if v]
        out.append(_mk(
            idx, f"TLS hodnocení {grade} — {key}",
            sev, "A04", "TLS audit", key,
            grade_desc.get(grade, "TLS audit."),
            evidence=f"Engine: {detail.get('engine', '?')}; protokoly: "
                     + (", ".join(enabled) if enabled else "—"),
            recommendation="Vypnout SSLv2/SSLv3/TLS 1.0/1.1, povolit jen TLS 1.2/1.3 "
                           "s AEAD šiframi a forward secrecy.",
        ))
        idx += 1

    # Certifikáty (expirace)
    certs = scan_results.get("certificates", {}) or {}
    for key, data in certs.items():
        if not isinstance(data, dict):
            continue
        status = (data.get("status") or "").lower()
        days = data.get("days")
        sev = None
        why = ""
        if "expir" in status or (isinstance(days, int) and days < 0):
            sev, why = "MEDIUM", "Certifikát je prošlý."
        elif isinstance(days, int) and days <= 15:
            sev, why = "LOW", f"Certifikát brzy vyprší (za {days} dní)."
        if sev:
            out.append(_mk(
                idx, f"Stav certifikátu — {key}",
                sev, "A04", "TLS audit", key, why,
                evidence=f"CN={data.get('cn', '?')}, vyprší {data.get('expiry', '?')}",
                recommendation="Obnovit certifikát a nasadit automatickou obnovu.",
            ))
            idx += 1
    return out, idx


def build_headers(scan_results, start_idx=1):
    """Nálezy z chybějících bezpečnostních HTTP hlaviček (agregováno na cíl)."""
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
        severities = [HEADER_RISK[h][0] for h in missing if h in HEADER_RISK]
        sev = worst(severities) if severities else "LOW"
        details = []
        for h in missing:
            if h in HEADER_RISK:
                details.append(f"• {HEADER_RISK[h][2]}")
        out.append(_mk(
            idx, f"Chybějící bezpečnostní hlavičky ({len(missing)}) — {key}",
            sev, "A02", "Bezpečnostní hlavičky", key,
            "Web nevrací část doporučených bezpečnostních HTTP hlaviček, což "
            "snižuje obranu prohlížeče proti běžným útokům.",
            evidence="Chybí: " + ", ".join(missing) + "\n" + "\n".join(details),
            recommendation="Doplnit hlavičky na webovém serveru / reverzní proxy "
                           "(HSTS, CSP, X-Frame-Options, X-Content-Type-Options, …).",
        ))
        idx += 1
    return out, idx


def build_ffuf(scan_results, start_idx=1):
    """Nálezy z ffuf — citlivé cesty samostatně, zbytek agregovaně na cíl."""
    out = []
    idx = start_idx
    results = scan_results.get("ffuf", []) or []
    found_codes = {200, 201, 204, 301, 302, 307, 401, 403, 405, 500}
    per_target_generic = {}  # base_url -> počet

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

        match = None
        for kw, risk in FFUF_SENSITIVE:
            if kw in plow:
                match = risk
                break

        if match:
            sev, owasp, desc = match
            # 401/403 = existuje, ale chráněno → o stupeň níž (kromě git/env)
            if status in (401, 403) and kw not in (".git", ".env"):
                order = SEVERITIES
                i = min(SEVERITY_RANK[sev] + 1, len(order) - 1)
                sev = order[i]
            out.append(_mk(
                idx, f"Citlivá cesta: {path} (HTTP {status})",
                sev, owasp, "Directory fuzzing (ffuf)", base,
                desc + ".",
                evidence=f"{url} → HTTP {status}, délka {data.get('length', '?')}",
                recommendation="Odstranit/zabezpečit přístup k citlivé cestě; "
                               "omezit oprávnění a přístup ze sítě.",
            ))
            idx += 1
        else:
            per_target_generic[base] = per_target_generic.get(base, 0) + 1

    for base, count in per_target_generic.items():
        out.append(_mk(
            idx, f"Directory fuzzing: {count} přístupných cest — {base}",
            "INFO", "A01", "Directory fuzzing (ffuf)", base,
            "ffuf objevil přístupné cesty/soubory. Samy o sobě nemusí být "
            "zranitelností, ale rozšiřují útočnou plochu (forced browsing).",
            evidence=f"{count} cest s odpovědí 2xx/3xx/40x",
            recommendation="Projít nalezené cesty, odstranit nepotřebné, citlivé "
                           "chránit autentizací/autorizací.",
        ))
        idx += 1
    return out, idx


# ZAP riziko -> naše závažnost (ZAP nemá CRITICAL)
ZAP_RISK_SEVERITY = {
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "informational": "INFO",
    "info": "INFO",
}

# Fallback mapování názvu alertu -> OWASP, když chybí tag
ZAP_KEYWORD_OWASP = [
    ("sql injection", "A05"),
    ("injection", "A05"),
    ("cross site scripting", "A05"),
    ("xss", "A05"),
    ("path traversal", "A01"),
    ("directory browsing", "A01"),
    ("remote code", "A05"),
    ("authentication", "A07"),
    ("session", "A07"),
    ("csrf", "A01"),
    ("cross-domain", "A02"),
    ("content security policy", "A02"),
    ("hsts", "A04"),
    ("strict-transport", "A04"),
    ("cookie", "A02"),
    ("x-frame", "A02"),
    ("x-content-type", "A02"),
    ("cors", "A02"),
    ("ssl", "A04"),
    ("tls", "A04"),
    ("cipher", "A04"),
    ("information disclosure", "A02"),
    ("vulnerable", "A03"),
    ("outdated", "A03"),
    ("deserialization", "A08"),
]


def _zap_owasp(alert):
    """Z OWASP tagu ZAP alertu odvodí kód A0X (2025), jinak fallback dle názvu."""
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
            # např. OWASP_2021_A03 → A03
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
    return "A06"  # Insecure Design jako neutrální default


def build_zap(scan_results, start_idx=1):
    """Nálezy z OWASP ZAP alertů (uložené v ``scan_results['zap']``)."""
    out = []
    idx = start_idx
    zap = scan_results.get("zap", {}) or {}
    # Podporuj {target: [alerts]} i {'alerts': {target: [...]}}
    if isinstance(zap, dict) and "alerts" in zap and isinstance(zap["alerts"], dict):
        per_target = zap["alerts"]
    elif isinstance(zap, dict):
        per_target = zap
    else:
        per_target = {}

    seen = set()  # deduplikace (název+url+param)
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
                evidence += f"\nParametr: {param}"
            if ev:
                evidence += f"\nDůkaz: {ev}"
            if cwe and str(cwe) not in ("-1", "0", ""):
                evidence += f"\nCWE-{cwe}"
            conf = a.get("confidence")
            if conf:
                evidence += f"\nDůvěra: {conf}"

            out.append(_mk(
                idx, f"ZAP: {name}",
                sev, owasp, "OWASP ZAP", target,
                desc or "Alert nahlášený nástrojem OWASP ZAP.",
                evidence=evidence,
                recommendation=(a.get("solution") or "").strip()
                               or "Ověřit a opravit dle doporučení OWASP ZAP.",
            ))
            idx += 1
    return out, idx


def build_webserver(scan_results, start_idx=1):
    """Nálezy z detekce webserveru (zveřejnění technologie/verze)."""
    out = []
    idx = start_idx
    ws = scan_results.get("webserver", {}) or {}
    for ip, info in ws.items():
        # info je buď {family, detail, source}, nebo {port: {...}}
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
            sev = "LOW" if has_version else "INFO"
            out.append(_mk(
                idx, f"Webserver: {family}" + (f" ({detail})" if detail else ""),
                sev, "A02", "Webserver", target,
                "Webový server prozrazuje svůj typ"
                + (" a verzi" if has_version else "")
                + ", což usnadňuje cílení útoků.",
                evidence=f"{family} | {detail or '—'} (zdroj: {rec.get('source', '?')})",
                recommendation="Skrýt/zobecnit hlavičku Server a X-Powered-By; "
                               "udržovat server aktualizovaný.",
            ))
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

SECTION_TITLES = {
    "ports": "Otevřené porty",
    "services": "Identifikace služeb",
    "vulns": "Zranitelnosti (nmap)",
    "tls": "TLS audit",
    "headers": "Bezpečnostní hlavičky",
    "ffuf": "Directory fuzzing (ffuf)",
    "webserver": "Webserver",
    "zap": "OWASP ZAP",
}


def build_findings(scan_results, sections=None, min_severity="INFO"):
    """Vyrobí nálezy ze ``scan_results`` pro zvolené sekce.

    * ``sections`` — seznam názvů sekcí (viz ``ALL_SECTIONS``); None = všechny.
    * ``min_severity`` — odfiltruje nálezy nižší závažnosti (default INFO = vše).

    Vrací dict: ``{'findings', 'summary', 'owasp', 'sections'}``.
    """
    if sections is None:
        sections = list(ALL_SECTIONS)
    sections = [s for s in sections if s in SECTION_BUILDERS]

    findings = []
    idx = 1
    for s in sections:
        part, idx = SECTION_BUILDERS[s](scan_results, idx)
        findings.extend(part)

    # Filtr min. závažnosti
    cap = SEVERITY_RANK.get(min_severity, SEVERITY_RANK["INFO"])
    findings = [f for f in findings if SEVERITY_RANK[f["severity"]] <= cap]

    # Seřadit dle závažnosti, pak kategorie, pak cíle
    findings.sort(key=lambda f: (SEVERITY_RANK[f["severity"]], f["category"], f["target"]))

    summary = {s: 0 for s in SEVERITIES}
    for f in findings:
        summary[f["severity"]] += 1

    owasp = {}
    for f in findings:
        a = f.get("owasp")
        if not a:
            continue
        owasp.setdefault(a, {"name": OWASP_2025.get(a, ""), "count": 0,
                             "severities": []})
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
    }
