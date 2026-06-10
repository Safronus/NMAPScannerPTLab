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

# --- Stupnice závažnosti (pořadí = priorita) -------------------------------
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # 0 = nejvyšší

SEVERITY_COLOR = {
    "CRITICAL": "#C00000",
    "HIGH": "#ED7D31",
    "MEDIUM": "#FFC000",
    "LOW": "#00B050",
    "INFO": "#2E75B6",
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

# Společná doporučení (CZ/EN)
REC_PORT = ("Ověřit nutnost služby; nepotřebné porty zavřít nebo omezit firewallem "
            "na management síť.",
            "Verify the service is needed; close unnecessary ports or restrict them "
            "to a management network via firewall.")
REC_VERSION = ("Skrýt/upravit bannery a hlavičky verzí; udržovat software aktualizovaný.",
               "Hide/adjust version banners and headers; keep software up to date.")
REC_VULN = ("Aktualizovat/patchovat dotčenou komponentu; ověřit exploitovatelnost a dopad.",
            "Update/patch the affected component; verify exploitability and impact.")
REC_TLS = ("Vypnout SSLv2/SSLv3/TLS 1.0/1.1, povolit jen TLS 1.2/1.3 s AEAD šiframi "
           "a forward secrecy.",
           "Disable SSLv2/SSLv3/TLS 1.0/1.1; allow only TLS 1.2/1.3 with AEAD ciphers "
           "and forward secrecy.")
REC_CERT = ("Obnovit certifikát a nasadit automatickou obnovu.",
            "Renew the certificate and set up automatic renewal.")
REC_HEADERS = ("Doplnit hlavičky na webovém serveru / reverzní proxy (HSTS, CSP, "
               "X-Frame-Options, X-Content-Type-Options, …).",
               "Add the headers on the web server / reverse proxy (HSTS, CSP, "
               "X-Frame-Options, X-Content-Type-Options, …).")
REC_FFUF_SENS = ("Odstranit/zabezpečit přístup k citlivé cestě; omezit oprávnění a "
                 "přístup ze sítě.",
                 "Remove/secure access to the sensitive path; restrict permissions "
                 "and network access.")
REC_FFUF_GEN = ("Projít nalezené cesty, odstranit nepotřebné, citlivé chránit "
                "autentizací/autorizací.",
                "Review discovered paths, remove unnecessary ones, protect sensitive "
                "ones with authentication/authorization.")
REC_WEBSERVER = ("Skrýt/zobecnit hlavičku Server a X-Powered-By; udržovat server "
                 "aktualizovaný.",
                 "Hide/generalize the Server and X-Powered-By headers; keep the server "
                 "up to date.")


# ===========================================================================
#  Tabulky rizik (popisy dvojjazyčné)
# ===========================================================================
PORT_RISK = {
    21: ("MEDIUM", "A04", ("FTP — přenos přihlašovacích údajů i dat v otevřené podobě",
                           "FTP — credentials and data transferred in cleartext")),
    23: ("HIGH", "A04", ("Telnet — vzdálená správa bez šifrování (hesla v plaintextu)",
                         "Telnet — remote management without encryption (cleartext passwords)")),
    25: ("INFO", "A02", ("SMTP — poštovní přenos", "SMTP — mail transport")),
    69: ("MEDIUM", "A02", ("TFTP — přenos souborů bez autentizace",
                           "TFTP — file transfer without authentication")),
    110: ("LOW", "A04", ("POP3 — pošta v otevřené podobě", "POP3 — mail in cleartext")),
    111: ("LOW", "A02", ("rpcbind/portmapper — mapování RPC služeb",
                         "rpcbind/portmapper — RPC service mapping")),
    135: ("MEDIUM", "A02", ("MSRPC — endpoint mapper Windows", "MSRPC — Windows endpoint mapper")),
    137: ("MEDIUM", "A02", ("NetBIOS Name Service", "NetBIOS Name Service")),
    139: ("MEDIUM", "A01", ("NetBIOS/SMB — sdílení souborů", "NetBIOS/SMB — file sharing")),
    143: ("LOW", "A04", ("IMAP — pošta v otevřené podobě", "IMAP — mail in cleartext")),
    161: ("MEDIUM", "A02", ("SNMP — často výchozí community string (public/private)",
                            "SNMP — often default community string (public/private)")),
    389: ("LOW", "A02", ("LDAP — adresářová služba", "LDAP — directory service")),
    445: ("HIGH", "A01", ("SMB — sdílení souborů (EternalBlue, ransomware vektor)",
                          "SMB — file sharing (EternalBlue, ransomware vector)")),
    512: ("HIGH", "A04", ("rexec — vzdálené spuštění bez šifrování",
                          "rexec — remote execution without encryption")),
    513: ("HIGH", "A04", ("rlogin — vzdálené přihlášení bez šifrování",
                          "rlogin — remote login without encryption")),
    514: ("HIGH", "A04", ("rsh — vzdálený shell bez šifrování",
                          "rsh — remote shell without encryption")),
    873: ("MEDIUM", "A01", ("rsync — synchronizace souborů (často bez autentizace)",
                            "rsync — file sync (often without authentication)")),
    1433: ("HIGH", "A01", ("MSSQL — databáze přístupná ze sítě",
                           "MSSQL — database reachable from the network")),
    1521: ("HIGH", "A01", ("Oracle DB — databáze přístupná ze sítě",
                           "Oracle DB — database reachable from the network")),
    2049: ("MEDIUM", "A01", ("NFS — síťový souborový systém", "NFS — network file system")),
    2375: ("CRITICAL", "A02", ("Docker API bez TLS — plná kontrola nad hostitelem",
                               "Docker API without TLS — full control over the host")),
    3306: ("HIGH", "A01", ("MySQL/MariaDB — databáze přístupná ze sítě",
                           "MySQL/MariaDB — database reachable from the network")),
    3389: ("MEDIUM", "A07", ("RDP — vzdálená plocha (brute-force, BlueKeep)",
                             "RDP — remote desktop (brute-force, BlueKeep)")),
    5432: ("HIGH", "A01", ("PostgreSQL — databáze přístupná ze sítě",
                           "PostgreSQL — database reachable from the network")),
    5900: ("HIGH", "A07", ("VNC — vzdálená plocha (často slabá/žádná autentizace)",
                           "VNC — remote desktop (often weak/no authentication)")),
    5985: ("MEDIUM", "A02", ("WinRM (HTTP) — vzdálená správa Windows",
                             "WinRM (HTTP) — Windows remote management")),
    6379: ("HIGH", "A01", ("Redis — ve výchozím stavu bez autentizace",
                           "Redis — unauthenticated by default")),
    9200: ("HIGH", "A01", ("Elasticsearch — často bez autentizace",
                           "Elasticsearch — often without authentication")),
    11211: ("HIGH", "A01", ("Memcached — bez autentizace, riziko DDoS amplifikace",
                            "Memcached — no authentication, DDoS amplification risk")),
    27017: ("HIGH", "A01", ("MongoDB — často bez autentizace",
                            "MongoDB — often without authentication")),
    22: ("LOW", "A02", ("SSH — vzdálená správa (omezit na management síť)",
                        "SSH — remote management (restrict to a management network)")),
    80: ("INFO", "A02", ("HTTP — webová služba", "HTTP — web service")),
    443: ("INFO", "A02", ("HTTPS — webová služba", "HTTPS — web service")),
    8080: ("INFO", "A02", ("HTTP (alt) — webová služba", "HTTP (alt) — web service")),
    8443: ("INFO", "A02", ("HTTPS (alt) — webová služba", "HTTPS (alt) — web service")),
    8000: ("INFO", "A02", ("HTTP (alt) — webová služba", "HTTP (alt) — web service")),
    8888: ("INFO", "A02", ("HTTP (alt) — webová služba", "HTTP (alt) — web service")),
}
_PORT_DEFAULT = ("INFO", "A02", ("Otevřený port — součást útočné plochy",
                                 "Open port — part of the attack surface"))

SERVICE_KEYWORD_RISK = [
    ("telnet", ("HIGH", "A04", ("Telnet — vzdálená správa bez šifrování",
                                "Telnet — remote management without encryption"))),
    ("ftp", ("MEDIUM", "A04", ("FTP — přenos v otevřené podobě", "FTP — cleartext transfer"))),
    ("vnc", ("HIGH", "A07", ("VNC — vzdálená plocha (slabá autentizace)",
                             "VNC — remote desktop (weak authentication)"))),
    ("rdp", ("MEDIUM", "A07", ("RDP — vzdálená plocha", "RDP — remote desktop"))),
    ("ms-wbt", ("MEDIUM", "A07", ("RDP — vzdálená plocha", "RDP — remote desktop"))),
    ("mysql", ("HIGH", "A01", ("MySQL — databáze přístupná ze sítě",
                               "MySQL — database reachable from the network"))),
    ("postgres", ("HIGH", "A01", ("PostgreSQL — databáze přístupná ze sítě",
                                  "PostgreSQL — database reachable from the network"))),
    ("mongodb", ("HIGH", "A01", ("MongoDB — databáze přístupná ze sítě",
                                 "MongoDB — database reachable from the network"))),
    ("redis", ("HIGH", "A01", ("Redis — často bez autentizace",
                               "Redis — often without authentication"))),
    ("microsoft-ds", ("HIGH", "A01", ("SMB — sdílení souborů", "SMB — file sharing"))),
    ("netbios", ("MEDIUM", "A02", ("NetBIOS", "NetBIOS"))),
    ("snmp", ("MEDIUM", "A02", ("SNMP — často výchozí community string",
                                "SNMP — often default community string"))),
    ("ldap", ("LOW", "A02", ("LDAP — adresářová služba", "LDAP — directory service"))),
    ("rlogin", ("HIGH", "A04", ("rlogin — bez šifrování", "rlogin — without encryption"))),
    ("rsh", ("HIGH", "A04", ("rsh — bez šifrování", "rsh — without encryption"))),
]

FFUF_SENSITIVE = [
    (".git", ("CRITICAL", "A02", ("Expozice gitového repozitáře — zdrojový kód, historie, tajemství",
                                  "Exposed git repository — source code, history, secrets"))),
    (".env", ("CRITICAL", "A02", ("Expozice .env — přístupové údaje a klíče v otevřené podobě",
                                  "Exposed .env — credentials and keys in cleartext"))),
    (".svn", ("HIGH", "A02", ("Expozice SVN metadat — únik zdrojového kódu",
                              "Exposed SVN metadata — source code leak"))),
    ("phpmyadmin", ("HIGH", "A01", ("phpMyAdmin — administrace databáze přístupná",
                                    "phpMyAdmin — database administration exposed"))),
    ("/backup", ("HIGH", "A02", ("Zálohy přístupné přes web", "Backups accessible over the web"))),
    ("actuator", ("HIGH", "A02", ("Spring Boot Actuator — citlivé interní endpointy",
                                  "Spring Boot Actuator — sensitive internal endpoints"))),
    ("server-status", ("MEDIUM", "A02", ("Apache server-status — interní informace o serveru",
                                         "Apache server-status — internal server information"))),
    ("server-info", ("MEDIUM", "A02", ("Apache server-info — konfigurace serveru",
                                       "Apache server-info — server configuration"))),
    (".htaccess", ("MEDIUM", "A02", ("Konfigurační soubor .htaccess přístupný",
                                     "Configuration file .htaccess accessible"))),
    (".sql", ("HIGH", "A02", ("SQL dump přístupný přes web", "SQL dump accessible over the web"))),
    (".bak", ("MEDIUM", "A02", ("Záložní soubor přístupný", "Backup file accessible"))),
    (".old", ("MEDIUM", "A02", ("Záložní soubor (.old) přístupný", "Backup file (.old) accessible"))),
    (".zip", ("MEDIUM", "A02", ("Archiv přístupný přes web", "Archive accessible over the web"))),
    (".tar.gz", ("MEDIUM", "A02", ("Archiv přístupný přes web", "Archive accessible over the web"))),
    ("wp-admin", ("MEDIUM", "A01", ("WordPress administrace", "WordPress administration"))),
    ("wp-login", ("MEDIUM", "A07", ("WordPress přihlášení — brute-force vektor",
                                    "WordPress login — brute-force vector"))),
    ("/admin", ("MEDIUM", "A01", ("Administrační rozhraní", "Administration interface"))),
    ("/login", ("LOW", "A07", ("Přihlašovací stránka", "Login page"))),
    ("/config", ("MEDIUM", "A02", ("Konfigurační adresář/soubor", "Configuration directory/file"))),
    (".ds_store", ("LOW", "A02", (".DS_Store — odhalení struktury adresářů",
                                  ".DS_Store — reveals directory structure"))),
    ("robots.txt", ("INFO", "A02", ("robots.txt — naznačuje skryté cesty",
                                    "robots.txt — hints at hidden paths"))),
    (".well-known", ("INFO", "A02", (".well-known", ".well-known"))),
]

HEADER_RISK = {
    "Strict-Transport-Security": ("MEDIUM", "A04",
        ("Chybí HSTS — riziko downgrade na HTTP / SSL stripping",
         "Missing HSTS — risk of downgrade to HTTP / SSL stripping")),
    "Content-Security-Policy": ("MEDIUM", "A02",
        ("Chybí CSP — slabší ochrana proti XSS a injektáži obsahu",
         "Missing CSP — weaker protection against XSS and content injection")),
    "X-Frame-Options": ("MEDIUM", "A02",
        ("Chybí X-Frame-Options — riziko clickjackingu",
         "Missing X-Frame-Options — clickjacking risk")),
    "X-Content-Type-Options": ("LOW", "A02",
        ("Chybí X-Content-Type-Options — MIME sniffing",
         "Missing X-Content-Type-Options — MIME sniffing")),
    "Referrer-Policy": ("LOW", "A02",
        ("Chybí Referrer-Policy — únik referreru", "Missing Referrer-Policy — referrer leakage")),
    "Permissions-Policy": ("LOW", "A02",
        ("Chybí Permissions-Policy — bez omezení API prohlížeče",
         "Missing Permissions-Policy — no browser API restrictions")),
}


# ===========================================================================
#  Stavitelé nálezů
# ===========================================================================
def _mk(idx, title, severity, owasp, category, target, description,
        lang, evidence="", recommendation=""):
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
    }


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
            risk = PORT_RISK.get(pnum)
            if risk is None:
                risk = _PORT_DEFAULT
                for kw, kw_risk in SERVICE_KEYWORD_RISK:
                    if kw in name:
                        risk = kw_risk
                        break
            sev, owasp, desc = risk
            product = " ".join(x for x in [info.get("product", ""), info.get("version", "")] if x).strip()
            ev = f"{proto.upper()} {pnum} ({name or '?'})"
            if product:
                ev += f" — {product}"
            if info.get("extrainfo"):
                ev += f" [{info['extrainfo']}]"
            title = (f"Otevřený port {pnum}/{proto} — {name or 'neznámá služba'}",
                     f"Open port {pnum}/{proto} — {name or 'unknown service'}")
            full_desc = (_t(desc, "cs") + ".", _t(desc, "en") + ".")
            out.append(_mk(idx, title, sev, owasp, CATEGORY["ports"], f"{ip}:{pnum}",
                           full_desc, lang, evidence=ev, recommendation=REC_PORT))
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
            sev = "LOW" if version else "INFO"
            title = (f"Zveřejnění verze služby — {banner}",
                     f"Service version disclosure — {banner}")
            desc = ("Služba prozrazuje produkt a verzi, což usnadňuje útočníkovi "
                    "vyhledání známých zranitelností.",
                    "The service discloses product and version, which helps an attacker "
                    "look up known vulnerabilities.")
            ev = (f"{proto.upper()} {pnum}: {banner}"
                  + (f" {info.get('extrainfo')}" if info.get("extrainfo") else ""))
            out.append(_mk(idx, title, sev, "A02", CATEGORY["services"], f"{ip}:{pnum}",
                           desc, lang, evidence=ev, recommendation=REC_VERSION))
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
                    sev = "HIGH"
                    if any(k in up for k in ("REMOTE CODE EXECUTION", " RCE", "CRITICAL", "UNAUTHENTICATED")):
                        sev = "CRITICAL"
                    has_cve = "CVE" in up
                    owasp = "A03" if has_cve else "A06"
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
                    out.append(_mk(idx, title, sev, owasp, CATEGORY["vulns"], f"{ip}:{port}",
                                   desc, lang, evidence=f"{sname}\n{snippet}",
                                   recommendation=REC_VULN))
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
    grade_sev = {"F": "HIGH", "C": "MEDIUM", "B": "LOW", "A": "INFO"}
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
        sev = grade_sev.get(grade, "INFO")
        protos = detail.get("protocols", {})
        enabled = [p for p, v in protos.items() if v]
        title = (f"TLS hodnocení {grade} — {key}", f"TLS grade {grade} — {key}")
        ev = (f"Engine: {detail.get('engine', '?')}; "
              + ("protokoly: " if lang != "en" else "protocols: ")
              + (", ".join(enabled) if enabled else "—"))
        out.append(_mk(idx, title, sev, "A04", CATEGORY["tls"], key,
                       grade_desc.get(grade, ("TLS audit.", "TLS audit.")), lang,
                       evidence=ev, recommendation=REC_TLS))
        idx += 1

    certs = scan_results.get("certificates", {}) or {}
    for key, data in certs.items():
        if not isinstance(data, dict):
            continue
        status = (data.get("status") or "").lower()
        days = data.get("days")
        sev = None
        why = None
        if "expir" in status or (isinstance(days, int) and days < 0):
            sev = "MEDIUM"
            why = ("Certifikát je prošlý.", "The certificate has expired.")
        elif isinstance(days, int) and days <= 15:
            sev = "LOW"
            why = (f"Certifikát brzy vyprší (za {days} dní).",
                   f"The certificate expires soon (in {days} days).")
        if sev:
            title = (f"Stav certifikátu — {key}", f"Certificate status — {key}")
            out.append(_mk(idx, title, sev, "A04", CATEGORY["tls"], key, why, lang,
                           evidence=f"CN={data.get('cn', '?')}, "
                                    + ("vyprší " if lang != "en" else "expires ")
                                    + str(data.get("expiry", "?")),
                           recommendation=REC_CERT))
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
        severities = [HEADER_RISK[h][0] for h in missing if h in HEADER_RISK]
        sev = worst(severities) if severities else "LOW"
        details = []
        for h in missing:
            if h in HEADER_RISK:
                details.append("• " + _t(HEADER_RISK[h][2], lang))
        title = (f"Chybějící bezpečnostní hlavičky ({len(missing)}) — {key}",
                 f"Missing security headers ({len(missing)}) — {key}")
        desc = ("Web nevrací část doporučených bezpečnostních HTTP hlaviček, což snižuje "
                "obranu prohlížeče proti běžným útokům.",
                "The site is missing some recommended security HTTP headers, reducing the "
                "browser's defenses against common attacks.")
        ev_lead = "Chybí: " if lang != "en" else "Missing: "
        out.append(_mk(idx, title, sev, "A02", CATEGORY["headers"], key, desc, lang,
                       evidence=ev_lead + ", ".join(missing) + "\n" + "\n".join(details),
                       recommendation=REC_HEADERS))
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

        match = None
        matched_kw = None
        for kw, risk in FFUF_SENSITIVE:
            if kw in plow:
                match = risk
                matched_kw = kw
                break

        if match:
            sev, owasp, desc = match
            if status in (401, 403) and matched_kw not in (".git", ".env"):
                i = min(SEVERITY_RANK[sev] + 1, len(SEVERITIES) - 1)
                sev = SEVERITIES[i]
            title = (f"Citlivá cesta: {path} (HTTP {status})",
                     f"Sensitive path: {path} (HTTP {status})")
            full_desc = (_t(desc, "cs") + ".", _t(desc, "en") + ".")
            ev = (f"{url} → HTTP {status}, "
                  + ("délka " if lang != "en" else "length ") + str(data.get("length", "?")))
            out.append(_mk(idx, title, sev, owasp, CATEGORY["ffuf"], base, full_desc, lang,
                           evidence=ev, recommendation=REC_FFUF_SENS))
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
        out.append(_mk(idx, title, "INFO", "A01", CATEGORY["ffuf"], base, desc, lang,
                       evidence=ev, recommendation=REC_FFUF_GEN))
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
            sev = "LOW" if has_version else "INFO"
            title = (f"Webserver: {family}" + (f" ({detail})" if detail else ""),
                     f"Web server: {family}" + (f" ({detail})" if detail else ""))
            if has_version:
                desc = ("Webový server prozrazuje svůj typ a verzi, což usnadňuje cílení útoků.",
                        "The web server discloses its type and version, which helps targeting attacks.")
            else:
                desc = ("Webový server prozrazuje svůj typ, což usnadňuje cílení útoků.",
                        "The web server discloses its type, which helps targeting attacks.")
            out.append(_mk(idx, title, sev, "A02", CATEGORY["webserver"], target, desc, lang,
                           evidence=f"{family} | {detail or '—'} "
                                    + (f"(zdroj: {rec.get('source', '?')})" if lang != "en"
                                       else f"(source: {rec.get('source', '?')})"),
                           recommendation=REC_WEBSERVER))
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
