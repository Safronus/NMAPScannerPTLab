"""Obohacení klasifikace z internetu — CVE (NVD) a End-of-Life (endoflife.date).

* **NVD** — pro nalezené CVE stáhne CVSS skóre + závažnost + popis
  (``https://services.nvd.nist.gov/rest/json/cves/2.0``).
* **EOL** — pro detekované produkty+verze zjistí, zda je verze po konci podpory
  (``https://endoflife.date/api/<produkt>.json``). Neudržovaný software = kritické
  (žádné bezpečnostní opravy).

Výsledky se **cachují** do ``~/.nmapscanner/`` (CVE natrvalo, EOL s TTL), síťové
volání má timeout a při výpadku degraduje (vrátí None). Čistá logika (mapování
verzí, CVSS→severity) je testovatelná bez sítě.
"""

import json
import os
import time

CACHE_DIR = os.path.join(os.path.expanduser("~"), ".nmapscanner")
_NVD_CACHE = os.path.join(CACHE_DIR, "nvd_cache.json")
_EOL_CACHE = os.path.join(CACHE_DIR, "eol_cache.json")
_KEV_CACHE = os.path.join(CACHE_DIR, "kev_cache.json")
_EPSS_CACHE = os.path.join(CACHE_DIR, "epss_cache.json")
_VCVE_CACHE = os.path.join(CACHE_DIR, "version_cve_cache.json")
_EOL_TTL = 14 * 24 * 3600   # 14 dní
_KEV_TTL = 24 * 3600        # 1 den (katalog se aktualizuje denně)
_EPSS_TTL = 3 * 24 * 3600   # 3 dny
_VCVE_TTL = 3 * 24 * 3600   # 3 dny (CVE dle verze)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}"
EOL_URL = "https://endoflife.date/api/{slug}.json"
# CISA Known Exploited Vulnerabilities — CVE s potvrzeným zneužitím ve volné přírodě.
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# FIRST EPSS — pravděpodobnost zneužití CVE v následujících 30 dnech (0–1).
EPSS_URL = "https://api.first.org/data/v1/epss?cve={id}"

# nmap product (lowercase substring) -> endoflife.date slug.
# Pořadí ZÁLEŽÍ — specifičtější klíče dřív (Tomcat/Coyote před Apache httpd; MariaDB
# před MySQL). Jen slugy ověřené na endoflife.date.
PRODUCT_SLUGS = {
    # web servery / aplikační
    "apache-coyote": "tomcat", "apache tomcat": "tomcat", "coyote": "tomcat", "tomcat": "tomcat",
    "apache httpd": "apache-http-server", "apache http": "apache-http-server",
    "nginx": "nginx", "caddy": "caddy", "traefik": "traefik", "envoy": "envoy",
    "haproxy": "haproxy", "squid": "squid",
    # databáze / cache / queue
    "mariadb": "mariadb", "mysql": "mysql", "postgresql": "postgresql", "postgres": "postgresql",
    "mongodb": "mongodb", "redis": "redis", "memcached": "memcached",
    "elasticsearch": "elasticsearch", "kibana": "kibana", "rabbitmq": "rabbitmq",
    "apache activemq": "apache-activemq", "activemq": "apache-activemq",
    "apache kafka": "apache-kafka", "kafka": "apache-kafka", "zookeeper": "zookeeper",
    "influxdb": "influxdb", "prometheus": "prometheus", "etcd": "etcd", "apache solr": "solr", "solr": "solr",
    "microsoft sql server": "mssqlserver", "ms sql": "mssqlserver", "mssql": "mssqlserver",
    # jazyky / runtime / knihovny
    "php": "php", "node.js": "nodejs", "nodejs": "nodejs", "python": "python",
    "openssl": "openssl", "log4j": "log4j", "spring boot": "spring-boot",
    "spring framework": "spring-framework",
    # CMS / web aplikace
    "wordpress": "wordpress", "drupal": "drupal", "joomla": "joomla", "typo3": "typo3",
    "magento": "magento", "moodle": "moodle", "roundcube": "roundcube",
    "nextcloud": "nextcloud", "phpmyadmin": "phpmyadmin", "django": "django",
    "grafana": "grafana", "keycloak": "keycloak", "jenkins": "jenkins",
    "gitlab": "gitlab", "confluence": "confluence", "jira": "jira-software",
    "coldfusion": "coldfusion", "apache airflow": "apache-airflow",
    # síťové / appliance / infrastruktura
    "big-ip": "big-ip", "bigip": "big-ip", "f5": "big-ip",
    "pan-os": "panos", "palo alto": "panos", "fortios": "fortios", "fortigate": "fortios",
    # OS / kontejnery
    "windows server": "windows-server", "ubuntu": "ubuntu", "debian": "debian",
    "centos": "centos", "red hat": "rhel", "rhel": "rhel",
    "docker": "docker-engine", "kubernetes": "kubernetes", "consul": "consul",
    "proftpd": "proftpd", "postfix": "postfix", "dovecot": "dovecot",
    "ruby": "ruby", "perl": "perl",
}


def _load(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save(path, data):
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception:
        pass


# ---------------------------------------------------------------------------
#  Čistá logika (testovatelná bez sítě)
# ---------------------------------------------------------------------------
def cvss_to_severity(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "INFO"
    if s >= 9.0:
        return "CRITICAL"
    if s >= 7.0:
        return "HIGH"
    if s >= 4.0:
        return "MEDIUM"
    if s > 0.0:
        return "LOW"
    return "INFO"


def product_slug(product_text):
    low = (product_text or "").lower()
    # delší (specifičtější) klíče napřed — „phpmyadmin" před „php", „mariadb" před …
    for kw in sorted(PRODUCT_SLUGS, key=len, reverse=True):
        if kw in low:
            return PRODUCT_SLUGS[kw]
    return None


def _version_tuple(v):
    out = []
    for part in str(v).split("."):
        num = "".join(ch for ch in part if ch.isdigit())
        out.append(int(num) if num else 0)
    return tuple(out)


def match_cycle(cycles, version):
    """Najde cyklus odpovídající verzi (nejdelší shoda předpony major.minor)."""
    ver = str(version).strip()
    best = None
    best_len = -1
    for c in cycles:
        cyc = str(c.get("cycle", ""))
        if not cyc:
            continue
        if ver == cyc or ver.startswith(cyc + ".") or ver.startswith(cyc + "-"):
            if len(cyc) > best_len:
                best, best_len = c, len(cyc)
    return best


def eol_status(cycle, today=None):
    """Z cyklu (endoflife.date) určí, zda je verze po konci podpory.

    Vrací (is_eol: bool, eol_date: str). ``today`` = 'YYYY-MM-DD' (default = dnes)."""
    eol = cycle.get("eol")
    if eol is True:
        return True, ""
    if eol is False or eol is None:
        return False, ""
    if isinstance(eol, str):
        td = today or time.strftime("%Y-%m-%d")
        return (eol <= td), eol
    return False, ""


# ---------------------------------------------------------------------------
#  Síťové dotazy (s cache)
# ---------------------------------------------------------------------------
def _http_get_json(url, timeout=10, api_key=None):
    import requests
    headers = {"User-Agent": "NMAPScanner-PTLab"}
    if api_key:
        headers["apiKey"] = api_key
    r = requests.get(url, timeout=timeout, headers=headers)
    r.raise_for_status()
    return r.json()


def _extract_cvss(cve):
    """Z NVD CVE objektu vytáhne nejlepší dostupné base score (v4 → v3.1 → v3 → v2)."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            return metrics[key][0].get("cvssData", {}).get("baseScore")
    return None


def _extract_desc(cve):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def validate_nvd_key(api_key, timeout=12):
    """Ověří platnost NVD API klíče drobným dotazem. Vrací (ok: bool, zpráva: str).

    NVD při neplatném klíči vrací 403/404; 200 = klíč přijat. Prázdný klíč = bez klíče."""
    if not (api_key or "").strip():
        return False, "Klíč není zadán."
    try:
        import requests
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"
        r = requests.get(url, timeout=timeout, headers={
            "User-Agent": "NMAPScanner-PTLab", "apiKey": api_key.strip()})
        if r.status_code == 200:
            return True, "Klíč je platný — NVD požadavek přijat."
        if r.status_code in (403, 404):
            return False, f"Klíč odmítnut (HTTP {r.status_code})."
        return False, f"Neočekávaná odpověď NVD (HTTP {r.status_code})."
    except Exception as e:  # noqa: BLE001
        return False, f"Chyba sítě: {e}"


def nvd_lookup(cve_id, timeout=12, api_key=None, force=False):
    """Vrátí {'cvss','severity','description'} pro CVE z NVD (cachované), nebo None."""
    cve_id = (cve_id or "").upper()
    if not cve_id:
        return None
    cache = _load(_NVD_CACHE)
    if not force and cve_id in cache:
        return cache[cve_id]
    try:
        data = _http_get_json(NVD_URL.format(id=cve_id), timeout, api_key)
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        cve = vulns[0]["cve"]
        score = _extract_cvss(cve)
        result = {"cvss": score, "severity": cvss_to_severity(score),
                  "description": _extract_desc(cve)[:500]}
        cache[cve_id] = result
        _save(_NVD_CACHE, cache)
        return result
    except Exception:
        return None


# ---------------------------------------------------------------------------
#  CVE podle verze služby (NVD CPE match + Vulners fallback)
# ---------------------------------------------------------------------------
# nmap produkt (lowercase substring) -> CPE 2.3 prefix "cpe:2.3:a:vendor:product".
# Pořadí záleží — specifičtější klíče dřív (řešeno tříděním dle délky).
CPE_MAP = {
    "apache tomcat": "cpe:2.3:a:apache:tomcat", "coyote": "cpe:2.3:a:apache:tomcat",
    "tomcat": "cpe:2.3:a:apache:tomcat",
    "apache httpd": "cpe:2.3:a:apache:http_server",
    "apache http": "cpe:2.3:a:apache:http_server",
    "nginx": "cpe:2.3:a:nginx:nginx", "openssh": "cpe:2.3:a:openbsd:openssh",
    "openssl": "cpe:2.3:a:openssl:openssl",
    "proftpd": "cpe:2.3:a:proftpd:proftpd", "vsftpd": "cpe:2.3:a:vsftpd_project:vsftpd",
    "pure-ftpd": "cpe:2.3:a:pureftpd:pure-ftpd",
    "postfix": "cpe:2.3:a:postfix:postfix", "exim": "cpe:2.3:a:exim:exim",
    "dovecot": "cpe:2.3:a:dovecot:dovecot", "sendmail": "cpe:2.3:a:proofpoint:sendmail",
    "mariadb": "cpe:2.3:a:mariadb:mariadb", "mysql": "cpe:2.3:a:oracle:mysql",
    "postgresql": "cpe:2.3:a:postgresql:postgresql",
    "mongodb": "cpe:2.3:a:mongodb:mongodb", "redis": "cpe:2.3:a:redis:redis",
    "memcached": "cpe:2.3:a:memcached:memcached",
    "elasticsearch": "cpe:2.3:a:elastic:elasticsearch",
    "microsoft iis": "cpe:2.3:a:microsoft:internet_information_services",
    "iis": "cpe:2.3:a:microsoft:internet_information_services",
    "php": "cpe:2.3:a:php:php", "wordpress": "cpe:2.3:a:wordpress:wordpress",
    "drupal": "cpe:2.3:a:drupal:drupal", "joomla": "cpe:2.3:a:joomla:joomla",
    "jenkins": "cpe:2.3:a:jenkins:jenkins", "grafana": "cpe:2.3:a:grafana:grafana",
    "jira": "cpe:2.3:a:atlassian:jira", "confluence": "cpe:2.3:a:atlassian:confluence",
    "samba": "cpe:2.3:a:samba:samba", "isc bind": "cpe:2.3:a:isc:bind",
    "bind": "cpe:2.3:a:isc:bind", "lighttpd": "cpe:2.3:a:lighttpd:lighttpd",
    "squid": "cpe:2.3:a:squid-cache:squid", "haproxy": "cpe:2.3:a:haproxy:haproxy",
    "node.js": "cpe:2.3:a:nodejs:node.js", "nodejs": "cpe:2.3:a:nodejs:node.js",
}


def cpe_for(product_text):
    """Vrátí CPE 2.3 prefix (cpe:2.3:a:vendor:product) pro produkt, nebo None."""
    low = (product_text or "").lower()
    for kw in sorted(CPE_MAP, key=len, reverse=True):
        if kw in low:
            return CPE_MAP[kw]
    return None


def _clean_version(version):
    """Z banneru verze vytáhne čisté X.Y.Z (NVD CPE nesnáší přípony typu '-ubuntu')."""
    m = __import__("re").match(r"\d+(?:\.\d+){0,3}", str(version or "").strip())
    return m.group(0) if m else ""


def nvd_cves_for_version(product_text, version, api_key=None, max_results=12,
                         timeout=20, force=False):
    """Najde CVE platná pro daný produkt+verzi přes NVD CPE match (cachované).

    Vrací list ``[{'cve','cvss','severity'}]`` seřazený dle CVSS sestupně (cap
    ``max_results``), nebo None. Šum se omezuje přesnou shodou verze (CPE)."""
    cpe = cpe_for(product_text)
    ver = _clean_version(version)
    if not cpe or not ver:
        return None
    vms = f"{cpe}:{ver}"
    cache = _load(_VCVE_CACHE)
    key = "nvd:" + vms
    entry = cache.get(key)
    fresh = entry and (time.time() - entry.get("_ts", 0) < _VCVE_TTL)
    if entry and fresh and not force:
        return entry.get("data")
    try:
        url = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
               f"?virtualMatchString={vms}&resultsPerPage=200")
        data = _http_get_json(url, timeout, api_key)
        out = []
        for v in data.get("vulnerabilities", []):
            cve = v.get("cve", {})
            cid = cve.get("id")
            if not cid:
                continue
            score = _extract_cvss(cve)
            out.append({"cve": cid.upper(), "cvss": score,
                        "severity": cvss_to_severity(score),
                        "description": _extract_desc(cve)[:300]})
        out.sort(key=lambda x: (x["cvss"] or 0), reverse=True)
        out = out[:max_results]
        cache[key] = {"_ts": time.time(), "data": out}
        _save(_VCVE_CACHE, cache)
        return out
    except Exception:
        return entry.get("data") if entry else None


def vulners_cves_for_version(product_text, version, api_key, timeout=20, force=False):
    """Fallback/augmentace přes Vulners (vyžaduje API klíč). Best-effort: při jakékoli
    chybě vrací None. Vrací list ``[{'cve','cvss','severity'}]`` nebo None."""
    if not api_key:
        return None
    ver = _clean_version(version)
    low = (product_text or "").lower()
    # vezmeme první „slovo" produktu jako název software pro Vulners
    soft = ""
    for kw in sorted(CPE_MAP, key=len, reverse=True):
        if kw in low:
            soft = kw.split()[-1]
            break
    if not soft or not ver:
        return None
    cache = _load(_VCVE_CACHE)
    key = f"vulners:{soft}:{ver}"
    entry = cache.get(key)
    fresh = entry and (time.time() - entry.get("_ts", 0) < _VCVE_TTL)
    if entry and fresh and not force:
        return entry.get("data")
    try:
        url = ("https://vulners.com/api/v3/burp/software/"
               f"?software={soft}&version={ver}&type=software&apiKey={api_key}")
        data = _http_get_json(url, timeout)
        if data.get("result") != "OK":
            return None
        out = []
        for item in (data.get("data", {}) or {}).get("search", []):
            src = item.get("_source", {}) or {}
            score = (src.get("cvss", {}) or {}).get("score")
            for cid in src.get("cvelist", []) or []:
                out.append({"cve": str(cid).upper(), "cvss": score,
                            "severity": cvss_to_severity(score)})
        # dedup dle CVE, ponech nejvyšší skóre
        best = {}
        for r in out:
            cur = best.get(r["cve"])
            if not cur or (r["cvss"] or 0) > (cur["cvss"] or 0):
                best[r["cve"]] = r
        res = sorted(best.values(), key=lambda x: (x["cvss"] or 0), reverse=True)[:12]
        cache[key] = {"_ts": time.time(), "data": res}
        _save(_VCVE_CACHE, cache)
        return res
    except Exception:
        return None


def version_cve_lookup(product_text, version, nvd_api_key=None, vulners_api_key=None,
                       max_results=12):
    """Sloučí CVE z NVD (CPE) a Vulners (fallback) pro produkt+verzi. Vrací list
    ``[{'cve','cvss','severity'}]`` seřazený dle CVSS, dedup, cap, nebo []."""
    merged = {}
    for src in (nvd_cves_for_version(product_text, version, api_key=nvd_api_key),
                vulners_cves_for_version(product_text, version, vulners_api_key)):
        for r in (src or []):
            cur = merged.get(r["cve"])
            if not cur or (r.get("cvss") or 0) > (cur.get("cvss") or 0):
                merged[r["cve"]] = r
    return sorted(merged.values(), key=lambda x: (x.get("cvss") or 0),
                  reverse=True)[:max_results]


def eol_lookup(product_text, version, timeout=12, force=False):
    """Vrátí {'is_eol','eol_date','latest','cycle','slug','product','version'} nebo None."""
    slug = product_slug(product_text)
    if not slug or not version:
        return None
    cache = _load(_EOL_CACHE)
    entry = cache.get(slug)
    fresh = entry and (time.time() - entry.get("_ts", 0) < _EOL_TTL)
    cycles = entry.get("data") if (entry and (fresh or force is False)) else None
    if cycles is None or force:
        try:
            cycles = _http_get_json(EOL_URL.format(slug=slug), timeout)
            cache[slug] = {"_ts": time.time(), "data": cycles}
            _save(_EOL_CACHE, cache)
        except Exception:
            if entry:
                cycles = entry.get("data")  # fallback na starou cache
            else:
                return None
    cyc = match_cycle(cycles or [], version)
    if not cyc:
        return None
    is_eol, eol_date = eol_status(cyc)
    return {"is_eol": is_eol, "eol_date": eol_date, "latest": cyc.get("latest", ""),
            "cycle": str(cyc.get("cycle", "")), "slug": slug,
            "product": product_text, "version": version}


# ---------------------------------------------------------------------------
#  Existence exploitu — CISA KEV + EPSS + lokální searchsploit (ExploitDB)
# ---------------------------------------------------------------------------
def epss_band(score):
    """Slovní zařazení EPSS pravděpodobnosti (0–1)."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return ""
    if s >= 0.50:
        return "velmi vysoká"
    if s >= 0.10:
        return "vysoká"
    if s >= 0.01:
        return "střední"
    return "nízká"


def kev_catalog(timeout=15, force=False):
    """Vrátí mapu {CVE: {dateAdded, name, ransomware, dueDate}} z CISA KEV (cachované)."""
    cache = _load(_KEV_CACHE)
    entry = cache.get("_catalog") if isinstance(cache, dict) else None
    fresh = entry and (time.time() - entry.get("_ts", 0) < _KEV_TTL)
    if entry and fresh and not force:
        return entry.get("data", {})
    try:
        data = _http_get_json(KEV_URL, timeout)
        out = {}
        for v in data.get("vulnerabilities", []):
            cid = (v.get("cveID") or "").upper()
            if cid:
                out[cid] = {
                    "dateAdded": v.get("dateAdded", ""),
                    "name": v.get("vulnerabilityName", ""),
                    "ransomware": v.get("knownRansomwareCampaignUse", "") == "Known",
                    "dueDate": v.get("dueDate", ""),
                }
        _save(_KEV_CACHE, {"_catalog": {"_ts": time.time(), "data": out}})
        return out
    except Exception:
        return entry.get("data", {}) if entry else {}


def kev_lookup(cve_id, timeout=15, force=False):
    """Je-li CVE v katalogu CISA KEV (aktivně zneužíváno), vrátí jeho záznam, jinak None."""
    cid = (cve_id or "").upper()
    if not cid:
        return None
    return kev_catalog(timeout=timeout, force=force).get(cid)


def epss_lookup(cve_id, timeout=10, force=False):
    """Vrátí {'epss','percentile','band'} z FIRST EPSS (cachované), nebo None."""
    cid = (cve_id or "").upper()
    if not cid:
        return None
    cache = _load(_EPSS_CACHE)
    entry = cache.get(cid)
    fresh = entry and (time.time() - entry.get("_ts", 0) < _EPSS_TTL)
    if entry and fresh and not force:
        return {k: entry[k] for k in ("epss", "percentile", "band") if k in entry}
    try:
        data = _http_get_json(EPSS_URL.format(id=cid), timeout)
        rows = data.get("data", [])
        if not rows:
            return None
        epss = float(rows[0].get("epss") or 0.0)
        pct = float(rows[0].get("percentile") or 0.0)
        res = {"epss": epss, "percentile": pct, "band": epss_band(epss)}
        cache[cid] = {"_ts": time.time(), **res}
        _save(_EPSS_CACHE, cache)
        return res
    except Exception:
        return None


def searchsploit_lookup(cve_id):
    """Pokud je lokálně nainstalován ``searchsploit`` (ExploitDB), vrátí počet a
    názvy exploitů pro CVE: {'count', 'titles'}. Bez nástroje vrací None (degraduje)."""
    import shutil
    import subprocess
    if not shutil.which("searchsploit"):
        return None
    cid = (cve_id or "").upper()
    if not cid:
        return None
    try:
        out = subprocess.run(["searchsploit", "--cve", cid, "-j"],
                             capture_output=True, text=True, timeout=20)
        data = json.loads(out.stdout or "{}")
        exploits = data.get("RESULTS_EXPLOIT", []) or []
        titles = [e.get("Title", "") for e in exploits[:10]]
        return {"count": len(exploits), "titles": titles}
    except Exception:
        return None


def exploit_lookup(cve_id, nvd_api_key=None, use_searchsploit=False):
    """Sloučí signály existence exploitu pro CVE do jednoho slovníku.

    Vrací ``{'kev','kev_date','ransomware','epss','epss_pct','epss_band',
    'edb_count','has_exploit'}``. ``has_exploit`` = KEV ∨ ExploitDB ∨ EPSS≥0.10."""
    res = {"kev": False, "kev_date": "", "ransomware": False, "epss": None,
           "epss_pct": None, "epss_band": "", "edb_count": 0, "has_exploit": False}
    kev = kev_lookup(cve_id)
    if kev:
        res.update(kev=True, kev_date=kev.get("dateAdded", ""),
                   ransomware=bool(kev.get("ransomware")))
    epss = epss_lookup(cve_id)
    if epss:
        res.update(epss=epss.get("epss"), epss_pct=epss.get("percentile"),
                   epss_band=epss.get("band", ""))
    if use_searchsploit:
        edb = searchsploit_lookup(cve_id)
        if edb:
            res["edb_count"] = edb.get("count", 0)
    res["has_exploit"] = bool(
        res["kev"] or res["edb_count"] > 0 or (res["epss"] or 0) >= 0.10)
    return res
