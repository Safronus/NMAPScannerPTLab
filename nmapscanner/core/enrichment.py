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
_EOL_TTL = 14 * 24 * 3600  # 14 dní

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}"
EOL_URL = "https://endoflife.date/api/{slug}.json"

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
        metrics = cve.get("metrics", {})
        score = None
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                score = metrics[key][0].get("cvssData", {}).get("baseScore")
                break
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        result = {"cvss": score, "severity": cvss_to_severity(score),
                  "description": desc[:500]}
        cache[cve_id] = result
        _save(_NVD_CACHE, cache)
        return result
    except Exception:
        return None


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
