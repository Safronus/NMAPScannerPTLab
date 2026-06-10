"""Detekce typu webového serveru (IIS / Apache / nginx / Tomcat / …) — bez Qt.

Vstup: HTTP hlavička ``Server`` (autoritativní), případně ``X-Powered-By`` /
``X-AspNet-Version`` a nmap ``product`` (``-sV``). Výstup: rodina serveru +
detail (původní řetězec) + zdroj. Testovatelné bez sítě.
"""

# Pořadí ZÁLEŽÍ — specifičtější značky dřív (Apache-Coyote = Tomcat, ne Apache;
# Microsoft-IIS dřív než holé IIS; openresty/kestrel dřív než nginx/iis).
_MARKERS = [
    ("apache-coyote", "Tomcat"),
    ("coyote", "Tomcat"),
    ("tomcat", "Tomcat"),
    ("microsoft-iis", "IIS"),
    ("openresty", "OpenResty"),
    ("nginx", "nginx"),
    ("apache", "Apache"),
    ("litespeed", "LiteSpeed"),
    ("caddy", "Caddy"),
    ("jetty", "Jetty"),
    ("lighttpd", "lighttpd"),
    ("kestrel", "Kestrel"),
    ("gunicorn", "Gunicorn"),
    ("uvicorn", "Uvicorn"),
    ("werkzeug", "Werkzeug"),
    ("cloudflare", "Cloudflare"),
    ("cowboy", "Cowboy"),
    ("gws", "Google"),
    ("amazons3", "Amazon S3"),
    ("iis", "IIS"),
]


def _family_from(text):
    low = (text or "").lower()
    if not low.strip():
        return None
    for marker, family in _MARKERS:
        if marker in low:
            return family
    return None


def detect_server(server="", powered_by="", nmap_product="", nmap_name=""):
    """Vrátí ``(family, detail, source)``.

    family = ``IIS`` / ``Apache`` / ``nginx`` / ``Tomcat`` / … nebo ``"neznámý"``.
    Priorita zdrojů: HTTP ``Server`` → nmap ``product`` → ``X-Powered-By``.
    """
    for text, src in ((server, "header"), (nmap_product, "nmap"),
                      (nmap_name, "nmap"), (powered_by, "x-powered-by")):
        fam = _family_from(text)
        if fam:
            return fam, (text or "").strip(), src
    # Nic konkrétního — vrátit aspoň nějaký detail, ať je co zobrazit.
    detail = (server or nmap_product or nmap_name or powered_by or "").strip()
    src = ("header" if server else "nmap" if (nmap_product or nmap_name)
           else "x-powered-by" if powered_by else "")
    return "neznámý", detail, src
