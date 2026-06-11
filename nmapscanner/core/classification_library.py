"""Referenční knihovna klasifikací — loader + přístupové funkce (bez Qt).

Zdroj pravidel pro klasifikaci nálezů (severity + OWASP + doporučení). Skládá se z:
* **bundled default** (`nmapscanner/data/classification_library.json`) — verzovaný v repu,
* **uživatelské override** (``~/.nmapscanner/classification_library.json``) — editovatelné
  přes správce knihovny; deep-merge nad default (uživatel vyhrává).

Přístupové funkce vrací hodnoty **už resolvované do jazyka** (cs/en), aby je
`report_classify` mohl použít přímo.
"""

import copy
import json
import os

_DEFAULT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data",
    "classification_library.json")

_cache = None  # efektivní (merged) knihovna


def user_library_path():
    return os.path.join(os.path.expanduser("~"), ".nmapscanner",
                        "classification_library.json")


def _load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def default_library():
    return _load_json(_DEFAULT_PATH)


def user_library():
    p = user_library_path()
    return _load_json(p) if os.path.exists(p) else {}


def _deep_merge(base, over):
    """Hluboké sloučení (dicty se mergují, ostatní typy override vyhrává)."""
    if not isinstance(over, dict) or not isinstance(base, dict):
        return copy.deepcopy(over)
    out = copy.deepcopy(base)
    for k, v in over.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def library(force_reload=False):
    """Efektivní knihovna (default + uživatelské override), cachovaná."""
    global _cache
    if _cache is None or force_reload:
        _cache = _deep_merge(default_library(), user_library())
    return _cache


def reload():
    global _cache
    _cache = None
    return library()


def save_user_library(data):
    """Uloží uživatelskou override knihovnu (a invaliduje cache)."""
    p = user_library_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, p)
    reload()


def reset_user_library():
    """Smaže uživatelské override (návrat na default)."""
    p = user_library_path()
    if os.path.exists(p):
        os.remove(p)
    reload()


# ---------------------------------------------------------------------------
#  Resolvování jazyka
# ---------------------------------------------------------------------------
def pick(val, lang):
    """Z hodnoty {'cs':..,'en':..} vybere dle jazyka; jinak vrátí val."""
    if isinstance(val, dict) and ("cs" in val or "en" in val):
        return val.get("en" if lang == "en" else "cs") or val.get("cs") or val.get("en") or ""
    return val


def _resolve_rule(rule, lang, defaults=None):
    """Z pravidla vrátí dict {severity, owasp, name, recommendation} resolvovaný."""
    rule = rule or {}
    d = defaults or {}
    return {
        "severity": rule.get("severity", d.get("severity", "INFO")),
        "owasp": rule.get("owasp", d.get("owasp", "A02")),
        "name": pick(rule.get("name", d.get("name", "")), lang),
        "recommendation": pick(rule.get("recommendation", d.get("recommendation", "")), lang),
        "impact": pick(rule.get("impact", d.get("impact", "")), lang),
        "recommended_value": rule.get("recommended_value", d.get("recommended_value", "")),
    }


def impact_for_severity(severity, lang="cs"):
    """Generický dopad dle závažnosti (z knihovny, editovatelné)."""
    m = (library().get("impact_by_severity", {}) or {}).get(severity, {})
    return pick(m, lang)


# ---------------------------------------------------------------------------
#  Accessory pro klasifikátor
# ---------------------------------------------------------------------------
def port_rule(port, lang="cs"):
    lib = library()
    rule = (lib.get("ports", {}) or {}).get(str(port))
    if rule:
        return _resolve_rule(rule, lang)
    return None


def port_default(lang="cs"):
    return _resolve_rule(library().get("port_default", {}), lang,
                         defaults={"severity": "INFO", "owasp": "A02"})


def _iter_keyed(coll):
    """Yielduje (match, entry) z dict (klíč=match) i ze staršího list formátu."""
    if isinstance(coll, dict):
        for k, v in coll.items():
            yield k, v
    elif isinstance(coll, list):
        for e in coll:
            yield e.get("match", ""), e


def service_keyword_rule(service_name, lang="cs"):
    name = (service_name or "").lower()
    for match, entry in _iter_keyed(library().get("service_keywords", {})):
        if match and match in name:
            return _resolve_rule(entry, lang)
    return None


def service_version_rule(has_version, lang="cs"):
    """Pravidlo pro zveřejnění verze služby (info/low) — z webserver.version_disclosed."""
    ws = library().get("webserver", {}) or {}
    key = "version_disclosed" if has_version else "type_disclosed"
    base = ws.get(key, {})
    res = _resolve_rule(base, lang, defaults={"severity": "LOW" if has_version else "INFO", "owasp": "A02"})
    return res


def tls_grade_rule(grade, lang="cs"):
    g = (library().get("tls_grade", {}) or {}).get(grade)
    if g:
        return _resolve_rule(g, lang)
    return None


def certificate_rule(kind, lang="cs"):
    c = (library().get("certificate", {}) or {}).get(kind)
    return _resolve_rule(c, lang) if c else None


def header_rule(header, lang="cs"):
    h = (library().get("headers", {}) or {}).get(header)
    return _resolve_rule(h, lang) if h else None


def header_keys():
    return list((library().get("headers", {}) or {}).keys())


def ffuf_rule(path, lang="cs"):
    """Najde citlivé pravidlo pro cestu; vrací (resolved_rule, matched_key) nebo (None, None)."""
    plow = (path or "").lower()
    for match, entry in _iter_keyed(library().get("ffuf", {})):
        if match and match in plow:
            return _resolve_rule(entry, lang), match
    return None, None


def ffuf_status_downgrade(status):
    st = (library().get("ffuf_status", {}) or {}).get(str(status), {})
    return int(st.get("downgrade", 0) or 0)


def webserver_rule(has_version, lang="cs"):
    return service_version_rule(has_version, lang)


def vuln_rule(has_cve, lang="cs"):
    v = library().get("vuln", {}) or {}
    base = v.get("confirmed_cve" if has_cve else "confirmed", {})
    return _resolve_rule(base, lang, defaults={"severity": "HIGH", "owasp": "A03" if has_cve else "A06"})


def cve_rule(cve_id, lang="cs"):
    c = (library().get("cve", {}) or {}).get((cve_id or "").upper())
    return _resolve_rule(c, lang) if c else None


def cve_link(kind, cve_id):
    tpl = (library().get("cve_links", {}) or {}).get(kind, "")
    return tpl.replace("{id}", cve_id) if tpl else ""
