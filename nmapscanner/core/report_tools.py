"""Detekce verzí použitých nástrojů pro sekci „Použité nástroje" v reportu.

Bez Qt. Spouští `--version` jednotlivých nástrojů s krátkým timeoutem; co není
nainstalováno, se přeskočí. Účel (purpose) je dvojjazyčný.
"""

import os
import re
import shutil
import subprocess
import glob

from .zap_runner import find_zap

# (klíč, [názvy na PATH], argument verze, regex na verzi, (purpose_cs, purpose_en))
_TOOLS = [
    ("nmap", ["nmap"], ["--version"], r"version\s+([0-9][0-9A-Za-z.\-]*)",
     ("Sken portů a služeb", "Port and service scanning")),
    ("ffuf", ["ffuf"], ["-V"], r"v?([0-9][0-9A-Za-z.\-]*)",
     ("Directory fuzzing (web)", "Directory fuzzing (web)")),
    ("sslscan", ["sslscan"], ["--version"], r"([0-9][0-9A-Za-z.\-]*)",
     ("TLS audit (engine)", "TLS audit (engine)")),
    ("testssl.sh", ["testssl.sh", "testssl"], ["--version"], r"([0-9][0-9A-Za-z.\-]*)",
     ("TLS audit", "TLS audit")),
    ("openssl", ["openssl"], ["version"], r"OpenSSL\s+([0-9][0-9A-Za-z.\-]*)",
     ("Detaily certifikátů", "Certificate details")),
]


def _run_version(names, args, pattern, timeout=5):
    path = None
    for n in names:
        path = shutil.which(n)
        if path:
            break
    if not path:
        return None
    try:
        out = subprocess.run([path] + args, capture_output=True, text=True,
                             timeout=timeout)
        text = (out.stdout or "") + (out.stderr or "")
    except Exception:
        return ""
    m = re.search(pattern, text)
    return m.group(1) if m else ""


def _sslyze_version():
    try:
        import importlib.metadata as md
        try:
            return md.version("sslyze")
        except Exception:
            pass
        import sslyze  # ověřit, že je nainstalováno
        v = getattr(sslyze, "__version__", "")
        return v if isinstance(v, str) else ""
    except Exception:
        return None


def _zap_version():
    zap_path = find_zap()
    if not zap_path:
        return None
    # zap-2.17.0.jar v adresáři launcheru → verze z názvu (rychlé, bez startu JVM)
    base = os.path.dirname(zap_path)
    for jar in glob.glob(os.path.join(base, "zap-*.jar")):
        m = re.search(r"zap-([0-9][0-9A-Za-z.\-]*)\.jar", os.path.basename(jar))
        if m:
            return m.group(1)
    return ""


def detect_tool_versions(scan_results=None, lang="cs"):
    """Vrátí seznam ``[{name, version, purpose}]`` nainstalovaných nástrojů.

    Verze, které nejsou k dispozici, se přeskočí. `purpose` dle jazyka.
    """
    i = 1 if lang == "en" else 0
    tools = []
    for name, paths, args, pat, purpose in _TOOLS:
        ver = _run_version(paths, args, pat)
        if ver is None:
            continue
        tools.append({"name": name, "version": ver or "—", "purpose": purpose[i]})

    sv = _sslyze_version()
    if sv is not None:
        tools.append({"name": "SSLyze", "version": sv or "—",
                      "purpose": ("TLS audit (engine)", "TLS audit (engine)")[i]})

    zv = _zap_version()
    if zv is not None:
        tools.append({"name": "OWASP ZAP", "version": zv or "—",
                      "purpose": ("Aktivní web sken", "Active web scan")[i]})

    return tools
