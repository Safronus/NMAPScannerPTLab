"""Detekce a aktualizace externích nástrojů (nmap, ffuf, OWASP ZAP, TLS, ExploitDB).

Zjišťuje nainstalovanou verzi a navrhuje příkaz k instalaci/aktualizaci podle
platformy (macOS → Homebrew, Linux → apt / pip / nativní). Příkazy se **nikdy
nespouští automaticky** — spustí je až uživatel ve správci aktualizací.
"""

import os
import re
import shutil
import subprocess
import sys

# ---------------------------------------------------------------------------
#  Registr nástrojů
# ---------------------------------------------------------------------------
# bins        — kandidátní názvy spustitelného souboru (PATH)
# version_arg — argument pro zjištění verze
# version_re  — regex na vytažení čísla verze z výstupu
# brew/apt/pip — příkaz instalace/aktualizace na dané platformě (None = nepodporováno)
# homepage    — odkaz pro ruční instalaci
TOOLS = [
    {
        "key": "nmap", "name": "Nmap", "kind": "Skener portů/služeb",
        "bins": ["nmap"], "version_arg": "--version",
        "version_re": r"Nmap version ([\d.]+)",
        "brew": "brew install nmap", "apt": "sudo apt-get install -y nmap",
        "winget": "winget install -e --id Insecure.Nmap --accept-source-agreements --accept-package-agreements",
        "winget_id": "Insecure.Nmap",
        "pip": None, "homepage": "https://nmap.org/download",
    },
    {
        "key": "ffuf", "name": "ffuf", "kind": "Directory fuzzing",
        "bins": ["ffuf"], "version_arg": "-V",
        "version_re": r"v?([\d.]+)",
        "brew": "brew install ffuf",
        "apt": "sudo apt-get install -y ffuf",
        "winget": "winget install -e --id ffuf.ffuf --accept-source-agreements --accept-package-agreements",
        "winget_id": "ffuf.ffuf",
        "pip": None, "homepage": "https://github.com/ffuf/ffuf",
    },
    {
        "key": "zap", "name": "OWASP ZAP", "kind": "DAST web skener",
        "bins": ["zap.sh", "zaproxy", "zap", "zap.bat"], "version_arg": "-version",
        "version_re": r"([\d]+\.[\d.]+)",
        "brew": "brew install --cask zap",
        "apt": "sudo snap install zaproxy --classic",
        "winget": "winget install -e --id ZAP.ZAP --accept-source-agreements --accept-package-agreements",
        "winget_id": "ZAP.ZAP",
        "pip": None, "homepage": "https://www.zaproxy.org/download/",
    },
    {
        "key": "testssl", "name": "testssl.sh", "kind": "Inspekce TLS",
        "bins": ["testssl.sh", "testssl"], "version_arg": "--version",
        "version_re": r"([\d.]+\w*)",
        "brew": "brew install testssl",
        "apt": "sudo apt-get install -y testssl.sh",
        "pip": None, "homepage": "https://github.com/drwetter/testssl.sh",
    },
    {
        "key": "sslscan", "name": "sslscan", "kind": "Inspekce TLS",
        "bins": ["sslscan"], "version_arg": "--version",
        "version_re": r"([\d.]+)",
        "brew": "brew install sslscan",
        "apt": "sudo apt-get install -y sslscan",
        "pip": None, "homepage": "https://github.com/rbsec/sslscan",
    },
    {
        "key": "sslyze", "name": "SSLyze", "kind": "Inspekce TLS",
        "bins": ["sslyze"], "version_arg": "--version",
        "version_re": r"([\d.]+)",
        "brew": None, "apt": None,
        "pip": "python3 -m pip install --upgrade sslyze",
        "homepage": "https://github.com/nabla-c0d3/sslyze",
    },
    {
        "key": "searchsploit", "name": "searchsploit (ExploitDB)",
        "kind": "Databáze exploitů",
        "bins": ["searchsploit"], "version_arg": "",
        "version_re": r"",
        "brew": "brew install exploitdb",
        "apt": "sudo apt-get install -y exploitdb",
        "pip": None, "homepage": "https://www.exploit-db.com/searchsploit",
    },
]


def _platform():
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform.startswith("win"):
        return "windows"
    return "linux"


def _find_bin(spec):
    # ZAP má speciální vyhledávání (i mimo PATH, např. /Applications)
    if spec["key"] == "zap":
        try:
            from .zap_runner import find_zap
            p = find_zap()
            if p:
                return p
        except Exception:
            pass
    for name in spec["bins"]:
        p = shutil.which(name)
        if p:
            return p
    return None


def _winget_installed(winget_id, timeout=20):
    """Na Windows zjistí přes ``winget list``, zda je balíček nainstalován
    (i když ještě není v PATH — čerstvá instalace vyžaduje nový proces)."""
    if not (sys.platform.startswith("win") and winget_id and shutil.which("winget")):
        return False
    try:
        r = subprocess.run(
            ["winget", "list", "--id", winget_id, "-e", "--accept-source-agreements"],
            capture_output=True, text=True, timeout=timeout)
        out = ((r.stdout or "") + (r.stderr or "")).lower()
        return r.returncode == 0 and winget_id.lower() in out
    except Exception:
        return False


def detect(spec):
    """Vrátí {'installed','version','path','needs_restart'} pro daný nástroj."""
    path = _find_bin(spec)
    if not path:
        # Windows fallback: nástroj může být nainstalován přes winget, ale běžící
        # proces má ještě starou PATH → hlásit jako nainstalovaný (nutný restart).
        if _winget_installed(spec.get("winget_id")):
            return {"installed": True, "version": "", "path": "",
                    "needs_restart": True}
        return {"installed": False, "version": "", "path": "", "needs_restart": False}
    version = ""
    arg = spec.get("version_arg")
    if arg:
        try:
            out = subprocess.run([path, arg], capture_output=True, text=True,
                                 timeout=15)
            blob = (out.stdout or "") + (out.stderr or "")
            m = re.search(spec.get("version_re") or r"([\d.]+)", blob)
            if m:
                version = m.group(1)
        except Exception:
            version = "?"
    return {"installed": True, "version": version, "path": path,
            "needs_restart": False}


def installable_here(spec, platform=None):
    """True, pokud pro tento nástroj existuje na dané platformě automatická
    instalace (brew/apt/winget/pip). Jinak jde jen o ruční instalaci."""
    return bool(update_command(spec, platform))


def unavailable_hint(spec):
    """Text pro nástroj bez automatické instalace na této platformě."""
    if sys.platform.startswith("win"):
        return ("Na Windows není nativní balík — použij WSL, nebo přeskoč "
                f"(ruční instalace: {spec.get('homepage', '')}).")
    return f"Automatická instalace není k dispozici — viz {spec.get('homepage', '')}."


def update_command(spec, platform=None):
    """Vrátí doporučený příkaz k instalaci/aktualizaci nástroje na dané platformě
    (nebo prázdné, pokud automaticky nepodporováno → odkaz na homepage)."""
    plat = platform or _platform()
    if plat == "darwin" and spec.get("brew"):
        return spec["brew"]
    if plat == "linux" and spec.get("apt"):
        return spec["apt"]
    if plat == "windows" and spec.get("winget"):
        return spec["winget"]           # Windows: winget (NE brew — ten na Win není)
    if spec.get("pip"):
        return spec["pip"]
    # Fallback brew jen mimo Windows (na Windows brew neexistuje → radši homepage)
    if plat != "windows" and spec.get("brew"):
        return spec["brew"]
    return ""


def detect_all():
    """Vrátí seznam (spec, stav) pro všechny registrované nástroje."""
    return [(s, detect(s)) for s in TOOLS]


def package_manager_available():
    """Zjistí, který správce balíčků je k dispozici (pro auto-aktualizaci)."""
    plat = _platform()
    if plat == "darwin":
        return "brew" if shutil.which("brew") else None
    if plat == "linux":
        if shutil.which("apt-get"):
            return "apt"
        if shutil.which("snap"):
            return "snap"
    return None
