"""Pomocné funkce pro OWASP ZAP daemon — detekce binárky a sestavení příkazu.

Čistá logika **bez Qt** (testovatelné). Samotné řízení daemonu a volání API je
ve ``workers/zap.py``. ZAP (Java aplikace) se instaluje zvlášť — tady ho jen
najdeme na obvyklých místech, případně poradíme s instalací.
"""

import os
import shutil

# Obvyklá umístění ZAP launcheru podle platformy
_CANDIDATES = [
    # macOS .app bundly
    "/Applications/ZAP.app/Contents/Java/zap.sh",
    "/Applications/OWASP ZAP.app/Contents/Java/zap.sh",
    os.path.expanduser("~/Applications/ZAP.app/Contents/Java/zap.sh"),
    # Linux balíčky / snap / ruční instalace
    "/usr/share/zaproxy/zap.sh",
    "/usr/bin/zaproxy",
    "/opt/zaproxy/zap.sh",
    "/snap/bin/zaproxy",
    # Windows
    r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat",
    r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat",
]

# Názvy na PATH (různé distribuce/instalace)
_PATH_NAMES = ["zap.sh", "zaproxy", "zap", "ZAP", "zap.bat"]


def find_zap():
    """Vrátí cestu k ZAP launcheru, nebo ``None`` když není nalezen."""
    env = os.environ.get("ZAP_PATH")
    if env and os.path.exists(env):
        return env
    for name in _PATH_NAMES:
        p = shutil.which(name)
        if p:
            return p
    for c in _CANDIDATES:
        if os.path.exists(c):
            return c
    return None


def java_version():
    """Vrátí major verzi nalezené Javy (int) nebo None. ZAP vyžaduje Javu 17+.

    Hledá ``java`` v PATH a v ``JAVA_HOME``. Nezablokuje sken (ZAP může mít vlastní
    nakonfigurovanou Javu) — slouží jen jako diagnostika při pádu daemonu."""
    import subprocess
    import re
    cands = []
    j = shutil.which("java")
    if j:
        cands.append(j)
    jh = os.environ.get("JAVA_HOME")
    if jh:
        cands.append(os.path.join(jh, "bin", "java.exe" if os.name == "nt" else "java"))
    for c in cands:
        try:
            r = subprocess.run([c, "-version"], capture_output=True, text=True, timeout=10)
            blob = (r.stderr or "") + (r.stdout or "")
            m = re.search(r'version "(\d+)(?:\.(\d+))?', blob)
            if m:
                major = int(m.group(1))
                # starý formát 1.8 → major je 8
                if major == 1 and m.group(2):
                    return int(m.group(2))
                return major
        except Exception:
            pass
    return None


def install_hint():
    """Vrátí krátkou nápovědu, jak ZAP doinstalovat (dle platformy)."""
    import sys
    if sys.platform == "darwin":
        return ("ZAP nebyl nalezen. Nainstaluj jej:\n"
                "  brew install --cask zap\n"
                "nebo stáhni z https://www.zaproxy.org/download/\n"
                "(volitelně nastav cestu přes proměnnou ZAP_PATH).")
    if sys.platform.startswith("linux"):
        return ("ZAP nebyl nalezen. Nainstaluj jej:\n"
                "  sudo snap install zaproxy --classic\n"
                "nebo stáhni z https://www.zaproxy.org/download/\n"
                "(volitelně nastav cestu přes proměnnou ZAP_PATH).")
    return ("ZAP nebyl nalezen. Stáhni jej z https://www.zaproxy.org/download/\n"
            "a nastav cestu přes proměnnou prostředí ZAP_PATH.")


def daemon_command(zap_path, host="127.0.0.1", port=8090, api_key="",
                   home_dir=None, extra=None):
    """Sestaví příkaz pro spuštění ZAP v daemon (headless) režimu.

    ``home_dir`` (``-dir``) dává daemonu vlastní profil, aby nekolidoval s GUI
    instancí ZAP („home directory already in use"). ``-config`` vypne kontrolu
    aktualizací add-onů při startu, ať daemon naběhne rychle a offline.
    """
    cmd = [
        zap_path, "-daemon",
        "-host", host, "-port", str(port),
        "-config", "api.disablekey=" + ("true" if not api_key else "false"),
    ]
    if home_dir:
        cmd += ["-dir", home_dir]
    if api_key:
        cmd += ["-config", f"api.key={api_key}"]
    # Klient zapv2 chodí přes proxy s magickým hostem http://zap/, proto musí být
    # povolen i host header „zap". Listener je vázán na 127.0.0.1 (-host), takže
    # povolení všech adres přes regex je bezpečné (zvenčí nedostupné).
    cmd += [
        "-config", "api.addrs.addr.name=.*",
        "-config", "api.addrs.addr.regex=true",
        "-config", "start.checkForUpdates=false",
    ]
    if extra:
        cmd += list(extra)
    return cmd


def default_home_dir():
    """Vlastní (dočasný) home adresář pro daemon — vyhne se kolizi s GUI ZAP."""
    import tempfile
    return os.path.join(tempfile.gettempdir(), "nmapscanner_zap_home")


def zap_available():
    """True, když je k dispozici jak ZAP binárka, tak python klient ``zapv2``."""
    if find_zap() is None:
        return False
    try:
        import zapv2  # noqa: F401
        return True
    except Exception:
        return False


def client_missing_hint():
    return ("Chybí Python klient ZAP. Nainstaluj jej:\n"
            "  pip install zaproxy\n"
            "(je i v requirements.txt — doinstaluje se při aktualizaci).")
