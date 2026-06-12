"""Soft-lock nad projektovou složkou — *varuje*, nezamyká.

Do složky projektu zapíše malý lock soubor (``.nmapproj.lock``) s identitou
(uživatel@stroj, PID, čas). Druhá instance při otevření téhož projektu uvidí
čerstvý zámek někoho jiného a dostane **varování** (může pokračovat — proto
„soft"). Zámek se *heartbeatem* obnovuje, takže po pádu/odpojení rychle zestárne
a přestane varovat (považuje se za opuštěný).

Vše best-effort: jakákoli I/O chyba se spolkne, aby nikdy nezablokovala práci.
"""

import getpass
import json
import os
import socket
import time

LOCK_NAME = ".nmapproj.lock"
# Po jak dlouhé nečinnosti (bez heartbeatu) se zámek považuje za opuštěný.
STALE_AFTER = 180  # s (3 zmeškané heartbeaty po 60 s)


def _identity():
    try:
        user = getpass.getuser()
    except Exception:
        user = "?"
    try:
        host = socket.gethostname()
    except Exception:
        host = "?"
    return {"user": user, "host": host, "pid": os.getpid()}


def lock_path(project_dir):
    return os.path.join(project_dir or "", LOCK_NAME)


def read_lock(project_dir):
    """Vrátí obsah lock souboru (dict) nebo None."""
    try:
        with open(lock_path(project_dir), "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else None
    except Exception:
        return None


def is_ours(lock):
    """True, pokud zámek patří TÉTO instanci (stejný stroj + PID)."""
    if not lock:
        return False
    me = _identity()
    return lock.get("host") == me["host"] and lock.get("pid") == me["pid"]


def is_active(lock, now=None):
    """True, pokud je zámek čerstvý (heartbeat v rámci STALE_AFTER)."""
    if not lock:
        return False
    ts = lock.get("ts", 0)
    try:
        ts = float(ts)
    except (TypeError, ValueError):
        return False
    return (now or time.time()) - ts < STALE_AFTER


def held_by_other(project_dir, now=None):
    """Vrátí lock dict, pokud složku drží ČERSTVÝ zámek JINÉ instance, jinak None."""
    lock = read_lock(project_dir)
    if lock and is_active(lock, now) and not is_ours(lock):
        return lock
    return None


def describe(lock):
    """Lidský popis zámku pro varování: 'uživatel@stroj (PID 123), od 14:05'."""
    if not lock:
        return "neznámý uživatel"
    who = f"{lock.get('user', '?')}@{lock.get('host', '?')}"
    pid = lock.get("pid", "?")
    when = ""
    try:
        when = time.strftime("%d.%m. %H:%M", time.localtime(float(lock.get("ts", 0))))
    except Exception:
        when = "?"
    return f"{who} (PID {pid}), naposledy aktivní {when}"


def acquire(project_dir, app_version=""):
    """Zapíše/přepíše náš zámek do složky projektu. Vrací True při úspěchu."""
    if not project_dir or not os.path.isdir(project_dir):
        return False
    data = _identity()
    data.update(ts=time.time(), app_version=app_version)
    try:
        tmp = lock_path(project_dir) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        os.replace(tmp, lock_path(project_dir))
        return True
    except Exception:
        return False


def refresh(project_dir, app_version=""):
    """Heartbeat — obnoví časové razítko, jen pokud je zámek náš (nebo chybí)."""
    lock = read_lock(project_dir)
    if lock and not is_ours(lock) and is_active(lock):
        return False  # drží ho někdo jiný a je čerstvý — nepřepisovat
    return acquire(project_dir, app_version)


def release(project_dir):
    """Smaže náš zámek (jen pokud je opravdu náš). Best-effort."""
    lock = read_lock(project_dir)
    if lock and not is_ours(lock):
        return
    try:
        os.remove(lock_path(project_dir))
    except Exception:
        pass
