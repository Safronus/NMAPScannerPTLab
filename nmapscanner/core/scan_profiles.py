"""Profily a vícestupňové žebříky skenů (čistá logika, bez závislosti na Qt).

Model: každá fáze má **žebřík variant** seřazený od nejintenzivnější (rung 0)
po nejmírnější. Adaptivní orchestrátor (`ScanManager`) začne na startovní příčce
podle profilu a při selhání/timeoutu **zmírňuje** (posune se na další příčku),
dokud něco neprojde — cíl je „zjistit co nejvíc, ale nespadnout".

Profily určují jen **startovní příčku** v žebříku; de-eskalace pokračuje směrem
dolů ze zvolené příčky:

- ``master``    – adaptivní, start na nejtvrdší variantě (doporučený default)
- ``intensive`` – start na nejtvrdší variantě
- ``medium``    – start uprostřed žebříku
- ``light``     – start na rychlých variantách
- ``custom``    – uživatel zadá vlastní příkaz (žebřík se nepoužije)

Tento modul je záměrně bez Qt, aby byl samostatně testovatelný.
"""

# Pořadí fází tak, jak je orchestrátor a UI používají.
PHASES = ["online", "tcp", "udp", "vuln", "osscan"]

# Hloubkové fáze (vše kromě discovery). 'vuln' se plánuje až po 'tcp', aby šel
# scope na nalezené otevřené porty.
DEEP_PHASES = ["tcp", "udp", "osscan", "vuln"]

# Výchozí strop souběžných nmap procesů (vyvážený režim).
DEFAULT_MAX_CONCURRENT = 6

# ---------------------------------------------------------------------------
# Žebříky variant: každá příčka = dict {label, timeout (s), cmd}.
# Šablona cmd MUSÍ obsahovat {target}; {ports} je volitelné (vuln) a orchestrátor
# ho nahradí buď „-p <porty>" (nalezené otevřené TCP porty), nebo prázdnem.
# Pořadí: nejintenzivnější -> nejmírnější.
# ---------------------------------------------------------------------------
LADDERS = {
    "online": [
        {"label": "ping/ARP discovery", "timeout": 120,
         "cmd": "nmap -sn -T4 -oX - {target}"},
    ],
    "tcp": [
        {"label": "vše -p- + version 9", "timeout": 1800,
         "cmd": "nmap -sS -sV --version-intensity 9 -p- -T4 -oX - {target}"},
        {"label": "vše -p-", "timeout": 1200,
         "cmd": "nmap -sS -sV -p- -T4 -oX - {target}"},
        {"label": "top 1000", "timeout": 600,
         "cmd": "nmap -sS -sV --top-ports 1000 -T4 -oX - {target}"},
        {"label": "top 1000 klidně (-T3)", "timeout": 900,
         "cmd": "nmap -sS --top-ports 1000 -T3 -oX - {target}"},
    ],
    "udp": [
        {"label": "top 1000 + version", "timeout": 1500,
         "cmd": "nmap -sU -sV --top-ports 1000 -T4 -oX - {target}"},
        {"label": "top 200", "timeout": 600,
         "cmd": "nmap -sU --top-ports 200 -T4 -oX - {target}"},
        {"label": "top 50 klidně (-T3)", "timeout": 600,
         "cmd": "nmap -sU --top-ports 50 -T3 -oX - {target}"},
    ],
    "vuln": [
        {"label": "vuln + version 9", "timeout": 1800,
         "cmd": "nmap -sV --version-intensity 9 --script vuln {ports} -T4 -oX - {target}"},
        {"label": "vuln", "timeout": 1200,
         "cmd": "nmap -sV --script vuln {ports} -T4 -oX - {target}"},
        {"label": "vuln klidně (-T3)", "timeout": 1200,
         "cmd": "nmap --script vuln {ports} -T3 -oX - {target}"},
    ],
    "osscan": [
        {"label": "OS detekce", "timeout": 300,
         "cmd": "nmap -O -T4 -oX - {target}"},
        {"label": "OS odhad (guess+fuzzy)", "timeout": 300,
         "cmd": "nmap -O --osscan-guess --fuzzy -T4 -oX - {target}"},
    ],
}

# Profil = startovní příčka v žebříku pro každou hloubkovou fázi.
PROFILES = {
    "master":    {"tcp": 0, "udp": 0, "vuln": 0, "osscan": 0},
    "intensive": {"tcp": 0, "udp": 0, "vuln": 0, "osscan": 0},
    "medium":    {"tcp": 2, "udp": 1, "vuln": 1, "osscan": 0},
    "light":     {"tcp": 2, "udp": 2, "vuln": 2, "osscan": 1},
}

# Pořadí a popisky pro UI (custom je zvláštní režim mimo žebřík).
PROFILE_ORDER = ["master", "intensive", "medium", "light", "custom"]
PROFILE_LABELS = {
    "master":    "Master (adaptivní)",
    "intensive": "Intensive",
    "medium":    "Medium",
    "light":     "Light",
    "custom":    "Vlastní příkaz",
}
PROFILE_HINTS = {
    "master":    "Začne nejtvrdší variantou a při selhání automaticky zmírňuje (-Pn, méně portů, mírnější timing). Doporučeno.",
    "intensive": "Maximální záběr — start na nejtvrdší variantě, de-eskalace stále chrání před pádem.",
    "medium":    "Vyvážený kompromis rychlost/přesnost — start uprostřed žebříku.",
    "light":     "Rychlý průlet — top porty, méně version detekce.",
    "custom":    "Spustí tvůj vlastní nmap příkaz na každý cíl (placeholder {target}).",
}


def ladder_len(phase):
    """Počet příček v žebříku dané fáze."""
    return len(LADDERS.get(phase, []))


def start_index(profile, phase):
    """Startovní příčka pro danou fázi a profil (ořezaná do platného rozsahu)."""
    idx = PROFILES.get(profile, PROFILES["master"]).get(phase, 0)
    return max(0, min(idx, ladder_len(phase) - 1)) if ladder_len(phase) else 0


def variant(phase, rung):
    """Vrátí dict příčky, nebo None mimo rozsah."""
    rungs = LADDERS.get(phase, [])
    if 0 <= rung < len(rungs):
        return rungs[rung]
    return None


def build_command(phase, rung, target, open_ports=None, use_pn=False):
    """Sestaví konkrétní nmap příkaz pro danou příčku.

    Vrací ``(command:str, timeout:int, label:str)`` nebo ``None`` mimo rozsah.
    ``{ports}`` se nahradí „-p p1,p2,…" když jsou známé otevřené porty, jinak
    prázdnem. ``use_pn=True`` přidá ``-Pn`` (přeskočí ping).
    """
    v = variant(phase, rung)
    if v is None:
        return None
    cmd = v["cmd"]
    if "{ports}" in cmd:
        if open_ports:
            ports = ",".join(str(p) for p in open_ports)
            cmd = cmd.replace("{ports}", f"-p {ports}")
        else:
            cmd = cmd.replace("{ports}", "")
    cmd = cmd.replace("{target}", target)
    cmd = " ".join(cmd.split())  # sjednotit mezery (po odstranění {ports})
    if use_pn and "-Pn" not in cmd.split():
        cmd += " -Pn"
    return cmd, v["timeout"], v["label"]


def phase_label(phase, rung, use_pn=False):
    """Lidský popisek příčky pro živý panel úloh, např. „TCP · top 1000 · -Pn"."""
    v = variant(phase, rung)
    base = phase.upper()
    if v is None:
        return base
    label = f"{base} · {v['label']}"
    if use_pn:
        label += " · -Pn"
    return label
