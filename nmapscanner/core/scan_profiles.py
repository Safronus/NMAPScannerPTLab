"""Profily a **progresivní** stupně skenů (čistá logika, bez závislosti na Qt).

Model (od 4.3.0): místo „de-eskalace při chybě" se používá **progresivní
pokrytí + priorita**:

* **Priorita fází** (přes prioritní frontu vláken): online → TCP → UDP → vuln →
  OS (poslední). Fáze se mohou překrývat, ale důležitější se plánují dřív a OS
  scan běží reálně až nakonec.
* **Progresivní stupně pokrytí** — každá fáze má jeden či více stupňů, které
  běží v pořadí *rychlé → úplné* a jejichž výsledky se **slučují**. Uživatel má
  něco hned (rychlý top-sken) a vše po delším čase (plný sken). Příklad TCP:
  ``top 1000`` → ``-p-``; UDP: ``top 100`` → ``top 1000``.
* **První zmírnění je ``-Pn``** — když ping nedetekuje online stav, jedou všechny
  hloubkové skeny s ``-Pn`` (řeší orchestrátor podle výsledku fáze online).
* **Timeout jen jako pojistka** — při zaseknutí/chybě se zkusí jednou klidnější
  varianta (``-T3``) a pokračuje se dál; workflow se nikdy nezablokuje.

Profily volí, jak hluboko se v progresi jde (kolik stupňů).
"""

PHASES = ["online", "tcp", "udp", "vuln", "osscan"]

# Pořadí, ve kterém orchestrátor plánuje hloubkové fáze (vuln se plánuje po TCP).
DEEP_PHASES = ["tcp", "udp", "osscan", "vuln"]

DEFAULT_MAX_CONCURRENT = 6

# Priorita pro prioritní frontu vláken (vyšší = dřív). OS je nejnižší → poslední.
PHASE_PRIORITY = {"online": 100, "tcp": 90, "udp": 70, "vuln": 40, "osscan": 10}

# Progresivní stupně pokrytí: běží VŠECHNY zvolené stupně v pořadí rychlé→úplné,
# výsledky se slučují. {target} povinné; {ports} (vuln) doplní orchestrátor.
STAGES = {
    "online": [
        {"label": "ping/ARP discovery", "timeout": 120,
         "cmd": "nmap -sn -T4 -oX - {target}"},
    ],
    "tcp": [
        {"label": "top 1000 (rychlé)", "timeout": 300,
         "cmd": "nmap -sS -sV --top-ports 1000 -T4 -oX - {target}"},
        {"label": "všechny porty -p-", "timeout": 1800,
         "cmd": "nmap -sS -sV -p- -T4 -oX - {target}"},
    ],
    "udp": [
        {"label": "top 100 (rychlé)", "timeout": 300,
         "cmd": "nmap -sU --top-ports 100 -T4 -oX - {target}"},
        {"label": "top 1000", "timeout": 1200,
         "cmd": "nmap -sU -sV --top-ports 1000 -T4 -oX - {target}"},
    ],
    "vuln": [
        {"label": "vuln skripty", "timeout": 1800,
         "cmd": "nmap -sV --script vuln {ports} -T4 -oX - {target}"},
    ],
    "osscan": [
        {"label": "OS detekce", "timeout": 300,
         "cmd": "nmap -O -T4 -oX - {target}"},
    ],
}

# Profil → které stupně (indexy) se pro danou fázi spustí.
PROFILE_STAGES = {
    "master":    {"tcp": [0, 1], "udp": [0, 1], "vuln": [0], "osscan": [0]},
    "intensive": {"tcp": [0, 1], "udp": [0, 1], "vuln": [0], "osscan": [0]},
    "medium":    {"tcp": [0, 1], "udp": [0],    "vuln": [0], "osscan": [0]},
    "light":     {"tcp": [0],    "udp": [0],    "vuln": [0], "osscan": [0]},
}

PROFILE_ORDER = ["master", "intensive", "medium", "light", "custom"]
PROFILE_LABELS = {
    "master":    "Master (adaptivní)",
    "intensive": "Intensive",
    "medium":    "Medium",
    "light":     "Light",
    "custom":    "Vlastní příkaz",
}
PROFILE_HINTS = {
    "master":    "Priorita online→TCP→UDP→vuln→OS (poslední). Progresivní porty (rychlé top → pak vše), -Pn když selže ping. Doporučeno.",
    "intensive": "Plné progresivní pokrytí všech fází (top porty → -p-), priorita a -Pn jako Master.",
    "medium":    "Vyvážený kompromis — TCP plně (top→-p-), UDP jen rychlé top porty.",
    "light":     "Rychlý průlet — jen rychlé top porty (bez plného -p-).",
    "custom":    "Spustí tvůj vlastní nmap příkaz na každý cíl (placeholder {target}).",
}


def stages_for(profile, phase):
    """Indexy stupňů ke spuštění pro daný profil a fázi (online vždy [0])."""
    if phase == "online":
        return [0]
    return list(PROFILE_STAGES.get(profile, PROFILE_STAGES["master"]).get(phase, [0]))


def stage(phase, idx):
    rungs = STAGES.get(phase, [])
    if 0 <= idx < len(rungs):
        return rungs[idx]
    return None


def priority(phase, stage_idx=0):
    """Priorita úlohy pro frontu vláken (pozdější stupeň o málo nižší)."""
    return PHASE_PRIORITY.get(phase, 0) - int(stage_idx)


def build_command(phase, stage_idx, target, open_ports=None, use_pn=False, calm=False):
    """Sestaví nmap příkaz pro daný stupeň. Vrací (command, timeout, label) nebo None.

    ``calm=True`` zklidní timing (-T4 → -T3) jako pojistku při zaseknutí.
    """
    st = stage(phase, stage_idx)
    if st is None:
        return None
    cmd = st["cmd"]
    if "{ports}" in cmd:
        if open_ports:
            cmd = cmd.replace("{ports}", "-p " + ",".join(str(p) for p in open_ports))
        else:
            cmd = cmd.replace("{ports}", "")
    cmd = cmd.replace("{target}", target)
    cmd = " ".join(cmd.split())
    if calm:
        cmd = cmd.replace("-T4", "-T3")
    if use_pn and "-Pn" not in cmd.split():
        cmd += " -Pn"
    return cmd, st["timeout"], st["label"]


def stage_label(phase, stage_idx, use_pn=False, calm=False):
    """Lidský popisek stupně pro živý panel, např. „TCP · top 1000 (rychlé) · -Pn"."""
    st = stage(phase, stage_idx)
    base = phase.upper()
    if st is None:
        return base
    label = f"{base} · {st['label']}"
    if calm:
        label += " · -T3"
    if use_pn:
        label += " · -Pn"
    return label
