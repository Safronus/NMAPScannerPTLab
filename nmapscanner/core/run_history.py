"""Historie běhů skenu a verzování výsledků (čistá logika, bez závislosti na Qt).

Model managementu projektu:

* **Master seznam cílů** (`master_targets`) — projektový seznam IP. Běhy u nich
  zaznamenávají stav; přidání/odebrání cíle mění master seznam, historie se
  nemaže.
* **Běh = verze** (`ScanRun`) — jedno spuštění skenu. Drží metadata (kdy,
  profil, cíle, stav, stav fází po cílech) a **snapshot výsledků** (`scan_results`).
  Každý běh je samostatná verze, mezi kterými lze v GUI přepínat.
* **RunHistory** — seznam běhů + master cíle + id aktivního běhu. Serializuje se
  do ``project.nmapproj`` (meta), velké snapshoty se ukládají vedle do
  ``results/<run_id>/snapshot.json``.

Tento modul je bez Qt, aby šel samostatně testovat.
"""

# Fáze nmap skenu (ostatní klíče ve scan_results jsou audity: certificates, …).
NMAP_PHASES = ["online", "tcp", "udp", "vuln", "osscan"]

# Stavy fáze považované za hotové → při „Navázat" se NEspouští znovu.
SUCCESS_STATUSES = {"hotovo", "online", "offline", "zakázáno", "přeskočeno"}


def run_id_from_timestamp(timestamp):
    return f"scan_{timestamp}"


def status_from_data(phase, data):
    """Odvodí stav fáze (cíl×fáze) z uloženého výsledku — stejná pravidla jako UI.

    Vrací jeden z: ``zakázáno`` / ``chyba`` / ``přeskočeno`` / ``online`` /
    ``offline`` / ``hotovo``.
    """
    if not isinstance(data, dict):
        return "hotovo"
    if data.get("status") == "skipped_by_user":
        return "zakázáno"
    if "error" in data:
        return "chyba"
    if data.get("status") == "skipped":
        return "přeskočeno"
    if phase == "online":
        state = data.get("status")
        state = state.get("state") if isinstance(state, dict) else None
        return "online" if state == "up" else "offline"
    return "hotovo"


def phase_status_from_snapshot(snapshot):
    """Z snapshotu (scan_results) sestaví {target: {phase: status}} pro nmap fáze."""
    out = {}
    for phase in NMAP_PHASES:
        for target, data in (snapshot.get(phase, {}) or {}).items():
            out.setdefault(target, {})[phase] = status_from_data(phase, data)
    return out


def targets_from_snapshot(snapshot):
    """Posbírá všechny cíle vyskytující se v nmap fázích snapshotu (seřazené dle IP)."""
    targets = set()
    for phase in NMAP_PHASES:
        targets.update((snapshot.get(phase, {}) or {}).keys())
    return sorted(targets, key=_ip_sort_key)


class ScanRun:
    """Jeden běh skenu = jedna verze výsledků."""

    def __init__(self, run_id, label="", created_at="", profile="master",
                 custom_command="", targets=None, enabled_phases=None):
        self.id = run_id
        self.label = label
        self.created_at = created_at
        self.finished_at = None
        self.status = "running"            # running | completed | aborted
        self.profile = profile
        self.custom_command = custom_command
        self.targets = list(targets or [])
        self.enabled_phases = dict(enabled_phases or {})
        self.phase_status = {}             # target -> {phase -> status}
        self.snapshot_path = None          # relativní cesta k snapshot.json (vůči kořeni projektu)
        self.timeline = []                 # historie událostí běhu (vytvořeno/navázáno/re-scan…)

    # ---- timeline (historie událostí) --------------------------------
    def add_event(self, when, action, detail=""):
        """Přidá událost do timeline běhu. ``when`` = ISO čas (dodá volající)."""
        self.timeline.append({"time": when, "action": action, "detail": detail})

    # ---- stav fází ----------------------------------------------------
    def set_status(self, target, phase, status):
        self.phase_status.setdefault(target, {})[phase] = status

    def get_status(self, target, phase):
        return self.phase_status.get(target, {}).get(phase)

    def needs_run(self, target, phase):
        """True, pokud (cíl×fáze) ještě nedoběhla úspěšně (kandidát na (do)běh)."""
        return self.get_status(target, phase) not in SUCCESS_STATUSES

    def is_incomplete(self):
        """True, pokud některá povolená fáze u některého cíle není hotová."""
        for t in self.targets:
            for ph in NMAP_PHASES:
                if self.enabled_phases.get(ph, True) and self.needs_run(t, ph):
                    return True
        return False

    def counts(self):
        """Souhrn: kolik (cíl×fáze) je hotových / chyba / zbývá (z povolených)."""
        done = err = pending = 0
        for t in self.targets:
            for ph in NMAP_PHASES:
                if not self.enabled_phases.get(ph, True):
                    continue
                st = self.get_status(t, ph)
                if st in SUCCESS_STATUSES:
                    done += 1
                elif st == "chyba":
                    err += 1
                else:
                    pending += 1
        return {"done": done, "error": err, "pending": pending}

    # ---- serializace metadat -----------------------------------------
    def to_meta(self):
        return {
            "id": self.id,
            "label": self.label,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "status": self.status,
            "profile": self.profile,
            "custom_command": self.custom_command,
            "targets": list(self.targets),
            "enabled_phases": dict(self.enabled_phases),
            "phase_status": {t: dict(ph) for t, ph in self.phase_status.items()},
            "snapshot_path": self.snapshot_path,
            "timeline": list(self.timeline),
        }

    @classmethod
    def from_meta(cls, d):
        run = cls(
            d.get("id", ""),
            label=d.get("label", ""),
            created_at=d.get("created_at", ""),
            profile=d.get("profile", "master"),
            custom_command=d.get("custom_command", ""),
            targets=d.get("targets", []),
            enabled_phases=d.get("enabled_phases", {}),
        )
        run.finished_at = d.get("finished_at")
        run.status = d.get("status", "completed")
        run.phase_status = {t: dict(ph) for t, ph in d.get("phase_status", {}).items()}
        run.snapshot_path = d.get("snapshot_path")
        run.timeline = list(d.get("timeline", []))
        return run


class RunHistory:
    """Seznam běhů projektu + master cíle + aktivní běh."""

    def __init__(self, master_targets=None):
        self.runs = []                      # list[ScanRun], chronologicky
        self.master_targets = list(master_targets or [])
        self.active_run_id = None

    # ---- běhy ---------------------------------------------------------
    def add_run(self, run):
        self.runs.append(run)
        self.active_run_id = run.id
        return run

    def get(self, run_id):
        return next((r for r in self.runs if r.id == run_id), None)

    def active(self):
        return self.get(self.active_run_id) if self.active_run_id else None

    def next_label(self):
        return f"Běh {len(self.runs) + 1}"

    def remove(self, run_id):
        run = self.get(run_id)
        if run is None:
            return None
        self.runs.remove(run)
        if self.active_run_id == run_id:
            self.active_run_id = self.runs[-1].id if self.runs else None
        return run

    # ---- master cíle --------------------------------------------------
    def merge_master_targets(self, targets):
        """Přidá nové cíle do master seznamu (zachová pořadí, bez duplicit)."""
        for t in targets:
            if t and t not in self.master_targets:
                self.master_targets.append(t)
        return self.master_targets

    # ---- serializace --------------------------------------------------
    def to_dict(self):
        return {
            "master_targets": list(self.master_targets),
            "active_run_id": self.active_run_id,
            "runs": [r.to_meta() for r in self.runs],
        }

    @classmethod
    def from_dict(cls, d):
        h = cls(master_targets=d.get("master_targets", []))
        h.runs = [ScanRun.from_meta(r) for r in d.get("runs", [])]
        h.active_run_id = d.get("active_run_id") or (h.runs[-1].id if h.runs else None)
        return h


# ---------------------------------------------------------------------------
# Diff dvou verzí (snapshotů scan_results)
# ---------------------------------------------------------------------------
def _collect_ports(snapshot, target):
    """Z fází tcp/udp/vuln posbírá porty cíle: {(proto, port): info}.

    Otevřené porty mají přednost (open překryje případný dřívější jiný stav).
    """
    out = {}
    for phase in ("tcp", "udp", "vuln"):
        data = (snapshot.get(phase, {}) or {}).get(target, {}) or {}
        for proto in ("tcp", "udp"):
            for port, info in (data.get(proto, {}) or {}).items():
                if not isinstance(info, dict):
                    continue
                try:
                    key = (proto, int(port))
                except (TypeError, ValueError):
                    continue
                entry = {
                    "state": info.get("state"),
                    "name": info.get("name", ""),
                    "version": info.get("version", ""),
                }
                if key not in out or entry["state"] == "open":
                    out[key] = entry
    return out


def _os_name(snapshot, target):
    data = (snapshot.get("osscan", {}) or {}).get(target, {}) or {}
    matches = data.get("osmatch") or []
    if matches and isinstance(matches, list):
        first = matches[0]
        if isinstance(first, dict):
            return first.get("name", "")
    return ""


def _online_state(snapshot, target):
    data = (snapshot.get("online", {}) or {}).get(target, {}) or {}
    status = data.get("status")
    if isinstance(status, dict):
        return status.get("state")
    return None


def diff_snapshots(snap_a, snap_b):
    """Porovná dva snapshoty výsledků (A = starší, B = novější).

    Vrací dict ``{target: {...}}`` jen pro cíle, kde je nějaký rozdíl, plus
    klíč ``_targets`` se seznamem všech porovnaných cílů. U každého cíle:

    * ``added``   – nově otevřené porty (v B, ne v A) → list (proto, port)
    * ``removed`` – zmizelé/zavřené porty (otevřené v A, ne otevřené v B)
    * ``changed`` – porty se změněnou službou/verzí → list (proto, port)
    * ``os_changed`` – (os_a, os_b) když se liší OS
    * ``online_changed`` – (state_a, state_b) když se liší online stav
    """
    snap_a = snap_a or {}
    snap_b = snap_b or {}
    targets = set()
    for snap in (snap_a, snap_b):
        for phase in NMAP_PHASES:
            targets.update((snap.get(phase, {}) or {}).keys())
    targets = sorted(targets, key=_ip_sort_key)

    diff = {"_targets": targets}
    for t in targets:
        pa = _collect_ports(snap_a, t)
        pb = _collect_ports(snap_b, t)
        open_a = {k for k, v in pa.items() if v["state"] == "open"}
        open_b = {k for k, v in pb.items() if v["state"] == "open"}

        added = sorted(open_b - open_a)
        removed = sorted(open_a - open_b)
        changed = sorted(
            k for k in (open_a & open_b)
            if (pa[k]["name"], pa[k]["version"]) != (pb[k]["name"], pb[k]["version"])
        )
        os_a, os_b = _os_name(snap_a, t), _os_name(snap_b, t)
        on_a, on_b = _online_state(snap_a, t), _online_state(snap_b, t)

        entry = {}
        if added:
            entry["added"] = added
        if removed:
            entry["removed"] = removed
        if changed:
            entry["changed"] = [(k, pa[k], pb[k]) for k in changed]
        if os_a != os_b and (os_a or os_b):
            entry["os_changed"] = (os_a, os_b)
        if on_a != on_b and (on_a or on_b):
            entry["online_changed"] = (on_a, on_b)
        if entry:
            diff[t] = entry
    return diff


def _ip_sort_key(ip):
    try:
        return tuple(int(p) for p in str(ip).split(":")[0].split("."))
    except (TypeError, ValueError):
        return (0, 0, 0, 0)
