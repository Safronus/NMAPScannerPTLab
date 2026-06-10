"""Orchestrace progresivního, prioritně paralelního skenu (od 4.3.0).

Strategie „Master":

1. **online** discovery (`-sn`). Když ping nedetekuje host, nepovažuje se za
   mrtvý — všechny hloubkové skeny pak jedou s ``-Pn`` (první zmírnění).
2. Jakmile discovery cíle skončí, spustí se jeho hloubkové fáze. Plánují se
   přes **prioritní frontu vláken** (online→TCP→UDP→vuln→OS), takže důležitější
   fáze jdou dřív a **OS scan běží reálně až nakonec**.
3. Každá fáze má **progresivní stupně** (rychlé top porty → plný sken), které
   běží v pořadí a jejichž výsledky se **slučují** — uživatel má něco hned a vše
   po delším čase. Průběžné výsledky se posílají do UI s ``final=False``,
   poslední stupeň s ``final=True``.
4. **Timeout/chyba = jen pojistka:** jednou se zkusí klidnější varianta (``-T3``)
   a pak se pokračuje dalším stupněm — workflow se nikdy nezablokuje.

Profil ``custom`` spustí uživatelův příkaz na každý cíl (bez stupňů).
"""
from PySide6.QtCore import QObject, Signal, Slot, QThreadPool

from . import scan_profiles as sp
from .run_history import SUCCESS_STATUSES
from ..workers.scan import ScanWorker, ProcessRegistry


class ScanManager(QObject):
    workflow_finished = Signal()

    def __init__(self, signals, max_concurrent=sp.DEFAULT_MAX_CONCURRENT):
        super().__init__()
        self.signals = signals
        self.max_concurrent = max_concurrent
        self.thread_pool = QThreadPool()
        self.is_running = False
        # Registr běžících nmap procesů — aby šly při zastavení/zavření tvrdě zabít.
        self.proc_registry = ProcessRegistry()
        # Sudo kontext (nastaví aplikace před spuštěním; _reset_state ho NEmaže):
        # sudo_password = bytes/bytearray nebo None; use_sudo = obalit nmap sudem.
        self.sudo_password = None
        self.use_sudo = True
        self.signals.task_outcome.connect(self.on_task_outcome)
        self._reset_state()

    def _reset_state(self):
        self.profile = "master"
        self.enabled_phases = {p: True for p in sp.PHASES}
        self.custom_command = ""
        self.targets = []
        self.needs_pn = {}             # target -> bool
        self.open_ports = {}           # target -> [int]
        self.vuln_scheduled = {}       # target -> bool
        self.merged = {}               # (target, phase) -> sloučená data ze stupňů
        self.stage_seq = {}            # (target, phase) -> [indexy stupňů]
        self.stage_pos = {}            # (target, phase) -> pozice v stage_seq
        self.phase_any_ok = {}         # (target, phase) -> bool
        self.last_error = {}           # (target, phase) -> str
        self.calm_done = {}            # (target, phase, stage) -> bool
        self.completed = {}            # phase -> int
        self.total = {}                # phase -> int
        self.resume = False
        self.prior_status = {}

    # ---- veřejné API -------------------------------------------------
    @Slot(list, str, dict, str, bool, dict)
    def start_workflow(self, targets, profile="master", enabled_phases=None,
                       custom_command="", resume=False, resume_ctx=None):
        self._reset_state()
        self.is_running = True
        self.profile = profile or "master"
        self.enabled_phases = dict(enabled_phases or {p: True for p in sp.PHASES})
        self.custom_command = (custom_command or "").strip()
        self.targets = [t for t in targets if t]
        self.resume = bool(resume) and self.profile != "custom"
        self.proc_registry.reset()

        ctx = resume_ctx or {}
        self.prior_status = ctx.get("status", {}) or {}
        prior_open = ctx.get("open_ports", {}) or {}
        prior_pn = ctx.get("needs_pn", {}) or {}
        for t in self.targets:
            self.needs_pn[t] = bool(prior_pn.get(t, False))
            self.open_ports[t] = list(prior_open.get(t, []))
            self.vuln_scheduled[t] = False

        self.thread_pool.setMaxThreadCount(self.max_concurrent)

        if self.profile == "custom":
            self._start_custom()
            return

        online_on = self.enabled_phases.get("online", True)
        if online_on:
            self._init_phase("online", sum(1 for t in self.targets if self._should_run(t, "online")))
        for ph in sp.DEEP_PHASES:
            if self.enabled_phases.get(ph, True):
                cnt = sum(len(sp.stages_for(self.profile, ph))
                          for t in self.targets if self._should_run(t, ph))
                self._init_phase(ph, cnt)

        label = sp.PROFILE_LABELS.get(self.profile, self.profile)
        mode = "navázání" if self.resume else "spuštění"
        self.signals.log.emit(
            "info", f"▶️ {mode.capitalize()} – profil '{label}', {len(self.targets)} cílů, "
                    f"priorita online→TCP→UDP→vuln→OS, strop {self.max_concurrent}.")

        if not self.total:
            self.signals.log.emit("warning", "Žádná fáze není povolena — není co skenovat.")
            self._finish()
            return
        if not any(self.total.values()):
            self.signals.log.emit("info", "Vše už je hotové — není co navazovat.")
            self._finish()
            return

        for t in self.targets:
            if not self.is_running:
                break
            if online_on and self._should_run(t, "online"):
                self._schedule(t, "online", 0, use_pn=False)
            else:
                self._launch_deep(t)

    def stop_workflow(self):
        self.is_running = False
        self.proc_registry.terminate_all()   # zabít běžící nmap procesy
        self.thread_pool.clear()              # zahodit frontu čekajících
        self.signals.log.emit("warning", "⏹️ Skenování zastaveno uživatelem.")
        self.workflow_finished.emit()

    def shutdown(self):
        """Tvrdé zastavení pro zavření aplikace — zabije procesy a počká na pool."""
        self.is_running = False
        self.proc_registry.terminate_all()
        self.thread_pool.clear()
        self.thread_pool.waitForDone(3000)

    # ---- příchozí výsledky workerů -----------------------------------
    @Slot(str, str, int, str, object, bool)
    def on_task_outcome(self, phase, target, stage_idx, outcome, data, used_pn):
        if not self.is_running:
            return

        # --- vlastní příkaz ---
        if self.profile == "custom":
            if outcome == "host_down" and not used_pn:
                self.signals.log.emit("info", f"↪️ {target}: host dole, opakuji vlastní příkaz s -Pn")
                self._schedule_custom(target, use_pn=True)
                return
            self.signals.scan_result.emit("tcp", target, data if isinstance(data, dict) else {}, True)
            self._bump("tcp")
            return

        # --- discovery ---
        if phase == "online":
            up = outcome == "ok"
            self.needs_pn[target] = not up
            self.signals.scan_result.emit(
                "online", target, {"status": {"state": "up" if up else "down"}}, True)
            self._bump("online")
            self._launch_deep(target)
            return

        # --- hloubkové stupně ---
        # 1) host dole a bez -Pn → zopakuj STEJNÝ stupeň s -Pn (první zmírnění)
        if outcome == "host_down" and not used_pn:
            self.needs_pn[target] = True
            self._schedule(target, phase, stage_idx, use_pn=True)
            return
        # 2) chyba/timeout a ještě bez klidnějšího pokusu → 1× -T3 (pojistka)
        if outcome == "fail" and not self.calm_done.get((target, phase, stage_idx)):
            self.calm_done[(target, phase, stage_idx)] = True
            self.signals.log.emit(
                "warning", f"↻ {phase.upper()} {target}: zaseklo se / chyba → klidnější pokus (-T3)")
            self._schedule(target, phase, stage_idx, use_pn=self.needs_pn.get(target, False), calm=True)
            return

        # stupeň terminálně dokončen (ok, nebo chyba i po -T3)
        if outcome == "ok":
            self.phase_any_ok[(target, phase)] = True
            self.merged[(target, phase)] = self._merge(self.merged.get((target, phase), {}), data)
            if phase == "tcp":
                self.open_ports[target] = self._extract_open_tcp(self.merged[(target, phase)])
        elif isinstance(data, dict) and data.get("error"):
            self.last_error[(target, phase)] = data["error"]

        self._bump(phase)

        seq = self.stage_seq.get((target, phase), [stage_idx])
        pos = self.stage_pos.get((target, phase), 0)
        merged = self.merged.get((target, phase), {})

        if pos < len(seq) - 1:
            # průběžný výsledek (UI doplní data, matice zůstane „probíhá")
            self.signals.scan_result.emit(phase, target, merged, False)
            self.stage_pos[(target, phase)] = pos + 1
            self._schedule(target, phase, seq[pos + 1], use_pn=self.needs_pn.get(target, False))
        else:
            # finální výsledek fáze pro cíl
            if self.phase_any_ok.get((target, phase)):
                payload = merged
            else:
                payload = {"error": self.last_error.get((target, phase), "všechny stupně selhaly")}
            self.signals.scan_result.emit(phase, target, payload, True)
            if phase == "tcp":
                self._start_vuln(target)

    # ---- interní -----------------------------------------------------
    def _should_run(self, target, phase):
        if not self.resume:
            return True
        st = (self.prior_status.get(target, {}) or {}).get(phase)
        return st not in SUCCESS_STATUSES

    def _init_phase(self, phase, count):
        self.total[phase] = count
        self.completed[phase] = 0
        self.signals.phase_progress.emit(phase, 0, count)

    def _launch_deep(self, target):
        if not self.is_running:
            return
        for ph in ("tcp", "udp", "osscan"):
            if self.enabled_phases.get(ph, True) and self._should_run(target, ph):
                self._start_phase(target, ph)
        # vuln až po TCP (scope na porty); když TCP nepoběží, hned
        if self.enabled_phases.get("vuln", True) and self._should_run(target, "vuln"):
            tcp_will_run = self.enabled_phases.get("tcp", True) and self._should_run(target, "tcp")
            if not tcp_will_run:
                self._start_vuln(target)

    def _start_phase(self, target, phase):
        seq = sp.stages_for(self.profile, phase)
        if not seq:
            return
        self.stage_seq[(target, phase)] = seq
        self.stage_pos[(target, phase)] = 0
        self.phase_any_ok[(target, phase)] = False
        self.merged[(target, phase)] = {}
        self._schedule(target, phase, seq[0], use_pn=self.needs_pn.get(target, False))

    def _start_vuln(self, target):
        if not self.is_running:
            return
        if not self.enabled_phases.get("vuln", True):
            return
        if not self._should_run(target, "vuln"):
            return
        if self.vuln_scheduled.get(target):
            return
        self.vuln_scheduled[target] = True
        self._start_phase(target, "vuln")

    def _schedule(self, target, phase, stage_idx, use_pn=False, calm=False):
        if not self.is_running:
            return
        open_ports = self.open_ports.get(target) if phase == "vuln" else None
        built = sp.build_command(phase, stage_idx, target, open_ports=open_ports,
                                 use_pn=use_pn, calm=calm)
        if built is None:
            return
        command, timeout, _vl = built
        label = sp.stage_label(phase, stage_idx, use_pn, calm)
        worker = ScanWorker(phase, target, stage_idx, command, label, use_pn, timeout,
                            self.signals, sudo_password=self.sudo_password,
                            use_sudo=self.use_sudo, registry=self.proc_registry)
        self.thread_pool.start(worker, sp.priority(phase, stage_idx))

    def _bump(self, phase):
        if phase in self.total:
            self.completed[phase] = min(self.completed.get(phase, 0) + 1, self.total[phase])
            self.signals.phase_progress.emit(phase, self.completed[phase], self.total[phase])
        self._check_done()

    def _check_done(self):
        if not self.is_running:
            return
        for ph, tot in self.total.items():
            if self.completed.get(ph, 0) < tot:
                return
        self._finish()

    def _finish(self):
        self.is_running = False
        self.signals.log.emit("info", "🏁 Všechny fáze dokončeny.")
        self.workflow_finished.emit()

    # ---- vlastní příkaz ----------------------------------------------
    def _start_custom(self):
        self._init_phase("tcp", len(self.targets))
        self.signals.log.emit(
            "info", f"▶️ Vlastní příkaz na {len(self.targets)} cílů, strop {self.max_concurrent}.")
        if not self.targets:
            self._finish()
            return
        for t in self.targets:
            if not self.is_running:
                break
            self._schedule_custom(t)

    def _schedule_custom(self, target, use_pn=False):
        if not self.is_running:
            return
        cmd = self.custom_command
        cmd = cmd.replace("{target}", target) if "{target}" in cmd else f"{cmd} {target}"
        if "-oX" not in cmd.split():
            cmd += " -oX -"
        if use_pn and "-Pn" not in cmd.split():
            cmd += " -Pn"
        label = "CUSTOM" + (" · -Pn" if use_pn else "")
        worker = ScanWorker("tcp", target, 0, cmd, label, use_pn, 3600, self.signals,
                            sudo_password=self.sudo_password, use_sudo=self.use_sudo,
                            registry=self.proc_registry)
        self.thread_pool.start(worker, sp.PHASE_PRIORITY["tcp"])

    # ---- pomocné -----------------------------------------------------
    @staticmethod
    def _merge(base, new):
        """Sloučí výsledky stupňů — porty se sjednotí, ostatní klíče přebijí novější."""
        if not isinstance(new, dict):
            return base or {}
        out = dict(base or {})
        for proto in ("tcp", "udp"):
            if isinstance(new.get(proto), dict):
                m = dict(out.get(proto, {}))
                m.update(new[proto])
                out[proto] = m
        for k, v in new.items():
            if k not in ("tcp", "udp") and v:
                out[k] = v
        return out

    @staticmethod
    def _extract_open_tcp(data):
        if not isinstance(data, dict):
            return []
        ports = []
        for port, info in (data.get("tcp", {}) or {}).items():
            if isinstance(info, dict) and info.get("state") == "open":
                try:
                    ports.append(int(port))
                except (TypeError, ValueError):
                    pass
        return sorted(ports)
