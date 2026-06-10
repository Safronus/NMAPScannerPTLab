"""Orchestrace vícestupňového adaptivního skenu.

Tok (profily master/intensive/medium/light):

1. Pro každý cíl se spustí discovery (``online``).
2. Jakmile discovery cíle skončí, **ihned** se pro něj spustí hloubkové fáze
   (tcp/udp/osscan) — nečeká se na ostatní cíle (pipeline). ``vuln`` se plánuje
   až po dokončení ``tcp``, aby šel zaměřit na nalezené otevřené porty.
3. Každá fáze běží jako žebřík variant. Při ``fail`` (chyba/timeout) se přejde
   na další (mírnější) příčku; při ``host_down`` se nejdřív zkusí ``-Pn``.
   Když žebřík dojde, fáze skončí stavem ``chyba`` — workflow nikdy nespadne.

Souběh je omezen stropem vláken (``max_concurrent``).

Profil ``custom`` spustí uživatelův vlastní příkaz na každý cíl (bez žebříku).
"""
from PySide6.QtCore import QObject, Signal, Slot, QThreadPool

from . import scan_profiles as sp
from .run_history import SUCCESS_STATUSES
from ..workers.scan import ScanWorker


class ScanManager(QObject):
    workflow_finished = Signal()

    def __init__(self, signals, max_concurrent=sp.DEFAULT_MAX_CONCURRENT):
        super().__init__()
        self.signals = signals
        self.max_concurrent = max_concurrent
        self.thread_pool = QThreadPool()
        self.is_running = False
        # Výsledky workerů (de-eskalace) chodí sem.
        self.signals.task_outcome.connect(self.on_task_outcome)
        self._reset_state()

    def _reset_state(self):
        self.profile = "master"
        self.enabled_phases = {p: True for p in sp.PHASES}
        self.custom_command = ""
        self.targets = []
        self.needs_pn = {}        # target -> bool
        self.open_ports = {}      # target -> [int]
        self.vuln_scheduled = {}  # target -> bool
        self.completed = {}       # phase -> int
        self.total = {}           # phase -> int
        self.resume = False
        self.prior_status = {}    # target -> {phase -> status} (jen při resume)

    # ---- veřejné API -------------------------------------------------
    @Slot(list, str, dict, str, bool, dict)
    def start_workflow(self, targets, profile="master", enabled_phases=None,
                       custom_command="", resume=False, resume_ctx=None):
        """Spustí (nebo naváže) workflow.

        ``resume=True`` + ``resume_ctx`` = {"status": {t:{ph:stav}},
        "open_ports": {t:[porty]}, "needs_pn": {t:bool}} → přeskočí (cíl×fáze),
        které už doběhly úspěšně, a u zbytku naváže (chyby a nedoběhlé znovu).
        """
        self._reset_state()
        self.is_running = True
        self.profile = profile or "master"
        self.enabled_phases = dict(enabled_phases or {p: True for p in sp.PHASES})
        self.custom_command = (custom_command or "").strip()
        self.targets = [t for t in targets if t]
        self.resume = bool(resume) and self.profile != "custom"

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

        # Spočítat počet (cíl×fáze), které se v tomto běhu reálně spustí.
        online_on = self.enabled_phases.get("online", True)
        if online_on:
            self._init_phase("online", self._count_to_run("online"))
        for ph in sp.DEEP_PHASES:
            if self.enabled_phases.get(ph, True):
                self._init_phase(ph, self._count_to_run(ph))

        label = sp.PROFILE_LABELS.get(self.profile, self.profile)
        mode = "navázání" if self.resume else "spuštění"
        self.signals.log.emit(
            "info", f"▶️ {mode.capitalize()} – profil '{label}', {len(self.targets)} cílů, "
                    f"strop {self.max_concurrent} souběžně.")

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

    def _should_run(self, target, phase):
        """Při resume přeskočí (cíl×fáze) s úspěšným stavem; jinak vždy True."""
        if not self.resume:
            return True
        st = (self.prior_status.get(target, {}) or {}).get(phase)
        return st not in SUCCESS_STATUSES

    def _count_to_run(self, phase):
        return sum(1 for t in self.targets if self._should_run(t, phase))

    def stop_workflow(self):
        self.is_running = False
        self.thread_pool.clear()
        self.signals.log.emit("warning", "⏹️ Skenování zastaveno uživatelem.")
        self.workflow_finished.emit()

    # ---- příchozí výsledky workerů -----------------------------------
    @Slot(str, str, int, str, dict, bool)
    def on_task_outcome(self, phase, target, rung, outcome, data, used_pn):
        if not self.is_running:
            return

        # --- vlastní příkaz: žádný žebřík, jen jedna příčka (+ -Pn fallback) ---
        if self.profile == "custom":
            if outcome == "host_down" and not used_pn:
                self.signals.log.emit("info", f"↪️ {target}: host dole, opakuji vlastní příkaz s -Pn")
                self._schedule_custom(target, use_pn=True)
                return
            self._finalize("tcp", target, data, "chyba" if outcome == "fail" else "hotovo")
            return

        # --- discovery ---
        if phase == "online":
            if outcome == "ok":
                self.needs_pn[target] = False
                self._finalize("online", target, {"status": {"state": "up"}}, "online")
            else:
                # host_down i fail bereme jako „neodpovídá" → dál s -Pn.
                self.needs_pn[target] = True
                payload = data if data else {"status": {"state": "down"}}
                self._finalize("online", target, payload, "offline")
            self._launch_deep(target)
            return

        # --- hloubkové fáze ---
        # Host dole a -Pn jsme ještě nezkoušeli → zopakuj STEJNOU příčku s -Pn.
        if outcome == "host_down" and not used_pn:
            self.needs_pn[target] = True
            self._schedule(target, phase, rung, use_pn=True)
            return

        if outcome == "fail":
            nxt = rung + 1
            if nxt < sp.ladder_len(phase):
                v = sp.variant(phase, nxt)
                self.signals.log.emit(
                    "warning", f"↓ Zmírňuji {phase.upper()} pro {target}: {v['label']}")
                self._schedule(target, phase, nxt, use_pn=self.needs_pn.get(target, False))
                return
            # Žebřík vyčerpán → terminální chyba (workflow pokračuje).
            err = data.get("error", "všechny varianty selhaly") if isinstance(data, dict) else "selhalo"
            self._finalize(phase, target, {"error": err}, "chyba")
            if phase == "tcp":
                self._maybe_schedule_vuln(target)
            return

        # outcome == "ok"
        if phase == "tcp":
            self.open_ports[target] = self._extract_open_tcp(data)
        self._finalize(phase, target, data, "hotovo")
        if phase == "tcp":
            self._maybe_schedule_vuln(target)

    # ---- interní -----------------------------------------------------
    def _init_phase(self, phase, count):
        self.total[phase] = count
        self.completed[phase] = 0
        self.signals.phase_progress.emit(phase, 0, count)

    def _launch_deep(self, target):
        if not self.is_running:
            return
        use_pn = self.needs_pn.get(target, False)
        for ph in ("tcp", "udp", "osscan"):
            if self.enabled_phases.get(ph, True) and self._should_run(target, ph):
                self._schedule(target, ph, sp.start_index(self.profile, ph), use_pn=use_pn)
        # vuln: pokud poběží tcp, počká se na něj (scope na porty); jinak hned.
        if self.enabled_phases.get("vuln", True) and self._should_run(target, "vuln"):
            tcp_will_run = self.enabled_phases.get("tcp", True) and self._should_run(target, "tcp")
            if not tcp_will_run:
                self._maybe_schedule_vuln(target)

    def _maybe_schedule_vuln(self, target):
        if not self.is_running:
            return
        if not self.enabled_phases.get("vuln", True):
            return
        if not self._should_run(target, "vuln"):
            return
        if self.vuln_scheduled.get(target):
            return
        self.vuln_scheduled[target] = True
        self._schedule(target, "vuln", sp.start_index(self.profile, "vuln"),
                       use_pn=self.needs_pn.get(target, False))

    def _schedule(self, target, phase, rung, use_pn=False):
        if not self.is_running:
            return
        open_ports = self.open_ports.get(target) if phase == "vuln" else None
        built = sp.build_command(phase, rung, target, open_ports=open_ports, use_pn=use_pn)
        if built is None:
            return
        command, timeout, _vlabel = built
        label = sp.phase_label(phase, rung, use_pn)
        worker = ScanWorker(phase, target, rung, command, label, use_pn, timeout, self.signals)
        self.thread_pool.start(worker)

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
        worker = ScanWorker("tcp", target, 0, cmd, label, use_pn, 3600, self.signals)
        self.thread_pool.start(worker)

    def _start_custom(self):
        self._init_phase("tcp", len(self.targets))
        self.signals.log.emit(
            "info", f"▶️ Vlastní příkaz na {len(self.targets)} cílů, strop {self.max_concurrent} souběžně.")
        if not self.targets:
            self._finish()
            return
        for t in self.targets:
            if not self.is_running:
                break
            self._schedule_custom(t)

    def _finalize(self, phase, target, data, status):
        """Terminální výsledek fáze pro cíl → poslat do UI a posunout progress."""
        self.signals.result.emit(phase, target, data if isinstance(data, dict) else {})
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
