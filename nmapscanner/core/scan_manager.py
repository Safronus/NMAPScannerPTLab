


from PySide6.QtCore import QObject, Signal, Slot, QThreadPool
from ..workers.scan import ScanWorker


class ScanManager(QObject):
    workflow_finished = Signal()

    def __init__(self, command_templates, signals):
        super().__init__()
        self.command_templates = command_templates
        self.signals = signals
        self.is_running = False
        self.phases = ['online', 'tcp', 'udp', 'vuln', 'osscan']
        self.enabled_phases = {p: True for p in self.phases}
        self.thread_pool = QThreadPool()
        
        # Nová počítadla pro progress
        self.phase_progress = {p: {'total': 0, 'completed': 0} for p in self.phases}

    def set_enabled_phases(self, enabled_phases):
        self.enabled_phases = enabled_phases

    @Slot(list)
    def start_workflow(self, targets):
        self.is_running = True
        self.thread_pool.setMaxThreadCount(20)
        self.signals.log.emit("info", f"Zahajuji paralelní online kontrolu pro {len(targets)} cílů...")
        for target in targets:
            if not self.is_running: break
            if self.enabled_phases.get('online', True):
                self._schedule_task('online', target)
            else:
                self.signals.log.emit("warning", f"Fáze 'online' je přeskočena pro cíl {target}")
                self.signals.result.emit('online', target, {'status': {'state': 'skipped_by_user'}})

    def _schedule_task(self, phase, target, use_pn=False):
        if not self.is_running:
            return
        
        base_phase = phase.replace("-Pn", "")  # OPRAVA: Bez mezery a závorek
        
        if not self.enabled_phases.get(base_phase, True):
            self.signals.log.emit("warning", f"Fáze '{phase}' je zakázána - přeskakuji cíl {target}")
            self.signals.result.emit(phase, target, {'status': 'skipped_by_user'})
            return
        
        command = self.command_templates[base_phase].replace('{target}', target)
        phase_name = phase
        
        if use_pn:
            command += " -Pn"
            phase_name += "-Pn"  # OPRAVA: Bez mezery a bez závorek
        
        # Zvýšit počet celkových úloh pro tuto fázi
        self.phase_progress[base_phase]['total'] += 1
        
        worker = ScanWorker(phase_name, command, target, self.signals)
        self.thread_pool.start(worker)
        
        # Logovat progress
        progress = self.phase_progress[base_phase]
        self.signals.log.emit("info", f"📊 [{base_phase.upper()}] Progress: {progress['completed']}/{progress['total']} úloh")


    @Slot(dict)
    def handle_online_phase_done(self, online_results):
        if not self.is_running:
            return
        
        self.signals.log.emit("info", "Online kontrola dokončena. Spouštím hloubkové skeny...")
        self.thread_pool.setMaxThreadCount(10)
        
        online_targets_count = sum(1 for data in online_results.values() if data.get('status', {}).get('state') == 'up')
        self.signals.log.emit("info", f"Nalezeno {online_targets_count} online cílů.")
        
        if not any(online_results.values()):
            self.workflow_finished.emit()
            return
        
        for target, data in online_results.items():
            is_online = data.get('status', {}).get('state') == 'up'
            skipped_by_user = data.get('status', {}).get('state') == 'skipped_by_user'
            
            # Přidat 'osscan' do seznamu fází
            for phase in ['tcp', 'udp', 'vuln', 'osscan']:
                if not self.is_running:
                    break
                
                if self.enabled_phases.get(phase, True):
                    self._schedule_task(phase, target, use_pn=not is_online and not skipped_by_user)
                else:
                    self.signals.log.emit("warning", f"Fáze '{phase}' přeskočena pro {target}")
                    self.signals.result.emit(phase, target, {'status': 'skipped_by_user'})
            
            if not self.is_running:
                break

    def stop_workflow(self):
        self.is_running = False
        self.thread_pool.clear()
        self.signals.log.emit("warning", "Všechny naplánované skeny byly zrušeny.")
        self.workflow_finished.emit()

