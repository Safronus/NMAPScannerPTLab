from PySide6.QtCore import QObject, Signal


class WorkerSignals(QObject):
    # --- Sdílené (nmap scan i ostatní workery: tls/cert/headers/ffuf) ---
    # Pro nmap scan: (phase, target, data); pro ostatní workery: (ip, port, data).
    result = Signal(str, str, dict)
    finished = Signal()
    log = Signal(str, str)                  # (level, message)
    screenshot_request = Signal(str, str, int, str)  # url, ip, port, path
    screenshot_taken = Signal(str, str)              # ip, filepath

    # --- Nmap workflow (vícestupňová adaptivní detekce) ---
    task_started = Signal(str, str, str)    # (phase, target, label) — příčka odstartovala
    # (phase, target, rung, outcome, data, used_pn) — worker -> ScanManager.
    # outcome ∈ {"ok", "fail", "host_down"}.
    task_outcome = Signal(str, str, int, str, dict, bool)
    phase_progress = Signal(str, int, int)  # (phase, completed, total) — manager -> UI
