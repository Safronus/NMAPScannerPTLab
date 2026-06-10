from PySide6.QtCore import QObject, Signal


class WorkerSignals(QObject):
    # --- Sdílené (nmap scan i ostatní workery: tls/cert/headers/ffuf) ---
    # Pro nmap scan: (phase, target, data); pro ostatní workery: (ip, port, data).
    result = Signal(str, str, dict)
    finished = Signal()
    log = Signal(str, str)                  # (level, message)
    screenshot_request = Signal(str, str, int, str)  # url, ip, port, path
    screenshot_taken = Signal(str, str)              # ip, filepath

    # --- Nmap workflow (progresivní vícestupňová detekce) ---
    task_started = Signal(str, str, str)    # (phase, target, label) — stupeň odstartoval
    # (phase, target, stage, outcome, data, used_pn) — worker -> ScanManager.
    # outcome ∈ {"ok", "fail", "host_down"}. ``data`` je deklarován jako ``object``,
    # ne ``dict`` — nmap výsledky mají INT klíče portů ({22: {...}}) a queued (cross-thread)
    # signál by je marshaloval na QVariantMap (str klíče) → spam "_pythonToCppCopy (int)".
    # ``object`` předá Python dict referencí bez konverze.
    task_outcome = Signal(str, str, int, str, object, bool)
    # (phase, target, data, final) — manager -> UI. final=True = fáze pro cíl je hotová
    # (poslední stupeň); final=False = průběžný výsledek. ``object`` ze stejného důvodu.
    scan_result = Signal(str, str, object, bool)
    phase_progress = Signal(str, int, int)  # (phase, completed, total) — manager -> UI
