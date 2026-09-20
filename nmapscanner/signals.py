from PySide6.QtCore import QObject, Signal


class WorkerSignals(QObject):
    # --- Sdílené (nmap scan i ostatní workery: tls/cert/headers/ffuf) ---
    # Pro nmap scan: (phase, target, data); pro ostatní workery: (ip, port, data).
    # POZOR: typ musí být ``object``, NE ``dict`` — data (TLS/cert/nmap) obsahují
    # vnořené INT klíče (porty, cipher ID). Přes vlákna by PySide `dict` marshaloval
    # na QVariantMap (vyžaduje str klíče) a pro každý int klíč vypsal do terminálu
    # „Shiboken _pythonToCppCopy: Cannot copy-convert (int) to C++". ``object``
    # předá Python objekt beze změny.
    result = Signal(str, str, object)
    finished = Signal()
    log = Signal(str, str)                  # (level, message)
    screenshot_request = Signal(str, str, int, str)  # url, ip, port, path
    screenshot_taken = Signal(str, str)              # ip, filepath (jen úspěch → galerie)
    # (ip, url, ok, info) — konec POKUSU o screenshot (úspěch i chyba) → průběh/souhrn.
    # info = cesta k souboru (ok) nebo text chyby (ne-ok).
    screenshot_done = Signal(str, str, bool, str)
    # (ip, {port: info}) — detekce web serveru pro cíl. ``object`` (ne dict): hodnoty
    # mají INT/různé typy a queued signál by je marshaloval na QVariantMap.
    webserver_result = Signal(str, object)

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
