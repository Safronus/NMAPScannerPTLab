


from PySide6.QtCore import QObject, Signal


class WorkerSignals(QObject):
    result = Signal(str, str, dict)
    finished = Signal()
    log = Signal(str, str)
    task_started = Signal(str, str)
    screenshot_request = Signal(str, str, int, str) # url, ip, port, path
    screenshot_taken = Signal(str, str) # ip, filepath


