


from PySide6.QtCore import Slot, QRunnable


class ScreenshotWorker(QRunnable):
    """
    Asynchronní worker pro pořízení screenshotu webové stránky.
    Musí být volán z hlavního vlákna kvůli QWebEngineView.
    """
    def __init__(self, url, ip, port, path, signals):
        super().__init__()
        self.url = url
        self.ip = ip
        self.port = port
        self.path = path
        self.signals = signals

    @Slot()
    def run(self):
        # Tato funkce je zjednodušená; v praxi je třeba view vytvořit
        # a spravovat v hlavním vlákně. Použijeme signály pro tento účel.
        self.signals.screenshot_request.emit(self.url, self.ip, self.port, self.path)

