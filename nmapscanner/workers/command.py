"""Worker pro spuštění shell příkazu se živým streamem výstupu.

Používá správce aktualizací k instalaci/aktualizaci nástrojů (brew/apt/pip).
Příkaz spouští v shellu, řádky stdout/stderr posílá přes signál ``line``.
"""

import subprocess

from PySide6.QtCore import QThread, Signal


class CommandWorker(QThread):
    line = Signal(str)        # jeden řádek výstupu
    finished = Signal(int)    # návratový kód (-1 = výjimka)

    def __init__(self, command, parent=None):
        super().__init__(parent)
        self.command = command
        self._proc = None

    def run(self):
        try:
            self.line.emit(f"$ {self.command}")
            self._proc = subprocess.Popen(
                self.command, shell=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1)
            for ln in iter(self._proc.stdout.readline, ""):
                self.line.emit(ln.rstrip("\n"))
            self._proc.stdout.close()
            code = self._proc.wait()
            self.finished.emit(code)
        except Exception as e:  # noqa: BLE001
            self.line.emit(f"CHYBA: {e}")
            self.finished.emit(-1)

    def stop(self):
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:
                pass
