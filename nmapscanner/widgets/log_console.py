


from PySide6.QtWidgets import (
    QTextEdit
)
from PySide6.QtCore import Slot


class LogConsole(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        # ZMĚNA: Priorita nastavena na Monaco/Menlo pro macOS, odstraněna Consolas
        self.setStyleSheet("background-color: #2b2b2b; color: #f0f0f0; font-family: 'Monaco', 'Menlo', 'Courier New', monospace;")

    @Slot(str, str)
    def log_message(self, level, message):
        colors = {"info": "#9E9E9E", "export": "#64B5F6", "warning": "#FFB74D", "error": "#E57373"}
        icons = {"info": "ⓘ", "export": "💾", "warning": "⚠️", "error": "❌"}
        self.append(f"{icons.get(level, 'ⓘ')} {message}")

