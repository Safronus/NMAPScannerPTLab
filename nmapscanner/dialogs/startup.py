import os
import json

from PySide6.QtWidgets import (
    QPushButton, QVBoxLayout, QHBoxLayout, QLabel, QDialog, QListWidget,
    QListWidgetItem, QWidget
)
from PySide6.QtCore import Qt


def _project_info(path):
    """Vrátí (název, popis) projektu načtený z .nmapproj; fallback na název složky."""
    name = os.path.basename(os.path.dirname(path)) or os.path.basename(path)
    desc = path
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        name = data.get("project_name") or name
        rh = data.get("run_history") or {}
        runs = rh.get("runs") or []
        n_targets = len(rh.get("master_targets") or [])
        if runs:
            desc = f"{len(runs)} běhů · {n_targets} cílů"
        elif data.get("scan_results"):
            desc = "starší formát (migruje se při otevření)"
    except Exception:
        pass
    return name, desc


class StartupDialog(QDialog):
    """Úvodní dialog: výběr posledního projektu, import nebo nový prázdný."""

    def __init__(self, recent_projects=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("NMAP Scanner PT Lab — start")
        self.setModal(True)
        self.resize(560, 440)
        self.choice = None  # "import", "new", nebo cesta k projektu
        self.recent_projects = [p for p in (recent_projects or []) if os.path.exists(p)]

        layout = QVBoxLayout(self)
        title = QLabel("Vyberte projekt")
        title.setStyleSheet("font-size: 16px; font-weight: bold;")
        layout.addWidget(title)

        if self.recent_projects:
            layout.addWidget(QLabel("Poslední projekty:"))
            self.list = QListWidget()
            self.list.setAlternatingRowColors(True)
            for path in self.recent_projects[:10]:
                name, desc = _project_info(path)
                item = QListWidgetItem()
                item.setData(Qt.UserRole, path)
                item.setToolTip(path)
                row = QWidget()
                rl = QVBoxLayout(row)
                rl.setContentsMargins(8, 6, 8, 6)
                rl.setSpacing(1)
                n = QLabel(f"📂 {name}")
                n.setStyleSheet("font-weight: bold;")
                d = QLabel(desc)
                d.setStyleSheet("color: #7f8c8d; font-size: 11px;")
                rl.addWidget(n)
                rl.addWidget(d)
                item.setSizeHint(row.sizeHint())
                self.list.addItem(item)
                self.list.setItemWidget(item, row)
            self.list.itemDoubleClicked.connect(self._open_selected)
            layout.addWidget(self.list, 1)

            open_btn = QPushButton("Otevřít vybraný projekt")
            open_btn.clicked.connect(self._open_selected)
            layout.addWidget(open_btn)
        else:
            hint = QLabel("Zatím žádné projekty. Spusť sken (založí se nový projekt) "
                          "nebo importuj existující .nmapproj.")
            hint.setWordWrap(True)
            hint.setStyleSheet("color: #7f8c8d;")
            layout.addWidget(hint)
            layout.addStretch(1)

        row = QHBoxLayout()
        self.import_btn = QPushButton("📁 Importovat .nmapproj…")
        self.import_btn.clicked.connect(lambda: self.make_choice("import"))
        self.new_btn = QPushButton("✨ Nový prázdný projekt")
        self.new_btn.clicked.connect(lambda: self.make_choice("new"))
        row.addWidget(self.import_btn)
        row.addWidget(self.new_btn)
        layout.addLayout(row)

    def _open_selected(self, *args):
        item = self.list.currentItem() if hasattr(self, "list") else None
        if item is None and hasattr(self, "list") and self.list.count():
            item = self.list.item(0)
        if item is not None:
            self.make_choice(item.data(Qt.UserRole))

    def make_choice(self, choice):
        self.choice = choice
        self.accept()
