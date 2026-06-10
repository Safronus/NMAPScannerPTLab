"""Manažer reportů — přehled všech vytvořených reportů v projektu.

Reporty (souhrnné PDF i dílčí exporty: ffuf, TLS, certifikáty, hlavičky, Word,
ZAP …) se evidují v ``reports/manifest.json``. Toto okno je zobrazí seskupené
podle zdroje (části aplikace, která report vygenerovala) a umožní je otevřít,
ukázat ve správci souborů nebo smazat.
"""

import os

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QDesktopServices
from PySide6.QtCore import QUrl
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTreeWidget, QTreeWidgetItem, QHeaderView,
    QPushButton, QLabel, QMessageBox,
)

from ..core import report_store


def _human_size(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


class ReportManagerDialog(QDialog):
    def __init__(self, reports_dir, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Manažer reportů")
        self.resize(860, 560)
        self.reports_dir = reports_dir

        layout = QVBoxLayout(self)
        self.info = QLabel("")
        layout.addWidget(self.info)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Název", "Typ", "Jazyk", "Vytvořeno", "Velikost"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        for c in (1, 2, 3, 4):
            self.tree.header().setSectionResizeMode(c, QHeaderView.ResizeToContents)
        self.tree.itemDoubleClicked.connect(lambda *_: self.open_selected())
        layout.addWidget(self.tree, 1)

        row = QHBoxLayout()
        self.open_btn = QPushButton("📂 Otevřít"); self.open_btn.clicked.connect(self.open_selected)
        self.reveal_btn = QPushButton("🔍 Ukázat ve složce"); self.reveal_btn.clicked.connect(self.reveal_selected)
        self.delete_btn = QPushButton("🗑 Smazat"); self.delete_btn.clicked.connect(self.delete_selected)
        refresh = QPushButton("↻ Obnovit"); refresh.clicked.connect(self.reload)
        open_dir = QPushButton("📁 Otevřít složku reports/"); open_dir.clicked.connect(self.open_reports_dir)
        row.addWidget(self.open_btn); row.addWidget(self.reveal_btn); row.addWidget(self.delete_btn)
        row.addStretch(); row.addWidget(open_dir); row.addWidget(refresh)
        close = QPushButton("Zavřít"); close.clicked.connect(self.accept)
        row.addWidget(close)
        layout.addLayout(row)

        self.reload()

    def reload(self):
        self.tree.clear()
        report_store.prune_missing(self.reports_dir)
        groups = report_store.reports_grouped(self.reports_dir)
        total = sum(len(v) for v in groups.values())
        self.info.setText(f"Reportů v projektu: {total}   ·   složka: {self.reports_dir}")
        if total == 0:
            placeholder = QTreeWidgetItem(self.tree, ["Zatím žádné reporty. Vytvoř report tlačítkem 📊."])
            placeholder.setForeground(0, QColor("#95A5A6"))
            return
        # seřadit skupiny dle známého pořadí labelů
        order = list(report_store.SOURCE_LABELS.keys())
        for src in sorted(groups.keys(), key=lambda s: order.index(s) if s in order else 999):
            entries = groups[src]
            label = report_store.SOURCE_LABELS.get(src, src)
            head = QTreeWidgetItem(self.tree, [f"{label}  ({len(entries)})"])
            head.setFont(0, QFont("Arial", 11, QFont.Bold))
            head.setForeground(0, QColor("#16233f"))
            head.setExpanded(True)
            head.setFirstColumnSpanned(True)
            for e in entries:
                child = QTreeWidgetItem(head, [
                    e.get("title", e.get("filename", "?")),
                    e.get("type", ""),
                    (e.get("language", "") or "").upper(),
                    e.get("created_at", ""),
                    _human_size(e.get("size")),
                ])
                child.setData(0, Qt.UserRole, e)

    def _selected_entry(self):
        items = self.tree.selectedItems()
        if not items:
            return None
        return items[0].data(0, Qt.UserRole)

    def _path_of(self, entry):
        return report_store.entry_path(entry, self.reports_dir)

    def open_selected(self):
        e = self._selected_entry()
        if not e:
            return
        path = self._path_of(e)
        if not os.path.exists(path):
            QMessageBox.warning(self, "Report", "Soubor už neexistuje.")
            self.reload()
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def reveal_selected(self):
        e = self._selected_entry()
        if not e:
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(self.reports_dir))

    def open_reports_dir(self):
        os.makedirs(self.reports_dir, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(self.reports_dir))

    def delete_selected(self):
        e = self._selected_entry()
        if not e:
            return
        reply = QMessageBox.question(
            self, "Smazat report",
            f"Opravdu smazat tento report?\n\n{e.get('title', e.get('filename'))}",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        report_store.remove_report(self.reports_dir, e.get("id"), delete_file=True)
        self.reload()
