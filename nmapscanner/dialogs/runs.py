"""Dialogy pro management běhů/verzí: porovnání verzí a správa historie."""
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QTreeWidget,
    QTreeWidgetItem, QPushButton, QInputDialog, QMessageBox, QAbstractItemView,
)
from PySide6.QtGui import QColor
from PySide6.QtCore import Qt

from ..core.run_history import diff_snapshots


_ADDED = QColor("#2ECC71")
_REMOVED = QColor("#E74C3C")
_CHANGED = QColor("#F39C12")
_INFO = QColor("#8E44AD")


def _run_caption(run):
    counts = run.counts()
    return (f"{run.label}  ·  {run.created_at[:19].replace('T', ' ')}  ·  "
            f"{_status_cz(run.status)}  ·  {len(run.targets)} cílů "
            f"(✓{counts['done']} ✗{counts['error']} …{counts['pending']})")


def _status_cz(status):
    return {"running": "běží", "completed": "dokončeno", "aborted": "zastaveno"}.get(status, status)


class DiffDialog(QDialog):
    """Porovná dvě verze (běhy): nové/zavřené porty, změny služeb a OS."""

    def __init__(self, runs, load_snapshot, parent=None, run_a=None, run_b=None):
        super().__init__(parent)
        self.setWindowTitle("Porovnání verzí")
        self.resize(820, 560)
        self.runs = list(runs)
        self.load_snapshot = load_snapshot

        layout = QVBoxLayout(self)

        sel = QHBoxLayout()
        sel.addWidget(QLabel("Starší (A):"))
        self.combo_a = QComboBox()
        sel.addWidget(self.combo_a, 1)
        sel.addWidget(QLabel("Novější (B):"))
        self.combo_b = QComboBox()
        sel.addWidget(self.combo_b, 1)
        compare_btn = QPushButton("Porovnat")
        compare_btn.clicked.connect(self.do_compare)
        sel.addWidget(compare_btn)
        layout.addLayout(sel)

        for combo in (self.combo_a, self.combo_b):
            for r in self.runs:
                combo.addItem(_run_caption(r), r.id)

        # Předvolba: A = předposlední, B = poslední
        if len(self.runs) >= 2:
            self.combo_a.setCurrentIndex(len(self.runs) - 2)
            self.combo_b.setCurrentIndex(len(self.runs) - 1)
        if run_a:
            i = self.combo_a.findData(run_a)
            if i >= 0:
                self.combo_a.setCurrentIndex(i)
        if run_b:
            i = self.combo_b.findData(run_b)
            if i >= 0:
                self.combo_b.setCurrentIndex(i)

        self.summary = QLabel("Vyber dvě verze a klikni na Porovnat.")
        self.summary.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.summary)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Cíl / změna", "Detail"])
        self.tree.setColumnWidth(0, 360)
        layout.addWidget(self.tree)

        close_btn = QPushButton("Zavřít")
        close_btn.clicked.connect(self.accept)
        row = QHBoxLayout()
        row.addStretch()
        row.addWidget(close_btn)
        layout.addLayout(row)

        if len(self.runs) >= 2:
            self.do_compare()

    def _run_by_id(self, run_id):
        return next((r for r in self.runs if r.id == run_id), None)

    def do_compare(self):
        id_a = self.combo_a.currentData()
        id_b = self.combo_b.currentData()
        if not id_a or not id_b:
            return
        if id_a == id_b:
            self.summary.setText("Vyber dvě různé verze.")
            self.tree.clear()
            return
        run_a = self._run_by_id(id_a)
        run_b = self._run_by_id(id_b)
        snap_a = self.load_snapshot(run_a) or {}
        snap_b = self.load_snapshot(run_b) or {}
        diff = diff_snapshots(snap_a, snap_b)

        self.tree.clear()
        changed_targets = [t for t in diff.get("_targets", []) if t in diff]
        if not changed_targets:
            self.summary.setText(f"Beze změn mezi '{run_a.label}' a '{run_b.label}'.")
            return
        self.summary.setText(
            f"'{run_a.label}' → '{run_b.label}': změny u {len(changed_targets)} cílů.")

        for t in changed_targets:
            e = diff[t]
            parent = QTreeWidgetItem(self.tree, [t, ""])
            parent.setExpanded(True)
            for proto, port in e.get("added", []):
                self._child(parent, f"➕ nový port {port}/{proto}", "otevřený v B", _ADDED)
            for proto, port in e.get("removed", []):
                self._child(parent, f"➖ zmizelý port {port}/{proto}", "už není otevřený", _REMOVED)
            for (proto, port), pa, pb in e.get("changed", []):
                old = f"{pa.get('name', '')} {pa.get('version', '')}".strip()
                new = f"{pb.get('name', '')} {pb.get('version', '')}".strip()
                self._child(parent, f"✎ {port}/{proto} služba", f"{old or '?'} → {new or '?'}", _CHANGED)
            if "os_changed" in e:
                oa, ob = e["os_changed"]
                self._child(parent, "✎ OS", f"{oa or '?'} → {ob or '?'}", _INFO)
            if "online_changed" in e:
                oa, ob = e["online_changed"]
                self._child(parent, "✎ Online", f"{oa or '?'} → {ob or '?'}", _INFO)

    def _child(self, parent, text, detail, color):
        item = QTreeWidgetItem(parent, [text, detail])
        item.setForeground(0, color)


class RunsManagerDialog(QDialog):
    """Správa běhů/verzí: přejmenovat, smazat, zobrazit, porovnat."""

    def __init__(self, run_history, load_snapshot, delete_files=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Správa běhů a verzí")
        self.resize(760, 460)
        self.history = run_history
        self.load_snapshot = load_snapshot
        self.delete_files = delete_files
        self.selected_view_run_id = None   # nastaví se, když uživatel zvolí „Zobrazit"

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Běhy (verze výsledků) v projektu:"))

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Běh", "Vytvořeno", "Stav", "Cíle", "✓ / ✗ / …"])
        self.tree.setSelectionMode(QAbstractItemView.SingleSelection)
        self.tree.setRootIsDecorated(False)
        layout.addWidget(self.tree)
        self._reload()

        row = QHBoxLayout()
        self.view_btn = QPushButton("Zobrazit verzi")
        self.rename_btn = QPushButton("Přejmenovat")
        self.delete_btn = QPushButton("Smazat")
        self.timeline_btn = QPushButton("📜 Timeline")
        self.diff_btn = QPushButton("Porovnat verze…")
        close_btn = QPushButton("Zavřít")
        self.view_btn.clicked.connect(self._view)
        self.rename_btn.clicked.connect(self._rename)
        self.delete_btn.clicked.connect(self._delete)
        self.timeline_btn.clicked.connect(self._timeline)
        self.diff_btn.clicked.connect(self._diff)
        close_btn.clicked.connect(self.accept)
        for b in (self.view_btn, self.rename_btn, self.delete_btn, self.timeline_btn, self.diff_btn):
            row.addWidget(b)
        row.addStretch()
        row.addWidget(close_btn)
        layout.addLayout(row)

    def _reload(self):
        self.tree.clear()
        for r in self.history.runs:
            c = r.counts()
            item = QTreeWidgetItem(self.tree, [
                r.label + (" (aktivní)" if r.id == self.history.active_run_id else ""),
                r.created_at[:19].replace("T", " "),
                _status_cz(r.status),
                str(len(r.targets)),
                f"{c['done']} / {c['error']} / {c['pending']}",
            ])
            item.setData(0, Qt.UserRole, r.id)
        for i in range(self.tree.columnCount()):
            self.tree.resizeColumnToContents(i)

    def _selected_run(self):
        items = self.tree.selectedItems()
        if not items:
            return None
        run_id = items[0].data(0, Qt.UserRole)
        return self.history.get(run_id)

    def _view(self):
        run = self._selected_run()
        if run:
            self.selected_view_run_id = run.id
            self.accept()

    def _rename(self):
        run = self._selected_run()
        if not run:
            return
        new, ok = QInputDialog.getText(self, "Přejmenovat běh", "Název:", text=run.label)
        if ok and new.strip():
            run.label = new.strip()
            self._reload()

    def _delete(self):
        run = self._selected_run()
        if not run:
            return
        if len(self.history.runs) <= 1:
            QMessageBox.information(self, "Nelze smazat", "Projekt musí mít alespoň jeden běh.")
            return
        reply = QMessageBox.question(
            self, "Smazat běh",
            f"Opravdu smazat '{run.label}' včetně jeho výsledků (verze)?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        if self.delete_files:
            self.delete_files(run)
        self.history.remove(run.id)
        self._reload()

    def _timeline(self):
        run = self._selected_run()
        if not run:
            return
        events = getattr(run, "timeline", []) or []
        if not events:
            QMessageBox.information(self, "Timeline", f"Běh '{run.label}' nemá zaznamenané události.")
            return
        lines = []
        for e in events:
            t = str(e.get("time", ""))[:19].replace("T", " ")
            action = e.get("action", "")
            detail = e.get("detail", "")
            lines.append(f"• {t}  —  {action}" + (f": {detail}" if detail else ""))
        box = QMessageBox(self)
        box.setWindowTitle(f"Timeline — {run.label}")
        box.setText(f"Historie událostí běhu '{run.label}':")
        box.setDetailedText("\n".join(lines))
        box.setInformativeText("\n".join(lines[:12]) + ("\n…" if len(lines) > 12 else ""))
        box.exec()

    def _diff(self):
        if len(self.history.runs) < 2:
            QMessageBox.information(self, "Porovnání", "K porovnání jsou potřeba alespoň dvě verze.")
            return
        DiffDialog(self.history.runs, self.load_snapshot, parent=self).exec()
