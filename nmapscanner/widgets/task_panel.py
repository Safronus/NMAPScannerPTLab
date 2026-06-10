"""Živý panel paralelních úloh — co právě běží a co skončilo.

Při paralelním skenování ukazuje dvě části:

* **Běžící** — každá úloha (cíl × fáze) s aktuálně běžící příčkou žebříku a
  živě běžícím časem (aktualizováno 1× za sekundu).
* **Dokončené** — historie ukončených úloh se stavem a celkovým časem.

Klíč běžící úlohy je dvojice ``(target, phase)``. Při de-eskalaci (zmírnění
varianty) se stejná úloha jen překreslí novým popiskem — nezakládá se nová.
"""
import time

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTreeWidget, QTreeWidgetItem
)
from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QColor

from ..utils import get_color_for_ip


_STATUS_COLORS = {
    "hotovo": QColor("#2ECC71"),
    "online": QColor("#2ECC71"),
    "offline": QColor("#95A5A6"),
    "přeskočeno": QColor("#BDC3C7"),
    "zakázáno": QColor("#95A5A6"),
    "chyba": QColor("#E74C3C"),
}


class LiveTaskPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._running = {}     # (target, phase) -> {"item": QTreeWidgetItem, "start": float, "label": str}
        self._done_count = 0

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        self.header_label = QLabel("Běžící úlohy: 0   |   Dokončené: 0")
        self.header_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.header_label)

        split = QHBoxLayout()
        split.setSpacing(6)

        running_box = QVBoxLayout()
        running_box.setSpacing(2)
        running_box.addWidget(QLabel("▶ Probíhá"))
        self.running_tree = QTreeWidget()
        self.running_tree.setHeaderLabels(["Cíl", "Fáze / varianta", "Čas"])
        self.running_tree.setRootIsDecorated(False)
        running_box.addWidget(self.running_tree)
        split.addLayout(running_box, 1)

        done_box = QVBoxLayout()
        done_box.setSpacing(2)
        done_box.addWidget(QLabel("✔ Dokončeno"))
        self.done_tree = QTreeWidget()
        self.done_tree.setHeaderLabels(["Cíl", "Fáze / varianta", "Stav", "Čas"])
        self.done_tree.setRootIsDecorated(False)
        done_box.addWidget(self.done_tree)
        split.addLayout(done_box, 1)

        layout.addLayout(split)

        # Tikání pro živé časy běžících úloh.
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._tick)

    # ---- API ----------------------------------------------------------
    def reset(self):
        """Vyčistí panel a spustí tikání času."""
        self._running.clear()
        self._done_count = 0
        self.running_tree.clear()
        self.done_tree.clear()
        self._update_header()
        if not self._timer.isActive():
            self._timer.start()

    def task_started(self, phase, target, label):
        """Úloha (cíl × fáze) odstartovala danou variantu. Upsert běžící řádek."""
        key = (target, phase)
        now = time.monotonic()
        entry = self._running.get(key)
        if entry is None:
            item = QTreeWidgetItem(self.running_tree, [target, label, "00:00"])
            item.setForeground(0, get_color_for_ip(target))
            item.setForeground(1, QColor("#E67E22"))
            self._running[key] = {"item": item, "start": now, "label": label}
        else:
            # De-eskalace: jen překreslit popisek a restartovat měřič příčky.
            entry["label"] = label
            entry["start"] = now
            entry["item"].setText(1, label)
        self._update_header()

    def task_finished(self, phase, target, status):
        """Úloha skončila (terminálně). Přesune z běžících do dokončených."""
        key = (target, phase)
        entry = self._running.pop(key, None)
        if entry is None:
            label = f"{phase.upper()}"
            elapsed = 0.0
        else:
            label = entry["label"]
            elapsed = time.monotonic() - entry["start"]
            idx = self.running_tree.indexOfTopLevelItem(entry["item"])
            if idx >= 0:
                self.running_tree.takeTopLevelItem(idx)

        done_item = QTreeWidgetItem([target, label, status, _fmt(elapsed)])
        done_item.setForeground(0, get_color_for_ip(target))
        done_item.setForeground(2, _STATUS_COLORS.get(status, QColor("#34495E")))
        self.done_tree.insertTopLevelItem(0, done_item)
        self._done_count += 1
        self._update_header()

    def stop(self):
        """Zastaví tikání (po dokončení/zastavení workflow)."""
        self._timer.stop()

    # ---- interní ------------------------------------------------------
    def _tick(self):
        now = time.monotonic()
        for entry in self._running.values():
            entry["item"].setText(2, _fmt(now - entry["start"]))

    def _update_header(self):
        self.header_label.setText(
            f"Běžící úlohy: {len(self._running)}   |   Dokončené: {self._done_count}"
        )


def _fmt(seconds):
    seconds = int(seconds)
    return f"{seconds // 60:02d}:{seconds % 60:02d}"
