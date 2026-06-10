"""Souhrnné progress bary pro jednotlivé fáze skenu.

Jeden řádek na fázi: popisek + ukazatel průběhu + text „hotovo/celkem".
Vypnuté fáze se zobrazí zašedle s textem „—".
"""
from PySide6.QtWidgets import (
    QWidget, QGridLayout, QLabel, QProgressBar
)


class PhaseProgressBars(QWidget):
    def __init__(self, phases, parent=None):
        super().__init__(parent)
        self._phases = list(phases)
        self._bars = {}
        self._counts = {}

        grid = QGridLayout(self)
        grid.setContentsMargins(4, 2, 4, 2)
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(2)

        for row, phase in enumerate(self._phases):
            name = QLabel(phase.capitalize())
            name.setMinimumWidth(70)
            bar = QProgressBar()
            bar.setRange(0, 1)
            bar.setValue(0)
            bar.setTextVisible(False)
            bar.setFixedHeight(14)
            count = QLabel("0/0")
            count.setMinimumWidth(48)
            grid.addWidget(name, row, 0)
            grid.addWidget(bar, row, 1)
            grid.addWidget(count, row, 2)
            self._bars[phase] = bar
            self._counts[phase] = count

        grid.setColumnStretch(1, 1)

    def reset(self, phases, enabled_phases):
        """Nastaví bary na začátek běhu. Vypnuté fáze zašedne."""
        for phase in self._phases:
            bar = self._bars[phase]
            count = self._counts[phase]
            enabled = enabled_phases.get(phase, False)
            if enabled:
                bar.setEnabled(True)
                bar.setRange(0, 0)   # neurčitý stav, dokud nepřijde první total
                bar.setValue(0)
                count.setText("0/0")
                count.setStyleSheet("")
            else:
                bar.setEnabled(False)
                bar.setRange(0, 1)
                bar.setValue(0)
                count.setText("—")
                count.setStyleSheet("color: #95A5A6;")

    def update(self, phase, completed, total):
        bar = self._bars.get(phase)
        count = self._counts.get(phase)
        if bar is None:
            return
        bar.setEnabled(True)
        if total <= 0:
            bar.setRange(0, 1)
            bar.setValue(0)
            count.setText("0/0")
            return
        bar.setRange(0, total)
        bar.setValue(completed)
        count.setText(f"{completed}/{total}")
