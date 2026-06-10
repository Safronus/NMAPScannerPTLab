


from PySide6.QtWidgets import (
    QComboBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QStandardItemModel, QStandardItem


class CheckableComboBox(QComboBox):
    """
    Vlastní ComboBox, který umožňuje zaškrtávání více položek.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setEditable(True)
        self.lineEdit().setReadOnly(True)
        self.model = QStandardItemModel(self)
        self.setModel(self.model)
        self.model.dataChanged.connect(self.update_text)

    def add_item(self, text, tooltip, checked=False):
        item = QStandardItem(text)
        item.setCheckable(True)
        item.setCheckState(Qt.Checked if checked else Qt.Unchecked)
        item.setToolTip(tooltip)
        item.setSelectable(False) 
        self.model.appendRow(item)
        if checked:
            self.update_text()

    def update_text(self):
        checked_items = []
        for i in range(self.model.rowCount()):
            item = self.model.item(i)
            if item.checkState() == Qt.Checked:
                checked_items.append(item.text())
        text_str = ",".join(checked_items)
        self.lineEdit().setText(text_str)

    def get_checked_codes(self):
        return self.lineEdit().text()

    def hidePopup(self):
        self.update_text()
        super().hidePopup()

    def set_item_checked(self, text, checked):
        """Programově zaškrtne/odškrtne položku podle textu."""
        for i in range(self.model.rowCount()):
            item = self.model.item(i)
            if item.text() == text:
                item.setCheckState(Qt.Checked if checked else Qt.Unchecked)
                self.update_text()
                return

