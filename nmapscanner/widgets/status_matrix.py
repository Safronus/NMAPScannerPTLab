


from PySide6.QtWidgets import (
    QTreeWidget, QTreeWidgetItem
)
from PySide6.QtGui import QColor
from ..utils import get_color_for_ip


class StatusMatrix(QTreeWidget):
    def __init__(self, phases, parent=None):
        super().__init__(parent)
        self.real_phases = phases
        self.ip_items = {}
        self.status_colors = {
            'čeká': QColor('#808080'),
            'probíhá': QColor('#FFA500'),
            'probíhá -Pn': QColor('#E67E22'),
            'online': QColor('#2ECC71'),
            'offline': QColor('#95A5A6'),
            'online bez ping': QColor('#F39C12'),
            'hotovo': QColor('#2ECC71'),
            'hotovo -Pn': QColor('#27AE60'),
            'chyba': QColor('#E74C3C'),
            'chyba -Pn': QColor('#C0392B'),
            'přeskočeno': QColor('#BDC3C7'),
            'přeskočeno -Pn': QColor('#95A5A6'),
            'zakázáno': QColor('#95A5A6')
        }


    def populate_targets(self, targets):
        self.clear()
        self.ip_items.clear()
        
        self.setColumnCount(len(self.real_phases) + 1)
        self.setHeaderLabels(['Cíl'] + [p.capitalize() for p in self.real_phases])
        
        for ip in targets:
            if not ip:
                continue
            
            item = QTreeWidgetItem(self, [ip] + ['čeká'] * len(self.real_phases))
            item.setForeground(0, get_color_for_ip(ip))
            for i in range(1, len(self.real_phases) + 1):
                item.setForeground(i, self.status_colors['čeká'])
            
            self.ip_items[ip] = item
        
        # PŘIDAT TYTO ŘÁDKY NA KONEC:
        # Automaticky přizpůsobit šířku sloupců podle obsahu
        self.resizeColumnToContents(0)  # Sloupec "Cíl"
        self.resizeColumnToContents(1)  # Sloupec "Online"

    def update_status(self, ip, phase, status):
        if ip in self.ip_items:
            base_phase = phase.replace('-Pn', '')
            display_status = status
            
            if status == 'skipped_by_user':
                display_status = 'zakázáno'
            elif '-Pn' in phase:
                if status == 'probíhá':
                    display_status = 'probíhá -Pn'
                elif status == 'probíhá -Pn':
                    display_status = 'probíhá -Pn'
                elif status == 'hotovo':
                    display_status = 'hotovo -Pn'
                elif status == 'přeskočeno':
                    display_status = 'přeskočeno -Pn'
                elif status == 'chyba':
                    display_status = 'chyba -Pn'
            
            if base_phase not in self.real_phases:
                return
            
            phase_idx = self.real_phases.index(base_phase) + 1
            self.ip_items[ip].setText(phase_idx, display_status)
            self.ip_items[ip].setForeground(phase_idx, self.status_colors.get(display_status, QColor('black')))
            
            if base_phase == 'online':
                self.resizeColumnToContents(1)


