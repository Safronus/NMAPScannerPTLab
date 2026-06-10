


from PySide6.QtWidgets import (
    QPushButton, QVBoxLayout, QLabel, QHBoxLayout, QCheckBox, QDialog,
    QMessageBox, QDialogButtonBox, QFrame, QRadioButton
)


class ExportMultipleDialog(QDialog):
    """Dialog pro výběr záložek k exportu."""
    def __init__(self, phases, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Export výsledků")
        self.setModal(True)
        self.phases = phases
        self.selected_phases = []
        
        layout = QVBoxLayout()
        
        # Nadpis
        label = QLabel("Vyberte záložky k exportu:")
        label.setStyleSheet("font-weight: bold; font-size: 12px; margin-bottom: 10px;")
        layout.addWidget(label)
        
        # Checkboxy pro každou záložku
        self.checkboxes = {}
        for phase in self.phases:
            checkbox = QCheckBox(phase.capitalize())
            checkbox.setChecked(True)  # Defaultně všechny zaškrtnuté
            self.checkboxes[phase] = checkbox
            layout.addWidget(checkbox)
        
        # Oddělovač
        separator = QLabel()
        separator.setFrameStyle(QFrame.HLine | QFrame.Sunken)
        layout.addWidget(separator)
        
        # Tlačítka pro rychlý výběr
        quick_select_layout = QHBoxLayout()
        
        select_all_btn = QPushButton("Vybrat vše")
        select_all_btn.clicked.connect(self.select_all)
        quick_select_layout.addWidget(select_all_btn)
        
        deselect_all_btn = QPushButton("Zrušit vše")
        deselect_all_btn.clicked.connect(self.deselect_all)
        quick_select_layout.addWidget(deselect_all_btn)
        
        layout.addLayout(quick_select_layout)
        
        # Tlačítka OK/Cancel
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self.setLayout(layout)
        self.resize(300, 250)
    
    def select_all(self):
        """Zaškrtne všechny checkboxy."""
        for checkbox in self.checkboxes.values():
            checkbox.setChecked(True)
    
    def deselect_all(self):
        """Zruší zaškrtnutí všech checkboxů."""
        for checkbox in self.checkboxes.values():
            checkbox.setChecked(False)
    
    def accept(self):
        """Uloží vybrané záložky a zavře dialog."""
        self.selected_phases = [phase for phase, checkbox in self.checkboxes.items() if checkbox.isChecked()]
        if not self.selected_phases:
            QMessageBox.warning(self, "Varování", "Musíte vybrat alespoň jednu záložku k exportu.")
            return
        super().accept()

class ExportPortsDialog(QDialog):
    """Dialog pro výběr stavů portů k exportu."""
    def __init__(self, available_states, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Export přehledu portů")
        self.setModal(True)
        self.available_states = available_states
        self.selected_states = []
        self.include_ips = True  # Defaultně s IP adresami
        
        layout = QVBoxLayout()
        
        # Nadpis
        label = QLabel("Vyberte stavy portů k exportu:")
        label.setStyleSheet("font-weight: bold; font-size: 12px; margin-bottom: 10px;")
        layout.addWidget(label)
        
        # Checkboxy pro každý stav
        self.checkboxes = {}
        state_labels = {
            'open': '🟢 Open (Otevřené)',
            'closed': '🔴 Closed (Zavřené)',
            'filtered': '🟠 Filtered (Filtrované)',
            'unfiltered': '🟡 Unfiltered',
            'open|filtered': '🟡 Open|Filtered',
            'closed|filtered': '🟠 Closed|Filtered',
            'unknown': '⚪ Unknown (Neznámé)'
        }
        
        for state in available_states:
            label_text = state_labels.get(state, state.capitalize())
            checkbox = QCheckBox(label_text)
            checkbox.setChecked(True)  # Defaultně všechny zaškrtnuté
            self.checkboxes[state] = checkbox
            layout.addWidget(checkbox)
        
        # Oddělovač
        separator = QLabel()
        separator.setFrameStyle(QFrame.HLine | QFrame.Sunken)
        layout.addWidget(separator)
        
        # Tlačítka pro rychlý výběr
        quick_select_layout = QHBoxLayout()
        
        select_all_btn = QPushButton("Vybrat vše")
        select_all_btn.clicked.connect(self.select_all)
        quick_select_layout.addWidget(select_all_btn)
        
        deselect_all_btn = QPushButton("Zrušit vše")
        deselect_all_btn.clicked.connect(self.deselect_all)
        quick_select_layout.addWidget(deselect_all_btn)
        
        layout.addLayout(quick_select_layout)
        
        # Oddělovač
        separator2 = QLabel()
        separator2.setFrameStyle(QFrame.HLine | QFrame.Sunken)
        layout.addWidget(separator2)
        
        # NOVÉ: Checkbox pro zahrnutí IP adres
        detail_label = QLabel("Podrobnost exportu:")
        detail_label.setStyleSheet("font-weight: bold; font-size: 11px; margin-top: 5px;")
        layout.addWidget(detail_label)
        
        self.include_ips_checkbox = QCheckBox("Zahrnout seznam IP adres")
        self.include_ips_checkbox.setChecked(True)  # Defaultně zaškrtnuté
        self.include_ips_checkbox.setToolTip("Pokud zaškrtnuto, export bude obsahovat seznam IP adres pro každý port")
        layout.addWidget(self.include_ips_checkbox)
        
        detail_hint = QLabel("  (podrobnější, ale delší export)")
        detail_hint.setStyleSheet("font-size: 9px; color: #666666; margin-left: 20px;")
        layout.addWidget(detail_hint)
        
        # Tlačítka OK/Cancel
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self.setLayout(layout)
        self.resize(350, 380)
    
    def select_all(self):
        """Zaškrtne všechny checkboxy."""
        for checkbox in self.checkboxes.values():
            checkbox.setChecked(True)
    
    def deselect_all(self):
        """Zruší zaškrtnutí všech checkboxů."""
        for checkbox in self.checkboxes.values():
            checkbox.setChecked(False)
    
    def accept(self):
        """Uloží vybrané stavy a zavře dialog."""
        self.selected_states = [state for state, checkbox in self.checkboxes.items() if checkbox.isChecked()]
        if not self.selected_states:
            QMessageBox.warning(self, "Varování", "Musíte vybrat alespoň jeden stav k exportu.")
            return
        
        # Uložit volbu zahrnutí IP adres
        self.include_ips = self.include_ips_checkbox.isChecked()
        
        super().accept()

class ExportServicesDialog(QDialog):
    """Dialog pro výběr protokolů služeb k exportu."""
    def __init__(self, available_protocols, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Export přehledu služeb")
        self.setModal(True)
        self.available_protocols = available_protocols
        self.selected_protocols = []
        self.detail_level = "summary"  # summary / ports / full
        
        layout = QVBoxLayout()
        
        # Nadpis
        label = QLabel("Vyberte protokoly k exportu:")
        label.setStyleSheet("font-weight: bold; font-size: 12px; margin-bottom: 10px;")
        layout.addWidget(label)
        
        # Checkboxy pro každý protokol
        self.checkboxes = {}
        protocol_labels = {
            'TCP': '🔵 TCP (Transmission Control Protocol)',
            'UDP': '🟣 UDP (User Datagram Protocol)'
        }
        
        for protocol in available_protocols:
            label_text = protocol_labels.get(protocol, protocol)
            checkbox = QCheckBox(label_text)
            checkbox.setChecked(True)  # Defaultně všechny zaškrtnuté
            self.checkboxes[protocol] = checkbox
            layout.addWidget(checkbox)
        
        # Oddělovač
        separator = QLabel()
        separator.setFrameStyle(QFrame.HLine | QFrame.Sunken)
        layout.addWidget(separator)
        
        # Tlačítka pro rychlý výběr
        quick_select_layout = QHBoxLayout()
        
        select_all_btn = QPushButton("Vybrat vše")
        select_all_btn.clicked.connect(self.select_all)
        quick_select_layout.addWidget(select_all_btn)
        
        deselect_all_btn = QPushButton("Zrušit vše")
        deselect_all_btn.clicked.connect(self.deselect_all)
        quick_select_layout.addWidget(deselect_all_btn)
        
        layout.addLayout(quick_select_layout)
        
        # Oddělovač
        separator2 = QLabel()
        separator2.setFrameStyle(QFrame.HLine | QFrame.Sunken)
        layout.addWidget(separator2)
        
        # NOVÉ: Radio buttony pro úroveň detailů
        detail_label = QLabel("Úroveň detailů:")
        detail_label.setStyleSheet("font-weight: bold; font-size: 11px; margin-top: 5px;")
        layout.addWidget(detail_label)
        
        self.summary_radio = QRadioButton("Souhrn - pouze služby")
        self.summary_radio.setToolTip("Jen seznam služeb s celkovým počtem IP adres")
        layout.addWidget(self.summary_radio)
        
        self.ports_radio = QRadioButton("Střední - služby + porty")
        self.ports_radio.setToolTip("Služby s výpisem portů a počtem IP adres")
        layout.addWidget(self.ports_radio)
        
        self.full_radio = QRadioButton("Detailní - služby + porty + IP adresy")
        self.full_radio.setToolTip("Kompletní export včetně seznamu všech IP adres")
        self.full_radio.setChecked(True)  # Defaultně detailní
        layout.addWidget(self.full_radio)
        
        detail_hint = QLabel("  Tip: Souhrn = rychlý přehled, Detailní = kompletní data")
        detail_hint.setStyleSheet("font-size: 9px; color: #666666; margin-left: 20px; margin-top: 5px;")
        layout.addWidget(detail_hint)
        
        # Tlačítka OK/Cancel
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self.setLayout(layout)
        self.resize(380, 380)
    
    def select_all(self):
        """Zaškrtne všechny checkboxy."""
        for checkbox in self.checkboxes.values():
            checkbox.setChecked(True)
    
    def deselect_all(self):
        """Zruší zaškrtnutí všech checkboxů."""
        for checkbox in self.checkboxes.values():
            checkbox.setChecked(False)
    
    def accept(self):
        """Uloží vybrané protokoly a zavře dialog."""
        self.selected_protocols = [proto for proto, checkbox in self.checkboxes.items() if checkbox.isChecked()]
        if not self.selected_protocols:
            QMessageBox.warning(self, "Varování", "Musíte vybrat alespoň jeden protokol k exportu.")
            return
        
        # Uložit zvolenou úroveň detailů
        if self.summary_radio.isChecked():
            self.detail_level = "summary"
        elif self.ports_radio.isChecked():
            self.detail_level = "ports"
        else:
            self.detail_level = "full"
        
        super().accept()
