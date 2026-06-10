import os
import time
import json
import subprocess
from datetime import datetime


from docx import Document
from docx.shared import RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

from PySide6.QtWidgets import (
    QApplication, QWidget, QTextEdit, QLineEdit, QPushButton, QVBoxLayout,
    QTreeWidget, QTreeWidgetItem, QLabel, QGroupBox, QHeaderView, QFileDialog,
    QTabWidget, QHBoxLayout, QSplitter, QCheckBox, QDialog, QMessageBox, QDialogButtonBox, QComboBox, QProgressDialog,
    QRadioButton, QInputDialog, QMenu
)
from PySide6.QtCore import Slot, Signal, QMutex, QMutexLocker, QTimer, Qt, QThread, QSettings, QThreadPool
from PySide6.QtGui import QColor, QPixmap
from . import VERSION
from .utils import clean_and_parse_ips, get_color_for_ip
from .signals import WorkerSignals
from .core.scan_manager import ScanManager
from .core import scan_profiles as sp
from .core.project import ProjectPaths, default_projects_dir, safe_name
from .core import run_history as rh
from .core.run_history import RunHistory, ScanRun, run_id_from_timestamp
from .core import project_store as pstore
from .core.vuln_classify import classify_vuln_output
from .core.webserver_detect import detect_server
from .workers.screenshot import ScreenshotManager
from .workers.webserver import WebServerWorker
from .dialogs.runs import DiffDialog, RunsManagerDialog
from .widgets.log_console import LogConsole
from .widgets.status_matrix import StatusMatrix
from .widgets.task_panel import LiveTaskPanel
from .widgets.phase_progress import PhaseProgressBars
from .dialogs.startup import StartupDialog
from .dialogs.tls import TlsAuditDialog
from .dialogs.headers import SecurityHeadersDialog
from .dialogs.certificate import CertificateDialog
from .dialogs.export import ExportMultipleDialog, ExportPortsDialog, ExportServicesDialog
from .dialogs.ffuf import FfufDialog
from PySide6.QtWebEngineWidgets import QWebEngineView


output_mutex = QMutex()

class NmapScannerApp(QWidget):
    # Spuštění skenu se posílá do vlákna manažera přes queued signál (cíle, profil,
    # povolené fáze, vlastní příkaz) — všechny mutace stavu manažeru tak běží
    # v jednom vlákně (žádné race podmínky).
    start_scan_requested = Signal(list, str, dict, str, bool, dict)

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"NMAP Scanner PT Lab - v{VERSION}")
        self.phases = ['online', 'tcp', 'udp', 'vuln', 'osscan']  # ODSTRANĚNA 'screenshot'
        self.scan_results = {}
        self.current_project_path = None
        self.screenshots = {}
        self.loading_project = False
        # Cesta, pro kterou je autosave zablokovaný (macOS práva / read-only FS) —
        # ať se neopakuje selhání a nezahltí log při každém triggeru.
        self._autosave_blocked = None
        # Průběh pořizování screenshotů (živý čítač pro status bar).
        self._shot_total = self._shot_done = self._shot_ok = self._shot_fail = 0
        self._shot_last_err = ""
        # Verzování běhů: historie + aktuálně zobrazená verze + cache snapshotů,
        # které ještě nejsou na disku (migrace / nový běh).
        self.run_history = RunHistory()
        self.viewing_run_id = None
        self._pending_snapshots = {}   # run_id -> scan_results (dosud neuložené na disk)
        self._stop_requested = False
        # Sudo heslo drženo POUZE v RAM (nikdy na disk) jako mazatelná bytearray.
        self._sudo_pw = None
        self._use_sudo = True

        # PŘIDÁNO: Inicializace FIXNÍCH šířek pro pravé sekce (nemění se)
        self.ip_summary_width = 1200  # Fixní 1200px
        self.port_summary_width = 350  # Fixní 300px
        self.service_summary_width = 270  # Fixní 300px

        
        # NOVÉ: Detekce rozlišení obrazovky a výpočet adaptivních rozměrů
        screen = QApplication.primaryScreen()
        screen_geometry = screen.availableGeometry()
        self.screen_width = screen_geometry.width()
        self.screen_height = screen_geometry.height()
        
        # Výpočet velikostí panelů podle rozlišení
        self.calculate_adaptive_sizes()
        
        # 1. Nejdříve vytvoříme GUI
        self.init_ui()
        
        # 2. Načteme uložená nastavení (profil, vlastní příkaz, vstupy)
        self.load_settings()

        # NOVÉ: Zjistit IP hned po startu
        self.fetch_public_ip()
        
        self.debounce_timer = QTimer(self)
        self.debounce_timer.setSingleShot(True)
        self.debounce_timer.setInterval(500)
        self.debounce_timer.timeout.connect(self.save_settings)
        
        self.raw_input_text.textChanged.connect(self.debounce_timer.start)
        
        self.manager_thread = QThread()
        self.worker_signals = WorkerSignals()
        self.scan_manager = ScanManager(self.worker_signals)
        self.scan_manager.moveToThread(self.manager_thread)
        self.manager_thread.start()

        self.worker_signals.scan_result.connect(self.on_scan_result)
        self.worker_signals.log.connect(self.log_console.log_message)
        self.worker_signals.task_started.connect(self.on_task_started)
        self.worker_signals.phase_progress.connect(self.on_phase_progress)
        # Screenshoty webu přes Selenium (headless Chrome) ve vlastním vlákně —
        # požadavky se zpracují sériově jedním znovupoužitým prohlížečem.
        self.screenshot_thread = QThread()
        self.screenshot_manager = ScreenshotManager(self.worker_signals)
        self.screenshot_manager.moveToThread(self.screenshot_thread)
        self.screenshot_thread.start()
        self.worker_signals.screenshot_request.connect(self.screenshot_manager.take_screenshot)
        self.worker_signals.screenshot_taken.connect(self.on_screenshot_taken)
        self.worker_signals.screenshot_done.connect(self.on_screenshot_done)
        self.worker_signals.webserver_result.connect(self.on_webserver_result)
        self.scan_manager.workflow_finished.connect(self.on_workflow_finished)
        
        self.scan_button.clicked.connect(self.start_new_run)
        self.stop_button.clicked.connect(self.on_stop_clicked)
        # Start skenu poběží ve vlákně manažeru (queued connection napříč vlákny)
        self.start_scan_requested.connect(self.scan_manager.start_workflow)
        
        # Startup dialog - výběr projektu s historií
        recent_projects = self.settings.value("recent_projects", [])
        if not isinstance(recent_projects, list):
            recent_projects = []
        
        dlg = StartupDialog(recent_projects=recent_projects, parent=self)
        if dlg.exec() == QDialog.Accepted:
            if dlg.choice == "import":
                self.import_project_dialog()
            elif dlg.choice == "new":
                # Nový prázdný projekt - nic nedělat
                pass
            elif dlg.choice and os.path.exists(dlg.choice):
                # Otevřít vybraný projekt z historie
                self.import_project(dlg.choice)

        # Inicializovat přepínač běhů/verzí (i pro prázdný projekt)
        self.refresh_runs_combo()


    def calculate_adaptive_sizes(self):
        """Adaptivní (preferované) velikosti panelů — proporčně k oknu, použitelné
        od FullHD po 4K, s normálním systémovým fontem. Panely nejsou tvrdě
        omezené — jdou roztáhnout splitterem."""
        w = max(int(self.screen_width or 1920), 1280)

        def clamp(value, lo, hi):
            return max(lo, min(int(value), hi))

        # Užší levý + pravé souhrnné panely, ať matice (střed) dostane víc místa
        # i na FullHD. Pravé panely jdou roztáhnout splitterem podle potřeby.
        self.left_panel_width = clamp(w * 0.16, 280, 420)
        self.ip_summary_width = clamp(w * 0.18, 300, 720)
        self.port_summary_width = clamp(w * 0.09, 150, 280)
        self.service_summary_width = clamp(w * 0.10, 170, 300)
        right_total = self.ip_summary_width + self.port_summary_width + self.service_summary_width
        # Střední panel = zbytek šířky (matice je hlavní pohled → dostane nejvíc).
        self.middle_panel_width = max(560, w - self.left_panel_width - right_total - 40)

        # Orientační šířky sloupců (stromy stejně používají ResizeToContents).
        self.ip_summary_col0 = int(self.ip_summary_width * 0.42)
        self.ip_summary_col1 = self.ip_summary_width - self.ip_summary_col0
        self.port_summary_col0 = int(self.port_summary_width * 0.55)
        self.port_summary_col1 = self.port_summary_width - self.port_summary_col0
        self.service_summary_col0 = int(self.service_summary_width * 0.6)
        self.service_summary_col1 = self.service_summary_width - self.service_summary_col0

        self.right_panel_width = (self.ip_summary_width
                                  + self.port_summary_width
                                  + self.service_summary_width)
        # Normální font (na velmi velkých monitorech o kousek větší).
        self.font_size = 10 if w >= 3440 else 9

    def fetch_public_ip(self):
        """Zjistí aktuální veřejnou IP adresu přes API."""
        self.my_ip_label.setText("Zjišťuji...")
        self.my_ip_label.setStyleSheet("color: #95A5A6;")
        
        # Použijeme QTimer pro lehké zpoždění, aby to neběželo v hlavním vlákně (nebo QThread pro profi řešení)
        # Pro jednoduchost zde použijeme přímý request, u krátkého API to macOS zvládne bez lagů
        try:
            # Využijeme existující import requests
            import requests
            def get_ip():
                try:
                    # api.ipify.org je rychlá a stabilní služba
                    response = requests.get('https://api.ipify.org', timeout=5)
                    if response.status_code == 200:
                        ip = response.text
                        self.my_ip_label.setText(ip)
                        self.my_ip_label.setStyleSheet("font-weight: bold; color: #2ECC71; font-size: 11pt;")
                    else:
                        self.my_ip_label.setText("Chyba API")
                        self.my_ip_label.setStyleSheet("color: #E74C3C;")
                except Exception as e:
                    self.my_ip_label.setText("Offline / Error")
                    self.my_ip_label.setStyleSheet("color: #E74C3C;")

            # Spustíme to po krátké pauze, aby se GUI stihlo překreslit
            QTimer.singleShot(100, get_ip)
            
        except Exception as e:
            self.my_ip_label.setText("Chyba")

    def init_ui(self):
        main_layout = QHBoxLayout(self)
        content_splitter = QSplitter(Qt.Horizontal)
        
        # Levý panel
        left_widget = QWidget()
        left_panel = QVBoxLayout(left_widget)
        
        # --- NOVÉ: Network Info Panel (Tvá IP) ---
        network_group = QGroupBox("Moje Síťová Identita")
        network_layout = QHBoxLayout(network_group)
        
        self.my_ip_label = QLabel("Zjišťuji IP...")
        self.my_ip_label.setStyleSheet("font-weight: bold; color: #E67E22; font-size: 11pt;")
        
        self.refresh_ip_btn = QPushButton("🔄")
        self.refresh_ip_btn.setFixedWidth(30)
        self.refresh_ip_btn.setToolTip("Aktualizovat veřejnou IP")
        self.refresh_ip_btn.clicked.connect(self.fetch_public_ip)
        
        network_layout.addWidget(QLabel("Veřejná IP:"))
        network_layout.addWidget(self.my_ip_label)
        network_layout.addStretch()
        network_layout.addWidget(self.refresh_ip_btn)
        
        left_panel.addWidget(network_group)
        # ------------------------------------------

        input_splitter = QSplitter(Qt.Vertical)
        
        # ŽÁDNÝ setStyleSheet - nativní Qt/macOS styl
        
        raw_widget = QWidget()
        raw_layout = QVBoxLayout(raw_widget)
        raw_layout.addWidget(QLabel("Neočištěný vstup:"))
        self.raw_input_text = QTextEdit(placeholderText="Vložte text s IP adresami...")
        raw_layout.addWidget(self.raw_input_text)
        
        # Tlačítko pro manuální zpracování IP adres
        self.process_ips_button = QPushButton("Zpracovat IP adresy →")
        self.process_ips_button.clicked.connect(self.update_cleaned_output)
        raw_layout.addWidget(self.process_ips_button)
        
        cleaned_widget = QWidget()
        cleaned_layout = QVBoxLayout(cleaned_widget)
        self.count_label = QLabel("Počet cílů: 0")
        cleaned_layout.addWidget(self.count_label)
        self.cleaned_output_text = QTextEdit()
        self.cleaned_output_text.setReadOnly(False)
        self.cleaned_output_text.setContextMenuPolicy(Qt.CustomContextMenu)
        self.cleaned_output_text.customContextMenuRequested.connect(self.show_context_menu)
        cleaned_layout.addWidget(self.cleaned_output_text)
        
        input_splitter.addWidget(raw_widget)
        input_splitter.addWidget(cleaned_widget)
        
        left_panel.addWidget(input_splitter)
        
        # Přidání pole pro název projektu
        left_panel.addWidget(QLabel("Název projektu:"))
        self.project_name_edit = QLineEdit("Můj Nmap Projekt")
        left_panel.addWidget(self.project_name_edit)

        # Cesta k aktuálnímu projektu (vybíratelná myší, plná cesta v tooltipu).
        self.project_path_label = QLabel("Projekt: (neuložený)")
        self.project_path_label.setWordWrap(True)
        self.project_path_label.setStyleSheet("color: #7f8c8d; font-size: 11px;")
        self.project_path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        left_panel.addWidget(self.project_path_label)

        # Výběr profilu skenu (Master / Intensive / Medium / Light / Vlastní)
        profile_layout = QHBoxLayout()
        profile_layout.addWidget(QLabel("Profil skenu:"))
        self.profile_combo = QComboBox()
        for key in sp.PROFILE_ORDER:
            self.profile_combo.addItem(sp.PROFILE_LABELS[key], key)
        self.profile_combo.currentIndexChanged.connect(self.on_profile_changed)
        profile_layout.addWidget(self.profile_combo)
        left_panel.addLayout(profile_layout)

        self.profile_hint_label = QLabel(sp.PROFILE_HINTS["master"])
        self.profile_hint_label.setWordWrap(True)
        self.profile_hint_label.setStyleSheet("color: #7f8c8d; font-size: 11px;")
        left_panel.addWidget(self.profile_hint_label)

        # Pole pro vlastní nmap příkaz (jen pro profil „Vlastní příkaz")
        self.custom_command_label = QLabel("Vlastní nmap příkaz (placeholder {target}):")
        left_panel.addWidget(self.custom_command_label)
        self.custom_command_edit = QLineEdit()
        self.custom_command_edit.setPlaceholderText("např. nmap -sV -p 80,443 {target}")
        left_panel.addWidget(self.custom_command_edit)

        # Povolené fáze (checkboxy)
        left_panel.addWidget(QLabel("Povolené fáze:"))
        self.phase_checkboxes = {}
        phases_row = QHBoxLayout()
        for phase in self.phases:
            checkbox = QCheckBox(phase.capitalize())
            checkbox.setChecked(True)
            self.phase_checkboxes[phase] = checkbox
            phases_row.addWidget(checkbox)
        phases_row.addStretch()
        left_panel.addLayout(phases_row)

        btn_layout = QHBoxLayout()
        self.scan_button = QPushButton("▶ Spustit nový běh")
        self.stop_button = QPushButton("⏹ Zastavit")
        self.stop_button.setEnabled(False)
        btn_layout.addWidget(self.scan_button)
        btn_layout.addWidget(self.stop_button)
        left_panel.addLayout(btn_layout)

        self.forget_sudo_btn = QPushButton("🔒 Zapomenout sudo heslo")
        self.forget_sudo_btn.setToolTip("Bezpečně vymaže sudo heslo z paměti (drží se jen v RAM, nikdy na disk).")
        self.forget_sudo_btn.clicked.connect(self.forget_sudo_password)
        left_panel.addWidget(self.forget_sudo_btn)

        # Nový layout pro Export / Import / Přepnutí projektu
        export_import_layout = QVBoxLayout()
        self.export_btn = QPushButton("Uložit / Exportovat projekt")
        self.export_btn.clicked.connect(self.export_project_dialog)
        export_import_layout.addWidget(self.export_btn)

        self.import_btn = QPushButton("Importovat projekt")
        self.import_btn.clicked.connect(self.import_project_dialog)
        export_import_layout.addWidget(self.import_btn)

        self.switch_project_btn = QPushButton("Přepnout projekt…")
        self.switch_project_btn.clicked.connect(self.switch_project)
        export_import_layout.addWidget(self.switch_project_btn)
        left_panel.addLayout(export_import_layout)
        
        self.status_label = QLabel("Připraven.")
        left_panel.addWidget(self.status_label)
        
        content_splitter.addWidget(left_widget)
        
        # Prostřední panel s toolbarem a tlačítky
        middle_container = QWidget()
        middle_main_layout = QVBoxLayout(middle_container)
        middle_main_layout.setContentsMargins(0, 0, 0, 0)
        middle_main_layout.setSpacing(5)
        
        # === NOVÝ: Toolbar s akcemi (ikony) ===
        actions_toolbar = QWidget()
        actions_layout = QHBoxLayout(actions_toolbar)
        actions_layout.setContentsMargins(5, 2, 5, 2)
        actions_layout.setSpacing(5)
        
        # Akce 1: Export všech výsledků
        self.export_all_btn = QPushButton("📄")
        self.export_all_btn.setToolTip("Exportovat vybrané výsledky do jednoho souboru")
        self.export_all_btn.setFixedSize(35, 35)
        self.export_all_btn.setStyleSheet("""
            QPushButton {
                font-size: 18px;
                border: 1px solid #CCCCCC;
                border-radius: 5px;
                background-color: #F9F9F9;
                padding: 2px;
            }
            QPushButton:hover {
                background-color: #E8E8E8;
                border: 1px solid #999999;
            }
            QPushButton:pressed {
                background-color: #D8D8D8;
            }
        """)
        self.export_all_btn.clicked.connect(self.export_multiple_results_dialog)
        actions_layout.addWidget(self.export_all_btn)
        
        # Akce 2: Export přehledu portů
        self.export_ports_btn = QPushButton("🔌")
        self.export_ports_btn.setToolTip("Exportovat přehled portů podle stavů")
        self.export_ports_btn.setFixedSize(35, 35)
        self.export_ports_btn.setStyleSheet("""
            QPushButton {
                font-size: 18px;
                border: 1px solid #CCCCCC;
                border-radius: 5px;
                background-color: #F9F9F9;
                padding: 2px;
            }
            QPushButton:hover {
                background-color: #E8E8E8;
                border: 1px solid #999999;
            }
            QPushButton:pressed {
                background-color: #D8D8D8;
            }
        """)
        self.export_ports_btn.clicked.connect(self.export_ports_summary_dialog)
        actions_layout.addWidget(self.export_ports_btn)
        
        # Akce 3: Export přehledu služeb
        self.export_services_btn = QPushButton("⚙️")
        self.export_services_btn.setToolTip("Exportovat přehled služeb podle protokolů")
        self.export_services_btn.setFixedSize(35, 35)
        self.export_services_btn.setStyleSheet("""
            QPushButton {
                font-size: 18px;
                border: 1px solid #CCCCCC;
                border-radius: 5px;
                background-color: #F9F9F9;
                padding: 2px;
            }
            QPushButton:hover {
                background-color: #E8E8E8;
                border: 1px solid #999999;
            }
            QPushButton:pressed {
                background-color: #D8D8D8;
            }
        """)
        self.export_services_btn.clicked.connect(self.export_services_summary_dialog)
        actions_layout.addWidget(self.export_services_btn)
        
        # Akce 4: Export do Word dokumentu s analýzou zranitelností
        self.export_word_btn = QPushButton("📋")
        self.export_word_btn.setToolTip("Exportovat analýzu zranitelností do Word (.docx)")
        self.export_word_btn.setFixedSize(35, 35)
        self.export_word_btn.setStyleSheet("""
            QPushButton {
                font-size: 18px;
                border: 1px solid #CCCCCC;
                border-radius: 5px;
                background-color: #F9F9F9;
                padding: 2px;
            }
            QPushButton:hover {
                background-color: #E8E8E8;
                border: 1px solid #999999;
            }
            QPushButton:pressed {
                background-color: #D8D8D8;
            }
        """)
        self.export_word_btn.clicked.connect(self.export_vulnerability_report)
        actions_layout.addWidget(self.export_word_btn)
        
        # Akce 5: Export seznamu hostnames
        self.export_hostnames_btn = QPushButton("🏠")
        self.export_hostnames_btn.setToolTip("Exportovat seznam IP adres a jejich hostnames")
        self.export_hostnames_btn.setFixedSize(35, 35)
        self.export_hostnames_btn.setStyleSheet("""
            QPushButton {
                font-size: 18px;
                border: 1px solid #CCCCCC;
                border-radius: 5px;
                background-color: #F9F9F9;
                padding: 2px;
            }
            QPushButton:hover {
                background-color: #E8E8E8;
                border: 1px solid #999999;
            }
            QPushButton:pressed {
                background-color: #D8D8D8;
            }
        """)
        self.export_hostnames_btn.clicked.connect(self.export_hostnames_list)
        actions_layout.addWidget(self.export_hostnames_btn)
        
        # === NOVÉ: Tlačítko pro FFUF ===
        self.ffuf_btn = QPushButton("📂")
        self.ffuf_btn.setToolTip("Directory Fuzzing (ffuf) - Najít skryté složky na webu")
        self.ffuf_btn.setFixedSize(35, 35)
        self.ffuf_btn.setStyleSheet("""
            QPushButton {
                font-size: 18px;
                border: 1px solid #CCCCCC;
                border-radius: 5px;
                background-color: #F9F9F9;
                padding: 2px;
                color: #8E44AD; /* Fialová barva pro odlišení */
            }
            QPushButton:hover {
                background-color: #E8E8E8;
                border: 1px solid #999999;
            }
            QPushButton:pressed {
                background-color: #D8D8D8;
            }
        """)
        self.ffuf_btn.clicked.connect(self.open_ffuf_dialog)
        actions_layout.addWidget(self.ffuf_btn)
        
        # === NOVÉ: Tlačítko pro Certifikáty ===
        self.cert_btn = QPushButton("🔒")
        self.cert_btn.setToolTip("Inspektor SSL/TLS certifikátů")
        self.cert_btn.setFixedSize(35, 35)
        self.cert_btn.setStyleSheet("""
            QPushButton {
                font-size: 18px;
                border: 1px solid #CCCCCC;
                border-radius: 5px;
                background-color: #F9F9F9;
                padding: 2px;
                color: #27AE60; /* Zelená barva pro SSL */
            }
            QPushButton:hover {
                background-color: #E8E8E8;
                border: 1px solid #999999;
            }
            QPushButton:pressed {
                background-color: #D8D8D8;
            }
        """)
        self.cert_btn.clicked.connect(self.open_certificate_dialog)
        actions_layout.addWidget(self.cert_btn)
        # =================================
        
        # Akce: Security Headers
        self.headers_btn = QPushButton("🛡️")
        self.headers_btn.setToolTip("Inspektor HTTP Security Headers")
        self.headers_btn.setFixedSize(35, 35)
        self.headers_btn.setStyleSheet("""
            QPushButton {
                font-size: 18px;
                border: 1px solid #CCCCCC;
                border-radius: 5px;
                background-color: #F9F9F9;
                padding: 2px;
                color: #E67E22;
            }
            QPushButton:hover { background-color: #E8E8E8; }
        """)
        self.headers_btn.clicked.connect(self.open_security_headers_dialog)
        actions_layout.addWidget(self.headers_btn)
        
        # Akce: TLS Audit
        self.tls_btn = QPushButton("🔐")
        self.tls_btn.setToolTip("Audit TLS protokolů a šifer")
        self.tls_btn.setFixedSize(35, 35)
        self.tls_btn.setStyleSheet("""
            QPushButton { font-size: 18px; border: 1px solid #CCCCCC; border-radius: 5px; background-color: #F9F9F9; color: #2C3E50; }
            QPushButton:hover { background-color: #E8E8E8; }
        """)
        self.tls_btn.clicked.connect(self.open_tls_audit_dialog)
        actions_layout.addWidget(self.tls_btn)
        
        # Přidat stretch aby akce byly vlevo
        actions_layout.addStretch()
        
        middle_main_layout.addWidget(actions_toolbar)
        
        # Horní panel s tlačítky pro skrytí/odkrytí sekcí
        top_buttons_widget = QWidget()
        top_buttons_layout = QHBoxLayout(top_buttons_widget)
        top_buttons_layout.setContentsMargins(0, 0, 0, 0)
        top_buttons_layout.setSpacing(5)
        
        top_buttons_layout.addStretch()
        
        self.ip_summary_toggle_btn = QPushButton("📋 Souhrn IP")
        self.ip_summary_toggle_btn.setCheckable(True)
        self.ip_summary_toggle_btn.setChecked(True)  # Defaultně zobrazená
        self.ip_summary_toggle_btn.toggled.connect(self.toggle_ip_summary)
        self.ip_summary_toggle_btn.setMaximumWidth(120)
        top_buttons_layout.addWidget(self.ip_summary_toggle_btn)
        
        self.port_summary_toggle_btn = QPushButton("🔌 Porty")
        self.port_summary_toggle_btn.setCheckable(True)
        self.port_summary_toggle_btn.setChecked(True)  # Defaultně zobrazená
        self.port_summary_toggle_btn.toggled.connect(self.toggle_port_summary)
        self.port_summary_toggle_btn.setMaximumWidth(120)
        top_buttons_layout.addWidget(self.port_summary_toggle_btn)
        
        self.service_summary_toggle_btn = QPushButton("⚙️ Služby")
        self.service_summary_toggle_btn.setCheckable(True)
        self.service_summary_toggle_btn.setChecked(True)  # Defaultně zobrazená
        self.service_summary_toggle_btn.toggled.connect(self.toggle_service_summary)
        self.service_summary_toggle_btn.setMaximumWidth(120)
        top_buttons_layout.addWidget(self.service_summary_toggle_btn)
        
        middle_main_layout.addWidget(top_buttons_widget)
        
        # Prostřední panel - obsah
        middle_widget = QWidget()
        middle_panel = QVBoxLayout(middle_widget)
        middle_panel.setContentsMargins(0, 0, 0, 0)
        # Lišta běhů/verzí: přepínač + akce (navázat, porovnat, správa)
        run_bar = QHBoxLayout()
        run_bar.addWidget(QLabel("Běh/verze:"))
        self.run_combo = QComboBox()
        self.run_combo.setMinimumWidth(220)
        self.run_combo.currentIndexChanged.connect(self._on_run_combo_changed)
        run_bar.addWidget(self.run_combo)
        self.run_status_label = QLabel("")
        self.run_status_label.setStyleSheet("color: #7f8c8d;")
        run_bar.addWidget(self.run_status_label)
        run_bar.addStretch()
        self.resume_button = QPushButton("▶ Navázat")
        self.resume_button.setToolTip("Doskenovat nedoběhlé a chybové fáze v tomto běhu (úspěšné se přeskočí)")
        self.resume_button.clicked.connect(self.resume_run)
        self.resume_button.setEnabled(False)
        self.diff_button = QPushButton("🔍 Porovnat verze…")
        self.diff_button.clicked.connect(self.open_diff_dialog)
        self.manage_runs_button = QPushButton("🗂 Správa běhů…")
        self.manage_runs_button.clicked.connect(self.open_runs_manager)
        for b in (self.resume_button, self.diff_button, self.manage_runs_button):
            run_bar.addWidget(b)
        middle_panel.addLayout(run_bar)

        middle_panel.addWidget(QLabel("Průběh fází (Matice):"))

        # Souhrnné progress bary pro jednotlivé fáze
        self.phase_progress_bars = PhaseProgressBars(self.phases)
        middle_panel.addWidget(self.phase_progress_bars)

        self.status_matrix = StatusMatrix(self.phases)
        self.status_matrix.itemClicked.connect(self.on_matrix_ip_clicked)

        # PŘIDAT: Reagovat i na změnu výběru (šipky)
        self.status_matrix.currentItemChanged.connect(self.on_matrix_selection_changed)

        # Kontextová akce nad cílem: re-scan (merge do aktuální verze + timeline)
        self.status_matrix.setContextMenuPolicy(Qt.CustomContextMenu)
        self.status_matrix.customContextMenuRequested.connect(self.on_matrix_context_menu)

        middle_panel.addWidget(self.status_matrix)

        self.tabs = QTabWidget()
        # Živý panel paralelních úloh — první záložka, ať je vidět během skenu
        self.live_task_panel = LiveTaskPanel()
        self.tabs.addTab(self.live_task_panel, "Živé úlohy")
        self.tree_widgets = {}
        self.export_buttons = {}
        
        for phase in self.phases:
            tab = self.create_phase_tab(phase)
            self.tabs.addTab(tab, phase.capitalize())
        
        # Nová záložka pro screenshoty s viewerem
        screenshot_tab = QWidget()
        screenshot_layout = QVBoxLayout(screenshot_tab)
        
        # Informační panel nahoře
        info_layout = QHBoxLayout()
        self.screenshot_info_label = QLabel("Žádné screenshoty k zobrazení")
        self.screenshot_info_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        info_layout.addWidget(self.screenshot_info_label)
        info_layout.addStretch()
        screenshot_layout.addLayout(info_layout)
        
        # Hlavní oblast pro zobrazení screenshotu
        self.screenshot_display = QLabel()
        self.screenshot_display.setAlignment(Qt.AlignCenter)
        self.screenshot_display.setStyleSheet("border: 2px solid #95A5A6; background-color: #ECF0F1;")
        self.screenshot_display.setMinimumHeight(600)
        self.screenshot_display.setScaledContents(False)
        screenshot_layout.addWidget(self.screenshot_display)
        
        # Tlačítka pro navigaci
        nav_layout = QHBoxLayout()
        self.prev_screenshot_btn = QPushButton("← Předchozí")
        self.prev_screenshot_btn.clicked.connect(self.show_previous_screenshot)
        self.prev_screenshot_btn.setEnabled(False)
        
        self.screenshot_counter_label = QLabel("0 / 0")
        self.screenshot_counter_label.setStyleSheet("font-size: 12px;")
        self.screenshot_counter_label.setAlignment(Qt.AlignCenter)
        
        self.next_screenshot_btn = QPushButton("Další →")
        self.next_screenshot_btn.clicked.connect(self.show_next_screenshot)
        self.next_screenshot_btn.setEnabled(False)
        
        nav_layout.addWidget(self.prev_screenshot_btn)
        nav_layout.addStretch()
        nav_layout.addWidget(self.screenshot_counter_label)
        nav_layout.addStretch()
        nav_layout.addWidget(self.next_screenshot_btn)
        screenshot_layout.addLayout(nav_layout)
        
        self.tabs.addTab(screenshot_tab, "Screenshots")
        
        # Inicializace screenshot vieweru
        self.current_screenshot_index = 0
        self.all_screenshots = []
        
        middle_panel.addWidget(self.tabs)
        
        middle_panel.addWidget(QLabel("Detailní log:"))
        self.log_console = LogConsole()
        self.log_console.setFixedHeight(200)
        middle_panel.addWidget(self.log_console)
        
        middle_main_layout.addWidget(middle_widget)
        
        content_splitter.addWidget(middle_container)
        
        # Pravá strana - HBOXLAYOUT místo QSplitter (jako v původní verzi)
        right_side_widget = QWidget()
        right_side_main_layout = QHBoxLayout(right_side_widget)
        right_side_main_layout.setContentsMargins(0, 0, 0, 0)
        right_side_main_layout.setSpacing(5)
        
        # === Sekce 1: IP Summary (Souhrn vybrané IP) ===
        self.ip_summary_container = QWidget()
        ip_summary_layout = QVBoxLayout(self.ip_summary_container)
        ip_summary_layout.setContentsMargins(0, 0, 0, 0)
        ip_summary_layout.addWidget(QLabel("Souhrn vybrané IP:"))
        
        self.ip_summary_tree = QTreeWidget()
        self.ip_summary_tree.setHeaderLabels(["Atribut", "Hodnota"])
        self.ip_summary_tree.setMinimumWidth(280)
        
        header_ip = self.ip_summary_tree.header()
        header_ip.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header_ip.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        
        ip_summary_layout.addWidget(self.ip_summary_tree)
        
        default_item = QTreeWidgetItem(self.ip_summary_tree, ["", "Vyberte IP v matici"])
        default_item.setForeground(1, QColor("#999999"))
        
        right_side_main_layout.addWidget(self.ip_summary_container, 3)

        # === Sekce 2: Port Summary (Přehled portů) ===
        self.port_summary_container = QWidget()
        port_summary_layout = QVBoxLayout(self.port_summary_container)
        port_summary_layout.setContentsMargins(0, 0, 0, 0)
        port_summary_layout.addWidget(QLabel("Přehled portů:"))
        
        self.port_summary_tree = QTreeWidget()
        self.port_summary_tree.setHeaderLabels(["Port/Stav", "Počet IP"])
        self.port_summary_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.port_summary_tree.customContextMenuRequested.connect(self.show_port_context_menu)
        self.port_summary_tree.setMinimumWidth(140)
        
        header_port = self.port_summary_tree.header()
        header_port.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header_port.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        
        port_summary_layout.addWidget(self.port_summary_tree)
        
        right_side_main_layout.addWidget(self.port_summary_container, 1)

        # === Sekce 3: Service Summary (Přehled služeb) ===
        self.service_summary_container = QWidget()
        service_summary_layout = QVBoxLayout(self.service_summary_container)
        service_summary_layout.setContentsMargins(0, 0, 0, 0)
        service_summary_layout.addWidget(QLabel("Přehled služeb:"))
        
        self.service_summary_tree = QTreeWidget()
        self.service_summary_tree.setHeaderLabels(["Služba/Port", "Počet IP"])
        self.service_summary_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.service_summary_tree.customContextMenuRequested.connect(self.show_service_context_menu)
        self.service_summary_tree.setMinimumWidth(160)
        
        header_serv = self.service_summary_tree.header()
        header_serv.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header_serv.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        
        service_summary_layout.addWidget(self.service_summary_tree)
        
        right_side_main_layout.addWidget(self.service_summary_container, 2)

        content_splitter.addWidget(right_side_widget)

        # Stretch: levý fixní; matice (střed) má přednost, pravý souhrn jen doplňkově.
        content_splitter.setStretchFactor(0, 0)
        content_splitter.setStretchFactor(1, 5)
        content_splitter.setStretchFactor(2, 2)

        # Výchozí velikosti proporčně k oknu (uživatel může přetáhnout).
        content_splitter.setSizes([self.left_panel_width,
                                   self.middle_panel_width,
                                   self.right_panel_width])
        
        self.content_splitter = content_splitter  # Uložit referenci
        self.right_side_widget = right_side_widget  # Uložit referenci pro toggle funkce
        
        main_layout.addWidget(content_splitter)
        
    def _autosave_after_audit(self):
        """Uloží výsledky auditu (TLS/cert/headers/ffuf) do verze, je-li projekt."""
        if self.current_project_path and not self.scan_manager.is_running:
            self.auto_save_project()

    def open_tls_audit_dialog(self):
        """Otevře dialog pro audit TLS a šifer."""
        dialog = TlsAuditDialog(self.scan_results, self,
                                project_name=self.project_name_edit.text(),
                                project_path=self.current_project_path)
        dialog.exec()
        self._autosave_after_audit()

    def open_security_headers_dialog(self):
        """Otevře dialog pro kontrolu Security Headers."""
        if not any(self.scan_results.get('tcp', {}).values()):
            QMessageBox.warning(self, "Žádná data", "Nejdříve spusťte TCP sken portů.")
            return
        dialog = SecurityHeadersDialog(self.scan_results, self)
        dialog.exec()
        self._autosave_after_audit()

    def open_certificate_dialog(self):
        """Otevře dialog pro kontrolu certifikátů."""
        if not any(self.scan_results.get(phase, {}) for phase in ['tcp', 'online']):
            QMessageBox.warning(self, "Žádná data", "Nejdříve spusťte skenování (TCP), aby bylo možné detekovat webové služby.")
            return

        dialog = CertificateDialog(self.scan_results, self)
        dialog.exec()
        self._autosave_after_audit()

    def open_ffuf_dialog(self):
        """Otevře ffuf dialog a spravuje předávání dat."""
        if "ffuf" not in self.scan_results:
            self.scan_results["ffuf"] = []

        # Předáváme referenci na naše výsledky
        dialog = FfufDialog(self.scan_results, self)

        if self.scan_results["ffuf"]:
            dialog.load_existing_results(self.scan_results["ffuf"])

        dialog.exec()
        self._autosave_after_audit()
        
        # Po zavření dialogu pro jistotu znovu synchronizujeme
        self.scan_results["ffuf"] = dialog.json_results
        self.auto_save_project()

    def toggle_ip_summary(self, checked):
        """Přepíná viditelnost sekce Souhrn vybrané IP."""
        self.ip_summary_container.setVisible(checked)
        self.update_middle_panel_width()
    
    def toggle_port_summary(self, checked):
        """Přepíná viditelnost sekce Přehled portů."""
        self.port_summary_container.setVisible(checked)
        self.update_middle_panel_width()
    
    def toggle_service_summary(self, checked):
        """Přepíná viditelnost sekce Přehled služeb."""
        self.service_summary_container.setVisible(checked)
        self.update_middle_panel_width()

    def update_middle_panel_width(self):
        """
        Přizpůsobí šířku středního panelu podle viditelnosti pravých sekcí.
        """
        if not hasattr(self, 'content_splitter'):
            return
        
        # Získat aktuální velikosti hlavního splitteru
        main_sizes = self.content_splitter.sizes()
        if len(main_sizes) < 3:
            return
        
        left_size = main_sizes[0]
        middle_size = main_sizes[1]
        right_size = main_sizes[2]
        
        # Spočítat potřebnou šířku pro viditelné pravé sekce
        needed_right_width = 0
        if self.ip_summary_container.isVisible():
            needed_right_width += self.ip_summary_width
        if self.port_summary_container.isVisible():
            needed_right_width += self.port_summary_width
        if self.service_summary_container.isVisible():
            needed_right_width += self.service_summary_width
        
        # Celková dostupná šířka pro střední + pravé panely
        total_available = middle_size + right_size
        
        # Nová šířka středního panelu
        new_middle_size = total_available - needed_right_width
        
        # Zajistit minimální šířku
        if new_middle_size < 600:
            new_middle_size = 600
            needed_right_width = total_available - new_middle_size
        
        # Nastavit velikosti v hlavním splitteru
        self.content_splitter.setSizes([left_size, new_middle_size, needed_right_width])

    def update_section_visibility(self):
        # Přizpůsobí velikosti v pravé části na základě viditelnosti kontejnerů
        visible_count = sum([
            self.ip_summary_container.isVisible(),
            self.port_summary_container.isVisible(),
            self.service_summary_container.isVisible()
        ])
        
        if visible_count == 0:
            # Tlačítka zůstanou, ale nic není vidět
            self.right_side_widget.setVisible(False)
            return
        else:
            self.right_side_widget.setVisible(True)
        
        # Nastavit stretch podle viditelných kontejnerů
        self.right_side_layout.setStretch(0, 1 if self.ip_summary_container.isVisible() else 0)
        self.right_side_layout.setStretch(1, 1 if self.port_summary_container.isVisible() else 0)
        self.right_side_layout.setStretch(2, 1 if self.service_summary_container.isVisible() else 0)
        
        # Střední panel by měl zabírat zbytek prostoru (nastavím stretch na main layout)
        # TODO: při implementaci středního panelu použit flexbox, tento krok může být specifický

    def adjust_column_widths(self):
        # Přizpůsobit sloupce všech přehledů podle obsahu
        for tree in [self.ip_summary_tree, self.port_summary_tree, self.service_summary_tree]:
            header = tree.header()
            for col in range(tree.columnCount()):
                header.setSectionResizeMode(col, QHeaderView.ResizeToContents)

    def update_screenshot_viewer(self):
        """Aktualizuje seznam screenshotů pro viewer."""
        self.all_screenshots = []
        for ip, filepaths in self.screenshots.items():
            for filepath in filepaths:
                if os.path.exists(filepath):
                    self.all_screenshots.append((ip, filepath))
        
        self.current_screenshot_index = 0
        self.show_current_screenshot()
    
    def show_current_screenshot(self):
        """Zobrazí aktuální screenshot podle indexu."""
        if not self.all_screenshots:
            self.screenshot_info_label.setText("Žádné screenshoty k zobrazení")
            self.screenshot_counter_label.setText("0 / 0")
            self.screenshot_display.clear()
            # Když poslední dávka skončila chybami, vysvětli proč (síť/práva/Chrome);
            # jinak poraď, jak screenshoty pořídit.
            if getattr(self, "_shot_fail", 0) and self._shot_done >= self._shot_total:
                hint = self._screenshot_failure_hint(getattr(self, "_shot_last_err", ""))
                self.screenshot_display.setText(
                    f"📸 Žádné screenshoty se neuložily.\n\n"
                    f"{self._shot_fail} z {self._shot_total} se nepodařilo.\n"
                    f"Příčina: {hint}.\n\n"
                    "Re-scan: pravý klik na cíl v matici Průběh fází → Re-scan screenshoty.")
            else:
                self.screenshot_display.setText(
                    "Žádné screenshoty k dispozici.\n\n"
                    "Pořídíš je při skenu (TCP nad webovým portem) nebo ručně:\n"
                    "pravý klik na cíl v matici Průběh fází → 📸 Re-scan screenshoty.")
            self.screenshot_display.setStyleSheet(
                "border: 2px solid #95A5A6; background-color: #ECF0F1; color: #555; font-size: 14px;")
            self.prev_screenshot_btn.setEnabled(False)
            self.next_screenshot_btn.setEnabled(False)
            return
        
        total = len(self.all_screenshots)
        ip, filepath = self.all_screenshots[self.current_screenshot_index]
        filename = os.path.basename(filepath)
        
        # Načíst a zobrazit obrázek
        pixmap = QPixmap(filepath)
        if not pixmap.isNull():
            # Škálovat na rozměry widgetu, zachovat poměr stran
            scaled_pixmap = pixmap.scaled(
                self.screenshot_display.width() - 10,
                self.screenshot_display.height() - 10,
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation
            )
            self.screenshot_display.setPixmap(scaled_pixmap)
        else:
            self.screenshot_display.setText(f"Nelze načíst screenshot: {filename}")
        
        # Aktualizovat informace
        self.screenshot_info_label.setText(f"IP: {ip} | Soubor: {filename}")
        self.screenshot_counter_label.setText(f"{self.current_screenshot_index + 1} / {total}")
        
        # Povolit/zakázat tlačítka
        self.prev_screenshot_btn.setEnabled(self.current_screenshot_index > 0)
        self.next_screenshot_btn.setEnabled(self.current_screenshot_index < total - 1)
    
    def show_previous_screenshot(self):
        """Zobrazí předchozí screenshot."""
        if self.current_screenshot_index > 0:
            self.current_screenshot_index -= 1
            self.show_current_screenshot()
    
    def show_next_screenshot(self):
        """Zobrazí následující screenshot."""
        if self.current_screenshot_index < len(self.all_screenshots) - 1:
            self.current_screenshot_index += 1
            self.show_current_screenshot()

    def create_phase_tab(self, phase):
        """Vytvoří záložku pro specifickou fázi."""
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        
        tree = QTreeWidget()
        
        # Pro online fázi speciální hlavičky
        if phase == 'online':
            tree.setHeaderLabels(["Cíl", "Stav"])
        else:
            tree.setHeaderLabels(["Cíl (Port / Skript)", "Status", "Detaily"])
        
        self.tree_widgets[phase] = tree
        tab_layout.addWidget(tree)
        
        # Nastavit automatické přizpůsobení šířky sloupců
        header = tree.header()
        if phase == 'online':
            header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Cíl
            header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Stav
        else:
            header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Cíl
            header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Status
            header.setSectionResizeMode(2, QHeaderView.Stretch)  # Detaily - roztáhnout zbytek
        
        export_btn = QPushButton(f"Exportovat {phase.capitalize()} jako text")
        export_btn.setEnabled(True)
        export_btn.clicked.connect(lambda _, p=phase: self.export_phase_minimal(p))
        self.export_buttons[phase] = export_btn
        tab_layout.addWidget(export_btn)
        
        return tab

    @Slot(str, str, int, str)
    def update_service_summary(self):
        """
        Aktualizuje přehled služeb - agregace podle názvu služby, protokolu a portu.
        Struktura: TCP/UDP -> Název služby (počet IP) -> Port (seznam IP)
        """
        self.service_summary_tree.clear()
        
        # Struktura: {protokol: {service_name: {port: set(ip_addresses)}}}
        service_data = {
            'TCP': {},
            'UDP': {}
        }
        
        # Projít všechny TCP a UDP výsledky
        for phase in ['tcp', 'udp']:
            phase_data = self.scan_results.get(phase, {})
            proto = phase.upper()
            
            for ip, ip_data in phase_data.items():
                if phase not in ip_data:
                    continue
                    
                for port, port_info in ip_data[phase].items():
                    state = port_info.get('state', 'unknown')
                    
                    # Pouze otevřené a open|filtered porty
                    if state not in ['open', 'open|filtered']:
                        continue
                    
                    service_name = port_info.get('name', 'unknown')
                    if not service_name or service_name == '':
                        service_name = 'unknown'
                    
                    # Inicializovat strukturu
                    if service_name not in service_data[proto]:
                        service_data[proto][service_name] = {}
                    
                    if port not in service_data[proto][service_name]:
                        service_data[proto][service_name][port] = set()
                    
                    service_data[proto][service_name][port].add(ip)
        
        # Vytvořit tree strukturu
        for proto in ['TCP', 'UDP']:
            if not service_data[proto]:
                continue
            
            # Hlavní položka protokolu
            proto_item = QTreeWidgetItem(self.service_summary_tree, [proto, ""])
            proto_item.setForeground(0, QColor("#16A085") if proto == 'TCP' else QColor("#9B59B6"))
            proto_item.setExpanded(True)
            
            # Seřadit služby ABECEDNĚ (a-z)
            sorted_services = sorted(
                service_data[proto].items(),
                key=lambda x: x[0].lower()
            )
            
            for service_name, ports_dict in sorted_services:
                # Celkový počet unikátních IP pro tuto službu
                all_ips = set()
                for port_ips in ports_dict.values():
                    all_ips.update(port_ips)
                
                total_ip_count = len(all_ips)
                
                # Položka služby
                service_item = QTreeWidgetItem(proto_item, [service_name, str(total_ip_count)])
                service_item.setForeground(0, QColor("#2980B9"))
                service_item.setExpanded(False)
                
                # Uložit data pro context menu včetně detailů portů
                service_item.setData(0, Qt.UserRole, {
                    'type': 'service',
                    'protocol': proto,
                    'service': service_name,
                    'ips': all_ips,
                    'ports_dict': ports_dict
                })
                
                # Seřadit porty numericky
                sorted_ports = sorted(ports_dict.items(), key=lambda x: int(x[0]))
                
                for port, ip_set in sorted_ports:
                    # Položka portu
                    port_item = QTreeWidgetItem(service_item, [port, str(len(ip_set))])
                    port_item.setForeground(0, QColor("#27AE60"))
                    
                    # Uložit data pro context menu
                    port_item.setData(0, Qt.UserRole, {
                        'type': 'port',
                        'protocol': proto,
                        'service': service_name,
                        'port': port,
                        'ips': ip_set
                    })
        
        # Automaticky přizpůsobit šířku sloupců podle obsahu
        self.service_summary_tree.resizeColumnToContents(0)
        self.service_summary_tree.resizeColumnToContents(1)
        
        # Rozšířit sloupec "Počet IP" aby se vešel nadpis
        min_width = self.service_summary_tree.fontMetrics().horizontalAdvance("Počet IP") + 20
        if self.service_summary_tree.columnWidth(1) < min_width:
            self.service_summary_tree.setColumnWidth(1, min_width)


    def show_service_context_menu(self, position):
        """Zobrazí kontextové menu pro služby."""
        item = self.service_summary_tree.itemAt(position)
        if not item:
            return
        
        item_data = item.data(0, Qt.UserRole)
        if not item_data:
            return
        
        from PySide6.QtWidgets import QMenu
        from PySide6.QtGui import QAction
        
        menu = QMenu()
        
        if item_data['type'] == 'service':
            # Pro službu: zobrazit IP adresy + detailní výpis IP:PORT
            show_ips_action = QAction("Zobrazit IP adresy", self)
            show_ips_action.triggered.connect(lambda: self.show_ips_for_service(item_data))
            menu.addAction(show_ips_action)
            
            show_details_action = QAction("Zobrazit detailní výpis IP:PORT", self)
            show_details_action.triggered.connect(lambda: self.show_service_details(item_data))
            menu.addAction(show_details_action)
            
        elif item_data['type'] == 'port':
            # Pro port: pouze zobrazit IP adresy
            show_ips_action = QAction("Zobrazit IP adresy", self)
            show_ips_action.triggered.connect(lambda: self.show_ips_for_service(item_data))
            menu.addAction(show_ips_action)
        
        menu.exec(self.service_summary_tree.mapToGlobal(position))

    def show_service_details(self, service_data):
        """Zobrazí detailní dialog s výpisem IP:PORT pro službu."""
        dialog = QDialog(self)
        title = f"{service_data['protocol']}: {service_data['service']}"
        dialog.setWindowTitle(f"Detailní výpis - {title}")
        dialog.resize(500, 450)
        
        layout = QVBoxLayout(dialog)
        
        label = QLabel(f"<b>{title}</b><br>Detailní výpis IP:PORT")
        layout.addWidget(label)
        
        details_text = QTextEdit()
        details_text.setReadOnly(True)
        details_text.setFontFamily("Courier New")  # Monospace font pro lepší zarovnání
        
        # Vytvořit strukturu: {ip: [port1, port2, ...]}
        ip_port_map = {}
        ports_dict = service_data.get('ports_dict', {})
        
        for port, ip_set in ports_dict.items():
            for ip in ip_set:
                if ip not in ip_port_map:
                    ip_port_map[ip] = []
                ip_port_map[ip].append(port)
        
        # Seřadit IP adresy numericky
        sorted_ips = sorted(
            ip_port_map.keys(),
            key=lambda ip: tuple(int(p) for p in ip.split('.'))
        )
        
        # Vytvořit výpis
        output_lines = [f"{service_data['service']}"]
        
        for ip in sorted_ips:
            # Seřadit porty numericky pro danou IP
            sorted_ports = sorted(ip_port_map[ip], key=lambda p: int(p))
            
            for port in sorted_ports:
                output_lines.append(f"  - {ip}:{port}")
        
        details_text.setPlainText('\n'.join(output_lines))
        layout.addWidget(details_text)
        
        # Tlačítka
        button_layout = QHBoxLayout()
        
        copy_button = QPushButton("Kopírovat do schránky")
        copy_button.clicked.connect(lambda: QApplication.clipboard().setText(details_text.toPlainText()))
        button_layout.addWidget(copy_button)
        
        close_button = QPushButton("Zavřít")
        close_button.clicked.connect(dialog.accept)
        button_layout.addWidget(close_button)
        
        layout.addLayout(button_layout)
        
        dialog.exec()


    def show_ips_for_service(self, service_data):
        """Zobrazí dialog se seznamem IP adres pro danou službu/port."""
        dialog = QDialog(self)
        
        if service_data['type'] == 'service':
            title = f"{service_data['protocol']}: {service_data['service']}"
        else:  # port
            title = f"{service_data['protocol']}: {service_data['service']}:{service_data['port']}"
        
        dialog.setWindowTitle(f"IP adresy - {title}")
        dialog.resize(450, 350)
        
        layout = QVBoxLayout(dialog)
        
        label = QLabel(f"<b>{title}</b><br>Celkem IP adres: {len(service_data['ips'])}")
        layout.addWidget(label)
        
        iplist = QTextEdit()
        iplist.setReadOnly(True)
        
        # Seřadit IP adresy
        sorted_ips = sorted(
            list(service_data['ips']),
            key=lambda ip: tuple(int(p) for p in ip.split('.'))
        )
        
        iplist.setPlainText('\n'.join(sorted_ips))
        layout.addWidget(iplist)
        
        buttonbox = QDialogButtonBox(QDialogButtonBox.Ok)
        buttonbox.accepted.connect(dialog.accept)
        layout.addWidget(buttonbox)
        
        dialog.exec()

    
    @Slot(str, str)
    def on_screenshot_taken(self, ip, filepath):
        """Reaguje na pořízení screenshotu a aktualizuje GUI."""
        if ip not in self.screenshots:
            self.screenshots[ip] = []
        self.screenshots[ip].append(filepath)

        # Aktualizovat screenshot viewer
        self.update_screenshot_viewer()

    def _register_screenshots(self, n):
        """Ohlásí ``n`` chystaných screenshotů do průběhu (volat před emitem requestů)."""
        if n <= 0:
            return
        if self._shot_done >= self._shot_total:   # předchozí dávka doběhla → start odznova
            self._shot_total = self._shot_done = self._shot_ok = self._shot_fail = 0
            self._shot_last_err = ""
        self._shot_total += n
        self._update_shot_status()

    def on_screenshot_done(self, ip, url, ok, info):
        """Konec pokusu o screenshot (úspěch i chyba) → posune průběh."""
        self._shot_done += 1
        if ok:
            self._shot_ok += 1
        else:
            self._shot_fail += 1
            self._shot_last_err = info or "neznámá chyba"
        self._update_shot_status()

    def _screenshot_failure_hint(self, err):
        """Z textu chyby odhadne příčinu selhání screenshotu (síť vs práva vs Chrome)."""
        low = (err or "").lower()
        if any(m in low for m in ("err_connection", "connection refused", "connection closed",
                                  "connection reset", "err_timed_out", "timeout",
                                  "err_address_unreachable", "err_name_not_resolved",
                                  "err_ssl", "err_cert", "err_empty_response", "net::")):
            return "cíl na daném portu nejspíš neslouží web (HTTP/HTTPS) nebo je nedostupný"
        if any(m in low for m in ("operation not permitted", "permission denied",
                                  "errno 1", "errno 13", "read-only")):
            return "macOS blokuje zápis do složky projektu (Plocha/iCloud) — ulož projekt jinam"
        if any(m in low for m in ("selenium", "chrome", "chromedriver", "nedostup", "webdriver")):
            return "Chrome/Selenium není dostupný — zkontroluj instalaci Google Chrome"
        return err or "neznámá chyba"

    def _update_shot_status(self):
        """Vykreslí průběh screenshotů do status baru; po dokončení dávky souhrn."""
        if self._shot_total <= 0:
            return
        if self._shot_done < self._shot_total:
            self.status_label.setText(
                f"📸 Screenshoty: {self._shot_done}/{self._shot_total} "
                f"(✓ {self._shot_ok} · ✗ {self._shot_fail})…")
            return
        # hotovo
        if self._shot_fail == 0:
            self.status_label.setText(f"📸 Screenshoty hotové: {self._shot_ok}/{self._shot_total} ✓")
        else:
            hint = self._screenshot_failure_hint(self._shot_last_err)
            self.status_label.setText(
                f"📸 Screenshoty: {self._shot_ok} ✓ / {self._shot_fail} ✗ z {self._shot_total} — {hint}")
            self.worker_signals.log.emit(
                "warning",
                f"⚠️ Screenshoty: {self._shot_fail} z {self._shot_total} se nepodařilo. "
                f"Příčina: {hint}. (Poslední chyba: {self._shot_last_err})")
        # Aktualizovat i prázdný stav v záložce Screenshots (ať uživatel ví, co se stalo).
        if hasattr(self, "screenshot_display"):
            self.show_current_screenshot()

    @Slot(QTreeWidgetItem, int)
    def on_matrix_ip_clicked(self, item, column):
        """Zobrazí souhrn výsledků pro vybranou IP z matici."""
        if item is None:
            return
        ip_address = item.text(0)
        self._summary_ip = ip_address   # pro pozdější překreslení (např. po detekci web serveru)

        # Automaticky odkrýt sekci "Souhrn vybrané IP" POUZE pokud je PRÁZDNÁ
        is_empty = self.ip_summary_tree.topLevelItemCount() == 0 or \
                   (self.ip_summary_tree.topLevelItemCount() == 1 and 
                    self.ip_summary_tree.topLevelItem(0).text(1) == "Vyberte IP v matici")
        
        if is_empty and not self.ip_summary_toggle_btn.isChecked():
            self.ip_summary_toggle_btn.setChecked(True)
        
        self.ip_summary_tree.clear()
        
        # IP Adresa
        ip_item = QTreeWidgetItem(self.ip_summary_tree, ["IP Adresa", ip_address])
        ip_item.setForeground(0, QColor("#2980B9"))
        ip_item.setForeground(1, QColor("#2ECC71"))
        
        # Hostname
        hostname = "N/A"
        for phase in ['online', 'tcp', 'udp', 'vuln', 'osscan']:
            phase_data = self.scan_results.get(phase, {}).get(ip_address, {})
            if 'hostnames' in phase_data and phase_data['hostnames']:
                hostname_list = phase_data['hostnames']
                if isinstance(hostname_list, list) and len(hostname_list) > 0:
                    hostname = hostname_list[0].get('name', 'N/A')
                    break
        
        hostname_item = QTreeWidgetItem(self.ip_summary_tree, ["Hostname", hostname])
        hostname_item.setForeground(0, QColor("#2980B9"))
        
        # Souhrn portů podle stavů
        port_stats = {
            'tcp': {'open': 0, 'filtered': 0, 'closed': 0, 'open|filtered': 0},
            'udp': {'open': 0, 'filtered': 0, 'closed': 0, 'open|filtered': 0}
        }
        
        # Spočítat porty podle protokolu a stavu
        for phase in ['tcp', 'udp']:
            phase_data = self.scan_results.get(phase, {}).get(ip_address, {})
            if phase in phase_data:
                for port, info in phase_data[phase].items():
                    port_state = info.get('state', 'unknown')
                    if port_state in port_stats[phase]:
                        port_stats[phase][port_state] += 1
        
        # Zobrazit souhrn portů
        ports_summary_parent = QTreeWidgetItem(self.ip_summary_tree, ["Souhrn portů", ""])
        ports_summary_parent.setForeground(0, QColor("#3498DB"))
        ports_summary_parent.setExpanded(True)
        
        # TCP souhrn
        tcp_total = sum(port_stats['tcp'].values())
        tcp_parent = QTreeWidgetItem(ports_summary_parent, ["TCP", f"Celkem: {tcp_total}"])
        tcp_parent.setForeground(0, QColor("#16A085"))
        tcp_parent.setExpanded(True)
        
        if port_stats['tcp']['open'] > 0:
            tcp_open = QTreeWidgetItem(tcp_parent, ["Otevřené", str(port_stats['tcp']['open'])])
            tcp_open.setForeground(0, QColor("#2ECC71"))
        
        if port_stats['tcp']['filtered'] > 0:
            tcp_filtered = QTreeWidgetItem(tcp_parent, ["Filtrované", str(port_stats['tcp']['filtered'])])
            tcp_filtered.setForeground(0, QColor("#F39C12"))
        
        if port_stats['tcp']['open|filtered'] > 0:
            tcp_open_filtered = QTreeWidgetItem(tcp_parent, ["Otevřené/Filtrované", str(port_stats['tcp']['open|filtered'])])
            tcp_open_filtered.setForeground(0, QColor("#E67E22"))
        
        if port_stats['tcp']['closed'] > 0:
            tcp_closed = QTreeWidgetItem(tcp_parent, ["Zavřené", str(port_stats['tcp']['closed'])])
            tcp_closed.setForeground(0, QColor("#95A5A6"))
        
        # UDP souhrn
        udp_total = sum(port_stats['udp'].values())
        udp_parent = QTreeWidgetItem(ports_summary_parent, ["UDP", f"Celkem: {udp_total}"])
        udp_parent.setForeground(0, QColor("#9B59B6"))
        udp_parent.setExpanded(True)
        
        if port_stats['udp']['open'] > 0:
            udp_open = QTreeWidgetItem(udp_parent, ["Otevřené", str(port_stats['udp']['open'])])
            udp_open.setForeground(0, QColor("#2ECC71"))
        
        if port_stats['udp']['filtered'] > 0:
            udp_filtered = QTreeWidgetItem(udp_parent, ["Filtrované", str(port_stats['udp']['filtered'])])
            udp_filtered.setForeground(0, QColor("#F39C12"))
        
        if port_stats['udp']['open|filtered'] > 0:
            udp_open_filtered = QTreeWidgetItem(udp_parent, ["Otevřené/Filtrované", str(port_stats['udp']['open|filtered'])])
            udp_open_filtered.setForeground(0, QColor("#E67E22"))
        
        if port_stats['udp']['closed'] > 0:
            udp_closed = QTreeWidgetItem(udp_parent, ["Zavřené", str(port_stats['udp']['closed'])])
            udp_closed.setForeground(0, QColor("#95A5A6"))
        
        # Operační systém
        osscan_data = self.scan_results.get('osscan', {}).get(ip_address, {})
        if 'osmatch' in osscan_data and osscan_data['osmatch']:
            os_parent = QTreeWidgetItem(self.ip_summary_tree, ["OS", ""])
            os_parent.setForeground(0, QColor("#8E44AD"))
            os_parent.setExpanded(True)
            
            for idx, match in enumerate(osscan_data['osmatch'][:3]):  # Top 3
                os_name = match.get('name', 'Neznámý')
                accuracy = match.get('accuracy', 'N/A')
                os_child = QTreeWidgetItem(os_parent, [f"#{idx+1}", f"{os_name} ({accuracy}%)"])
                os_child.setForeground(1, QColor("#555555"))
        else:
            os_item = QTreeWidgetItem(self.ip_summary_tree, ["OS", "Nedostupný"])
            os_item.setForeground(0, QColor("#8E44AD"))
            os_item.setForeground(1, QColor("#999999"))
        
        # Služby a verze - shromáždit z TCP a UDP fází
        services = []
        
        for phase in ['tcp', 'udp']:
            phase_data = self.scan_results.get(phase, {}).get(ip_address, {})
            if phase in phase_data:
                for port, info in phase_data[phase].items():
                    port_state = info.get('state', 'unknown')
                    
                    # Zobrazit otevřené i filtrované porty (ale ne closed)
                    if port_state in ['open', 'filtered', 'open|filtered']:
                        service_name = info.get('name', 'unknown')
                        service_version = info.get('version', '')
                        service_product = info.get('product', '')
                        
                        # Pouze pokud existuje nějaká služba (ne "unknown")
                        if service_name != 'unknown' or service_product or service_version:
                            # Sestavit popis služby
                            service_desc = service_name
                            if service_product:
                                service_desc = f"{service_product}"
                            if service_version:
                                service_desc += f" {service_version}"
                            
                            services.append({
                                'port': port,
                                'protocol': phase.upper(),
                                'service': service_desc,
                                'state': port_state
                            })
        
        # Přidat služby do tree
        if services:
            services_parent = QTreeWidgetItem(self.ip_summary_tree, ["Služby", f"({len(services)} portů se službami)"])
            services_parent.setForeground(0, QColor("#E67E22"))
            services_parent.setExpanded(True)
            
            # Seřadit podle portu
            services.sort(key=lambda x: int(x['port']))
            
            for svc in services:
                port_label = f"{svc['port']}/{svc['protocol']} ({svc['state']})"
                svc_child = QTreeWidgetItem(services_parent, [port_label, svc['service']])
                
                # Barevné rozlišení podle stavu
                if svc['state'] == 'open':
                    svc_child.setForeground(0, QColor("#16A085"))
                elif svc['state'] == 'filtered':
                    svc_child.setForeground(0, QColor("#F39C12"))
                else:
                    svc_child.setForeground(0, QColor("#95A5A6"))
                
                svc_child.setForeground(1, QColor("#555555"))
        else:
            services_item = QTreeWidgetItem(self.ip_summary_tree, ["Služby", "Žádné služby nenalezeny"])
            services_item.setForeground(0, QColor("#E67E22"))
            services_item.setForeground(1, QColor("#999999"))

        # Webový server (IIS/Apache/nginx) — z aktivní detekce, jinak pasivně z nmap -sV.
        ws_active = (self.scan_results.get('webserver', {}) or {}).get(ip_address, {}) or {}
        ws_rows = []  # (port, family, detail)
        if ws_active:
            for port, info in sorted(ws_active.items(),
                                     key=lambda kv: int(kv[0]) if str(kv[0]).isdigit() else 0):
                fam = info.get('family', 'neznámý')
                detail = (info.get('detail') or info.get('server') or '').strip()
                if info.get('error') and fam == 'neznámý':
                    ws_rows.append((str(port), 'nedostupný', str(info.get('error', ''))[:60]))
                else:
                    ws_rows.append((str(port), fam, detail))
        else:
            for pnum, scheme, product in self._web_ports_for(ip_address):
                fam, detail, _src = detect_server('', '', product)
                if fam != 'neznámý' or product:
                    ws_rows.append((str(pnum), fam, detail or product))

        if ws_rows:
            ws_parent = QTreeWidgetItem(self.ip_summary_tree, ["Webový server", f"({len(ws_rows)})"])
            ws_parent.setForeground(0, QColor("#2980B9"))
            ws_parent.setForeground(1, QColor("#2980B9"))
            ws_parent.setExpanded(True)
            for port, fam, detail in ws_rows:
                txt = fam if (not detail or detail.lower() == fam.lower()) else f"{fam} — {detail}"
                row = QTreeWidgetItem(ws_parent, [f"Port {port}", txt])
                row.setForeground(0, QColor("#34495E"))
                row.setForeground(1, QColor("#95A5A6") if fam in ('neznámý', 'nedostupný') else QColor("#2C3E50"))
        elif self._web_ports_for(ip_address):
            ws_item = QTreeWidgetItem(
                self.ip_summary_tree,
                ["Webový server", "nezjištěn — pravý klik na cíl → Detekovat web server"])
            ws_item.setForeground(0, QColor("#2980B9"))
            ws_item.setForeground(1, QColor("#95A5A6"))

        # Zranitelnosti - shromáždit z fáze vuln - POUZE POTVRZENÉ
        # (klasifikace sjednocena do core.vuln_classify, ať souhlasí s vuln záložkou).
        vulnerabilities = []
        vuln_data = self.scan_results.get('vuln', {}).get(ip_address, {})

        for proto in ['tcp', 'udp']:
            if proto in vuln_data:
                for port, info in vuln_data[proto].items():
                    if 'script' in info:
                        for script_name, script_output in info['script'].items():
                            # Přidat pouze potvrzené zranitelnosti (ne chyby/čisté výstupy).
                            if classify_vuln_output(script_output) == "finding":
                                vuln_entry = {
                                    'port': port,
                                    'protocol': proto.upper(),
                                    'service': info.get('name', 'unknown'),
                                    'script': script_name,
                                    'details': script_output.strip()
                                }
                                vulnerabilities.append(vuln_entry)
        
        # Přidat zranitelnosti do tree
        if vulnerabilities:
            vuln_parent = QTreeWidgetItem(self.ip_summary_tree, ["Zranitelnosti", f"({len(vulnerabilities)} potvrzeno)"])
            vuln_parent.setForeground(0, QColor("#E74C3C"))
            vuln_parent.setForeground(1, QColor("#E74C3C"))
            vuln_parent.setExpanded(True)
            
            for idx, vuln in enumerate(vulnerabilities):
                # Hlavní položka zranitelnosti
                vuln_label = f"Port {vuln['port']}/{vuln['protocol']}"
                vuln_item = QTreeWidgetItem(vuln_parent, [vuln_label, vuln['service']])
                vuln_item.setForeground(0, QColor("#C0392B"))
                vuln_item.setForeground(1, QColor("#555555"))
                vuln_item.setExpanded(True)
                
                # Název skriptu
                script_item = QTreeWidgetItem(vuln_item, ["Skript", vuln['script']])
                script_item.setForeground(0, QColor("#95A5A6"))
                script_item.setForeground(1, QColor("#7F8C8D"))
                
                # Detaily zranitelnosti - rozdělit na řádky pro lepší čitelnost
                details_lines = vuln['details'].split('\n')
                if len(details_lines) > 5:
                    # Zobrazit pouze prvních 5 řádků a přidat "..." pro delší výstupy
                    display_text = '\n'.join(details_lines[:5]) + "\n..."
                else:
                    display_text = vuln['details']
                
                details_item = QTreeWidgetItem(vuln_item, ["Detaily", display_text[:500]])  # Limit 500 znaků
                details_item.setForeground(0, QColor("#95A5A6"))
                details_item.setForeground(1, QColor("#555555"))
        else:
            vuln_item = QTreeWidgetItem(self.ip_summary_tree, ["Zranitelnosti", "Žádné potvrzené nenalezeny"])
            vuln_item.setForeground(0, QColor("#E74C3C"))
            vuln_item.setForeground(1, QColor("#2ECC71"))
        
        # Screenshoty
        if ip_address in self.screenshots:
            screenshot_parent = QTreeWidgetItem(self.ip_summary_tree, ["Screenshots", f"({len(self.screenshots[ip_address])} nalezeno)"])
            screenshot_parent.setForeground(0, QColor("#1ABC9C"))
            screenshot_parent.setExpanded(True)
            
            for filepath in self.screenshots[ip_address]:
                filename = os.path.basename(filepath)
                screenshot_item = QTreeWidgetItem(screenshot_parent, ["", filename])
                screenshot_item.setForeground(1, QColor("#555555"))
        else:
            screenshot_item = QTreeWidgetItem(self.ip_summary_tree, ["Screenshots", "Žádné nenalezeny"])
            screenshot_item.setForeground(0, QColor("#1ABC9C"))
            screenshot_item.setForeground(1, QColor("#999999"))
            
        # Na konci funkce - přizpůsobit šířku sloupců
        self.ip_summary_tree.resizeColumnToContents(0)
        self.ip_summary_tree.resizeColumnToContents(1)
        
        # Rozšířit sloupce pokud jsou příliš úzké
        min_width_attr = self.ip_summary_tree.fontMetrics().horizontalAdvance("Atribut") + 30
        min_width_value = self.ip_summary_tree.fontMetrics().horizontalAdvance("Hodnota") + 30
        
        if self.ip_summary_tree.columnWidth(0) < min_width_attr:
            self.ip_summary_tree.setColumnWidth(0, min_width_attr)
        if self.ip_summary_tree.columnWidth(1) < min_width_value:
            self.ip_summary_tree.setColumnWidth(1, min_width_value)
            
    def on_matrix_selection_changed(self, current, previous):
        """
        Reaguje na změnu výběru v matici (např. šipkami nahoru/dolů).
        Volá se i při kliknutí, ale v tom případě se data aktualizují dvakrát
        (jednou z itemClicked, podruhé z currentItemChanged), což je v pořádku.
        """
        if not current:
            return
        
        # Získat IP adresu z aktuální položky
        ip_address = current.text(0)
        
        # Zavolat stejnou logiku jako při kliknutí
        # ale použít column=0 jako defaultní hodnotu
        self.on_matrix_ip_clicked(current, 0)

    def update_port_summary(self):
        """Aktualizuje přehled portů podle stavů s počtem IP adres."""
        # Struktura: {stav: {port_key: set(ips)}}
        port_data = {}
        
        for phase in ['tcp', 'udp']:
            if phase not in self.scan_results:
                continue
            
            for target, data in self.scan_results[phase].items():
                if phase in data:
                    for port, info in data[phase].items():
                        port_state = info.get('state', 'unknown')
                        port_key = f"{port}/{phase.upper()}"
                        
                        if port_state not in port_data:
                            port_data[port_state] = {}
                        
                        if port_key not in port_data[port_state]:
                            port_data[port_state][port_key] = set()
                        
                        port_data[port_state][port_key].add(target)
        
        self.port_summary_tree.clear()
        
        # Barvy podle stavů
        state_colors = {
            'open': QColor("#2ECC71"),
            'closed': QColor("#E74C3C"),
            'filtered': QColor("#F39C12"),
            'unfiltered': QColor("#FFB74D"),
            'open|filtered': QColor("#FFD54F"),
            'closed|filtered': QColor("#E57373"),
            'unknown': QColor("#9E9E9E")
        }
        
        # Vytvořit skupiny podle stavů
        sorted_states = sorted(port_data.keys())
        for state in sorted_states:
            
            # Seskupit podle protokolu (TCP, UDP)
            sorted_ports = sorted(port_data[state].items(), 
                                key=lambda x: (x[0].split('/')[1], int(x[0].split('/')[0])))
            
            protocol_groups = {'TCP': [], 'UDP': []}
            for port_key, ip_set in sorted_ports:
                port, proto = port_key.split('/')
                protocol_groups[proto].append((port, ip_set))
            
            # Hlavní položka pro stav
            # Spočítat celkový počet různých portů a celkový počet výskytů
            total_unique_ports = len(port_data[state])
            total_occurrences = sum(len(ip_set) for ip_set in port_data[state].values())
            
            state_label = f"{state.upper()} - {total_unique_ports} portů ({total_occurrences}×)"
            state_item = QTreeWidgetItem(self.port_summary_tree, [state_label, ""])
            state_item.setForeground(0, state_colors.get(state, QColor("black")))
            state_item.setExpanded(True)
            
            for proto in ['TCP', 'UDP']:
                if not protocol_groups[proto]:
                    continue
                
                # Spočítat pro skupinu TCP/UDP
                proto_unique_ports = len(protocol_groups[proto])
                proto_occurrences = sum(len(ip_set) for _, ip_set in protocol_groups[proto])
                
                proto_label = f"{proto} - {proto_unique_ports} portů ({proto_occurrences}×)"
                proto_item = QTreeWidgetItem(state_item, [proto_label, ""])
                proto_item.setExpanded(True)
                
                for port, ip_set in protocol_groups[proto]:
                    port_item = QTreeWidgetItem(proto_item, [f"  {port}", str(len(ip_set))])
                    port_item.setForeground(0, state_colors.get(state, QColor("black")))
                    port_item.setData(0, Qt.UserRole, {'port': f"{port}/{proto}", 'state': state, 'ips': list(ip_set)})
        
        # Automaticky přizpůsobit šířku sloupců podle obsahu
        self.port_summary_tree.resizeColumnToContents(0)
        self.port_summary_tree.resizeColumnToContents(1)
        
        # Rozšířit sloupec "Počet IP" aby se vešel nadpis
        min_width = self.port_summary_tree.fontMetrics().horizontalAdvance("Počet IP") + 20
        if self.port_summary_tree.columnWidth(1) < min_width:
            self.port_summary_tree.setColumnWidth(1, min_width)

    def show_port_context_menu(self, position):
        """Zobrazí kontextové menu pro port summary."""
        from PySide6.QtWidgets import QMenu
        from PySide6.QtGui import QAction
        
        item = self.port_summary_tree.itemAt(position)
        if not item:
            return
        
        # Zkontrolovat, zda má položka data (port detail)
        port_data = item.data(0, Qt.UserRole)
        if not port_data:
            return
        
        menu = QMenu()
        
        show_ips_action = QAction("Zobrazit IP adresy", self)
        show_ips_action.triggered.connect(lambda: self.show_ips_for_port(port_data))
        menu.addAction(show_ips_action)
        
        menu.exec(self.port_summary_tree.mapToGlobal(position))

    def show_ips_for_port(self, port_data):
        """Zobrazí dialog se seznamem IP adres pro daný port."""
        port = port_data['port']
        state = port_data['state']
        ips = port_data['ips']
        
        dialog = QDialog(self)
        dialog.setWindowTitle(f"IP adresy s portem {port} ({state})")
        dialog.resize(400, 300)
        
        layout = QVBoxLayout(dialog)
        
        label = QLabel(f"Port: {port}\nStav: {state}\nPočet IP adres: {len(ips)}")
        layout.addWidget(label)
        
        ip_list = QTextEdit()
        ip_list.setReadOnly(True)
        ip_list.setPlainText('\n'.join(sorted(ips, key=lambda ip: tuple(int(p) for p in ip.split('.')))))
        layout.addWidget(ip_list)
        
        button_box = QDialogButtonBox(QDialogButtonBox.Ok)
        button_box.accepted.connect(dialog.accept)
        layout.addWidget(button_box)
        
        dialog.exec()

    def _ensure_project_folder(self):
        """Vrátí ProjectPaths aktuálního projektu. Pokud žádný projekt není
        otevřený, založí novou projektovou složku pod výchozí základní složkou
        (fallback dle nastavení 'default_projects_dir', default ~/NmapScannerProjects).
        Veškerá data skenu se ukládají dovnitř této složky."""
        if self.current_project_path:
            paths = ProjectPaths.from_project_file(self.current_project_path)
            paths.ensure()
            return paths

        base_dir = self.settings.value("default_projects_dir", default_projects_dir())
        name = f"{safe_name(self.project_name_edit.text())}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        paths = ProjectPaths.create(base_dir, name)
        self.current_project_path = str(paths.project_file)
        self.worker_signals.log.emit("info", f"🔄 Vytvořena projektová složka: {paths.root}")
        return paths

    # ====================== SUDO HESLO (jen v RAM) ======================
    def _ensure_sudo(self):
        """Zajistí, že nmap půjde spustit s root právy. Vrací True, lze-li pokračovat.

        Pořadí: už root? → sudo bez hesla (NOPASSWD/cache)? → dříve zadané platné
        heslo? → zeptat se v dialogu (max 3 pokusy). Heslo se nikdy neukládá na
        disk, drží se jen jako mazatelná bytearray v RAM.
        """
        # 1) Už běžíme jako root → sudo netřeba.
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self._use_sudo = False
            return True
        self._use_sudo = True
        # 2) sudo bez hesla (NOPASSWD nebo platná cache)?
        try:
            r = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=5)
            if r.returncode == 0 and self._sudo_pw is None:
                return True
        except Exception:
            pass
        # 3) Už máme platné heslo z dřívějška?
        if self._sudo_pw is not None and self._sudo_validate(self._sudo_pw):
            return True
        # 4) Zeptat se (max 3 pokusy).
        for _ in range(3):
            pw = self._ask_sudo_password()
            if pw is None:
                return False  # zrušeno uživatelem
            if self._sudo_validate(pw):
                self._set_sudo_password(pw)
                return True
            # špatné heslo → vynulovat pokus a zkusit znovu
            self._wipe(pw)
            QMessageBox.warning(self, "Sudo", "Špatné heslo. Zkus to prosím znovu.")
        return False

    def _ask_sudo_password(self):
        """Modální dialog na sudo heslo. Vrací bytearray nebo None (zrušeno)."""
        text, ok = QInputDialog.getText(
            self, "Sudo heslo",
            "Nmap potřebuje root oprávnění (SYN/UDP/OS sken).\n"
            "Zadej sudo heslo — neukládá se na disk, drží se jen v paměti:",
            QLineEdit.Password)
        if not ok:
            return None
        # Z Qt přijde nemazatelný str; co nejdřív převedeme na mazatelnou bytearray.
        return bytearray(text, "utf-8")

    def _sudo_validate(self, pw_bytes):
        """Ověří heslo přes `sudo -S -v` (heslo jde na stdin, ne do `ps`)."""
        try:
            r = subprocess.run(["sudo", "-S", "-p", "", "-v"],
                               input=bytes(pw_bytes) + b"\n",
                               capture_output=True, timeout=10)
            return r.returncode == 0
        except Exception:
            return False

    def _set_sudo_password(self, pw_bytes):
        self._clear_sudo_password()
        self._sudo_pw = pw_bytes

    @staticmethod
    def _wipe(ba):
        """Přepíše bytearray nulami (nejlepší možné smazání z RAM v CPythonu)."""
        if isinstance(ba, bytearray):
            for i in range(len(ba)):
                ba[i] = 0

    def _clear_sudo_password(self):
        """Bezpečně zapomene sudo heslo (vynuluje buffer a zahodí referenci)."""
        self._wipe(self._sudo_pw)
        self._sudo_pw = None
        # zneukazovat heslo manažeru po vymazání
        if hasattr(self, "scan_manager"):
            self.scan_manager.sudo_password = None

    @Slot()
    def forget_sudo_password(self):
        if self.scan_manager.is_running:
            QMessageBox.information(self, "Sudo", "Nelze zapomenout heslo během skenování.")
            return
        had = self._sudo_pw is not None
        self._clear_sudo_password()
        self.status_label.setText("Sudo heslo zapomenuto." if had else "Žádné sudo heslo není uložené.")

    # ====================== BĚHY / VERZE ======================
    def _parse_active_targets(self):
        cleaned_text = self.cleaned_output_text.toPlainText()
        return [line.strip() for line in cleaned_text.splitlines()
                if line.strip() and not line.strip().startswith('#')]

    def start_new_run(self):
        """Spustí NOVÝ běh (verzi). Předchozí běhy/verze zůstávají zachované."""
        if self.scan_manager.is_running:
            self.status_label.setText("Sken už běží.")
            return
        targets = self._parse_active_targets()
        if not targets:
            self.status_label.setText("Žádné cíle k testování (zakomentované nebo prázdné).")
            return
        profile = self.profile_combo.currentData() or "master"
        custom_command = self.custom_command_edit.text().strip()
        if profile == "custom" and not custom_command:
            self.status_label.setText("Zadej vlastní nmap příkaz (s {target}).")
            return
        enabled_phases = {phase: cb.isChecked() for phase, cb in self.phase_checkboxes.items()}
        if profile != "custom" and not any(enabled_phases.values()):
            self.status_label.setText("Není povolena žádná fáze.")
            return

        # Root oprávnění pro nmap (případně dialog na sudo heslo) — před změnami stavu.
        if not self._ensure_sudo():
            self.status_label.setText("Sken zrušen — bez root oprávnění (sudo) nelze skenovat.")
            return

        # Uložit dosavadní aktivní verzi (ať o ni nepřijdeme) a doplnit master cíle.
        self._persist_active_snapshot()
        self.run_history.merge_master_targets(targets)

        timestamp = time.strftime("%Y%m%d-%H%M%S")
        run_id = run_id_from_timestamp(timestamp)
        run = ScanRun(run_id, label=self.run_history.next_label(),
                      created_at=datetime.now().isoformat(timespec="seconds"),
                      profile=profile, custom_command=custom_command,
                      targets=targets, enabled_phases=enabled_phases)
        self.run_history.add_run(run)
        run.add_event(run.created_at, "vytvořeno",
                      f"{len(targets)} cílů, profil {sp.PROFILE_LABELS.get(profile, profile)}")
        self.viewing_run_id = run_id

        # Čistá data pro nový běh (verzi)
        self.scan_results = {p: {} for p in self.phases}
        self.scan_results['certificates'] = {}
        self._begin_run_ui(targets, profile, enabled_phases)

        paths = self._ensure_project_folder()
        self.base_export_path = paths.run_dir(run_id)
        self.worker_signals.log.emit("info", f"🆕 Nový běh '{run.label}' → {self.base_export_path}")

        self._stop_requested = False
        self._lock_run_ui()
        self.refresh_runs_combo()
        self.status_label.setText(f"Skenuji '{run.label}' — {len(targets)} cílů…")
        # Předat sudo kontext manažeru (queued emit zajistí viditelnost ve vlákně manažeru).
        self.scan_manager.sudo_password = self._sudo_pw
        self.scan_manager.use_sudo = self._use_sudo
        self.start_scan_requested.emit(targets, profile, enabled_phases, custom_command, False, {})

    def resume_run(self):
        """Naváže na aktivní (nedokončený) běh — doskenuje chyby a nedoběhlé fáze."""
        if self.scan_manager.is_running:
            return
        run = self.run_history.active()
        if run is None:
            self.status_label.setText("Není žádný běh k navázání.")
            return
        if self.viewing_run_id != run.id:
            self._switch_view(run.id)
        if run.profile == "custom":
            self.status_label.setText("Vlastní příkaz nelze navazovat — spusť nový běh.")
            return
        if not run.is_incomplete():
            self.status_label.setText("Tento běh je kompletní — není co navazovat.")
            return

        if not self._ensure_sudo():
            self.status_label.setText("Navázání zrušeno — bez root oprávnění (sudo) nelze skenovat.")
            return

        ctx = self._build_resume_ctx(run)
        run.status = "running"
        run.add_event(datetime.now().isoformat(timespec="seconds"), "navázáno",
                      "doskenování chyb a nedoběhlých")

        self.log_console.clear()
        self.live_task_panel.reset()
        self.phase_progress_bars.reset(self.phases, run.enabled_phases)
        if hasattr(self, 'tabs'):
            self.tabs.setCurrentWidget(self.live_task_panel)
        self.status_label.setText(f"Navazuji na běh '{run.label}'…")

        paths = self._ensure_project_folder()
        self.base_export_path = paths.run_dir(run.id)
        self.worker_signals.log.emit("info", f"▶️ Navazuji na běh '{run.label}'…")

        self._stop_requested = False
        self._lock_run_ui()
        self.refresh_runs_combo()
        self.scan_manager.sudo_password = self._sudo_pw
        self.scan_manager.use_sudo = self._use_sudo
        self.start_scan_requested.emit(run.targets, run.profile, run.enabled_phases,
                                       run.custom_command, True, ctx)

    def _begin_run_ui(self, targets, profile, enabled_phases):
        """Společný UI reset pro start NOVÉHO běhu (matice, progress, panel)."""
        self.log_console.clear()
        for tree in self.tree_widgets.values():
            tree.clear()
        self.status_matrix.populate_targets(targets)
        self.live_task_panel.reset()
        if profile == "custom":
            self.phase_progress_bars.reset(self.phases, {"tcp": True})
        else:
            self.phase_progress_bars.reset(self.phases, enabled_phases)
        for target in targets:
            for phase in self.phases:
                if profile == "custom":
                    self.status_matrix.update_status(target, phase, 'čeká' if phase == 'tcp' else 'přeskočeno')
                elif not enabled_phases[phase]:
                    self.status_matrix.update_status(target, phase, 'skipped_by_user')
        if hasattr(self, 'tabs') and hasattr(self, 'live_task_panel'):
            self.tabs.setCurrentWidget(self.live_task_panel)

    def _build_resume_ctx(self, run):
        """Sestaví kontext pro navázání: stavy fází + porty/needs_pn z dat běhu."""
        status = {t: dict(ph) for t, ph in run.phase_status.items()}
        open_ports, needs_pn = {}, {}
        for t, d in (self.scan_results.get("tcp", {}) or {}).items():
            ports = [int(p) for p, info in (d.get("tcp", {}) or {}).items()
                     if isinstance(info, dict) and info.get("state") == "open"]
            if ports:
                open_ports[t] = sorted(ports)
        for t, d in (self.scan_results.get("online", {}) or {}).items():
            st = d.get("status")
            if isinstance(st, dict) and st.get("state") == "down":
                needs_pn[t] = True
        return {"status": status, "open_ports": open_ports, "needs_pn": needs_pn}

    def on_stop_clicked(self):
        self._stop_requested = True
        self.scan_manager.stop_workflow()

    # ---- kontextový re-scan cíle (merge do aktuální verze + timeline) ----
    def _matrix_selected_targets(self, clicked_item):
        """Cíle, na které má kontextová akce platit. Pravý klik DOVNITŘ výběru →
        celý výběr; klik MIMO výběr → jen ten jeden řádek (standardní chování)."""
        items = list(self.status_matrix.selectedItems())
        if clicked_item is not None and clicked_item not in items:
            items = [clicked_item]
        targets = []
        for it in items:
            t = it.text(0).split(' ')[0].strip()
            if t and t not in targets:
                targets.append(t)
        return targets

    def on_matrix_context_menu(self, pos):
        item = self.status_matrix.itemAt(pos)
        if item is None:
            return
        targets = self._matrix_selected_targets(item)
        if not targets:
            return
        # Popisek: jeden cíl → jeho jméno; více → počet.
        sfx = targets[0] if len(targets) == 1 else f"{len(targets)} cílů"
        menu = QMenu(self)
        menu.addAction(f"🔁 Re-scan TCP — {sfx}", lambda: self.rescan_target(targets, ["tcp"]))
        menu.addAction(f"🔁 Re-scan UDP — {sfx}", lambda: self.rescan_target(targets, ["udp"]))
        menu.addAction(f"🔁 Re-scan Vuln — {sfx}", lambda: self.rescan_target(targets, ["vuln"]))
        menu.addAction(f"🔁 Re-scan OS — {sfx}", lambda: self.rescan_target(targets, ["osscan"]))
        menu.addSeparator()
        menu.addAction(f"🌐 Detekovat web server (IIS/Apache/nginx) — {sfx}",
                       lambda: self.detect_webserver(targets))
        menu.addAction(f"📸 Re-scan screenshoty (HTTP/HTTPS) — {sfx}",
                       lambda: self.rescan_screenshots(targets))
        menu.addAction(f"🔁 Re-scan vše (TCP+UDP+vuln+OS) — {sfx}",
                       lambda: self.rescan_target(targets, ["tcp", "udp", "osscan", "vuln"]))
        menu.exec(self.status_matrix.viewport().mapToGlobal(pos))

    def rescan_target(self, targets, phases):
        """Znovu proskenuje vybrané fáze daných cílů a výsledky vmerguje do AKTUÁLNÍ
        verze (běhu). Funguje pro jeden cíl i pro výběr více cílů (multiselect) —
        spustí se jako JEDEN běh nad všemi cíli. Událost se zapíše do timeline."""
        if isinstance(targets, str):
            targets = [targets]
        targets = [t for t in dict.fromkeys(targets) if t]  # unikátní, zachovat pořadí
        if not targets:
            return
        if self.scan_manager.is_running:
            self.status_label.setText("Sken už běží — počkej na dokončení.")
            return
        run = self.run_history.active()
        if run is None:
            self.status_label.setText("Nejdřív spusť běh (re-scan merguje do aktuální verze).")
            return
        if run.profile == "custom":
            self.status_label.setText("Re-scan není dostupný pro profil Vlastní příkaz.")
            return
        # Re-scan se vždy týká aktivní verze — případně na ni přepnout.
        if self.viewing_run_id != run.id:
            self._switch_view(run.id)
        if not self._ensure_sudo():
            self.status_label.setText("Re-scan zrušen — bez root oprávnění (sudo).")
            return

        for target in targets:
            if target not in run.targets:
                run.targets.append(target)
        self.run_history.merge_master_targets(targets)

        label = targets[0] if len(targets) == 1 else f"{len(targets)} cílů"
        when = datetime.now().isoformat(timespec="seconds")
        run.add_event(when, "re-scan", f"{label}: {', '.join(phases)} (merge)")
        run.status = "running"

        enabled_phases = {p: (p in phases) for p in self.phases}
        ctx = self._build_resume_ctx(run)  # seed open_ports/needs_pn z aktuálních dat

        # UI: nečistit data, jen reset progressu JEN re-scanovaných fází (ostatní
        # fáze si nechají svůj dosavadní průběh) + označit dotčené buňky matice.
        self.live_task_panel.reset()
        self.phase_progress_bars.reset_phases(phases)
        for target in targets:
            for phase in phases:
                self.status_matrix.update_status(target, phase, 'čeká')
        if hasattr(self, 'tabs'):
            self.tabs.setCurrentWidget(self.live_task_panel)

        paths = self._ensure_project_folder()
        self.base_export_path = paths.run_dir(run.id)
        self.worker_signals.log.emit("info", f"🔁 Re-scan {label}: {', '.join(phases)} → merge do '{run.label}'")
        self.status_label.setText(f"Re-scan {label} ({', '.join(phases)})…")

        self._stop_requested = False
        self._lock_run_ui()
        self.refresh_runs_combo()
        self.scan_manager.sudo_password = self._sudo_pw
        self.scan_manager.use_sudo = self._use_sudo
        self.start_scan_requested.emit(targets, run.profile, enabled_phases, run.custom_command, False, ctx)

    def rescan_screenshots(self, targets):
        """Znovu pořídí screenshoty HTTP/HTTPS portů daných cílů (z aktuálních dat).
        Funguje pro jeden cíl i pro výběr více cílů (multiselect)."""
        if isinstance(targets, str):
            targets = [targets]
        targets = [t for t in dict.fromkeys(targets) if t]
        if not targets:
            return
        run = self.run_history.active()
        common_web_ports = [80, 443, 8080, 8000, 8008, 8443]
        paths = self._ensure_project_folder()
        self.base_export_path = paths.run_dir(run.id) if run else paths.run_dir("rescan")

        total_ports = 0
        without_web = []
        for target in targets:
            tcp_data = (self.scan_results.get("tcp", {}) or {}).get(target, {}) or {}
            web_ports = []
            for port, info in (tcp_data.get("tcp", {}) or {}).items():
                if not isinstance(info, dict) or info.get("state") != "open":
                    continue
                name = (info.get("name") or "").lower()
                try:
                    pnum = int(port)
                except (TypeError, ValueError):
                    continue
                if pnum in common_web_ports or "http" in name:
                    scheme = "https" if ("https" in name or pnum in (443, 8443)) else "http"
                    web_ports.append((pnum, scheme))
            if not web_ports:
                without_web.append(target)
                continue
            # Zaregistrovat do průběhu (rozsvítí živý čítač) PŘED emitem requestů.
            self._register_screenshots(len(web_ports))
            for pnum, scheme in web_ports:
                url = f"{scheme}://{target}:{pnum}"
                ip_dir = self.base_export_path / target.replace('.', '_')
                # mkdir může na Ploše/iCloudu (macOS TCC) spadnout na EPERM — nepadat,
                # request stejně pošli; ScreenshotManager pak nahlásí reálnou chybu.
                try:
                    ip_dir.mkdir(exist_ok=True, parents=True)
                except OSError as e:
                    self.worker_signals.log.emit("error", f"⚠️ Nelze vytvořit složku {ip_dir}: {e}")
                self.worker_signals.screenshot_request.emit(url, target, pnum, str(ip_dir))
            total_ports += len(web_ports)
            if run is not None:
                run.add_event(datetime.now().isoformat(timespec="seconds"),
                              "re-scan screenshoty", f"{target}: {len(web_ports)} portů")

        if total_ports == 0:
            self.status_label.setText("Žádné webové (HTTP/HTTPS) porty pro screenshot u vybraných cílů.")
            return
        scope = targets[0] if len(targets) == 1 else f"{len(targets) - len(without_web)} cílů"
        self.worker_signals.log.emit(
            "info", f"📸 Re-scan screenshotů {scope}: {total_ports} portů ve frontě "
            "(probíhá sériově, sleduj průběh dole ve stavovém řádku).")

    # ---- detekce web serveru (IIS/Apache/nginx) ----------------------
    def _web_ports_for(self, target):
        """Vrátí webové porty cíle jako [(port, scheme, nmap_product)] z TCP dat."""
        tcp_data = (self.scan_results.get("tcp", {}) or {}).get(target, {}) or {}
        common_web_ports = [80, 443, 8080, 8000, 8008, 8443, 8081, 8888, 9443]
        out = []
        for port, info in (tcp_data.get("tcp", {}) or {}).items():
            if not isinstance(info, dict) or info.get("state") != "open":
                continue
            name = (info.get("name") or "").lower()
            try:
                pnum = int(port)
            except (TypeError, ValueError):
                continue
            if pnum in common_web_ports or "http" in name:
                scheme = "https" if ("https" in name or "ssl" in name or pnum in (443, 8443, 9443)) else "http"
                product = " ".join(x for x in [info.get("product", ""), info.get("version", "")] if x).strip()
                out.append((pnum, scheme, product))
        return out

    def detect_webserver(self, targets):
        """Kontextová akce: zjistí typ web serveru (IIS/Apache/nginx/…) z HTTP
        hlaviček (+ nmap) pro webové porty vybraných cílů. Výsledek se uloží do
        projektu (``scan_results['webserver']``) a ukáže v souhrnu IP."""
        if isinstance(targets, str):
            targets = [targets]
        targets = [t for t in dict.fromkeys(targets) if t]
        jobs = [(t, self._web_ports_for(t)) for t in targets]
        jobs = [(t, web) for t, web in jobs if web]
        if not jobs:
            self.status_label.setText("Vybrané cíle nemají otevřené webové porty (spusť nejdřív TCP sken).")
            return
        self._ws_pending = len(jobs)
        nports = sum(len(w) for _, w in jobs)
        scope = jobs[0][0] if len(jobs) == 1 else f"{len(jobs)} cílů"
        self.status_label.setText(f"🌐 Detekuji web server: {scope} ({nports} portů)…")
        self.worker_signals.log.emit("info", f"🌐 Detekce web serveru: {scope}, {nports} portů…")
        pool = QThreadPool.globalInstance()
        for t, web in jobs:
            pool.start(WebServerWorker(t, web, self.worker_signals))

    def on_webserver_result(self, ip, results):
        """Uloží detekci web serveru pro cíl a zaloguje souhrn; persistuje do projektu."""
        store = self.scan_results.setdefault("webserver", {})
        store[ip] = results
        parts = []
        for port, info in sorted(results.items(), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 0):
            fam = info.get("family", "neznámý")
            detail = (info.get("detail") or info.get("server") or "").strip()
            txt = fam if (not detail or detail.lower() == fam.lower()) else f"{fam} ({detail})"
            if info.get("error") and fam == "neznámý":
                txt = f"port {port}: nedostupný"
            else:
                txt = f"port {port}: {txt}"
            parts.append(txt)
        self.worker_signals.log.emit("info", f"🌐 {ip} → " + "; ".join(parts))

        self._ws_pending = getattr(self, "_ws_pending", 1) - 1
        if self._ws_pending <= 0:
            self.status_label.setText("🌐 Detekce web serveru hotová.")

        # Když je tenhle cíl právě zobrazený v souhrnu IP, překreslit (ukáže web server).
        if getattr(self, "_summary_ip", None) == ip:
            self.on_matrix_ip_clicked(self.status_matrix.ip_items.get(ip), 0)
        # Uložit do projektu (je-li otevřený a neběží sken).
        self._autosave_after_audit()

    # ---- přepínač / ovládání běhů ------------------------------------
    def refresh_runs_combo(self):
        cz = {"running": "běží", "completed": "dokončeno", "aborted": "zastaveno"}
        self.run_combo.blockSignals(True)
        self.run_combo.clear()
        for r in self.run_history.runs:
            mark = "● " if r.id == self.run_history.active_run_id else "○ "
            self.run_combo.addItem(f"{mark}{r.label} [{cz.get(r.status, r.status)}]", r.id)
        idx = self.run_combo.findData(self.viewing_run_id)
        if idx >= 0:
            self.run_combo.setCurrentIndex(idx)
        self.run_combo.blockSignals(False)
        self._update_run_controls()
        self._update_project_path_label()

    def _update_project_path_label(self):
        if not hasattr(self, "project_path_label"):
            return
        if self.current_project_path:
            self.project_path_label.setText(f"📁 {self.current_project_path}")
            self.project_path_label.setToolTip(self.current_project_path)
        else:
            self.project_path_label.setText("📁 Projekt zatím neuložen (založí se při spuštění skenu)")
            self.project_path_label.setToolTip("")

    def _update_run_controls(self):
        running = self.scan_manager.is_running
        active = self.run_history.active()
        viewing_active = active is not None and self.viewing_run_id == active.id
        can_resume = (viewing_active and not running and active.profile != "custom"
                      and active.is_incomplete())
        self.resume_button.setEnabled(can_resume)
        self.run_combo.setEnabled(not running and len(self.run_history.runs) > 0)
        self.diff_button.setEnabled(not running and len(self.run_history.runs) >= 2)
        self.manage_runs_button.setEnabled(not running and len(self.run_history.runs) > 0)
        if hasattr(self, 'switch_project_btn'):
            self.switch_project_btn.setEnabled(not running)
        viewed = self.run_history.get(self.viewing_run_id)
        if viewed is None:
            self.run_status_label.setText("")
        elif self.viewing_run_id == self.run_history.active_run_id:
            self.run_status_label.setText("(aktivní)")
        else:
            self.run_status_label.setText("(verze – jen čtení)")

    def _lock_run_ui(self):
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.run_combo.setEnabled(False)
        self.resume_button.setEnabled(False)
        self.diff_button.setEnabled(False)
        self.manage_runs_button.setEnabled(False)
        if hasattr(self, 'switch_project_btn'):
            self.switch_project_btn.setEnabled(False)

    def _on_run_combo_changed(self):
        if self.scan_manager.is_running:
            return
        run_id = self.run_combo.currentData()
        if run_id and run_id != self.viewing_run_id:
            self._switch_view(run_id)

    def _switch_view(self, run_id):
        """Přepne zobrazenou verzi (uloží dosavadní aktivní, načte vybranou)."""
        if self.scan_manager.is_running:
            return
        if self.viewing_run_id == self.run_history.active_run_id:
            self._persist_active_snapshot()
        run = self.run_history.get(run_id)
        if run is None:
            return
        self.scan_results = self._load_snapshot(run)
        if 'certificates' not in self.scan_results:
            self.scan_results['certificates'] = {}
        self.viewing_run_id = run_id
        self._display_run(run)
        self.refresh_runs_combo()
        self.status_label.setText(f"Zobrazena verze: {run.label}")

    def _display_run(self, run):
        """Vykreslí data daného běhu do matice, stromů a souhrnů."""
        self.loading_project = True
        for tree in self.tree_widgets.values():
            tree.clear()
        targets = run.targets if run and run.targets else rh.targets_from_snapshot(self.scan_results)
        self.status_matrix.populate_targets(targets)
        # final=False: jen naplnit stromy/porty z uložených dat, ale NEoznačovat
        # buňky matice jako „hotovo" podle přítomnosti dat. Stav buněk pak nastaví
        # autoritativně _apply_run_status_to_matrix podle skutečného stavu fází
        # (přerušená fáze, např. zastavené UDP, tak nezůstane jako „hotovo").
        for phase in self.phases:
            for target, data in (self.scan_results.get(phase, {}) or {}).items():
                self.handle_single_result(phase, target, data, final=False)
        self._apply_run_status_to_matrix(run)
        self._apply_run_progress(run)
        self.loading_project = False
        if hasattr(self, "port_summary_tree"):
            self.update_port_summary()
            self.update_service_summary()
            self.update_online_display_with_ports()

    def _apply_run_progress(self, run):
        """Obnoví progress bary fází z uloženého stavu běhu (i u načteného projektu)."""
        if run is None:
            return
        self.phase_progress_bars.reset(self.phases, run.enabled_phases)
        for phase in self.phases:
            if not run.enabled_phases.get(phase, True):
                continue
            total = len(run.targets)
            done = sum(1 for t in run.targets
                       if run.get_status(t, phase) in rh.SUCCESS_STATUSES)
            self.phase_progress_bars.update(phase, done, total)

    def _apply_run_status_to_matrix(self, run):
        if run is None:
            return
        for target in run.targets:
            for phase in self.phases:
                st = run.get_status(target, phase)
                if st:
                    self.status_matrix.update_status(target, phase, st)
                elif not run.enabled_phases.get(phase, True):
                    self.status_matrix.update_status(target, phase, 'skipped_by_user')

    # ---- snapshoty verzí na disku ------------------------------------
    def _persist_active_snapshot(self, raise_on_error=False):
        """Uloží data AKTIVNÍ verze atomicky do results/<run_id>/data.json (v4).
        ``raise_on_error`` přepošle výjimku volajícímu (autosave ji řeší centrálně)."""
        active = self.run_history.active()
        if active is None or self.viewing_run_id != active.id:
            return
        if not self.current_project_path:
            import copy
            self._pending_snapshots[active.id] = copy.deepcopy(self.scan_results)
            return
        try:
            paths = ProjectPaths.from_project_file(self.current_project_path)
            pstore.save_run_data(paths.run_data_file(active.id), active.id, self.scan_results)
            self._pending_snapshots.pop(active.id, None)
        except Exception as e:
            if raise_on_error:
                raise
            self.worker_signals.log.emit("error", f"⚠️ Uložení dat verze selhalo: {e}")

    def _load_snapshot(self, run):
        if run is None:
            return {p: {} for p in self.phases}
        if run.id in self._pending_snapshots:
            import copy
            return copy.deepcopy(self._pending_snapshots[run.id])
        if self.current_project_path:
            try:
                paths = ProjectPaths.from_project_file(self.current_project_path)
                data = pstore.load_run_data(paths.run_data_file(run.id),
                                            snapshot_fallback=paths.run_snapshot(run.id))
                if data:
                    return data
            except Exception as e:
                self.worker_signals.log.emit("error", f"⚠️ Načtení dat verze selhalo: {e}")
        return {p: {} for p in self.phases}

    def _delete_run_files(self, run):
        if not self.current_project_path:
            self._pending_snapshots.pop(run.id, None)
            return
        try:
            import shutil
            root = ProjectPaths.from_project_file(self.current_project_path).root
            rundir = root / "results" / run.id
            if rundir.exists():
                shutil.rmtree(rundir, ignore_errors=True)
        except Exception as e:
            self.worker_signals.log.emit("error", f"⚠️ Smazání souborů verze selhalo: {e}")
        self._pending_snapshots.pop(run.id, None)

    # ---- dialogy běhů / verzí ----------------------------------------
    def open_diff_dialog(self):
        if len(self.run_history.runs) < 2:
            QMessageBox.information(self, "Porovnání verzí",
                                    "K porovnání jsou potřeba alespoň dvě verze (běhy).")
            return
        self._persist_active_snapshot()
        DiffDialog(self.run_history.runs, self._load_snapshot, parent=self).exec()

    def open_runs_manager(self):
        if not self.run_history.runs:
            QMessageBox.information(self, "Správa běhů", "Projekt zatím nemá žádný běh.")
            return
        self._persist_active_snapshot()
        dlg = RunsManagerDialog(self.run_history, self._load_snapshot,
                                delete_files=self._delete_run_files, parent=self)
        dlg.exec()
        if dlg.selected_view_run_id:
            self._switch_view(dlg.selected_view_run_id)
        else:
            self.refresh_runs_combo()
        if self.current_project_path:
            self.auto_save_project()

    def switch_project(self):
        if self.scan_manager.is_running:
            QMessageBox.warning(self, "Nelze přepnout", "Nejdřív zastav skenování.")
            return
        if self.current_project_path:
            self.auto_save_project()
        recent = self.settings.value("recent_projects", [])
        if not isinstance(recent, list):
            recent = []
        dlg = StartupDialog(recent_projects=recent, parent=self)
        if dlg.exec() == QDialog.Accepted:
            if dlg.choice == "import":
                self.import_project_dialog()
            elif dlg.choice == "new":
                self._reset_to_empty_project()
            elif dlg.choice and os.path.exists(dlg.choice):
                self.import_project(dlg.choice)

    def _reset_to_empty_project(self):
        self.current_project_path = None
        self.run_history = RunHistory()
        self.viewing_run_id = None
        self._pending_snapshots = {}
        self.scan_results = {p: {} for p in self.phases}
        self.scan_results['certificates'] = {}
        for tree in self.tree_widgets.values():
            tree.clear()
        self.status_matrix.populate_targets([])
        self.refresh_runs_combo()
        self.status_label.setText("Nový prázdný projekt.")

    def export_project_dialog(self):
        """Uloží projekt do vlastní projektové složky. Uživatel vybere nadřazenou
        složku (výchozí = nastavená základní složka), uvnitř ní vznikne složka
        pojmenovaná podle projektu s podsložkami results/screenshots/reports a
        stavovým souborem project.nmapproj. Povoleno jen, když neběží testování."""
        if self.scan_manager.is_running:
            QMessageBox.warning(self, "Uložení nelze", "Uložení není možné během probíhajícího testování.")
            return

        base_dir = self.settings.value("default_projects_dir", default_projects_dir())
        os.makedirs(base_dir, exist_ok=True)
        parent = QFileDialog.getExistingDirectory(self, "Vyberte nadřazenou složku pro projekt", base_dir)
        if not parent:
            return

        # Uložit aktivní snapshot do STÁVAJÍCÍ složky, ať je co kopírovat.
        # (Když je stará složka jen pro čtení, snapshot je v paměti / pending.)
        self._persist_active_snapshot()

        try:
            # Vytvořit cílovou složku (může selhat, když je i nové místo jen pro čtení).
            paths = ProjectPaths.create(parent, self.project_name_edit.text())
            # Zapamatovat zvolenou základní složku pro příště (konfigurovatelný default).
            self.settings.setValue("default_projects_dir", parent)

            # Zkopírovat data všech verzí (běhů) do nové složky (v4 data.json).
            for run in self.run_history.runs:
                snap = self._load_snapshot(run)
                if snap and (any(snap.get(ph) for ph in rh.NMAP_PHASES)
                             or snap.get("certificates") or snap.get("tls_audit")):
                    pstore.save_run_data(paths.run_data_file(run.id), run.id, snap)

            # Přepnout na novou složku a uložit metadata (atomicky, v4).
            self.current_project_path = str(paths.project_file)
            self._pending_snapshots = {}
            pstore.save_project_file(self.current_project_path, self._project_meta(),
                                     self.run_history,
                                     datetime.now().isoformat(timespec="seconds"))

            self._autosave_blocked = None  # nové místo je zapisovatelné → autosave zase OK
            self.add_to_recent_projects(self.current_project_path)
            self.settings.setValue("last_project_path", self.current_project_path)
            self._update_project_path_label()
            self.status_label.setText(f"Projekt uložen do {paths.root}")
            self.worker_signals.log.emit("export", f"Projekt úspěšně uložen do složky {paths.root}.")
        except Exception as e:
            QMessageBox.critical(
                self, "Chyba uložení",
                f"Nelze uložit projekt do vybraného místa:\n{e}\n\n"
                "Vyber prosím složku, kam lze zapisovat (ne Plocha/iCloud) — "
                "např. ~/NmapScannerProjects nebo ~/Documents.")

    def import_project_dialog(self):
        """Import projektu ze souboru JSON (.nmapproj). Povoleno jen, když neběží testování."""
        if self.scan_manager.is_running:
            QMessageBox.warning(self, "Import nelze", "Import není možný během probíhajícího testování.")
            return

        path, _ = QFileDialog.getOpenFileName(self, "Importovat projekt", "", "Nmap Project (*.nmapproj)")
        if not path:
            return
        self.import_project(path)

    def import_project(self, path):
        """Načte projekt ze souboru s detailním progress dialogem."""
        try:
            self.current_project_path = path
            
            # Načíst soubor
            with open(path, 'r', encoding='utf-8') as f:
                project_data = json.load(f)
            
            # Spočítat celkový počet kroků
            total_steps = 0
            total_steps += 1  # Základní data (název projektu atd.)
            total_steps += len(project_data.get('scan_results', {}))  # Fáze
            total_steps += len(project_data.get('screenshots', {}))  # Screenshoty
            total_steps += 2  # Aktualizace UI
            
            # Vytvořit progress dialog
            progress = QProgressDialog("Načítám projekt...", "Zrušit", 0, total_steps, self)
            progress.setWindowTitle("Import projektu")
            progress.setWindowModality(Qt.WindowModal)
            progress.setMinimumDuration(0)
            
            current_step = 0
            
            # Načíst základní data
            progress.setLabelText("Načítám základní informace...")
            current_step += 1
            progress.setValue(current_step)
            QApplication.processEvents()
            
            if progress.wasCanceled():
                return
            
            # Načíst scan results
            for phase in project_data.get('scan_results', {}):
                progress.setLabelText(f"Načítám výsledky fáze: {phase}...")
                current_step += 1
                progress.setValue(current_step)
                QApplication.processEvents()
                
                if progress.wasCanceled():
                    return
            
            # Načíst screenshoty
            for ip in project_data.get('screenshots', {}):
                progress.setLabelText(f"Načítám screenshoty pro: {ip}...")
                current_step += 1
                progress.setValue(current_step)
                QApplication.processEvents()
                
                if progress.wasCanceled():
                    return
            
            # Aplikovat data
            progress.setLabelText("Aplikuji data do rozhraní...")
            current_step += 1
            progress.setValue(current_step)
            QApplication.processEvents()
            
            self.apply_project_data(project_data)
            
            # Finalizace
            progress.setLabelText("Dokončuji...")
            current_step += 1
            progress.setValue(current_step)
            QApplication.processEvents()
            
            self.add_to_recent_projects(path)
            self.status_label.setText(f"Projekt načten z {path}")
            self.worker_signals.log.emit("info", f"Projekt úspěšně načten z {path}.")

            progress.setValue(total_steps)
            progress.close()

            # Hned ověřit, že do složky projektu lze zapisovat — když ne (Plocha/
            # iCloud blokované macOS TCC), varovat DŘÍV, než uživatel přijde o data.
            self._maybe_warn_unwritable()

        except Exception as e:
            if 'progress' in locals():
                progress.close()
            QMessageBox.critical(self, "Chyba importu", f"Nelze načíst projekt: {e}")

    def add_to_recent_projects(self, path):
        """Přidá projekt do historie posledních projektů."""
        recent_projects = self.settings.value("recent_projects", [])
        if not isinstance(recent_projects, list):
            recent_projects = []
        
        # Odebrat cestu pokud už existuje (aby se přesunula nahoru)
        if path in recent_projects:
            recent_projects.remove(path)
        
        # Přidat na začátek seznamu
        recent_projects.insert(0, path)
        
        # Zachovat pouze posledních 5
        recent_projects = recent_projects[:5]
        
        # Uložit zpět do nastavení
        self.settings.setValue("recent_projects", recent_projects)

    def _project_meta(self):
        """Metadata projektu pro projektový soubor (v4)."""
        return {
            "name": self.project_name_edit.text(),
            "scan_profile": self.profile_combo.currentData(),
            "custom_command": self.custom_command_edit.text(),
            "raw_input": self.raw_input_text.toPlainText(),
            "cleaned_input": self.cleaned_output_text.toPlainText(),
            "screenshots": self.screenshots,
        }

    def apply_project_data(self, data):
        """Načte stav projektu (formát v4) přes ProjectStore. Zvládne i migraci
        ze staršího formátu v3 a úplně starého inline scan_results."""
        self.loading_project = True

        meta, history, pending = pstore.parse_project(data)
        p_name = meta.get("name") or "Můj Nmap Projekt"
        self.project_name_edit.setText(p_name)
        self._set_profile(meta.get("scan_profile", "master"))
        self.custom_command_edit.setText(meta.get("custom_command", ""))
        self.screenshots = meta.get("screenshots", {}) or {}
        self.raw_input_text.setPlainText(meta.get("raw_input", ""))
        self.cleaned_output_text.setPlainText(meta.get("cleaned_input", ""))

        self.run_history = history
        self._pending_snapshots = dict(pending)

        active = self.run_history.active()
        self.viewing_run_id = active.id if active else None
        if active:
            for ph, cb in self.phase_checkboxes.items():
                cb.setChecked(active.enabled_phases.get(ph, True))

        self.scan_results = self._load_snapshot(active) if active else {p: {} for p in self.phases}
        if 'certificates' not in self.scan_results:
            self.scan_results['certificates'] = {}

        self.loading_project = False
        if active:
            self._display_run(active)
        else:
            self.repopulate_ui_from_results()
        self.refresh_runs_combo()
        n = len(self.run_history.runs)
        self.status_label.setText(f"Projekt '{p_name}' načten ({n} běhů/verzí).")

    def repopulate_ui_from_results(self):
        """OPRAVA PÁDU: Vynechání persistence klíčů z matice IP adres."""
        for tree in self.tree_widgets.values():
            tree.clear()
        
        all_targets = set()
        for phase, phase_data in self.scan_results.items():
            if phase in ["ffuf", "certificates", "security_headers", "tls_audit"]:
                continue
            all_targets.update(phase_data.keys())
        
        if not all_targets:
            return
        
        # Robustní seřazení IP adres (ignoruijeme klíče, které nejsou ve formátu IP)
        def safe_ip_sort(ip):
            try: 
                clean_ip = ip.split(':')[0] # Odstranění portu pro jistotu
                return tuple(int(p) for p in clean_ip.split("."))
            except: 
                return (0, 0, 0, 0)

        self.status_matrix.populate_targets(sorted(all_targets, key=safe_ip_sort))
        
        self.loading_project = True
        
        for phase in self.phases:
            if phase not in self.scan_results:
                continue
            phase_data = self.scan_results[phase]
            # Handle_single_result voláme pouze pro standardní nmap fáze
            if isinstance(phase_data, dict) and phase != "certificates":
                for target, data in phase_data.items():
                    self.handle_single_result(phase, target, data)
        
        self.loading_project = False
        if hasattr(self, "port_summary_tree"):
            self.update_port_summary()
            self.update_service_summary()
            self.update_online_display_with_ports()

    @Slot(str, str, str)
    def on_task_started(self, phase, target, label):
        self.status_matrix.update_status(target, phase, 'probíhá')
        if not getattr(self, 'loading_project', False):
            self.live_task_panel.task_started(phase, target, label)

    @Slot(str, int, int)
    def on_phase_progress(self, phase, completed, total):
        self.phase_progress_bars.update(phase, completed, total)
        # Autosave po dokončení celé fáze
        if total > 0 and completed >= total and not getattr(self, 'loading_project', False):
            self.worker_signals.log.emit("info", f"✅ Fáze {phase.upper()} dokončena – autosave…")
            self.auto_save_project()


    @Slot(str, str, object, bool)
    def on_scan_result(self, phase, target, data, final):
        """Výsledek stupně nmap fáze. final=False = průběžný (rychlý stupeň),
        final=True = poslední stupeň (fáze pro cíl hotová)."""
        self.handle_single_result(phase, target, data, final=final)

    @Slot(str, str, dict)
    def handle_single_result(self, phase, target, data, final=True):
        with QMutexLocker(output_mutex):
            base_phase = phase.replace("-Pn", "")  # OPRAVA: Odstranit -Pn (bez mezer a závorek)
            self.scan_results[base_phase][target] = data

            self.update_cumulative_reports(target)

            tree = self.tree_widgets[base_phase]
            items = tree.findItems(target, Qt.MatchFlag.MatchExactly | Qt.MatchFlag.MatchRecursive, 0)

            if not items:
                target_item = QTreeWidgetItem(tree, [target])
                target_item.setForeground(0, get_color_for_ip(target))
            else:
                target_item = items[0]

            # Data jsou kumulativní (slučují se přes stupně) → překresli děti od nuly,
            # ať se nehromadí duplicitní porty mezi rychlým a plným skenem.
            target_item.takeChildren()

            status = "hotovo"
            
            if data.get('status') == 'skipped_by_user':
                status = 'zakázáno'
                target_item.setText(1, 'Fáze zakázána uživatelem')
                target_item.setForeground(1, QColor("#95A5A6"))

            elif base_phase == 'vuln':
                # Vuln tab: za „nález" se bere jen POTVRZENÁ zranitelnost. Benigní
                # hlášky („Couldn't find any…"), chyby skriptů a timeouty se NEukazují
                # jako červené nálezy — schovají se do sbaleného šedého uzlu.
                status = "hotovo"
                findings, others = [], []
                for proto in ('tcp', 'udp'):
                    for port, info in (data.get(proto, {}) or {}).items():
                        scripts = info.get('script') if isinstance(info, dict) else None
                        if isinstance(scripts, dict):
                            for sname, sout in scripts.items():
                                rec = (f"{port}/{proto}", sname, str(sout))
                                if classify_vuln_output(str(sout)) == "finding":
                                    findings.append(rec)
                                else:
                                    others.append(rec)
                if findings:
                    for portproto, sname, sout in findings:
                        it = QTreeWidgetItem(target_item,
                                             [f"{portproto} → {sname}", sout.strip().replace('\n', ' ')[:300]])
                        it.setForeground(0, QColor("#E74C3C"))
                        it.setForeground(1, QColor("#E74C3C"))
                    target_item.setText(1, f"{len(findings)} zranitelností")
                    target_item.setForeground(1, QColor("#E74C3C"))
                else:
                    msg = QTreeWidgetItem(target_item, ["✓ Žádné zranitelnosti nenalezeny", ""])
                    msg.setForeground(0, QColor("#2ECC71"))
                    target_item.setText(1, "bez nálezů")
                    target_item.setForeground(1, QColor("#2ECC71"))
                # Ostatní výstupy (čisté/chyby/timeouty) — sbaleno a šedě, ať to „neřve".
                if others:
                    grp = QTreeWidgetItem(
                        target_item,
                        [f"ℹ️ Výstupy skriptů ({len(others)}) — bez potvrzených nálezů", ""])
                    grp.setForeground(0, QColor("#95A5A6"))
                    grp.setExpanded(False)
                    for portproto, sname, sout in others:
                        child = QTreeWidgetItem(
                            grp, [f"{portproto} → {sname}", sout.strip().replace('\n', ' ')[:200]])
                        child.setForeground(0, QColor("#95A5A6"))
                        child.setForeground(1, QColor("#95A5A6"))
                if 'error' in data:
                    note = QTreeWidgetItem(target_item,
                                           ["(vuln sken nedoběhl úplně)", str(data.get('error', ''))[:200]])
                    note.setForeground(0, QColor("#95A5A6"))
                    note.setForeground(1, QColor("#95A5A6"))

            elif 'error' in data:
                status = "chyba"
                QTreeWidgetItem(target_item, ["Chyba", data['error']]).setForeground(0, QColor("#E74C3C"))
            
            elif data.get("status") == "skipped":
                status = "přeskočeno"
            
            elif base_phase == 'online':
                is_online = data.get('status', {}).get('state') == 'up'
                status = 'online' if is_online else 'offline'
                target_item.setText(1, status)
                target_item.setForeground(1, QColor("#2ECC71") if is_online else QColor("#95A5A6"))
            
            elif base_phase == 'osscan':
                if 'osmatch' in data and data['osmatch']:
                    for match in data['osmatch']:
                        name = match.get('name', 'Neznámý OS')
                        accuracy = match.get('accuracy', 'N/A')
                        os_item = QTreeWidgetItem(target_item, [f"OS: {name}", f"Přesnost: {accuracy}%"])
                        os_item.setForeground(0, QColor("#8E44AD"))
                else:
                    QTreeWidgetItem(target_item, ["OS", "Detekce selhala"]).setForeground(0, QColor("#E74C3C"))
            
            else:  # tcp, udp, vuln
                if not data or ('tcp' not in data and 'udp' not in data):
                    if status != "přeskočeno":
                        status = "hotovo"
                else:
                    has_http = False
                    
                    for proto in ['tcp', 'udp']:
                        if proto in data:
                            for port, info in data[proto].items():
                                port_state = info.get('state', 'unknown')
                                service = f"{info.get('name', 'n/a')} {info.get('version', '')}".strip()
                                port_item = QTreeWidgetItem(target_item, [f"{port}/{proto}", f"{port_state} | {service}"])
                                
                                if port_state == 'open':
                                    port_item.setForeground(1, QColor("#2ECC71"))
                                elif port_state == 'closed':
                                    port_item.setForeground(1, QColor("#E74C3C"))
                                else:
                                    port_item.setForeground(1, QColor("#F39C12"))
                                
                                if 'script' in info:
                                    for script_name, script_out in info['script'].items():
                                        QTreeWidgetItem(port_item, [f" -> {script_name}", script_out.strip().replace('\n', ' ')]).setForeground(0, QColor("#E74C3C"))
                                
                                # Detekce HTTP/HTTPS služeb pro screenshot - POUZE TCP A SPECIFICKÉ PORTY
                                service_name = info.get('name', '').lower()
                                port_num = int(port)
                                
                                # Definice webových portů
                                common_web_ports = [80, 443, 8080, 8000, 8008]
                                
                                # Screenshot pouze pro TCP, specifické porty NEBO detekovanou HTTP/HTTPS službu
                                should_screenshot = (
                                    base_phase == 'tcp' and  # Pouze TCP protokol
                                    (port_num in common_web_ports or 'http' in service_name)  # Port v seznamu NEBO HTTP služba
                                )
                                
                                if should_screenshot:
                                    has_http = True

                                    # Screenshot jen z finálního výsledku fáze (ne z průběžného
                                    # stupně) a ne při načítání projektu — ať se neopakuje.
                                    if final and not getattr(self, 'loading_project', False):
                                        # Určit správné schéma
                                        if 'https' in service_name or port_num == 443:
                                            scheme = 'https'
                                        else:
                                            scheme = 'http'
                                        
                                        url = f"{scheme}://{target}:{port}"
                                        ip_dir = self.base_export_path / target.replace('.', '_')
                                        ip_dir.mkdir(exist_ok=True, parents=True)
                                        
                                        # Označit v matici, že screenshot probíhá
                                        self.status_matrix.update_status(target, 'screenshot', 'probíhá')
                                        
                                        # Logovat pokus o screenshot
                                        self.worker_signals.log.emit("info", f"🌐 Plánuji screenshot pro {url} (port {port}, služba: {service_name or 'nedetekována'})")
                                        
                                        # Emitovat screenshot request signál
                                        self.worker_signals.screenshot_request.emit(url, target, port_num, str(ip_dir))
                    
                    # Pokud TCP fáze nemá žádné HTTP služby, označit screenshot jako hotovo
                    if final and base_phase == 'tcp' and not has_http:
                        if not getattr(self, 'loading_project', False):
                            self.status_matrix.update_status(target, 'screenshot', 'hotovo')

            # Finalizace fáze pro cíl — jen z FINÁLNÍHO výsledku (poslední stupeň).
            # Průběžné stupně jen doplní data; matice zůstává „probíhá".
            if final:
                self.status_matrix.update_status(target, phase, status)

                # Dokončit úlohu v živém panelu + zaznamenat stav do aktivního běhu
                # (jen při reálném běhu, ne při načítání projektu / prohlížení verze)
                if not getattr(self, 'loading_project', False):
                    self.live_task_panel.task_finished(base_phase, target, status)
                    active = self.run_history.active()
                    if active is not None and self.viewing_run_id == active.id:
                        active.set_status(target, base_phase, status)

            self.sort_tree_by_ip(tree)

            # Aktualizace přehledu portů
            if hasattr(self, 'port_summary_tree'):
                self.update_port_summary()
                self.update_service_summary()
                self.update_online_display_with_ports()


    @Slot()
    def on_workflow_finished(self):
        """Voláno při dokončení (nebo zastavení) celého workflow všech fází."""
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)

        # Uzavřít aktivní běh: dokončeno vs zastaveno (uživatel dal Stop).
        active = self.run_history.active()
        if active is not None and active.status == "running":
            active.finished_at = datetime.now().isoformat(timespec="seconds")
            active.status = "aborted" if self._stop_requested else "completed"
        aborted = bool(active and active.status == "aborted")
        self._stop_requested = False

        if aborted:
            self.status_label.setText("Skenování zastaveno. Můžeš ho později navázat.")
        else:
            self.status_label.setText("Skenování dokončeno! Připraveno k exportu.")
        self.worker_signals.log.emit("export", "Výsledky jsou k dispozici pro export.")

        # Zastavit živé tikání času v panelu úloh
        if hasattr(self, 'live_task_panel'):
            self.live_task_panel.stop()

        # Finální autosave (uloží snapshot verze + metadata běhů) a refresh přepínače.
        self.auto_save_project()
        self.refresh_runs_combo()

    def update_online_display_with_ports(self):
        """Aktualizuje záložku Online s aktuálními stavy (včetně 'online bez pingu')."""
        tree = self.tree_widgets.get('online')
        if not tree:
            return
        
        tree.clear()
        
        # Získat všechny cíle
        cleaned_text = self.cleaned_output_text.toPlainText()
        active_targets = [line.strip() for line in cleaned_text.splitlines() 
                        if line.strip() and not line.strip().startswith('#')]
        sorted_targets = sorted(active_targets, key=lambda ip: tuple(int(p) for p in ip.split('.')))
        
        for ip in sorted_targets:
            actual_status = self.get_actual_ip_status(ip)
            
            # Určit text, barvu a stav pro matici
            if actual_status == 'up':
                status_text = "Online"
                color = QColor("#2ECC71")
                matrix_status = 'online'
            elif actual_status == 'up_no_ping':
                status_text = "Online bez pingu"
                color = QColor("#F39C12")
                matrix_status = 'online bez ping'
            else:
                status_text = "Offline"
                color = QColor("#95A5A6")
                matrix_status = 'offline'
            
            # Přidat do tree
            item = QTreeWidgetItem(tree, [ip, status_text])
            item.setForeground(1, color)
            tree.addTopLevelItem(item)
            
            # Aktualizovat matici
            self.status_matrix.update_status(ip, 'online', matrix_status)
        
        # Přizpůsobit šířku sloupců po naplnění dat
        tree.resizeColumnToContents(0)
        tree.resizeColumnToContents(1)
        
        # Rozšířit sloupec "Stav" aby se vešel nadpis
        min_width = tree.fontMetrics().horizontalAdvance("Stav") + 20
        if tree.columnWidth(1) < min_width:
            tree.setColumnWidth(1, min_width)

    def update_cleaned_output(self):
        formatted_ips, ip_count = clean_and_parse_ips(self.raw_input_text.toPlainText())
        self.cleaned_output_text.setPlainText("\n".join(formatted_ips))
        self.count_label.setText(f"Počet cílů: {ip_count}")
        self.status_matrix.populate_targets([line for line in formatted_ips if line])

    @Slot()
    def on_profile_changed(self):
        """Aktualizuje nápovědu profilu a viditelnost pole pro vlastní příkaz."""
        profile = self.profile_combo.currentData() or "master"
        self.profile_hint_label.setText(sp.PROFILE_HINTS.get(profile, ""))
        is_custom = profile == "custom"
        self.custom_command_label.setVisible(is_custom)
        self.custom_command_edit.setVisible(is_custom)
        # Při vlastním příkazu nemá smysl vybírat fáze (běží jeden příkaz na cíl)
        for cb in self.phase_checkboxes.values():
            cb.setEnabled(not is_custom)

    def _set_profile(self, profile_key):
        """Nastaví profil v comboboxu podle klíče (master/intensive/…/custom)."""
        idx = self.profile_combo.findData(profile_key)
        if idx < 0:
            idx = self.profile_combo.findData("master")
        self.profile_combo.blockSignals(True)
        self.profile_combo.setCurrentIndex(max(0, idx))
        self.profile_combo.blockSignals(False)
        self.on_profile_changed()

    def update_cumulative_reports(self, target_ip):
        if not hasattr(self, 'base_export_path'):
            return
        # Při načítání projektu / prohlížení starší verze nepřepisovat výstupy na disku.
        if getattr(self, 'loading_project', False):
            return

        ip_full_data = {p: self.scan_results[p].get(target_ip, {}) for p in self.phases}
        safe_name = target_ip.replace('/', '_')
        ip_dir = self.base_export_path / safe_name
        ip_dir.mkdir(parents=True, exist_ok=True)
        
        with open(ip_dir / "full_report.json", 'w', encoding='utf-8') as f:
            json.dump(ip_full_data, f, indent=4, ensure_ascii=False)
        
        with open(self.base_export_path / "master_report.json", 'w', encoding='utf-8') as f:
            json.dump(self.scan_results, f, indent=4, ensure_ascii=False)
            
    def get_actual_ip_status(self, ip_address):
        """
        Určí skutečný stav IP adresy na základě online check a nalezených portů.
        Vrací: 'up', 'down', nebo 'up_no_ping'
        """
        online_status = self.scan_results.get('online', {}).get(ip_address, {}).get('status', {}).get('state', 'unknown')
        
        # Zkontrolovat, zda má IP otevřené porty v TCP nebo UDP
        # ALE POUZE pokud nebylo skenování přeskočeno
        has_open_ports = False
        
        for phase in ['tcp', 'udp']:
            phase_data = self.scan_results.get(phase, {}).get(ip_address, {})
            
            # Pokud je fáze označena jako "skipped" nebo "skipped_by_user", ignorovat ji
            if phase_data.get('status') in ['skipped', 'skipped_by_user']:
                continue
            
            # Kontrolovat otevřené porty pouze pokud není přeskočeno
            if phase in phase_data:
                for port, info in phase_data[phase].items():
                    if info.get('state') == 'open':
                        has_open_ports = True
                        break
            
            if has_open_ports:
                break
        
        # Určit skutečný stav
        if online_status == 'up':
            return 'up'
        elif has_open_ports:
            return 'up_no_ping'  # Online bez ping odpovědi (má otevřené porty)
        else:
            return 'down'  # Offline (žádné porty nebo vše přeskočeno)

    def export_phase_minimal(self, phase):
        with QMutexLocker(output_mutex):
            data = self.scan_results.get(phase, {})
            
            if not data:
                # Detailnější diagnostika
                available_phases = [p for p, d in self.scan_results.items() if d]
                self.worker_signals.log.emit("warning", f"Pro fázi '{phase}' nejsou žádná data k exportu.")
                if available_phases:
                    self.worker_signals.log.emit("info", f"Dostupné fáze s daty: {', '.join(available_phases)}")
                else:
                    self.worker_signals.log.emit("warning", "Žádná fáze nemá data. Byl sken dokončen?")
                return
            
            filename, _ = QFileDialog.getSaveFileName(
                self, 
                f"Exportovat souhrn fáze '{phase}'", 
                f"nmap_summary_{phase}.txt", 
                "Text Files (*.txt)"
            )
            
            if not filename:
                self.worker_signals.log.emit("info", "Export zrušen uživatelem.")
                return
            
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    # Hlavička s názvem projektu a timestampem
                    project_name = self.project_name_edit.text()
                    if hasattr(self, 'base_export_path') and self.base_export_path:
                        timestamp = self.base_export_path.name.replace('nmap_scan_results_', '')
                    else:
                        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
                    
                    f.write(f"Projekt: {project_name}\n")
                    f.write(f"Čas testování: {timestamp}\n")
                    f.write(f"Souhrn výsledků skenování pro fázi: {phase.upper()}\n")
                    f.write(f"Exportováno: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("="*40 + "\n\n")
                    
                    # Speciální formát pro fázi ONLINE - UPRAVENO
                    if phase == 'online':
                        cleaned_text = self.cleaned_output_text.toPlainText()
                        active_targets = [
                            line.strip() for line in cleaned_text.splitlines()
                            if line.strip() and not line.strip().startswith('#')
                        ]
                        sorted_targets = sorted(
                            active_targets, key=lambda ip: tuple(int(p) for p in ip.split('.'))
                        )
                        
                        f.write("Seznam testovaných cílů:\n")
                        f.write("=" * 40 + "\n\n")
                        
                        # Kategorizovat IP podle skutečného stavu
                        online_ips = []
                        online_no_ping_ips = []
                        offline_ips = []
                        
                        for target in sorted_targets:
                            actual_status = self.get_actual_ip_status(target)
                            if actual_status == 'up':
                                online_ips.append(target)
                            elif actual_status == 'up_no_ping':
                                online_no_ping_ips.append(target)
                            else:
                                offline_ips.append(target)
                        
                        # Sekce: Online
                        f.write(f"Online ({len(online_ips)}):\n")
                        f.write("-" * 40 + "\n")
                        for ip in online_ips:
                            f.write(f"{ip}\n")
                        f.write("\n")
                        
                        # Sekce: Online bez pingu
                        f.write(f"Online bez pingu ({len(online_no_ping_ips)}):\n")
                        f.write("-" * 40 + "\n")
                        for ip in online_no_ping_ips:
                            f.write(f"{ip}\n")
                        f.write("\n")
                        
                        # Sekce: Offline
                        f.write(f"Offline ({len(offline_ips)}):\n")
                        f.write("-" * 40 + "\n")
                        for ip in offline_ips:
                            f.write(f"{ip}\n")
                    
                    # Speciální formát pro fázi OSSCAN
                    elif phase == 'osscan':
                        sorted_ips = sorted(data.keys(), key=lambda ip: tuple(int(p) for p in ip.split('.')))
                        
                        for ip in sorted_ips:
                            res = data[ip]
                            f.write(f"Cíl: {ip}\n")
                            
                            if res.get("status") == "skipped_by_user":
                                f.write("  Status: Fáze zakázána uživatelem\n")
                            elif res.get("status") == "skipped":
                                f.write("  Status: Přeskočeno (cíl byl offline)\n")
                            elif 'error' in res:
                                f.write(f"  Chyba: {res['error']}\n")
                            else:
                                # Export OS detekce
                                if 'osmatch' in res and res['osmatch']:
                                    f.write("  Detekované operační systémy:\n")
                                    for match in res['osmatch']:
                                        os_name = match.get('name', 'Neznámý OS')
                                        accuracy = match.get('accuracy', 'N/A')
                                        f.write(f"    - {os_name} (Přesnost: {accuracy}%)\n")
                                        
                                        # Pokud jsou dostupné další detaily (OS class)
                                        if 'osclass' in match:
                                            for osclass in match['osclass']:
                                                vendor = osclass.get('vendor', '')
                                                osfamily = osclass.get('osfamily', '')
                                                osgen = osclass.get('osgen', '')
                                                f.write(f"      Vendor: {vendor}, Family: {osfamily}, Gen: {osgen}\n")
                                else:
                                    f.write("  - Detekce operačního systému selhala nebo nebyla nalezena žádná shoda.\n")
                            
                            f.write("\n" + "-"*40 + "\n\n")
                    
                    # Původní formát pro ostatní fáze (tcp, udp, vuln)
                    else:
                        sorted_ips = sorted(data.keys(), key=lambda ip: tuple(int(p) for p in ip.split('.')))
                        
                        for ip in sorted_ips:
                            res = data[ip]
                            f.write(f"Cíl: {ip}\n")
                            
                            if res.get("status") == "skipped_by_user":
                                f.write("  Status: Fáze zakázána uživatelem\n")
                            elif res.get("status") == "skipped":
                                f.write("  Status: Přeskočeno (cíl byl offline)\n")
                            elif 'error' in res:
                                f.write(f"  Chyba: {res['error']}\n")
                            else:
                                found_ports = False
                                for proto in ['tcp', 'udp']:
                                    if proto in res:
                                        for port, info in res[proto].items():
                                            found_ports = True
                                            port_state = info.get('state', 'unknown')
                                            service = f"{info.get('name', 'n/a')} {info.get('version', '')}".strip()
                                            f.write(f"  - Port {port}/{proto}: {port_state} | Služba: {service}\n")
                                            
                                            if 'script' in info:
                                                for script_name, script_out in info['script'].items():
                                                    f.write(f"    -> Skript '{script_name}': {script_out.strip().replace(chr(10), ' ')}\n")
                                
                                if not found_ports:
                                    f.write("  - Žádné relevantní porty nebo zranitelnosti nenalezeny.\n")
                            
                            f.write("\n" + "-"*40 + "\n\n")
                
                self.worker_signals.log.emit("export", f"Výsledky fáze '{phase}' úspěšně exportovány do {filename}.")
            
            except Exception as e:
                self.worker_signals.log.emit("error", f"Při exportu fáze '{phase}' nastala chyba: {e}")


    def sort_tree_by_ip(self, tree):
        items = []
        for i in range(tree.topLevelItemCount()):
            items.append(tree.takeTopLevelItem(0))
        def ip_sort_key(item):
            try: return tuple(int(p) for p in item.text(0).split('.'))
            except: return (0,0,0,0)
        items.sort(key=ip_sort_key)
        tree.addTopLevelItems(items)
        
        
        
        
        
        
    def show_context_menu(self, position):
        """Zobrazí kontextové menu pro zakomentování/odkomentování IP adres."""
        from PySide6.QtWidgets import QMenu
        from PySide6.QtGui import QAction
        
        menu = QMenu()
        
        comment_action = QAction("Zakomentovat vybrané řádky (# prefix)", self)
        comment_action.triggered.connect(self.comment_selected_lines)
        menu.addAction(comment_action)
        
        uncomment_action = QAction("Odkomentovat vybrané řádky", self)
        uncomment_action.triggered.connect(self.uncomment_selected_lines)
        menu.addAction(uncomment_action)
        
        menu.exec(self.cleaned_output_text.mapToGlobal(position))
        
    def comment_selected_lines(self):
        """Zakomentuje vybrané řádky přidáním # na začátek."""
        cursor = self.cleaned_output_text.textCursor()
        
        # Získat celý text
        full_text = self.cleaned_output_text.toPlainText()
        lines = full_text.split('\n')
        
        # Zjistit, které řádky jsou vybrané
        start = cursor.selectionStart()
        end = cursor.selectionEnd()
        
        if start == end:
            # Žádný výběr - použít aktuální řádek
            current_pos = cursor.position()
            text_before = full_text[:current_pos]
            current_line = text_before.count('\n')
            
            if current_line < len(lines):
                line = lines[current_line]
                if line.strip() and not line.strip().startswith('#'):
                    lines[current_line] = '# ' + line
        else:
            # Má výběr - zjistit rozsah řádků
            text_before_start = full_text[:start]
            text_before_end = full_text[:end]
            start_line = text_before_start.count('\n')
            end_line = text_before_end.count('\n')
            
            # Zakomentovat všechny řádky v rozsahu
            for i in range(start_line, end_line + 1):
                if i < len(lines):
                    line = lines[i]
                    if line.strip() and not line.strip().startswith('#'):
                        lines[i] = '# ' + line
        
        # Nastavit zpět celý text
        new_text = '\n'.join(lines)
        self.cleaned_output_text.setPlainText(new_text)
        
        # Aktualizovat počet cílů
        active_count = sum(1 for line in lines if line.strip() and not line.strip().startswith('#'))
        self.count_label.setText(f"Počet cílů: {active_count}")

    def uncomment_selected_lines(self):
        """Odkomentuje vybrané řádky odstraněním # z začátku."""
        cursor = self.cleaned_output_text.textCursor()
        
        # Získat celý text
        full_text = self.cleaned_output_text.toPlainText()
        lines = full_text.split('\n')
        
        # Zjistit, které řádky jsou vybrané
        start = cursor.selectionStart()
        end = cursor.selectionEnd()
        
        if start == end:
            # Žádný výběr - použít aktuální řádek
            current_pos = cursor.position()
            text_before = full_text[:current_pos]
            current_line = text_before.count('\n')
            
            if current_line < len(lines):
                line = lines[current_line]
                if line.strip().startswith('#'):
                    lines[current_line] = line.lstrip('#').lstrip()
        else:
            # Má výběr - zjistit rozsah řádků
            text_before_start = full_text[:start]
            text_before_end = full_text[:end]
            start_line = text_before_start.count('\n')
            end_line = text_before_end.count('\n')
            
            # Odkomentovat všechny řádky v rozsahu
            for i in range(start_line, end_line + 1):
                if i < len(lines):
                    line = lines[i]
                    if line.strip().startswith('#'):
                        lines[i] = line.lstrip('#').lstrip()
        
        # Nastavit zpět celý text
        new_text = '\n'.join(lines)
        self.cleaned_output_text.setPlainText(new_text)
        
        # Aktualizovat počet cílů
        active_count = sum(1 for line in lines if line.strip() and not line.strip().startswith('#'))
        self.count_label.setText(f"Počet cílů: {active_count}")






    def export_multiple_results_dialog(self):
        """Zobrazí dialog pro výběr záložek a následný export do jednoho souboru."""
        # Zkontrolovat, zda jsou nějaké výsledky
        if not any(self.scan_results.get(phase, {}) for phase in self.phases):
            QMessageBox.information(self, "Export", "Nejsou k dispozici žádné výsledky k exportu.")
            return
        
        # Zobrazit dialog pro výběr záložek
        dialog = ExportMultipleDialog(self.phases, self)
        if dialog.exec() != QDialog.Accepted:
            return
        
        selected_phases = dialog.selected_phases
        
        # Vybrat kam uložit
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        default_filename = f"nmap_export_{timestamp}.txt"
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Uložit export výsledků",
            default_filename,
            "Text Files (*.txt);;All Files (*)"
        )
        
        if not path:
            return
        
        # Exportovat vybrané záložky do jednoho souboru
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("NMAP SCANNER - EXPORT VÝSLEDKŮ\n")
                f.write("=" * 80 + "\n")
                f.write(f"Datum exportu: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Projekt: {self.project_name_edit.text()}\n")
                f.write(f"Exportované záložky: {', '.join([p.capitalize() for p in selected_phases])}\n")
                f.write("=" * 80 + "\n\n")
                
                # Exportovat každou vybranou záložku
                for phase in selected_phases:
                    f.write("\n" + "=" * 80 + "\n")
                    f.write(f"ZÁLOŽKA: {phase.upper()}\n")
                    f.write("=" * 80 + "\n\n")
                    
                    # Získat data ze záložky
                    tree = self.tree_widgets.get(phase)
                    if not tree:
                        f.write("  [Žádná data]\n\n")
                        continue
                    
                    # Export struktury záložky
                    root = tree.invisibleRootItem()
                    self._export_tree_item(f, root, 0)
                
                f.write("\n" + "=" * 80 + "\n")
                f.write("KONEC EXPORTU\n")
                f.write("=" * 80 + "\n")
            
            QMessageBox.information(self, "Export", f"Výsledky úspěšně exportovány do:\n{path}")
            self.worker_signals.log.emit("info", f"Export výsledků dokončen: {path}")
            
        except Exception as e:
            QMessageBox.critical(self, "Chyba exportu", f"Nelze uložit soubor: {e}")
            
    def _export_tree_item(self, file, item, indent):
        """Rekurzivně exportuje položky stromu do souboru."""
        for i in range(item.childCount()):
            child = item.child(i)
            
            # Získat text ze všech sloupců
            columns = []
            for col in range(child.columnCount()):
                text = child.text(col)
                if text:
                    columns.append(text)
            
            # Zapsat s odsazením
            if columns:
                indent_str = "  " * indent
                file.write(f"{indent_str}{' | '.join(columns)}\n")
            
            # Rekurzivně zpracovat potomky
            if child.childCount() > 0:
                self._export_tree_item(file, child, indent + 1)

    def export_ports_summary_dialog(self):
        """Zobrazí dialog pro výběr stavů portů a následný export."""
        # Získat dostupné stavy z port_summary_tree
        available_states = set()
        root = self.port_summary_tree.invisibleRootItem()
        
        for i in range(root.childCount()):
            state_item = root.child(i)
            state_text = state_item.text(0)
            # Extrahovat stav z textu (např. "OPEN - 5 portů (10×)")
            if ' - ' in state_text:
                state = state_text.split(' - ')[0].lower()
                available_states.add(state)
        
        if not available_states:
            QMessageBox.information(self, "Export portů", "Nejsou k dispozici žádné porty k exportu.")
            return
        
        # Zobrazit dialog pro výběr stavů
        dialog = ExportPortsDialog(sorted(available_states), self)
        if dialog.exec() != QDialog.Accepted:
            return
        
        selected_states = dialog.selected_states
        include_ips = dialog.include_ips  # Získat volbu zahrnutí IP adres
        
        # Vygenerovat název souboru s timestampem
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        project_name = self.project_name_edit.text().replace(" ", "_")
        default_filename = f"port_summary_{project_name}_{timestamp}.txt"
        
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Uložit export přehledu portů",
            default_filename,
            "Text Files (*.txt);;All Files (*)"
        )
        
        if not path:
            return
        
        # Exportovat vybrané stavy portů
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("PŘEHLED PORTŮ - EXPORT\n")
                f.write("=" * 80 + "\n")
                f.write(f"Datum exportu: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Projekt: {self.project_name_edit.text()}\n")
                f.write(f"Exportované stavy: {', '.join([s.upper() for s in selected_states])}\n")
                f.write(f"Zahrnout IP adresy: {'Ano' if include_ips else 'Ne'}\n")
                f.write("=" * 80 + "\n\n")
                
                # Projít port_summary_tree a exportovat vybrané stavy
                root = self.port_summary_tree.invisibleRootItem()
                
                for i in range(root.childCount()):
                    state_item = root.child(i)
                    state_text = state_item.text(0)
                    
                    # Extrahovat stav
                    if ' - ' in state_text:
                        state = state_text.split(' - ')[0].lower()
                    else:
                        continue
                    
                    # Přeskočit pokud není ve vybraných stavech
                    if state not in selected_states:
                        continue
                    
                    # Zapsat stav
                    f.write("\n" + "=" * 80 + "\n")
                    f.write(f"STAV: {state_text}\n")
                    f.write("=" * 80 + "\n\n")
                    
                    # Exportovat protokoly (TCP/UDP)
                    for j in range(state_item.childCount()):
                        proto_item = state_item.child(j)
                        proto_text = proto_item.text(0)
                        f.write(f"\n{proto_text}\n")
                        f.write("-" * 40 + "\n")
                        
                        # Exportovat jednotlivé porty
                        for k in range(proto_item.childCount()):
                            port_item = proto_item.child(k)
                            port_text = port_item.text(0).strip()
                            count_text = port_item.text(1)
                            
                            # Získat seznam IP z UserRole (pokud existuje)
                            port_data = port_item.data(0, Qt.UserRole)
                            if port_data and isinstance(port_data, dict):
                                port_num = port_data.get('port', port_text)
                                ips = port_data.get('ips', [])
                                
                                if include_ips and ips:
                                    # PODROBNÝ export s IP adresami
                                    f.write(f"  Port {port_num}: {count_text} IP adres\n")
                                    f.write(f"    IP: {', '.join(sorted(ips))}\n")
                                else:
                                    # ZÁKLADNÍ export bez IP adres
                                    f.write(f"  Port {port_num}: {count_text} IP adres\n")
                            else:
                                f.write(f"  {port_text}: {count_text} IP adres\n")
                
                f.write("\n" + "=" * 80 + "\n")
                f.write("KONEC EXPORTU\n")
                f.write("=" * 80 + "\n")
            
            QMessageBox.information(self, "Export", f"Přehled portů úspěšně exportován do:\n{path}")
            self.worker_signals.log.emit("info", f"Export přehledu portů dokončen: {path}")
            
        except Exception as e:
            QMessageBox.critical(self, "Chyba exportu", f"Nelze uložit soubor: {e}")

    def export_services_summary_dialog(self):
        """Zobrazí dialog pro výběr protokolů služeb a následný export."""
        # Získat dostupné protokoly z service_summary_tree
        available_protocols = set()
        root = self.service_summary_tree.invisibleRootItem()
        
        for i in range(root.childCount()):
            proto_item = root.child(i)
            proto_text = proto_item.text(0)
            if proto_text in ['TCP', 'UDP']:
                available_protocols.add(proto_text)
        
        if not available_protocols:
            QMessageBox.information(self, "Export služeb", "Nejsou k dispozici žádné služby k exportu.")
            return
        
        # Zobrazit dialog pro výběr protokolů
        dialog = ExportServicesDialog(sorted(available_protocols), self)
        if dialog.exec() != QDialog.Accepted:
            return
        
        selected_protocols = dialog.selected_protocols
        detail_level = dialog.detail_level  # summary / ports / full
        
        # Vygenerovat název souboru s timestampem
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        project_name = self.project_name_edit.text().replace(" ", "_")
        level_names = {"summary": "summary", "ports": "ports", "full": "detailed"}
        detail_suffix = level_names.get(detail_level, "export")
        default_filename = f"service_{detail_suffix}_{project_name}_{timestamp}.txt"
        
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Uložit export přehledu služeb",
            default_filename,
            "Text Files (*.txt);;All Files (*)"
        )
        
        if not path:
            return
        
        # Exportovat vybrané protokoly služeb
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                if detail_level == "summary":
                    f.write("PŘEHLED SLUŽEB - SOUHRN\n")
                    export_desc = "Souhrn (pouze služby)"
                elif detail_level == "ports":
                    f.write("PŘEHLED SLUŽEB - STŘEDNÍ EXPORT\n")
                    export_desc = "Střední (služby + porty)"
                else:
                    f.write("PŘEHLED SLUŽEB - DETAILNÍ EXPORT\n")
                    export_desc = "Detailní (služby + porty + IP adresy)"
                
                f.write("=" * 80 + "\n")
                f.write(f"Datum exportu: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Projekt: {self.project_name_edit.text()}\n")
                f.write(f"Exportované protokoly: {', '.join(selected_protocols)}\n")
                f.write(f"Typ exportu: {export_desc}\n")
                f.write("=" * 80 + "\n\n")
                
                # Projít service_summary_tree a exportovat vybrané protokoly
                root = self.service_summary_tree.invisibleRootItem()
                
                for i in range(root.childCount()):
                    proto_item = root.child(i)
                    proto_text = proto_item.text(0)
                    
                    # Přeskočit pokud není ve vybraných protokolech
                    if proto_text not in selected_protocols:
                        continue
                    
                    # Zapsat protokol
                    f.write("\n" + "=" * 80 + "\n")
                    f.write(f"PROTOKOL: {proto_text}\n")
                    f.write("=" * 80 + "\n\n")
                    
                    if detail_level == "summary":
                        # ===== SOUHRN - Jen seznam služeb =====
                        for j in range(proto_item.childCount()):
                            service_item = proto_item.child(j)
                            service_name = service_item.text(0)
                            total_count = service_item.text(1)
                            f.write(f"  {service_name}: {total_count} IP adres\n")
                    
                    elif detail_level == "ports":
                        # ===== STŘEDNÍ - Služby + porty (bez IP) =====
                        for j in range(proto_item.childCount()):
                            service_item = proto_item.child(j)
                            service_name = service_item.text(0)
                            total_count = service_item.text(1)
                            
                            f.write(f"\n{'─' * 70}\n")
                            f.write(f"Služba: {service_name}\n")
                            f.write(f"Celkem: {total_count} IP adres\n")
                            f.write(f"{'─' * 70}\n")
                            
                            # Exportovat porty bez IP adres
                            for k in range(service_item.childCount()):
                                port_item = service_item.child(k)
                                port_num = port_item.text(0)
                                port_count = port_item.text(1)
                                f.write(f"  Port {port_num}: {port_count} IP adres\n")
                    
                    else:
                        # ===== DETAILNÍ - Porty a IP adresy =====
                        for j in range(proto_item.childCount()):
                            service_item = proto_item.child(j)
                            service_name = service_item.text(0)
                            total_count = service_item.text(1)
                            
                            f.write(f"\n{'─' * 70}\n")
                            f.write(f"Služba: {service_name}\n")
                            f.write(f"Celkem: {total_count} IP adres\n")
                            f.write(f"{'─' * 70}\n")
                            
                            # Exportovat porty pro tuto službu
                            for k in range(service_item.childCount()):
                                port_item = service_item.child(k)
                                port_num = port_item.text(0)
                                port_count = port_item.text(1)
                                
                                # Získat seznam IP z UserRole
                                port_data = port_item.data(0, Qt.UserRole)
                                
                                if port_data and isinstance(port_data, dict):
                                    ips = port_data.get('ips', set())
                                    
                                    if ips:
                                        f.write(f"\n  Port {port_num} ({port_count} IP adres):\n")
                                        # IP adresy pod sebou bez čárek
                                        for ip in sorted(ips):
                                            f.write(f"    {ip}\n")
                                    else:
                                        f.write(f"\n  Port {port_num}: {port_count} IP adres\n")
                                else:
                                    f.write(f"\n  Port {port_num}: {port_count} IP adres\n")
                            
                            # Pokud služba nemá žádné podpoložky portů
                            if service_item.childCount() == 0:
                                service_data = service_item.data(0, Qt.UserRole)
                                if service_data and isinstance(service_data, dict):
                                    all_ips = service_data.get('ips', set())
                                    if all_ips:
                                        f.write(f"\n  IP adresy:\n")
                                        # IP adresy pod sebou bez čárek
                                        for ip in sorted(all_ips):
                                            f.write(f"    {ip}\n")
                
                f.write("\n" + "=" * 80 + "\n")
                f.write("KONEC EXPORTU\n")
                f.write("=" * 80 + "\n")
            
            level_names_cz = {"summary": "souhrnný", "ports": "střední", "full": "detailní"}
            export_type = level_names_cz.get(detail_level, "export")
            QMessageBox.information(self, "Export", f"Přehled služeb ({export_type}) úspěšně exportován do:\n{path}")
            self.worker_signals.log.emit("info", f"Export přehledu služeb ({export_type}) dokončen: {path}")
            
        except Exception as e:
            QMessageBox.critical(self, "Chyba exportu", f"Nelze uložit soubor: {e}")

    def export_vulnerability_report(self):
        """Exportuje analýzu zranitelností do Word dokumentu s použitím vzorové šablony."""
        if not any(self.scan_results.get(phase, {}) for phase in ['tcp', 'udp']):
            QMessageBox.information(self, "Export", "Nejsou k dispozici žádné výsledky pro export.")
            return
        
        # Najít šablonu ve složce skriptu
        import os
        import re
        script_dir = os.path.dirname(os.path.abspath(__file__))
        template_path = os.path.join(script_dir, "Pentest-Report.docx")
        
        if not os.path.exists(template_path):
            QMessageBox.warning(self, "Varování", f"Šablona 'Pentest-Report.docx' nebyla nalezena ve složce:\n{script_dir}")
            return
        
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        project_name = self.project_name_edit.text().replace(" ", "_")
        default_filename = f"vulnerability_report_{project_name}_{timestamp}.docx"
        
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Uložit analýzu zranitelností",
            default_filename,
            "Word Documents (*.docx);;All Files (*)"
        )
        
        if not path:
            return
        
        try:
            from copy import deepcopy
            
            # Načíst vzorový dokument
            template_doc = Document(template_path)
            
            # Uložit vzorovou tabulku
            template_table_element = None
            if len(template_doc.tables) > 0:
                template_table_element = template_doc.tables[0]._element
            
            # Vyčistit dokument
            for paragraph in template_doc.paragraphs[:]:
                p = paragraph._element
                p.getparent().remove(p)
            
            for table in template_doc.tables[:]:
                tbl = table._element
                tbl.getparent().remove(tbl)
            
            doc = template_doc
            
            # Přidat nadpis a metadata
            title = doc.add_heading('Analýza zranitelností sítě', 0)
            title.alignment = WD_ALIGN_PARAGRAPH.CENTER
            
            doc.add_paragraph(f"Projekt: {self.project_name_edit.text()}")
            doc.add_paragraph(f"Datum vytvoření: {time.strftime('%d.%m.%Y %H:%M:%S')}")
            doc.add_paragraph()
            
            # Získat všechny IP adresy
            all_targets = set()
            for phase in ['tcp', 'udp']:
                if phase in self.scan_results:
                    all_targets.update(self.scan_results[phase].keys())
            
            # Pro každý cíl
            for target_idx, target in enumerate(sorted(all_targets)):
                # Získat porty
                ports_data = []
                
                # NAČÍST DATA Z VULN FÁZE (tam jsou CVE)
                vuln_data = {}
                if 'vuln' in self.scan_results and target in self.scan_results['vuln']:
                    vuln_data = self.scan_results['vuln'][target]
                
                for phase in ['tcp', 'udp']:
                    if phase not in self.scan_results:
                        continue
                    
                    target_data = self.scan_results[phase].get(target, {})
                    
                    if phase in target_data:
                        for port_num, port_info in target_data[phase].items():
                            state = port_info.get('state', 'unknown')
                            
                            if state in ['open', 'open|filtered']:
                                service = port_info.get('name', 'unknown')
                                version = port_info.get('version', '')
                                product = port_info.get('product', '')
                                cves = port_info.get('cves', [])
                                
                                # ZÍSKAT SCRIPTS Z VULN FÁZE!
                                scripts = {}
                                if phase in vuln_data and port_num in vuln_data[phase]:
                                    scripts = vuln_data[phase][port_num].get('script', {})
                                
                                service_desc = service if service != 'unknown' else ''
                                
                                has_vulnerability = False
                                vuln_text = ""
                                risk_level = ""
                                risk_color = None
                                max_cvss = 0.0
                                
                                # PARSOVAT VULNERS SCRIPT PRO CVE A CVSS
                                cve_list = []
                                if 'vulners' in scripts:
                                    vulners_output = str(scripts['vulners'])
                                    
                                    # Regex: CVE-rok-číslo následované whitespace a pak číslem
                                    cve_pattern = r'CVE-(\d{4}-\d+)\s+([\d.]+)'
                                    matches = re.findall(cve_pattern, vulners_output)
                                    
                                    for cve_year_num, cvss_str in matches:
                                        cve_id = f"CVE-{cve_year_num}"
                                        try:
                                            cvss = float(cvss_str)
                                            # Filtrovat jenom čísla 0.1 - 10.0 (validní CVSS)
                                            if 0.1 <= cvss <= 10.0:
                                                cve_list.append((cve_id, cvss))
                                                if cvss > max_cvss:
                                                    max_cvss = cvss
                                        except ValueError:
                                            continue
                                
                                # Hledat EXPLOIT v jakémkoliv scriptu
                                exploit_found = False
                                if scripts:
                                    for script_name, script_output in scripts.items():
                                        if 'EXPLOIT' in str(script_output).upper():
                                            exploit_found = True
                                            break
                                
                                # Pokud jsou CVE ze scriptu nebo z cves pole nebo exploit
                                if cve_list or cves or exploit_found:
                                    has_vulnerability = True
                                    vuln_lines = ["A06 - zranitelná komponenta"]
                                    
                                    if exploit_found:
                                        vuln_lines[0] = "A06 - zranitelná komponenta se známým exploitem"
                                        risk_level = "C."
                                        risk_color = "800080"  # Tmavě fialová
                                    
                                    # Přidat CVE ze scriptu (s nejvyšším skóre první)
                                    if cve_list:
                                        cve_list.sort(key=lambda x: x[1], reverse=True)
                                        # Vzít top 5 CVE
                                        for cve_id, cvss in cve_list[:5]:
                                            vuln_lines.append(f"{cve_id} (CVSS: {cvss})")
                                    
                                    # Přidat CVE z pole (pokud tam jsou a nejsou ve scriptu)
                                    existing_cves = {cve_id for cve_id, _ in cve_list}
                                    for cve in cves:
                                        if cve not in existing_cves:
                                            vuln_lines.append(f"{cve}")
                                    
                                    vuln_text = '\n'.join(vuln_lines)
                                    
                                    # Určit risk level podle CVSS 3.0 (pokud už není nastaveno exploit)
                                    if not risk_level:
                                        if max_cvss >= 9.0:
                                            risk_level = "C."
                                            risk_color = "800080"  # Tmavě fialová
                                        elif max_cvss >= 7.0:
                                            risk_level = "H."
                                            risk_color = "FF0000"  # Červená
                                        elif max_cvss >= 4.0:
                                            risk_level = "M."
                                            risk_color = "FFC000"  # Oranžová
                                        elif max_cvss > 0.0:
                                            risk_level = "L."
                                            risk_color = "00B050"  # ← ZMĚNA: Zelená (místo žluté)
                                        else:
                                            risk_level = "M."
                                            risk_color = "FFC000"  # Default oranžová
                                
                                # ========================================
                                # DETEKCE ZÁKLADNÍCH ZRANITELNOSTÍ
                                # ========================================
                                
                                # 1. Identifikovaná verze služby
                                if version and version.strip() and version.lower() not in ['unknown', 'n/a', '']:
                                    if not has_vulnerability:
                                        has_vulnerability = True
                                        vuln_lines = []
                                    else:
                                        vuln_lines = vuln_text.split('\n')
                                    
                                    vuln_lines.append("A05 - Identifikovaná verze")
                                    
                                    # Sestavit popis: product + version
                                    version_desc = ""
                                    if product and product.strip():
                                        version_desc = f"{product} {version}"
                                    else:
                                        version_desc = version
                                    
                                    vuln_lines.append(version_desc)
                                    vuln_text = '\n'.join(vuln_lines)
                                    
                                    # Nastavit LOW risk pokud není vyšší
                                    if not risk_level or risk_level == "L.":
                                        risk_level = "L."
                                        risk_color = "00B050"  # Zelená

                                
                                # 2. MSRPC služba
                                if 'msrpc' in service.lower():
                                    if not has_vulnerability:
                                        has_vulnerability = True
                                        vuln_lines = []
                                    else:
                                        vuln_lines = vuln_text.split('\n')
                                    
                                    vuln_lines.append("A04 - Nezabezpečený design")
                                    vuln_lines.append("Exponovaná systémová služba MSRPC")
                                    vuln_text = '\n'.join(vuln_lines)
                                    
                                    # Nastavit MEDIUM pokud není vyšší
                                    if not risk_level or risk_level in ["L."]:
                                        risk_level = "M."
                                        risk_color = "FFC000"  # Oranžová
                                
                                # 3. RDP služba (port 3389)
                                if port_num == '3389' or 'rdp' in service.lower() or 'ms-wbt-server' in service.lower():
                                    if not has_vulnerability:
                                        has_vulnerability = True
                                        vuln_lines = []
                                    else:
                                        vuln_lines = vuln_text.split('\n')
                                    
                                    vuln_lines.append("A05 - Bezpečnostní chybná konfigurace")
                                    vuln_lines.append("Exponovaná služba RDP")
                                    vuln_text = '\n'.join(vuln_lines)
                                    
                                    # Nastavit MEDIUM pokud není vyšší
                                    if not risk_level or risk_level in ["L."]:
                                        risk_level = "M."
                                        risk_color = "FFC000"  # Oranžová
                                
                                ports_data.append({
                                    'port': f"{port_num}/{phase.upper()}",
                                    'service': service_desc,
                                    'vulnerability': vuln_text,
                                    'risk': risk_level,
                                    'risk_color': risk_color,
                                    'has_vuln': has_vulnerability
                                })
                
                # VYTVOŘ HEADING
                heading = doc.add_heading(target, level=3)
                
                if not ports_data:
                    doc.add_paragraph("Žádné otevřené porty nebyly nalezeny.")
                    doc.add_paragraph()
                    continue
                
                ports_data.sort(key=lambda x: int(x['port'].split('/')[0]))
                
                # ZKOPÍRUJ A VLOŽ TABULKU
                if template_table_element is not None:
                    new_tbl_element = deepcopy(template_table_element)
                    
                    # Vlož tabulku přímo za heading element
                    heading._element.addnext(new_tbl_element)
                    
                    # Najdi nově přidanou tabulku
                    table = doc.tables[-1]
                    
                    # Upravit počet řádků
                    needed_rows = len(ports_data) + 1
                    while len(table.rows) < needed_rows:
                        table.add_row()
                    while len(table.rows) > needed_rows:
                        tr = table.rows[-1]._element
                        tr.getparent().remove(tr)
                else:
                    table = doc.add_table(rows=len(ports_data) + 1, cols=5)
                
                # Vyplnit hlavičku
                hdr_cells = table.rows[0].cells
                headers = ['IP', 'Porty', 'Služba', 'Zranitelnost', 'Risk']
                for i, header_text in enumerate(headers):
                    if i < len(hdr_cells):
                        hdr_cells[i].text = header_text
                
                # Vyplnit data
                for idx, port_data in enumerate(ports_data, start=1):
                    if idx >= len(table.rows):
                        break
                    
                    row_cells = table.rows[idx].cells
                    
                    for cell in row_cells:
                        cell.text = ''
                    
                    row_cells[0].text = target
                    row_cells[1].text = port_data['port']
                    row_cells[2].text = port_data['service']
                    
                    if port_data['has_vuln']:
                        row_cells[3].text = port_data['vulnerability']
                        shading = OxmlElement('w:shd')
                        shading.set(qn('w:fill'), port_data['risk_color'])
                        row_cells[3]._element.get_or_add_tcPr().append(shading)
                        
                        row_cells[4].text = port_data['risk']
                        shading = OxmlElement('w:shd')
                        shading.set(qn('w:fill'), port_data['risk_color'])
                        row_cells[4]._element.get_or_add_tcPr().append(shading)
                
                # Přidat mezeru
                doc.add_paragraph()
            
            doc.save(path)
            
            QMessageBox.information(self, "Export", f"Analýza zranitelností úspěšně exportována do:\n{path}")
            self.worker_signals.log.emit("info", f"Export analýzy zranitelností dokončen: {path}")
            
        except Exception as e:
            import traceback
            QMessageBox.critical(self, "Chyba exportu", f"Nelze uložit dokument: {e}\n\n{traceback.format_exc()}")

    def export_hostnames_list(self):
        """Exportuje seznam IP adres a jejich hostnames do TXT."""
        # Zkontrolovat, zda jsou k dispozici výsledky
        if not any(self.scan_results.get(phase, {}) for phase in ['tcp', 'udp', 'online']):
            QMessageBox.information(self, "Export", "Nejsou k dispozici žádné výsledky pro export.")
            return
        
        # Dialog pro výběr filtrování
        filter_dialog = QDialog(self)
        filter_dialog.setWindowTitle("Nastavení exportu hostnames")
        filter_dialog.setModal(True)
        
        layout = QVBoxLayout()
        
        label = QLabel("Vyberte, které cíle exportovat:")
        layout.addWidget(label)
        
        # Radio buttons
        only_with_hostname = QRadioButton("Pouze cíle s určeným hostname")
        only_with_hostname.setChecked(True)  # Default
        all_targets = QRadioButton("Všechny cíle (včetně neurčených)")
        
        layout.addWidget(only_with_hostname)
        layout.addWidget(all_targets)
        
        # Tlačítka
        button_box = QHBoxLayout()
        ok_btn = QPushButton("OK")
        cancel_btn = QPushButton("Zrušit")
        
        ok_btn.clicked.connect(filter_dialog.accept)
        cancel_btn.clicked.connect(filter_dialog.reject)
        
        button_box.addWidget(ok_btn)
        button_box.addWidget(cancel_btn)
        
        layout.addLayout(button_box)
        filter_dialog.setLayout(layout)
        
        # Zobrazit dialog
        if filter_dialog.exec() != QDialog.DialogCode.Accepted:
            return
        
        # Zjistit volbu
        export_all = all_targets.isChecked()
        
        # Vygenerovat název souboru
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        project_name = self.project_name_edit.text().replace(" ", "_")
        default_filename = f"hostnames_{project_name}_{timestamp}.txt"
        
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Uložit seznam hostnames",
            default_filename,
            "Text Files (*.txt);;All Files (*)"
        )
        
        if not path:
            return
        
        try:
            # Získat všechny IP adresy a jejich hostnames
            hostnames_data = {}
            
            # Projít všechny fáze
            for phase in ['online', 'tcp', 'udp', 'vuln']:
                if phase not in self.scan_results:
                    continue
                
                for ip, ip_data in self.scan_results[phase].items():
                    if ip not in hostnames_data:
                        hostnames_data[ip] = set()
                    
                    # Získat hostnames
                    if 'hostnames' in ip_data:
                        hostnames = ip_data['hostnames']
                        if isinstance(hostnames, list):
                            for hostname in hostnames:
                                if isinstance(hostname, dict):
                                    name = hostname.get('name', '')
                                    if name:
                                        hostnames_data[ip].add(name)
                                elif isinstance(hostname, str) and hostname:
                                    hostnames_data[ip].add(hostname)
            
            # Filtrovat podle volby
            if not export_all:
                hostnames_data = {ip: hostnames for ip, hostnames in hostnames_data.items() if hostnames}
            
            # Spočítat statistiky
            total_hosts = len(hostnames_data)
            hosts_with_hostname = sum(1 for hostnames in hostnames_data.values() if hostnames)
            hosts_without_hostname = total_hosts - hosts_with_hostname
            
            # Zapsat do TXT
            with open(path, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write(f"SEZNAM HOSTNAMES - {self.project_name_edit.text()}\n")
                f.write(f"Datum exportu: {time.strftime('%d.%m.%Y %H:%M:%S')}\n")
                if not export_all:
                    f.write("Filtr: Pouze cíle s určeným hostname\n")
                f.write("=" * 80 + "\n\n")
                
                # Data
                for ip in sorted(hostnames_data.keys(), key=lambda x: tuple(map(int, x.split('.')))):
                    hostnames_list = sorted(hostnames_data[ip]) if hostnames_data[ip] else []
                    
                    if hostnames_list:
                        # Pokud má více hostnames, každý na řádek
                        for hostname in hostnames_list:
                            f.write(f"IP: {ip} -> {hostname}\n")
                    else:
                        f.write(f"IP: {ip} -> Neurčeno\n")
                
                # Statistiky
                f.write("\n")
                f.write("=" * 80 + "\n")
                f.write("STATISTIKY\n")
                f.write("=" * 80 + "\n")
                f.write(f"Celkem exportovaných cílů: {total_hosts}\n")
                if export_all:
                    f.write(f"Cílů s hostname: {hosts_with_hostname}\n")
                    f.write(f"Cílů bez hostname: {hosts_without_hostname}\n")
                f.write("=" * 80 + "\n")
            
            QMessageBox.information(self, "Export", f"Seznam hostnames úspěšně exportován do:\n{path}\n\nExportováno cílů: {total_hosts}")
            self.worker_signals.log.emit("info", f"Export hostnames dokončen: {path}")
            
        except Exception as e:
            import traceback
            QMessageBox.critical(self, "Chyba exportu", f"Nelze uložit soubor: {e}\n\n{traceback.format_exc()}")

    def analyze_vulnerabilities(self, service_name, version, cves):
        """
        Analyzuje zranitelnosti podle OWASP TOP 10 a vrací seznam kategorií.
        
        Returns:
            list: Seznam tuple (kategorie, popis)
        """
        vulnerabilities = []
        
        # A05 - Security Misconfiguration (pokud má identifikovanou verzi)
        if version and version.lower() not in ['unknown', '', 'n/a']:
            vulnerabilities.append(("A05", "Identifikovaná verze služby"))
        
        # A06 - Vulnerable and Outdated Components (pokud má CVE)
        if cves:
            vulnerabilities.append(("A06", "Zranitelná komponenta"))
            for cve in cves:
                vulnerabilities.append(("A06", f"CVE: {cve}"))
        
        # Specifické služby a jejich typické zranitelnosti
        service_lower = service_name.lower()
        
        # A01 - Broken Access Control
        if any(s in service_lower for s in ['ftp', 'telnet', 'rlogin', 'rsh']):
            vulnerabilities.append(("A01", "Nezabezpečený protokol - riziko neoprávněného přístupu"))
        
        # A02 - Cryptographic Failures
        if any(s in service_lower for s in ['http', 'ftp', 'telnet', 'smtp']) and 'ssl' not in service_lower and 'tls' not in service_lower:
            vulnerabilities.append(("A02", "Nešifrovaná komunikace"))
        
        # A04 - Insecure Design
        if 'msrpc' in service_lower or 'microsoft-ds' in service_lower:
            vulnerabilities.append(("A04", "Exponovaná systémová služba"))
        
        # A07 - Identification and Authentication Failures
        if any(s in service_lower for s in ['ssh', 'rdp', 'vnc', 'mysql', 'postgresql', 'mssql']):
            vulnerabilities.append(("A07", "Autentizační služba - riziko brute-force útoku"))
        
        return vulnerabilities if vulnerabilities else [("INFO", "Služba detekována")]
    
    def get_cvss_risk_level(self, cvss_score):
        """
        Vrací úroveň rizika podle CVSS 3.0 skóre.
        
        CVSS 3.0 rating:
        0.0: None
        0.1-3.9: LOW
        4.0-6.9: MEDIUM
        7.0-8.9: HIGH
        9.0-10.0: CRITICAL
        """
        if cvss_score is None:
            return "UNKNOWN", RGBColor(128, 128, 128)  # Šedá
        
        if cvss_score == 0.0:
            return "NONE", RGBColor(0, 128, 0)  # Zelená
        elif cvss_score < 4.0:
            return "LOW", RGBColor(255, 255, 0)  # Žlutá
        elif cvss_score < 7.0:
            return "MEDIUM", RGBColor(255, 165, 0)  # Oranžová
        elif cvss_score < 9.0:
            return "HIGH", RGBColor(255, 0, 0)  # Červená
        else:
            return "CRITICAL", RGBColor(139, 0, 139)  # Fialová
    





    def auto_save_project(self):
        """Automaticky uloží projekt (snapshot aktivní verze + metadata běhů)."""
        # Pokud je autosave pro tuto cestu zablokovaný (macOS práva / read-only),
        # nezkoušej to znovu — jen by to spamovalo log a zdržovalo GUI.
        if self._autosave_blocked and self._autosave_blocked == self.current_project_path:
            return
        # Zajistí projektovou složku (případně ji založí pod výchozí základnou).
        self._ensure_project_folder()

        try:
            # Data aktivní verze (atomicky) + metadata projektu (atomicky, v4).
            self._persist_active_snapshot(raise_on_error=True)
            pstore.save_project_file(self.current_project_path, self._project_meta(),
                                     self.run_history,
                                     datetime.now().isoformat(timespec="seconds"))
            # Aby se projekt objevil ve startup dialogu i bez ručního „Uložit".
            self.add_to_recent_projects(self.current_project_path)
            self.settings.setValue("last_project_path", self.current_project_path)
            self._update_project_path_label()
            self._autosave_blocked = None  # úspěch → případnou blokaci zrušit
            self.worker_signals.log.emit("info", f"💾 Autosave: Projekt uložen do {self.current_project_path}")
        except Exception as e:
            self._handle_autosave_failure(e)

    def _project_writable(self):
        """Rychlý test zápisu do složky projektu (macOS TCC / read-only FS).
        Bez otevřeného projektu vrací True (zatím není kam zapisovat)."""
        if not self.current_project_path:
            return True
        try:
            root = ProjectPaths.from_project_file(self.current_project_path).root
            root.mkdir(parents=True, exist_ok=True)
            probe = root / ".nmapscanner_write_test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            return True
        except OSError:
            return False

    def _maybe_warn_unwritable(self):
        """Po načtení projektu: když do jeho složky nejde zapisovat, varovat hned
        a nabídnout uložení jinam — ať uživatel nepřijde o výsledky (autosave by
        jinak jen tiše selhával a data by po zavření zmizela)."""
        if self._project_writable():
            self._autosave_blocked = None
            return
        self._autosave_blocked = self.current_project_path
        self.worker_signals.log.emit(
            "error", "⛔ Do složky projektu nelze zapisovat (Plocha/iCloud blokované "
            "macOS). Výsledky se sem NEULOŽÍ — ulož projekt jinam.")
        self.status_label.setText("⛔ Složka projektu je jen pro čtení — ulož projekt jinam!")
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle("Do složky projektu nelze zapisovat")
        box.setText("Tento projekt je ve složce, kam aplikace nemůže zapisovat "
                    "(typicky Plocha nebo iCloud — Ochrana soukromí macOS).")
        box.setInformativeText(
            f"{self.current_project_path}\n\n"
            "⚠️ Výsledky skenů, TLS audity a screenshoty se sem NEULOŽÍ a po zavření "
            "aplikace zmizí. Ulož projekt do zapisovatelné složky (např. "
            "~/NmapScannerProjects) — data z paměti se přenesou.")
        relocate = box.addButton("Uložit projekt jinam…", QMessageBox.AcceptRole)
        box.addButton("Pokračovat (neukládat)", QMessageBox.RejectRole)
        box.exec()
        if box.clickedButton() is relocate:
            self.export_project_dialog()

    def _handle_autosave_failure(self, e):
        """Selhání autosave. Práva (EPERM/EACCES) = typicky projekt na Ploše/iCloudu,
        kam macOS nedovolí zapisovat → autosave pro tu cestu vypnout a nabídnout přesun."""
        import errno
        is_perm = (isinstance(e, PermissionError)
                   or getattr(e, "errno", None) in (errno.EPERM, errno.EACCES))
        if is_perm:
            already = (self._autosave_blocked == self.current_project_path)
            self._autosave_blocked = self.current_project_path
            self.worker_signals.log.emit(
                "error", "⛔ Autosave vypnut — macOS blokuje zápis do složky projektu "
                f"({self.current_project_path}). Výsledky se neukládají — ulož projekt jinam.")
            self.status_label.setText("⛔ Autosave vypnut — složka projektu je jen pro čtení.")
            if already:
                return  # varování už padlo (neotravovat opakovaně)
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Warning)
            box.setWindowTitle("Autosave zablokován (práva macOS)")
            box.setText("Nelze ukládat do složky projektu — výsledky se NEUKLÁDAJÍ "
                        "a po zavření aplikace zmizí.")
            box.setInformativeText(
                f"{self.current_project_path}\n\n"
                "Složka je nejspíš na Ploše nebo v iCloudu (Ochrana soukromí macOS). "
                "Ulož projekt do zapisovatelné složky (např. ~/NmapScannerProjects) — "
                "data z paměti se přenesou. Alternativně povol aplikaci přístup v "
                "Nastavení → Soukromí a zabezpečení → Soubory a složky a restartuj ji.")
            relocate = box.addButton("Uložit projekt jinam…", QMessageBox.AcceptRole)
            box.addButton("Teď ne", QMessageBox.RejectRole)
            box.exec()
            if box.clickedButton() is relocate:
                self.export_project_dialog()
        else:
            self.worker_signals.log.emit(
                "error", f"⚠️ Autosave: Chyba při automatickém ukládání: {e}")


    def save_settings(self):
        settings = QSettings("UTB", "NmapScannerApp")
        settings.setValue("last_input", self.raw_input_text.toPlainText())
        settings.setValue("cleaned_output", self.cleaned_output_text.toPlainText())
        settings.setValue("scan_profile", self.profile_combo.currentData())
        settings.setValue("custom_command", self.custom_command_edit.text())
    
    def load_settings(self):
        self.settings = QSettings("UTB", "NmapScannerApp")
        last_input = self.settings.value("last_input", "")
        self.raw_input_text.setPlainText(last_input)
        
        cleaned_output = self.settings.value("cleaned_output", "")
        if cleaned_output:
            self.cleaned_output_text.setPlainText(cleaned_output)
            lines = cleaned_output.split('\n')
            active_count = sum(1 for line in lines if line.strip() and not line.strip().startswith('#'))
            self.count_label.setText(f"Počet cílů: {active_count}")
        else:
            self.update_cleaned_output()
        
        # Načtení profilu skenu (výchozí: master) a vlastního příkazu
        profile = self.settings.value("scan_profile", "master")
        self.custom_command_edit.setText(self.settings.value("custom_command", ""))
        self._set_profile(profile)

    def closeEvent(self, event):
        """Při zavření aplikace nabídnout uložení projektu."""
        self.save_settings()
        # Bezpečně vymazat sudo heslo z paměti při zavírání.
        self._clear_sudo_password()

        # Pokud běží skenování, nejdřív ho zastavit
        if self.scan_manager.is_running:
            reply = QMessageBox.question(
                self,
                "Probíhá skenování",
                "Skenování stále probíhá. Opravdu chcete ukončit aplikaci?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply == QMessageBox.No:
                event.ignore()
                return
            
            self.scan_manager.stop_workflow()
        
        # Dialog pro uložení projektu
        msgbox = QMessageBox(self)
        msgbox.setIcon(QMessageBox.Question)
        msgbox.setWindowTitle("Uložit projekt")
        msgbox.setText("Chcete před zavřením uložit aktuální projekt?")
        
        # Tlačítka
        save_current_btn = None
        if self.current_project_path:
            # Projekt byl otevřen ze souboru - nabídnout přepsat
            msgbox.setInformativeText(f"Aktuálně otevřený projekt:\n{self.current_project_path}")
            save_current_btn = msgbox.addButton("Uložit do současného", QMessageBox.AcceptRole)
        
        save_new_btn = msgbox.addButton("Uložit jako nový...", QMessageBox.ActionRole)
        dont_save_btn = msgbox.addButton("Neukládat", QMessageBox.RejectRole)
        cancel_btn = msgbox.addButton("Zrušit zavření", QMessageBox.NoRole)
        
        msgbox.setDefaultButton(save_new_btn if not self.current_project_path else save_current_btn)
        msgbox.exec()
        
        clicked = msgbox.clickedButton()
        
        if clicked == cancel_btn:
            # Zrušit zavření
            event.ignore()
            return
        
        # Zjistit, CO uložit (samotné uložení proběhne níže s progress dialogem,
        # protože může chvíli trvat — velká data verze + fsync).
        save_label, save_fn = None, None
        if clicked == save_current_btn and self.current_project_path:
            save_label = "Ukládám projekt…"
            save_fn = self.auto_save_project
        elif clicked == save_new_btn:
            path, _ = QFileDialog.getSaveFileName(
                self, "Uložit projekt jako", "", "Nmap Project (*.nmapproj)")
            if path:
                def _save_new(p=path):
                    self._persist_active_snapshot()
                    pstore.save_project_file(p, self._project_meta(), self.run_history,
                                             datetime.now().isoformat(timespec="seconds"))
                    self.worker_signals.log.emit("export", f"Projekt uložen do {p}")
                save_label, save_fn = "Ukládám projekt…", _save_new
            else:
                # Uživatel zrušil dialog - zeptat se, zda chce pokračovat bez uložení
                reply = QMessageBox.question(
                    self, "Neuloženo",
                    "Projekt nebyl uložen. Opravdu chcete ukončit bez uložení?",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                if reply == QMessageBox.No:
                    event.ignore()
                    return
        # (dont_save_btn → save_fn zůstává None, jen se zavře)

        # --- Zavírací sekvence s progress dialogem ---
        prog = QProgressDialog("Zavírám aplikaci…", None, 0, 3, self)
        prog.setWindowTitle("Zavírání")
        prog.setWindowModality(Qt.WindowModal)
        prog.setCancelButton(None)
        prog.setMinimumDuration(0)
        prog.setAutoClose(False)
        prog.setAutoReset(False)
        prog.setValue(0)
        QApplication.processEvents()

        if save_fn is not None:
            prog.setLabelText(save_label)
            QApplication.processEvents()
            try:
                save_fn()
                if clicked == save_current_btn:
                    self.worker_signals.log.emit("export", f"Projekt uložen do {self.current_project_path}")
            except Exception as e:
                prog.close()
                QMessageBox.critical(self, "Chyba uložení", f"Nelze uložit projekt: {e}")
                event.ignore()
                return
        prog.setValue(1)

        # Korektní ukončení vláken. KLÍČOVÉ: nejdřív zabít běžící procesy (nmap i TLS
        # enginy sslscan/sslyze/testssl), jinak by se workery zasekly na subprocess
        # a global thread pool by při ukončení appky čekal na jejich timeout.
        prog.setLabelText("Ukončuji běžící procesy…")
        QApplication.processEvents()
        try:
            from .workers.tls import TLS_PROCS
            TLS_PROCS.terminate_all()
        except Exception:
            pass
        try:
            self.scan_manager.shutdown()
        except Exception:
            pass
        try:
            self.screenshot_manager.shutdown()
        except Exception:
            pass
        prog.setValue(2)

        prog.setLabelText("Zavírám vlákna…")
        QApplication.processEvents()
        self.screenshot_thread.quit()
        self.screenshot_thread.wait(3000)
        self.manager_thread.quit()
        self.manager_thread.wait(3000)
        prog.setValue(3)
        prog.close()
        event.accept()

