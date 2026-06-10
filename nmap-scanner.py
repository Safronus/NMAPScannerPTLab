# Verze aplikace
VERSION = "2.1.0"  # Přidán přehled služeb (Service Summary)

from docx import Document
from docx.shared import Pt, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

import sys
import os
import time
import nmap
import requests
import subprocess
import json
import re
import ipaddress
import shutil
import ssl
import socket
import tempfile
from pathlib import Path
from datetime import datetime
from xml.etree import ElementTree as ET
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWebEngineCore import QWebEnginePage
from PySide6.QtWidgets import (
    QApplication, QWidget, QTextEdit, QLineEdit, QPushButton, QVBoxLayout,
    QTreeWidget, QTreeWidgetItem, QLabel, QGroupBox, QHeaderView, QMenu, 
    QFileDialog, QTabWidget, QHBoxLayout, QSplitter, QCheckBox, QDialog, QMessageBox, QDialogButtonBox, QComboBox,
    QListWidget, QListWidgetItem, QLabel, QGridLayout, QProgressBar, QScrollArea, QSizePolicy, QFrame, QProgressDialog, QRadioButton
)
from PySide6.QtCore import QObject, Signal, Slot, QMutex, QMutexLocker, QTimer, Qt, QThread, QSettings, QRunnable, QThreadPool
from PySide6.QtGui import QColor, QImage, QPainter, QPixmap, QFont, QIcon

# FIX pro macOS QWebEngine / Chromium pády
os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = "--disable-gpu --disable-software-rasterizer"
# Pokud používáš PySide 6.4+, zkus i tohle, pokud pád přetrvá:
# QCoreApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts)

output_mutex = QMutex()

print("Python nmap modul OK")
result = subprocess.run(["nmap", "--version"], capture_output=True, text=True)
print("Nmap binárka OK:", result.stdout.splitlines()[0] if result.returncode == 0 else "CHYBA")

def clean_and_parse_ips(raw_text):
    ip_pattern = r'\b((?:\d{1,3}\.){3}\d{1,3})\b'
    range_pattern = r'\b((?:\d{1,3}\.){3}\d{1,3})-(\d{1,3})\b'
    cidr_pattern = r'\b(?:\d{1,3}\.){3}\d{1,2}\b'
    found_ips, found_ranges, found_cidrs = re.findall(ip_pattern, raw_text), re.findall(range_pattern, raw_text), re.findall(cidr_pattern, raw_text)
    processed_ips = set(found_ips)
    for base, end_str in found_ranges:
        try:
            start_ip, end_octet = ipaddress.ip_address(base), int(end_str)
            start_octet = int(str(start_ip).split('.')[-1])
            if start_octet > end_octet: start_octet, end_octet = end_octet, start_octet
            base_prefix = ".".join(str(start_ip).split('.')[:-1])
            for i in range(start_octet, end_octet + 1): processed_ips.add(f"{base_prefix}.{i}")
        except (ValueError, IndexError): continue
    for cidr in found_cidrs:
        try:
            if cidr.endswith('/'): continue
            for ip in ipaddress.ip_network(cidr, strict=False): processed_ips.add(str(ip))
        except ValueError: continue
    sorted_ips = sorted(list(processed_ips), key=lambda ip: int(ipaddress.ip_address(ip)))
    formatted_output, last_prefix = [], None
    for ip in sorted_ips:
        current_prefix = ".".join(ip.split('.')[:3])
        if last_prefix and last_prefix != current_prefix: formatted_output.append("")
        formatted_output.append(ip)
        last_prefix = current_prefix
    return formatted_output, len(sorted_ips)

def get_color_for_ip(ip_str):
    color_palette = ["#4E79A7", "#F28E2B", "#E15759", "#76B7B2", "#59A14F",
                     "#EDC948", "#B07AA1", "#FF9DA7", "#9C755F", "#BAB0AC"]
    try:
        third_octet = int(ip_str.split('.')[2])
        return QColor(color_palette[third_octet % len(color_palette)])
    except:
        return QColor("black")

class SecurityHeadersWorker(QRunnable):
    def __init__(self, ip, port, signals):
        super().__init__()
        self.ip = ip
        self.port = str(port)
        self.signals = signals
        # PŘESNĚ 6 HLAVIČEK PODLE TVÉHO ZADÁNÍ
        self.target_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy"
        ]

    @Slot()
    def run(self):
        protocol = "https" if self.port in ["443", "8443"] else "http"
        url = f"{protocol}://{self.ip}:{self.port}"
        
        # Zjištění doménového jména (Reverse DNS)
        try:
            import socket
            domain_name = socket.gethostbyaddr(self.ip)[0]
        except:
            domain_name = "-"
        
        try:
            import requests
            from urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            
            response = requests.get(url, verify=False, timeout=8, allow_redirects=True)
            headers = response.headers
            
            found = {}
            missing_count = 0
            
            for h in self.target_headers:
                val = headers.get(h)
                found[h] = val if val else "CHYBÍ"
                if not val: missing_count += 1
            
            # Hodnocení stavu
            if missing_count == 0:
                status = "Zabezpečeno"
            elif missing_count <= 2:
                status = "Dobré (chybí drobnosti)"
            elif missing_count <= 4:
                status = "Varování (chybí zásadní)"
            else:
                status = "Slabé zabezpečení"
            
            result_data = {
                'ip': self.ip, 'port': self.port,
                'domain': domain_name, # NOVÉ
                'status': status,
                'headers': found,
                'server': headers.get("Server", "Neznámý"),
                'missing_count': missing_count
            }
            self.signals.result.emit(self.ip, self.port, result_data)

        except Exception as e:
            self.signals.result.emit(self.ip, self.port, {
                'status': "Chyba spojení",
                'error': str(e)[:50]
            })
        finally:
            self.signals.finished.emit()

class TlsAuditWorker(QRunnable):
    """
    Asynchronní worker pro testování TLS verzí a šifer pomocí Nmap (ssl-enum-ciphers).
    Získává detailní seznam Cipher Suites jako Qualys SSL Labs.
    """
    def __init__(self, ip, port, signals):
        super().__init__()
        self.ip = ip
        self.port = str(port)
        self.signals = signals

    def evaluate_cipher(self, name):
        """
        Vyhodnotí sílu šifry podle pravidel Qualys SSL Labs.
        Vrací: (Slovní hodnocení, Barva, Tag)
        """
        name_upper = name.upper()
        
        # 1. KRITICKÉ / NEBEZPEČNÉ (INSECURE)
        # Anonymní, Null, slabé algoritmy
        if any(x in name_upper for x in ['NULL', 'ANON', 'RC4', '3DES', 'DES', 'EXPORT', 'MD5', 'IDEA', 'PSK']):
            return "INSECURE", "#E74C3C", "(INSECURE)" # Červená
            
        # 2. SLABÉ (WEAK)
        # Statická RSA (chybí Forward Secrecy) - začíná TLS_RSA_ nebo SSL_RSA_
        # (Pozor: TLS 1.3 šifry jako TLS_AES_128... nezačínají RSA, to je OK)
        if "TLS_RSA_" in name_upper or "SSL_RSA_" in name_upper:
            return "WEAK", "#F39C12", "(WEAK - No FS)" # Oranžová
            
        # CBC Mód (Lucky13, POODLE atd. - Qualys penalizuje)
        # Většina moderních konfigurací preferuje GCM/Poly1305
        if "_CBC_" in name_upper:
            return "WEAK", "#F39C12", "(WEAK)"
            
        # 3. BEZPEČNÉ (SECURE)
        # GCM, CHACHA20-POLY1305, CCM s ECDHE/DHE
        return "SECURE", "#2ECC71", "" # Zelená

    @Slot()
    def run(self):
        try:
            domain_name = socket.gethostbyaddr(self.ip)[0]
        except:
            domain_name = "-"

        # Používáme --script ssl-enum-ciphers pro detailní audit
        cmd = [
            "nmap", "-n", "-Pn", "-T4", 
            "-p", self.port, 
            "--script", "ssl-enum-ciphers", 
            "-oX", "-", 
            self.ip
        ]
        
        scan_data = {
            'ip': self.ip, 'port': self.port, 'domain': domain_name,
            'protocols': {},
            'cipher_tree': {},
            'check_time': datetime.now().strftime('%d.%m.%Y %H:%M:%S'),
            'status': "Hotovo"
        }

        try:
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            
            if process.returncode == 0 and process.stdout:
                root = ET.fromstring(process.stdout)
                
                # Najít script element pro daný port
                script_elem = None
                for port in root.findall(".//port"):
                    if port.get('portid') == self.port:
                        for s in port.findall("script"):
                            if s.get('id') == "ssl-enum-ciphers":
                                script_elem = s
                                break
                
                if script_elem is not None:
                    # Nmap XML: <table key="TLSv1.2"> ... </table>
                    for proto_table in script_elem.findall("table"):
                        proto_key = proto_table.get("key") # Např. "TLSv1.2"
                        
                        # Ignorujeme tabulku "least strength" která je na konci
                        if "strength" in str(proto_key).lower():
                            continue

                        # Normalizace pro známkování
                        norm_key = None
                        if "TLSv1.3" in proto_key: norm_key = "tls1_3"
                        elif "TLSv1.2" in proto_key: norm_key = "tls1_2"
                        elif "TLSv1.1" in proto_key: norm_key = "tls1_1"
                        elif "TLSv1.0" in proto_key: norm_key = "tls1_0"
                        elif "SSLv3" in proto_key: norm_key = "sslv3"
                        elif "SSLv2" in proto_key: norm_key = "sslv2"
                        
                        if norm_key:
                            scan_data['protocols'][norm_key] = True

                        # Hledání šifer v pod-tabulce "ciphers"
                        ciphers_list = []
                        
                        # Musíme najít <table key="ciphers"> uvnitř aktuálního proto_table
                        ciphers_table_elem = None
                        for child in proto_table.findall("table"):
                            if child.get("key") == "ciphers":
                                ciphers_table_elem = child
                                break
                        
                        if ciphers_table_elem is not None:
                            # Iterace přes jednotlivé šifry
                            for cipher_row in ciphers_table_elem.findall("table"):
                                c_name = "Unknown"
                                c_kex = ""
                                
                                for elem in cipher_row.findall("elem"):
                                    k = elem.get("key")
                                    v = elem.text
                                    if k == "name": c_name = v
                                    elif k == "kex_info": c_kex = v
                                
                                # Aplikovat VLASTNÍ Qualys-like hodnocení
                                grade_label, grade_color, grade_tag = self.evaluate_cipher(c_name)
                                
                                ciphers_list.append({
                                    'name': c_name,
                                    'grade_label': grade_label, # SECURE/WEAK/INSECURE
                                    'grade_color': grade_color, # HEX barva
                                    'grade_tag': grade_tag,     # Text do závorky
                                    'kex_info': c_kex
                                })
                        
                        # Uložit pouze pokud protokol obsahuje nějaké šifry
                        if ciphers_list:
                            scan_data['cipher_tree'][proto_key] = ciphers_list
                else:
                    # Script nenašel nic -> chyba spojení
                    scan_data['status'] = "Chyba spojení"
            else:
                scan_data['status'] = "Chyba spojení"

        except Exception as e:
            scan_data['status'] = "Chyba spojení"
            scan_data['error'] = str(e)

        self.signals.result.emit(self.ip, self.port, scan_data)
        self.signals.finished.emit()

class SslLabsWorker(QRunnable):
    """
    Worker pro skenování pomocí veřejného API Qualys SSL Labs.
    Funguje pouze na veřejně dostupné domény a IP adresy.
    """
    def __init__(self, ip, port, signals):
        super().__init__()
        self.ip = ip
        self.port = str(port)
        self.signals = signals
        self.api_url = "https://api.ssllabs.com/api/v3/analyze"

    @Slot()
    def run(self):
        scan_data = {
            'ip': self.ip, 'port': self.port, 'domain': self.ip,
            'protocols': {}, 'cipher_tree': {},
            'check_time': datetime.now().strftime('%d.%m.%Y %H:%M:%S'),
            'status': "Hotovo"
        }
        
        # Qualys testuje převážně port 443. Lze to specifikovat v API, ale je to pomalé.
        if self.port != "443":
            scan_data['status'] = "Chyba"
            scan_data['error'] = "Qualys API primárně podporuje port 443."
            self.signals.result.emit(self.ip, self.port, scan_data)
            self.signals.finished.emit()
            return

        try:
            import requests
            import time
            
            # Prvotní dotaz pro spuštění skenu
            params = {'host': self.ip, 'publish': 'off', 'all': 'done', 'ignoreMismatch': 'on'}
            
            while True:
                response = requests.get(self.api_url, params=params, timeout=15)
                if response.status_code != 200:
                    raise Exception(f"API Error: HTTP {response.status_code}")
                
                data = response.json()
                status = data.get('status', 'ERROR')
                
                if status == 'READY':
                    break
                elif status == 'ERROR':
                    raise Exception(data.get('statusMessage', 'API vrátilo chybu nebo cíl není veřejný.'))
                elif status == 'DNS':
                    # Průběžný update do GUI
                    scan_data['status'] = "Qualys: Resolving DNS..."
                    self.signals.result.emit(self.ip, self.port, scan_data)
                elif status == 'IN_PROGRESS':
                    scan_data['status'] = "Qualys: Probíhá hloubkový audit (1-3 min)..."
                    self.signals.result.emit(self.ip, self.port, scan_data)
                
                time.sleep(10) # Polling každých 10 vteřin
            
            # Zpracování výsledků
            endpoints = data.get('endpoints', [])
            if not endpoints:
                raise Exception("Žádné endpointy nenalezeny.")
                
            endpoint = endpoints[0]
            if 'details' not in endpoint:
                raise Exception(endpoint.get('statusMessage', 'Chybí detailní výsledky.'))
                
            details = endpoint['details']
            
            # Protokoly
            for p in details.get('protocols', []):
                v = p.get('version', '')
                if v == "1.3": scan_data['protocols']['tls1_3'] = True
                elif v == "1.2": scan_data['protocols']['tls1_2'] = True
                elif v == "1.1": scan_data['protocols']['tls1_1'] = True
                elif v == "1.0": scan_data['protocols']['tls1_0'] = True
                elif v == "3.0": scan_data['protocols']['sslv3'] = True
                elif v == "2.0": scan_data['protocols']['sslv2'] = True

            # Cipher Suites
            # Qualys API formátuje suites trochu jinak, namapujeme je na náš vizuál
            cipher_tree = {}
            for suite_list in details.get('suites', []):
                proto_id = suite_list.get('protocol', 0)
                # Ošklivé API Qualysu: protocol ID se musí překládat (772 = TLS 1.3 atd.)
                proto_name = "Neznámý protokol"
                if proto_id == 772: proto_name = "TLSv1.3"
                elif proto_id == 771: proto_name = "TLSv1.2"
                elif proto_id == 770: proto_name = "TLSv1.1"
                elif proto_id == 769: proto_name = "TLSv1.0"
                elif proto_id == 768: proto_name = "SSLv3"
                elif proto_id == 2: proto_name = "SSLv2"
                
                cipher_list = []
                for s in suite_list.get('list', []):
                    # Získání hodnocení přímo od Qualysu (q=0 je insecure)
                    q = s.get('q', 1)
                    if q == 0: grade_label, grade_color = "INSECURE", "#E74C3C"
                    elif q == 1: grade_label, grade_color = "WEAK", "#F39C12"
                    else: grade_label, grade_color = "SECURE", "#2ECC71"
                    
                    cipher_list.append({
                        'name': s.get('name', 'Unknown'),
                        'grade_label': grade_label,
                        'grade_color': grade_color,
                        'grade_tag': "",
                        'kex_info': f"Kx={s.get('kxType', '?')} Au={s.get('auType', '?')}"
                    })
                
                if cipher_list:
                    cipher_tree[proto_name] = cipher_list
            
            scan_data['cipher_tree'] = cipher_tree
            scan_data['status'] = "Hotovo"
            
        except Exception as e:
            scan_data['status'] = "Chyba"
            scan_data['error'] = str(e)

        self.signals.result.emit(self.ip, self.port, scan_data)
        self.signals.finished.emit()


class TestSslWorker(QRunnable):
    """
    Worker využívající lokální nástroj testssl.sh.
    Skvělý pro interní IP adresy. Vyžaduje instalaci (brew install testssl).
    """
    def __init__(self, ip, port, signals):
        super().__init__()
        self.ip = ip
        self.port = str(port)
        self.signals = signals

    @Slot()
    def run(self):
        scan_data = {
            'ip': self.ip, 'port': self.port, 'domain': self.ip,
            'protocols': {}, 'cipher_tree': {},
            'check_time': datetime.now().strftime('%d.%m.%Y %H:%M:%S'),
            'status': "Hotovo"
        }

        # Kontrola závislostí na macOS
        testssl_bin = shutil.which("testssl.sh") or shutil.which("testssl")
        if not testssl_bin:
            scan_data['status'] = "Chyba"
            scan_data['error'] = "Nástroj 'testssl' nebyl nalezen. Nainstaluj ho pomocí: brew install testssl"
            self.signals.result.emit(self.ip, self.port, scan_data)
            self.signals.finished.emit()
            return

        try:
            import tempfile
            import json
            
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
                json_path = tmp.name

            # testssl.sh příkaz (rychlý scan protokolů a šifer)
            # --quiet: potlačí banner, -p: protokoly, -E: ciphers podle protokolů
            cmd = [testssl_bin, "--quiet", "-p", "-E", "--warnings", "off", "--jsonfile", json_path, f"{self.ip}:{self.port}"]
            
            scan_data['status'] = "TestSSL: Prověřuji..."
            self.signals.result.emit(self.ip, self.port, scan_data)
            
            subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            # Čtení JSON výsledků
            if os.path.exists(json_path):
                with open(json_path, 'r', encoding='utf-8') as f:
                    results = json.load(f)
                os.remove(json_path)
            else:
                raise Exception("Nepodařilo se vygenerovat JSON report.")

            cipher_tree = {}
            for item in results:
                id_val = item.get('id', '')
                finding = str(item.get('finding', ''))
                severity = item.get('severity', '')
                
                # Protokoly
                if id_val == "SSLv2" and "not offered" not in finding: scan_data['protocols']['sslv2'] = True
                elif id_val == "SSLv3" and "not offered" not in finding: scan_data['protocols']['sslv3'] = True
                elif id_val == "TLS1" and "not offered" not in finding: scan_data['protocols']['tls1_0'] = True
                elif id_val == "TLS1_1" and "not offered" not in finding: scan_data['protocols']['tls1_1'] = True
                elif id_val == "TLS1_2" and "not offered" not in finding: scan_data['protocols']['tls1_2'] = True
                elif id_val == "TLS1_3" and "not offered" not in finding: scan_data['protocols']['tls1_3'] = True
                
                # Ciphers (testssl je označuje jako cipher-<protokol>)
                if id_val.startswith("cipher-"):
                    proto_raw = id_val.split("-")[1] # např. TLS1.2
                    proto_name = proto_raw.replace("TLS1.", "TLSv1.").replace("TLS1", "TLSv1.0")
                    
                    if proto_name not in cipher_tree:
                        cipher_tree[proto_name] = []
                    
                    # TestSSL severity mapping: HIGH/CRITICAL -> INSECURE, MEDIUM -> WEAK, LOW/OK -> SECURE
                    if severity in ["CRITICAL", "HIGH"]: grade_label, grade_color = "INSECURE", "#E74C3C"
                    elif severity == "MEDIUM": grade_label, grade_color = "WEAK", "#F39C12"
                    else: grade_label, grade_color = "SECURE", "#2ECC71"
                    
                    cipher_tree[proto_name].append({
                        'name': finding,
                        'grade_label': grade_label,
                        'grade_color': grade_color,
                        'grade_tag': f"[{severity}]",
                        'kex_info': ""
                    })

            scan_data['cipher_tree'] = cipher_tree
            scan_data['status'] = "Hotovo"

        except Exception as e:
            scan_data['status'] = "Chyba"
            scan_data['error'] = str(e)[:100]

        self.signals.result.emit(self.ip, self.port, scan_data)
        self.signals.finished.emit()

class TlsAuditDialog(QDialog):
    """Dialog pro audit TLS a šifer - Vizuální shoda s verzí 2.1.4c."""
    def __init__(self, scan_results, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Inspektor TLS & Cipher Suites (Qualys Style)")
        self.resize(1150, 700) # Zvětšeno pro detaily
        self.scan_results = scan_results
        self.thread_pool = QThreadPool()
        self.item_map = {}
        self.init_ui()
        self.load_targets()

    def init_ui(self):
        """
        Inicializace UI dialogu pro TLS Audit.
        Verze 2.2.0: Tři nezávislé enginy pro skenování (Nmap, Qualys, TestSSL).
        """
        layout = QVBoxLayout(self)
        info_layout = QHBoxLayout()
        info_layout.addWidget(QLabel("<b>SSL/TLS Audit cílů (včetně Cipher Suites):</b>"))
        
        info_layout.addSpacing(15)
        info_layout.addWidget(QLabel("Engine:"))
        self.engine_combo = QComboBox()
        self.engine_combo.addItems([
            "Nmap (Rychlý lokální sken)", 
            "Qualys SSL Labs API (Veřejné cíle, detailní)",
            "TestSSL.sh (Detailní, pro lokální i veřejné)"
        ])
        info_layout.addWidget(self.engine_combo)
        
        info_layout.addStretch()
        
        self.filter_secure = QCheckBox("Skrýt bezpečné (A)")
        self.filter_secure.stateChanged.connect(self.apply_filters)
        self.filter_error = QCheckBox("Skrýt chyby")
        self.filter_error.setChecked(True)
        self.filter_error.stateChanged.connect(self.apply_filters)
        
        info_layout.addWidget(self.filter_secure)
        info_layout.addWidget(self.filter_error)
        self.status_label = QLabel("Připraveno")
        info_layout.addWidget(self.status_label)
        layout.addLayout(info_layout)

        # Manuální přidání cíle
        add_layout = QHBoxLayout()
        add_layout.addWidget(QLabel("Přidat cíl:"))
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("IP adresa nebo doména")
        
        self.port_input = QLineEdit()
        self.port_input.setFixedWidth(60)
        self.port_input.setText("443")
        self.port_input.setPlaceholderText("Port")
        
        self.add_btn = QPushButton("➕ Přidat")
        self.add_btn.clicked.connect(self.add_manual_target)
        
        add_layout.addWidget(self.target_input)
        add_layout.addWidget(self.port_input)
        add_layout.addWidget(self.add_btn)
        layout.addLayout(add_layout)

        # Tabulka
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels([
            "Cíl / Port / Protokol / Šifra", "Známka", 
            "SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"
        ])
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_context_menu)
        
        header = self.tree.header()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        
        for i in range(2, 8):
            header.setSectionResizeMode(i, QHeaderView.Fixed)
            header.resizeSection(i, 65)
            self.tree.headerItem().setTextAlignment(i, Qt.AlignCenter)
        
        layout.addWidget(self.tree)

        # Spodní tlačítka
        btn_layout = QHBoxLayout()
        
        self.check_all_btn = QPushButton("🔐 Prověřit vše")
        self.check_all_btn.clicked.connect(lambda: self.start_checks(False))
        btn_layout.addWidget(self.check_all_btn)

        self.check_new_btn = QPushButton("⏳ Prověřit neprověřené")
        self.check_new_btn.clicked.connect(lambda: self.start_checks(True))
        btn_layout.addWidget(self.check_new_btn)

        self.export_pdf_btn = QPushButton("📄 Exportovat PDF")
        self.export_pdf_btn.clicked.connect(self.export_to_pdf)
        btn_layout.addWidget(self.export_pdf_btn)
        
        close_btn = QPushButton("Zavřít")
        close_btn.clicked.connect(self.reject)
        btn_layout.addWidget(close_btn)
        
        layout.addLayout(btn_layout)

    def start_checks(self, only_new=False):
        """
        Spustí skenování s dynamickým výběrem workera podle ComboBoxu.
        """
        tasks = [k for k, v in self.item_map.items() if not only_new or "Čeká" in v.text(0)]
        if not tasks: return
        self.check_all_btn.setEnabled(False)
        self.check_new_btn.setEnabled(False)
        self.engine_combo.setEnabled(False) # Zamezení změny enginu během běhu
        self.processing_count = len(tasks)
        
        engine_idx = self.engine_combo.currentIndex()
        
        for (ip, port) in tasks:
            item = self.item_map[(ip, port)]
            
            if engine_idx == 0:
                engine_text = "Nmap"
                WorkerClass = TlsAuditWorker
            elif engine_idx == 1:
                engine_text = "Qualys API"
                WorkerClass = SslLabsWorker
            else:
                engine_text = "TestSSL"
                WorkerClass = TestSslWorker

            item.setText(0, f"Port {port} | Prověřuji ({engine_text})...")
            item.takeChildren()

            signals = WorkerSignals()
            signals.result.connect(self.update_result)
            signals.finished.connect(self.on_worker_finished)
            
            self.thread_pool.start(WorkerClass(ip, port, signals))

    def on_worker_finished(self):
        """Uvolní zámky UI po dokončení všech vláken."""
        self.processing_count -= 1
        if self.processing_count <= 0:
            self.check_all_btn.setEnabled(True)
            self.check_new_btn.setEnabled(True)
            self.engine_combo.setEnabled(True)
            self.status_label.setText("Hotovo.")

    def load_targets(self):
        """Načte cíle a vytvoří automatické sondy pro TLS audit."""
        self.tree.clear()
        self.item_map = {}
        saved_data = self.scan_results.get('tls_audit', {})
        
        targets_dict = {}
        tls_ports = ['443', '8443', '993', '995', '465', '587']
        
        # A) Z NMAP výsledků (TCP)
        tcp_data = self.scan_results.get('tcp', {})
        for ip, ports in tcp_data.items():
            if ip not in targets_dict: targets_dict[ip] = set()
            if 'tcp' in ports:
                for port, info in ports['tcp'].items():
                    if info.get('state') == 'open' and str(port) in tls_ports:
                        targets_dict[ip].add((str(port), "Čeká (Nmap)"))

        # B) AUTOMATICKÁ SONDA (Online hosti)
        all_ips = set()
        for phase in ['online', 'tcp', 'udp']:
            phase_data = self.scan_results.get(phase, {})
            if phase_data: all_ips.update(phase_data.keys())
            
        for ip in all_ips:
            if ip not in targets_dict: targets_dict[ip] = set()
            if not any(p[0] == '443' for p in targets_dict[ip]):
                targets_dict[ip].add(('443', "Čeká (Sonda)"))

        # C) Z HISTORIE / MANUÁLNÍ CÍLE (NOVÉ - FIX PERSISTENCE)
        # Projdeme uložené výsledky a přidáme ty, které nejsou v Nmapu (manuálně přidané)
        for key in saved_data.keys():
            try:
                # Klíč je ve formátu "IP:PORT"
                if ':' in key:
                    saved_ip, saved_port = key.split(':')
                    
                    if saved_ip not in targets_dict:
                        targets_dict[saved_ip] = set()
                    
                    # Zkontrolujeme, zda už tento port není v seznamu z Nmapu
                    is_present = any(p[0] == saved_port for p in targets_dict[saved_ip])
                    
                    if not is_present:
                        # Pokud není, přidáme ho jako "Načteno"
                        targets_dict[saved_ip].add((saved_port, "Načteno (Historie)"))
            except:
                continue

        # Řazení a vykreslení
        def ip_sort_key(ip):
            try: return tuple(int(part) for part in ip.split('.'))
            except: return (0, 0, 0, 0)
        
        for ip in sorted(targets_dict.keys(), key=ip_sort_key):
            ports = targets_dict[ip]
            if not ports: continue
            
            # IP Hlavička (Modrá)
            ip_item = QTreeWidgetItem(self.tree, [ip])
            ip_item.setFont(0, QFont("Arial", 11, QFont.Bold))
            ip_item.setForeground(0, QColor("#3498DB"))
            ip_item.setExpanded(True)
            
            for port, note in sorted(list(ports), key=lambda x: int(x[0])):
                # Port řádek (Oranžový)
                port_item = QTreeWidgetItem(ip_item)
                port_item.setText(0, f"Port {port} | {note}")
                port_item.setFont(0, QFont("Arial", 10, QFont.Bold))
                port_item.setForeground(0, QColor("#E67E22"))
                
                self.item_map[(ip, port)] = port_item
                
                # Načtení historie
                if f"{ip}:{port}" in saved_data:
                    self.update_result(ip, port, saved_data[f"{ip}:{port}"])

        self.apply_filters()

    def add_manual_target(self):
        """Manuálně přidá cíl do seznamu (čeká na spuštění tlačítkem)."""
        target = self.target_input.text().strip()
        port = self.port_input.text().strip()
        
        if not target or not port:
            return

        # Kontrola duplicit
        if (target, port) in self.item_map:
            QMessageBox.warning(self, "Info", "Tento cíl již v seznamu existuje.")
            return

        # 1. Najít nebo vytvořit IP uzel (Modrý design)
        ip_item = None
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            existing_text = root.child(i).text(0).split(' ')[0]
            if existing_text == target:
                ip_item = root.child(i)
                break
        
        if not ip_item:
            ip_item = QTreeWidgetItem(self.tree, [target])
            ip_item.setFont(0, QFont("Arial", 11, QFont.Bold))
            ip_item.setForeground(0, QColor("#3498DB"))
            ip_item.setExpanded(True)

        # 2. Přidat port (Oranžový design) - STAV ČEKÁ
        port_item = QTreeWidgetItem(ip_item)
        port_item.setText(0, f"Port {port} | Čeká (Manuální)") # Důležité: Text obsahuje "Čeká"
        port_item.setFont(0, QFont("Arial", 10, QFont.Bold))
        port_item.setForeground(0, QColor("#E67E22"))
        
        # Přidání do mapy, aby ho našla metoda start_checks()
        self.item_map[(target, port)] = port_item
        
        self.target_input.clear()
        
        # UPRAVENO: Nespouštíme hned worker.
        # Uživatel musí kliknout na "Prověřit neprověřené", což zavolá start_checks(),
        # která najde všechny položky s textem "Čeká" v item_map.
        self.status_label.setText(f"Přidán cíl: {target}:{port}. Klikněte na 'Prověřit neprověřené'.")

    def calculate_grade(self, results):
        """
        Vypočítá TLS známku (A-F).
        UPRAVENO: Rozlišuje chybu spojení (ERR) od špatné konfigurace (F).
        """
        # Pokud se nepodařilo detekovat žádný protokol, jde o chybu spojení, ne známku F
        if not any(results.values()):
            return "ERR", "#95A5A6" # Šedá barva pro chybu
        
        # SSLv3 je okamžitá smrt (F)
        if results.get("sslv3"): return "F", "#C0392B"
        if results.get("tls1_0") or results.get("tls1_1"): return "F", "#E74C3C"
        if not results.get("tls1_2") and not results.get("tls1_3"): return "F", "#E74C3C"
        if results.get("tls1_3") and not results.get("tls1_0"): return "A", "#2ECC71"
        return "B", "#27AE60"

    @Slot(str, str, dict)
    def update_result(self, ip, port, data):
        item = self.item_map.get((ip, port))
        if not item: return
        
        if 'tls_audit' not in self.scan_results: self.scan_results['tls_audit'] = {}
        self.scan_results['tls_audit'][f"{ip}:{port}"] = data
        
        domain = data.get('domain', '-')
        parent = item.parent()
        if parent:
            parent.setText(0, f"{ip} ({domain})" if domain != "-" else ip)

        check_time = data.get('check_time', 'Čeká...')
        item.setText(0, f"Port {port} | {check_time}")
        item.takeChildren()

        is_connection_error = data.get('status') == "Chyba spojení"

        if 'protocols' in data and not is_connection_error:
            grade, color = self.calculate_grade(data['protocols'])
            
            if grade == "ERR":
                item.setText(1, "Chyba")
                item.setFont(1, QFont("Arial", 10))
            else:
                item.setText(1, grade)
                item.setFont(1, QFont("Arial", 12, QFont.Bold))
            
            item.setForeground(1, QColor(color))
            item.setTextAlignment(1, Qt.AlignCenter)

            p = data['protocols']
            # UPRAVENO: Mapování pro 6 protokolů (včetně SSLv2/v3)
            mapping = [
                ("sslv2", 2), ("sslv3", 3), 
                ("tls1_0", 4), ("tls1_1", 5), 
                ("tls1_2", 6), ("tls1_3", 7)
            ]
            
            for key, col in mapping:
                supported = p.get(key)
                text = "-" if grade == "ERR" else ("✅" if supported else "❌")
                item.setText(col, text)
                item.setTextAlignment(col, Qt.AlignCenter)
                
                # Červená pro nebezpečné (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
                if key in ["sslv2", "sslv3", "tls1_0", "tls1_1"] and supported:
                    item.setForeground(col, QColor("#E74C3C"))
                else:
                    item.setForeground(col, QColor("#f0f0f0"))

            # 3. Strom šifer s vizuálním seskupením a počty
            cipher_tree = data.get('cipher_tree', {})
            sorted_protos = sorted(cipher_tree.keys(), reverse=True)
            
            proto_safety = {
                "TLSv1.3": ("SECURE", "#2ECC71", "🔒"),
                "TLSv1.2": ("SECURE", "#27AE60", "🔒"),
                "TLSv1.1": ("INSECURE", "#E67E22", "🔓"),
                "TLSv1.0": ("INSECURE", "#C0392B", "🔓"),
                "SSLv3":   ("INSECURE", "#C0392B", "🔓"),
                "SSLv2":   ("INSECURE", "#C0392B", "🔓")
            }
            
            rank_map = {"SECURE": 0, "WEAK": 1, "INSECURE": 2}

            for proto in sorted_protos:
                ciphers = cipher_tree[proto]
                
                ciphers.sort(key=lambda x: (
                    rank_map.get(x.get('grade_label', 'INSECURE'), 3), 
                    x.get('name', '')
                ))

                group_counts = {}
                for c in ciphers:
                    lbl = c.get('grade_label', 'INSECURE')
                    group_counts[lbl] = group_counts.get(lbl, 0) + 1

                safety_label, safety_color, icon = proto_safety.get(proto, ("UNKNOWN", "#95A5A6", "?"))
                
                proto_item = QTreeWidgetItem(item)
                proto_item.setText(0, f"{icon} {proto}   [{safety_label}]")
                proto_item.setFont(0, QFont("Arial", 10, QFont.Bold))
                proto_item.setForeground(0, QColor(safety_color))
                proto_item.setExpanded(True)
                
                last_group = None
                
                for c in ciphers:
                    current_group = c.get('grade_label', 'INSECURE')
                    
                    if current_group != last_group:
                        separator = QTreeWidgetItem(proto_item)
                        
                        sep_title = current_group
                        sep_color = "#999"
                        
                        if current_group == "SECURE": 
                            sep_title = "Strong / Secure Suites"
                            sep_color = "#27AE60"
                        elif current_group == "WEAK": 
                            sep_title = "Weak Suites"
                            sep_color = "#F39C12"
                        elif current_group == "INSECURE": 
                            sep_title = "Insecure Suites"
                            sep_color = "#E74C3C"
                        
                        count = group_counts.get(current_group, 0)
                        separator.setText(0, f"▼ {sep_title} ({count})")
                        
                        separator.setForeground(0, QColor(sep_color))
                        separator.setFont(0, QFont("Arial", 9, QFont.Bold))
                        separator.setFirstColumnSpanned(True)
                        separator.setFlags(Qt.ItemIsEnabled)
                        
                        last_group = current_group

                    c_name = c.get('name', 'Unknown')
                    c_kex = c.get('kex_info', '')
                    
                    name_display = f"  {c_name}"
                    if c_kex:
                        name_display += f" ({c_kex})"
                    
                    tag = c.get('grade_tag')
                    if tag:
                        name_display += f" {tag}"
                        
                    cipher_item = QTreeWidgetItem(proto_item)
                    cipher_item.setText(0, name_display)
                    
                    c_color = c.get('grade_color')
                    if not c_color:
                        old_grade = c.get('grade', 'C')
                        if old_grade == 'A': c_color = "#2ECC71"
                        elif old_grade in ['B', 'C']: c_color = "#F39C12"
                        elif old_grade in ['D', 'E', 'F']: c_color = "#E74C3C"
                        else: c_color = "#95A5A6"
                    
                    cipher_item.setForeground(0, QColor(c_color))
                    cipher_item.setFont(0, QFont("Consolas", 9))

        else:
            item.setText(1, "Chyba")
            item.setForeground(1, QColor("#95A5A6"))
            item.setToolTip(1, data.get('error', 'Chyba spojení'))
            
            # Vyčistit sloupce pro chybu (všech 6 protokolů)
            for col in range(2, 8):
                item.setText(col, "-")
                item.setForeground(col, QColor("#95A5A6"))
                item.setTextAlignment(col, Qt.AlignCenter)
            
        self.apply_filters()
        
    # --- Zbytek třídy (apply_filters, load_targets, atd.) zůstává stejný ---
    def apply_filters(self):
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            ip_item = root.child(i)
            ip_visible = False
            for j in range(ip_item.childCount()):
                port_item = ip_item.child(j)
                grade = port_item.text(1)
                hide = (grade == "A" and self.filter_secure.isChecked()) or \
                       ("Chyba" in grade and self.filter_error.isChecked())
                port_item.setHidden(hide)
                if not hide: ip_visible = True
            ip_item.setHidden(not ip_visible)

    def show_context_menu(self, position):
        item = self.tree.itemAt(position)
        if not item: return
        menu = QMenu()
        
        if item.parent() and not item.parent().parent(): # Je to Port položka
             remove_action = menu.addAction("❌ Odstranit vybrané")
             if menu.exec(self.tree.mapToGlobal(position)) == remove_action:
                self.remove_target(item)
        elif not item.parent(): # IP položka
             remove_action = menu.addAction("❌ Odstranit vybrané")
             if menu.exec(self.tree.mapToGlobal(position)) == remove_action:
                self.remove_target(item)

    def remove_target(self, item):
        if item.parent(): # Je to port
            ip = item.parent().text(0).split(' ')[0]
            port = item.text(0).split('|')[0].replace("Port ", "").strip()
            self.item_map.pop((ip, port), None)
            if 'tls_audit' in self.scan_results:
                self.scan_results['tls_audit'].pop(f"{ip}:{port}", None)
            item.parent().removeChild(item)
        else: # Je to IP
            ip = item.text(0).split(' ')[0]
            keys_to_remove = [k for k in self.item_map.keys() if k[0] == ip]
            for k in keys_to_remove: self.item_map.pop(k, None)
            if 'tls_audit' in self.scan_results:
                for k in keys_to_remove: self.scan_results['tls_audit'].pop(f"{k[0]}:{k[1]}", None)
            self.tree.takeTopLevelItem(self.tree.indexOfTopLevelItem(item))
            
    def export_to_pdf(self):
        """
        Vygeneruje profesionální vícestránkový PDF report pro TLS Audit.
        Inspirováno Qualys SSL Labs reportem.
        UPRAVENO: Přidáno vizuální seskupování Cipher Suites (Secure/Weak/Insecure).
        """
        # 1. Sběr dat pro výběrový dialog s aplikací filtrů
        available_data = []
        saved_data = self.scan_results.get('tls_audit', {})
        
        # Získání stavu filtrů
        hide_secure = self.filter_secure.isChecked()
        hide_errors = self.filter_error.isChecked()

        for key, data in saved_data.items():
            # Musíme zjistit stav/známku pro aplikaci filtru
            should_include = True
            
            is_connection_error = data.get('status') == "Chyba spojení"
            grade = "N/A"

            if 'protocols' in data and not is_connection_error:
                grade_val, _ = self.calculate_grade(data['protocols'])
                if grade_val == "ERR":
                    grade = "Chyba"
                else:
                    grade = grade_val
            else:
                grade = "Chyba"

            # Logika filtrování
            if grade == "A" and hide_secure:
                should_include = False
            elif "Chyba" in grade and hide_errors:
                should_include = False
            
            if should_include:
                available_data.append({
                    'name': key, 
                    'data': data
                })
        
        if not available_data:
            QMessageBox.warning(self, "Export", "Nejsou k dispozici žádná data (nebo jsou všechna skryta filtry).")
            return

        # 2. Mini-dialog pro výběr cílů
        selector = QDialog(self)
        selector.setWindowTitle("Výběr cílů pro TLS Report")
        selector.resize(450, 550)
        sel_layout = QVBoxLayout(selector)
        sel_layout.addWidget(QLabel("<b>Vyberte cíle pro zahrnutí do SSL/TLS reportu:</b>"))
        
        list_widget = QListWidget()
        for d in available_data:
            domain_info = f" [{d['data'].get('domain', '-')}]" if d['data'].get('domain') != "-" else ""
            it = QListWidgetItem(f"{d['name']}{domain_info}")
            it.setCheckState(Qt.Checked)
            it.setData(Qt.UserRole, d)
            list_widget.addItem(it)
        sel_layout.addWidget(list_widget)
        
        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(selector.accept)
        btns.rejected.connect(selector.reject)
        sel_layout.addWidget(btns)
        
        if selector.exec() != QDialog.Accepted: return
            
        selected_targets = [list_widget.item(i).data(Qt.UserRole) for i in range(list_widget.count()) 
                            if list_widget.item(i).checkState() == Qt.Checked]
                
        if not selected_targets: return

        path, _ = QFileDialog.getSaveFileName(self, "Uložit TLS Report", "SSL_TLS_Audit_Report.pdf", "PDF Files (*.pdf)")
        if not path: return

        # 3. HTML Šablona
        full_html = "<html><head><style>"
        full_html += """
                body { font-family: Arial, sans-serif; color: #333; line-height: 1.4; padding: 0; margin: 0; }
                .page { page-break-after: always; padding: 40px; box-sizing: border-box; min-height: 980px; }
                .page:last-child { page-break-after: auto; }
                .header { display: flex; align-items: center; border-bottom: 2px solid #eee; padding-bottom: 15px; margin-bottom: 20px; }
                .grade { font-size: 70px; font-weight: bold; color: white; width: 120px; height: 120px; 
                         display: flex; align-items: center; justify-content: center; border-radius: 10px; 
                         margin-right: 30px; flex-shrink: 0; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
                .summary-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                .summary-table th, .summary-table td { padding: 12px; border: 1px solid #eee; text-align: left; font-size: 12px; }
                .summary-badge { padding: 4px 10px; border-radius: 4px; color: white; font-weight: bold; }
                
                .proto-table { width: 100%; border-collapse: collapse; margin-top: 15px; margin-bottom: 25px; }
                .proto-table td { padding: 8px; border-bottom: 1px solid #eee; font-size: 13px; }
                .proto-table .label { font-weight: bold; width: 200px; }
                
                .cipher-table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 11px; }
                .cipher-table th { background: #f8f9fa; padding: 6px; text-align: left; border-bottom: 2px solid #ddd; }
                .cipher-table td { padding: 4px 6px; border-bottom: 1px solid #f1f1f1; }
                .proto-header { background-color: #eef4f9; color: #2980B9; font-weight: bold; padding: 8px !important; }
                
                .status-yes { color: #27AE60; font-weight: bold; }
                .status-no { color: #BDC3C7; }
                .status-weak { color: #E74C3C; font-weight: bold; }
                
                .cipher-secure { color: #27AE60; }
                .cipher-weak { color: #F39C12; }
                .cipher-insecure { color: #E74C3C; font-weight: bold; }
                
                .recommendation-box { margin-top: 30px; padding: 20px; border: 1px solid #3498DB; 
                                     border-left: 10px solid #3498DB; background: #f0f7fb; }
                .links-box { margin-top: 30px; padding-top: 15px; border-top: 1px solid #eee; font-size: 11px; color: #555; }
        """
        full_html += "</style></head><body>"

        # --- STRANA 1: MANAŽERSKÉ SHRNUTÍ ---
        full_html += f"""
        <div class="page">
            <h1 style="color:#2C3E50;">SSL/TLS Security Audit Report</h1>
            <p>Datum vygenerování: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}</p>
            <h3 style="margin-top:40px; border-bottom: 2px solid #3498DB; padding-bottom:10px;">Souhrnné hodnocení cílů</h3>
            <table class="summary-table">
                <tr><th>IP:Port</th><th>Doménové jméno</th><th style="text-align:center;">Známka</th></tr>"""
        
        for target in selected_targets:
            if 'protocols' in target['data']:
                g, c = self.calculate_grade(target['data']['protocols'])
                if g == "ERR": 
                    g, c = "ERR", "#95A5A6"
            else:
                 g, c = "ERR", "#95A5A6"

            full_html += f"""
                <tr>
                    <td><strong>{target['name']}</strong></td>
                    <td>{target['data'].get('domain', '-')}</td>
                    <td style="text-align:center;"><span class="summary-badge" style="background-color:{c};">{g}</span></td>
                </tr>"""
        full_html += "</table><p style='margin-top:40px; color:#666;'>Tento report hodnotí podporu TLS protokolů a kvalitu šifrovacích sad (Cipher Suites).</p></div>"

        # --- DETAILNÍ STRANY ---
        for target in selected_targets:
            t_data = target['data']
            protocols = t_data.get('protocols', {})
            cipher_tree = t_data.get('cipher_tree', {})
            
            grade, color = "ERR", "#95A5A6"
            if protocols:
                grade, color = self.calculate_grade(protocols)
            
            # --- Generování tabulky Cipher Suites ---
            ciphers_html = ""
            if cipher_tree:
                ciphers_html += """
                <h3 style="color:#2980B9; margin-top:30px; border-bottom:1px solid #eee;">Cipher Suites (Šifrovací sady)</h3>
                <table class="cipher-table">
                """
                sorted_protos = sorted(cipher_tree.keys(), reverse=True)
                
                # Mapa pro řazení šifer (nejdříve SECURE, pak WEAK, pak INSECURE)
                rank_map = {"SECURE": 0, "WEAK": 1, "INSECURE": 2}

                for proto in sorted_protos:
                    ciphers = cipher_tree[proto]
                    
                    # 1. Seřadit šifry podle síly a pak podle jména
                    ciphers.sort(key=lambda x: (
                        rank_map.get(x.get('grade_label', 'INSECURE'), 3), 
                        x.get('name', '')
                    ))

                    # 2. Hlavička protokolu
                    ciphers_html += f"<tr><td colspan='2' class='proto-header'>{proto}</td></tr>"
                    
                    # 3. Iterace a vkládání vizuálních oddělovačů (Headers)
                    last_group = None
                    
                    for c in ciphers:
                        current_group = c.get('grade_label', 'INSECURE')
                        
                        # Pokud se změnila skupina, vložíme řádek s nadpisem
                        if current_group != last_group:
                            group_color = "#777"
                            if current_group == "SECURE": group_color = "#27AE60"
                            elif current_group == "WEAK": group_color = "#F39C12"
                            elif current_group == "INSECURE": group_color = "#E74C3C"
                            
                            group_title = current_group
                            if current_group == "SECURE": group_title = "Strong / Secure Suites"
                            elif current_group == "WEAK": group_title = "Weak Suites"
                            elif current_group == "INSECURE": group_title = "Insecure Suites"
                            
                            ciphers_html += f"""
                            <tr><td colspan='2' style='background:#fafafa; color:{group_color}; font-size:10px; font-weight:bold; border-bottom:1px solid #eee; padding-top:8px; padding-left:8px;'>
                                ▼ {group_title}
                            </td></tr>
                            """
                            last_group = current_group

                        # Styl řádku šifry
                        style_class = "cipher-secure"
                        if current_group == "WEAK": style_class = "cipher-weak"
                        elif current_group == "INSECURE": style_class = "cipher-insecure"
                        
                        name_display = c.get('name', 'Unknown')
                        c_kex = c.get('kex_info', '')
                        if c_kex:
                            name_display += f" <span style='color:#777;'>({c_kex})</span>"
                            
                        # Zobrazení tagu (např. WEAK - No FS)
                        grade_display = current_group
                        tag = c.get('grade_tag', '')
                        if tag:
                            grade_display = f"{current_group} {tag}"
                            
                        ciphers_html += f"""
                        <tr>
                            <td style="width:75%; font-family:monospace; padding-left:20px;">{name_display}</td>
                            <td class="{style_class}" style="text-align:right;">{grade_display}</td>
                        </tr>
                        """
                ciphers_html += "</table>"
            else:
                ciphers_html = "<p>Žádná data o šifrách.</p>"

            # --- Doporučení ---
            remediation = []
            if grade == "ERR":
                remediation.append("<li><b>Chyba spojení:</b> Nepodařilo se navázat zabezpečené spojení.</li>")
            else:
                if protocols.get("tls1_0") or protocols.get("tls1_1"):
                    remediation.append("<li><b>Kritické:</b> Deaktivujte podporu TLS 1.0 a TLS 1.1.</li>")
                if not protocols.get("tls1_3"):
                    remediation.append("<li><b>Doporučení:</b> Aktivujte podporu TLS 1.3.</li>")
                if not remediation:
                    remediation.append("<li>Konfigurace SSL/TLS je v souladu se standardy.</li>")

            full_html += f"""
            <div class="page">
                <div class="header">
                    <div class="grade" style="background-color: {color};">{grade}</div>
                    <div>
                        <h2 style="margin:0;">Detailní analýza: {target['name']}</h2>
                        <p style="margin:5px 0;">Doména: <strong>{t_data.get('domain', '-')}</strong></p>
                        <p style="font-size:11px; color:#7F8C8D;">Čas měření: {t_data.get('check_time', '-')}</p>
                    </div>
                </div>
                
                <h3 style="color:#2980B9; border-bottom:1px solid #eee; padding-bottom:5px;">Konfigurace protokolů</h3>
                <table class="proto-table">
                    <tr><td class="label">TLS 1.3</td><td class="{'status-yes' if protocols.get('tls1_3') else 'status-no'}">{'ANO' if protocols.get('tls1_3') else 'NE'}</td></tr>
                    <tr><td class="label">TLS 1.2</td><td class="{'status-yes' if protocols.get('tls1_2') else 'status-no'}">{'ANO' if protocols.get('tls1_2') else 'NE'}</td></tr>
                    <tr><td class="label">TLS 1.1</td><td class="{'status-weak' if protocols.get('tls1_1') else 'status-no'}">{'ANO (Zranitelné)' if protocols.get('tls1_1') else 'NE'}</td></tr>
                    <tr><td class="label">TLS 1.0</td><td class="{'status-weak' if protocols.get('tls1_0') else 'status-no'}">{'ANO (Zranitelné)' if protocols.get('tls1_0') else 'NE'}</td></tr>
                </table>

                {ciphers_html}

                <div class="recommendation-box">
                    <h3 style="margin-top:0; color:#2980B9;">🛠️ Doporučení</h3>
                    <ul style="margin-bottom:0; padding-left:20px;">
                        {''.join(remediation)}
                    </ul>
                </div>
            </div>"""

        full_html += "</body></html>"

        # 4. Renderování
        self.status_label.setText(f"Generuji PDF ({len(selected_targets) + 1} stran)...")
        self.pdf_page = QWebEnginePage()
        self.pdf_page.setHtml(full_html)
        self.pdf_page.loadFinished.connect(lambda ok: self.pdf_page.printToPdf(path) if ok else None)
            
class SecurityHeadersDialog(QDialog):
    """Dialog pro kontrolu Security Headers - Vizuální shoda s SSL Inspektorem."""
    def __init__(self, scan_results, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Inspektor Security Headers")
        self.resize(1400, 750)
        self.scan_results = scan_results
        self.thread_pool = QThreadPool()
        self.item_map = {}
        
        self.init_ui()
        self.load_targets()

    def init_ui(self):
        """
        Inicializace UI s automaticky aktivovaným filtrem chyb.
        Verze 2.1.4c: Checkbox "Skrýt chyby" je nyní ve výchozím stavu zaškrtnut.
        """
        layout = QVBoxLayout(self)
        
        # Horní panel
        info_layout = QHBoxLayout()
        info_layout.addWidget(QLabel("<b>Webové hlavičky cílů:</b>"))
        info_layout.addStretch()
        
        # Filtry
        self.filter_missing = QCheckBox("Skrýt plně zabezpečené (A)")
        self.filter_missing.stateChanged.connect(self.apply_filters)
        
        # SURGICAL FIX: Checkbox pro chyby je nyní automaticky zaškrtnut
        self.filter_error = QCheckBox("Skrýt chyby")
        self.filter_error.setChecked(True) 
        self.filter_error.stateChanged.connect(self.apply_filters)
        
        info_layout.addWidget(self.filter_missing)
        info_layout.addWidget(self.filter_error)
        
        self.status_label = QLabel("Připraveno")
        info_layout.addWidget(self.status_label)
        layout.addLayout(info_layout)

        # Správa cílů (Add)
        add_layout = QHBoxLayout()
        add_layout.addWidget(QLabel("Přidat cíl:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("IP adresa")
        self.port_input = QLineEdit()
        self.port_input.setFixedWidth(60)
        self.port_input.setText("443")
        self.add_btn = QPushButton("➕ Přidat")
        self.add_btn.clicked.connect(self.add_target)
        add_layout.addWidget(self.target_input)
        add_layout.addWidget(self.port_input)
        add_layout.addWidget(self.add_btn)
        layout.addLayout(add_layout)

        # Tabulka - 8 sloupců
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels([
            "Cíl / Port / Server / Čas", "Známka", "HSTS", "CSP", "X-Frame", "X-Content", "Referrer", "Permissions"
        ])
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_context_menu)
        
        header = self.tree.header()
        header.setStretchLastSection(False)
        
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents) 
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.tree.headerItem().setTextAlignment(1, Qt.AlignCenter)
        
        font_metrics = self.tree.fontMetrics()
        target_width = font_metrics.horizontalAdvance("Permissions") + 5
        
        for i in range(2, 8):
            header.setSectionResizeMode(i, QHeaderView.Fixed)
            header.resizeSection(i, target_width)
            self.tree.headerItem().setTextAlignment(i, Qt.AlignCenter)
            
        layout.addWidget(self.tree)

        # Spodní tlačítka
        btn_layout = QHBoxLayout()
        self.check_all_btn = QPushButton("🛡️ Prověřit vše")
        self.check_all_btn.clicked.connect(lambda: self.start_checks(only_new=False))
        btn_layout.addWidget(self.check_all_btn)

        self.check_new_btn = QPushButton("⏳ Prověřit neprověřené")
        self.check_new_btn.clicked.connect(lambda: self.start_checks(only_new=True))
        btn_layout.addWidget(self.check_new_btn)
        
        self.export_pdf_btn = QPushButton("📄 Exportovat PDF")
        self.export_pdf_btn.clicked.connect(self.export_to_pdf)
        btn_layout.addWidget(self.export_pdf_btn)
        
        close_btn = QPushButton("Zavřít")
        close_btn.clicked.connect(self.reject)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)
        
        self.resize(1050, 600)

    def load_targets(self):
        """Načte cíle z Nmapu a vytvoří automatické HTTPS sondy pro všechny online IP."""
        self.tree.clear()
        self.item_map = {}
        saved_data = self.scan_results.get('security_headers', {})
        
        targets_dict = {}
        web_ports = ['80', '443', '8080', '8443']
        
        # A) Z NMAP (Identifikované otevřené porty)
        tcp_data = self.scan_results.get('tcp', {})
        for ip, ports in tcp_data.items():
            if ip not in targets_dict: targets_dict[ip] = set()
            if 'tcp' in ports:
                for port, info in ports['tcp'].items():
                    state = info.get('state')
                    if state == 'open' and str(port) in web_ports:
                        targets_dict[ip].add((str(port), "Čeká (Nmap)"))

        # B) AUTOMATICKÁ SONDA (Pro každou online IP zkusíme HTTPS)
        all_ips = set()
        for phase in ['online', 'tcp', 'udp']:
            phase_data = self.scan_results.get(phase, {})
            if phase_data: all_ips.update(phase_data.keys())
            
        for ip in all_ips:
            if ip not in targets_dict: targets_dict[ip] = set()
            # Pokud IP nemá z Nmapu port 80 nebo 443, přidáme sondu na 443
            has_web = any(p[0] in ['80', '443'] for p in targets_dict[ip])
            if not has_web:
                targets_dict[ip].add(('443', "Čeká (Sonda)"))

        # Řazení IP adres
        def ip_sort_key(ip):
            try: return tuple(int(part) for part in ip.split('.'))
            except: return (0, 0, 0, 0)
        sorted_ips = sorted(targets_dict.keys(), key=ip_sort_key)

        # Vykreslení (Vizuální shoda s certifikáty)
        for ip in sorted_ips:
            ports = targets_dict[ip]
            if not ports: continue
            
            # DESIGN: Modrá hlavička IP
            ip_item = QTreeWidgetItem(self.tree, [ip])
            ip_item.setFont(0, QFont("Arial", 11, QFont.Bold))
            ip_item.setForeground(0, QColor("#3498DB"))
            ip_item.setExpanded(True)
            
            # Seřadit porty numericky
            sorted_ports = sorted(list(ports), key=lambda x: int(x[0]))
            
            for port, note in sorted_ports:
                # DESIGN: Oranžový port
                port_item = QTreeWidgetItem(ip_item, [f"Port {port}", note])
                port_item.setFont(0, QFont("Arial", 10, QFont.Bold))
                port_item.setForeground(0, QColor("#E67E22"))
                
                # Pokud je to sonda, označíme status šedě
                if "Sonda" in note:
                    port_item.setForeground(1, QColor("#95A5A6"))
                
                self.item_map[(ip, port)] = port_item
                
                # PERSISTENCE: Načtení dříve uložených výsledků z projektu
                if f"{ip}:{port}" in saved_data:
                    self.update_result(ip, port, saved_data[f"{ip}:{port}"])

        count = len(self.item_map)
        if count == 0:
            self.status_label.setText("Nebyly nalezeny žádné webové služby.")
        else:
            self.status_label.setText(f"Načteno {count} služeb na {len(sorted_ips)} IP adresách.")

    def apply_filters(self):
        """
        Projde strom a skryje řádky podle nastavení filtrů (Zabezpečené / Chyby).
        """
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            ip_item = root.child(i)
            ip_visible = False
            
            for j in range(ip_item.childCount()):
                port_item = ip_item.child(j)
                status_val = port_item.text(1) # Sloupec "Známka"
                
                hide_secure = (status_val == "A" and self.filter_missing.isChecked())
                # Skrýváme pokud text obsahuje "Chyba" (Chyba spojení) a je zaškrtnut filtr
                hide_error = ("Chyba" in status_val and self.filter_error.isChecked())
                
                should_hide = hide_secure or hide_error
                
                port_item.setHidden(should_hide)
                if not should_hide: 
                    ip_visible = True
                    
            # Celou IP adresu skryjeme pouze, pokud jsou skryty všechny její porty
            ip_item.setHidden(not ip_visible)

    def start_checks(self, only_new=False):
        """Spustí prověření. Pokud only_new=True, přeskočí již prověřené cíle."""
        tasks = []
        for (ip, port), item in self.item_map.items():
            current_status = item.text(1)
            # Neprověřené jsou ty, co mají "Čeká..." nebo "Chyba spojení" (pokud chceme retry)
            if only_new:
                if "Čeká" in current_status:
                    tasks.append((ip, port))
            else:
                tasks.append((ip, port))

        if not tasks:
            self.status_label.setText("Žádné nové cíle k prověření.")
            return

        self.check_all_btn.setEnabled(False)
        self.check_new_btn.setEnabled(False)
        self.status_label.setText(f"Prověřuji ({len(tasks)})...")
        self.processing_count = len(tasks)
        
        for (ip, port) in tasks:
            signals = WorkerSignals()
            signals.result.connect(self.update_result)
            signals.finished.connect(self.on_worker_finished)
            self.thread_pool.start(SecurityHeadersWorker(ip, port, signals))

    @Slot(str, str, dict)
    def update_result(self, ip, port, data):
        """
        Aktualizuje řádek s fixem pro zobrazení času i u chybových stavů.
        Verze 2.1.4a: Timestamp se generuje vždy při dokončení testu.
        """
        item = self.item_map.get((ip, port))
        if not item:
            return
        
        # 1. SURGICAL FIX: Časové razítko se generuje pro KAŽDÝ výsledek z workeru
        if 'check_time' not in data:
            data['check_time'] = datetime.now().strftime('%d.%m.%Y %H:%M:%S')

        # 2. Persistence
        if 'security_headers' not in self.scan_results: 
            self.scan_results['security_headers'] = {}
        self.scan_results['security_headers'][f"{ip}:{port}"] = data
        
        # 3. Doména v hlavičce (rodič)
        domain = data.get('domain', '-')
        parent = item.parent()
        if parent:
            parent.setText(0, f"{ip} ({domain})" if domain != "-" else ip)

        # 4. Sloučení informací (Port / Server / Čas) - Čas je nyní vždy přítomen
        server = data.get('server', '-')
        check_time = data.get('check_time', 'Čeká...')
        item.setText(0, f"Port {port} | Server: {server} | {check_time}")

        # 5. Známka (Grade) nebo Stav chyby
        status_text = data.get('status', 'Neznámý')
        item.setTextAlignment(1, Qt.AlignCenter)
        
        if 'headers' in data:
            grade, color = self.calculate_grade(data['headers'])
            item.setText(1, grade)
            item.setForeground(1, QColor(color))
            item.setFont(1, QFont("Arial", 12, QFont.Bold))
        else:
            # Pokud je to chyba, zobrazíme ji, ale čas v sloupci 0 už bude správný
            display_status = "Chyba" if status_text == "Chyba spojení" else status_text
            item.setText(1, display_status)
            item.setForeground(1, QColor("#E74C3C") if display_status == "Chyba" else QColor("#95A5A6"))
            item.setFont(1, QFont("Arial", 10))

        # 6. Vyplnění technických sloupců (jen pokud máme data)
        if 'headers' in data:
            h = data['headers']
            mapping = [
                ("Strict-Transport-Security", 2), ("Content-Security-Policy", 3),
                ("X-Frame-Options", 4), ("X-Content-Type-Options", 5),
                ("Referrer-Policy", 6), ("Permissions-Policy", 7)
            ]
            for h_name, col_idx in mapping:
                val = h.get(h_name, "CHYBÍ")
                item.setText(col_idx, "✅" if val != "CHYBÍ" else "❌")
                item.setTextAlignment(col_idx, Qt.AlignCenter)
        
        self.apply_filters()

    def on_worker_finished(self):
        self.processing_count -= 1
        if self.processing_count <= 0: 
            self.check_all_btn.setEnabled(True)
            self.check_new_btn.setEnabled(True)
            self.status_label.setText("Hotovo.")
            
    def add_target(self):
        """Manuálně přidá cíl do auditu hlaviček."""
        ip = self.target_input.text().strip()
        port = self.port_input.text().strip()
        
        if not ip or not port:
            return

        # Kontrola, zda už neexistuje
        if (ip, port) in self.item_map:
            QMessageBox.warning(self, "Info", "Tento cíl již v seznamu existuje.")
            return

        # Najít nebo vytvořit IP uzel (Modrý design)
        ip_item = None
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            if root.child(i).text(0) == ip:
                ip_item = root.child(i)
                break
        
        if not ip_item:
            ip_item = QTreeWidgetItem(self.tree, [ip])
            ip_item.setFont(0, QFont("Arial", 11, QFont.Bold))
            ip_item.setForeground(0, QColor("#3498DB"))
            ip_item.setExpanded(True)

        # Přidat port (Oranžový design)
        port_item = QTreeWidgetItem(ip_item, [f"Port {port}", "Čeká (Manuální)"])
        port_item.setFont(0, QFont("Arial", 10, QFont.Bold))
        port_item.setForeground(0, QColor("#E67E22"))
        
        self.item_map[(ip, port)] = port_item
        self.target_input.clear()
        self.status_label.setText(f"Přidán cíl: {ip}:{port}")

    def show_context_menu(self, position):
        """Zobrazí menu pro odstranění cíle."""
        item = self.tree.itemAt(position)
        if not item:
            return
            
        menu = QMenu()
        remove_action = menu.addAction("❌ Odstranit vybrané")
        action = menu.exec(self.tree.mapToGlobal(position))
        
        if action == remove_action:
            self.remove_target(item)

    def remove_target(self, item):
        """Odstraní cíl z UI, mapy i persistence."""
        # Pokud je to IP (rodič)
        if item.childCount() > 0 or not item.parent():
            ip = item.text(0)
            # Odstranit všechny porty dané IP z mapy a persistence
            keys_to_remove = [k for k in self.item_map.keys() if k[0] == ip]
            for k in keys_to_remove:
                del self.item_map[k]
                if 'security_headers' in self.scan_results:
                    self.scan_results['security_headers'].pop(f"{k[0]}:{k[1]}", None)
            
            index = self.tree.indexOfTopLevelItem(item)
            self.tree.takeTopLevelItem(index)
            
        # Pokud je to konkrétní port (dítě)
        else:
            ip = item.parent().text(0)
            port = item.text(0).replace("Port ", "")
            
            self.item_map.pop((ip, port), None)
            if 'security_headers' in self.scan_results:
                self.scan_results['security_headers'].pop(f"{ip}:{port}", None)
            
            parent = item.parent()
            parent.removeChild(item)
            
            # Pokud IP už nemá porty, smažeme i ji
            if parent.childCount() == 0:
                index = self.tree.indexOfTopLevelItem(parent)
                self.tree.takeTopLevelItem(index)
        
        self.status_label.setText("Cíl byl odstraněn.")
        
    def calculate_grade(self, headers):
        """Vypočítá známku (A-F) na základě přítomnosti hlaviček."""
        score = 100
        # Váhy jednotlivých chybějících hlaviček
        penalties = {
            "Strict-Transport-Security": 25,
            "Content-Security-Policy": 25,
            "X-Frame-Options": 15,
            "X-Content-Type-Options": 10,
            "Referrer-Policy": 10,
            "Permissions-Policy": 10
        }
        
        for header, penalty in penalties.items():
            if headers.get(header) == "CHYBÍ":
                score -= penalty
        
        if score >= 90: return "A", "#2ECC71"
        if score >= 75: return "B", "#27AE60"
        if score >= 60: return "C", "#F1C40F"
        if score >= 40: return "D", "#E67E22"
        return "F", "#E74C3C"
    
    def export_to_pdf(self):
        """
        Vygeneruje profesionální vícestránkový PDF report.
        Obsahuje: Úvodní souhrn (TOC), Detailní analýzu, OWASP Remediation a MDN odkazy.
        """
        # 1. Příprava dat pro výběrový dialog
        available_data = []
        saved_data = self.scan_results.get('security_headers', {})
        for key, data in saved_data.items():
            if 'headers' in data:
                available_data.append({
                    'name': key, 
                    'settings': data.get('server', 'Neznámý'), 
                    'data': data
                })
        
        if not available_data:
            QMessageBox.warning(self, "Export", "Nejsou k dispozici žádná data z auditů pro export.")
            return

        # 2. Mini-dialog pro výběr cílů k exportu
        selector = QDialog(self)
        selector.setWindowTitle("Výběr cílů pro PDF Report")
        selector.resize(450, 550)
        sel_layout = QVBoxLayout(selector)
        sel_layout.addWidget(QLabel("<b>Vyberte cíle pro zahrnutí do auditní zprávy:</b>"))
        
        list_widget = QListWidget()
        for d in available_data:
            domain_info = f" [{d['data'].get('domain', '-')}]" if d['data'].get('domain') != "-" else ""
            it = QListWidgetItem(f"{d['name']}{domain_info}")
            it.setCheckState(Qt.Checked)
            it.setData(Qt.UserRole, d)
            list_widget.addItem(it)
        sel_layout.addWidget(list_widget)
        
        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(selector.accept)
        btns.rejected.connect(selector.reject)
        sel_layout.addWidget(btns)
        
        if selector.exec() != QDialog.Accepted:
            return
            
        selected_targets = [list_widget.item(i).data(Qt.UserRole) for i in range(list_widget.count()) 
                            if list_widget.item(i).checkState() == Qt.Checked]
                
        if not selected_targets:
            return

        path, _ = QFileDialog.getSaveFileName(self, "Uložit PDF Report", "Security_Audit_Report.pdf", "PDF Files (*.pdf)")
        if not path:
            return

        # 3. Sestavení vícestránkového HTML šablony
        full_html = "<html><head><style>"
        full_html += """
                body { font-family: Arial, sans-serif; color: #333; line-height: 1.4; padding: 0; margin: 0; }
                .page { page-break-after: always; padding: 40px; box-sizing: border-box; position: relative; min-height: 980px; }
                .page:last-child { page-break-after: auto; }
                .header { display: flex; align-items: center; border-bottom: 2px solid #eee; padding-bottom: 15px; margin-bottom: 20px; }
                .grade { font-size: 60px; font-weight: bold; color: white; width: 100px; height: 100px; 
                         display: flex; align-items: center; justify-content: center; border-radius: 10px; 
                         margin-right: 25px; flex-shrink: 0; }
                .summary-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                .summary-table th, .summary-table td { padding: 12px; border: 1px solid #eee; text-align: left; font-size: 12px; }
                .summary-badge { padding: 4px 10px; border-radius: 4px; color: white; font-weight: bold; }
                table { width: 100%; border-collapse: collapse; margin-top: 15px; table-layout: fixed; }
                th, td { padding: 8px; text-align: left; border-bottom: 1px solid #eee; font-size: 11px; word-wrap: break-word; }
                th { background-color: #f8f9fa; }
                pre { background: #f4f4f4; padding: 10px; border-radius: 5px; font-size: 10px; border: 1px solid #ddd; white-space: pre-wrap; }
                .fail { color: #e74c3c; font-weight: bold; }
                .pass { color: #2ecc71; font-weight: bold; }
                .recommendation-box { margin-top: 20px; padding: 15px; border: 1px solid #3498DB; 
                                     border-left: 5px solid #3498DB; background: #f0f7fb; }
                .links-box { margin-top: 30px; padding-top: 15px; border-top: 1px solid #eee; font-size: 11px; color: #555; }
                .links-box a { color: #3498DB; text-decoration: none; font-weight: bold; }
                .desc { font-size: 9px; color: #777; display: block; margin-top: 2px; }
        """
        full_html += "</style></head><body>"

        # --- STRANA 1: SOUHRNNÉ MANAŽERSKÉ SHRNUTÍ ---
        full_html += f"""
        <div class="page">
            <h1 style="color:#2C3E50; margin-bottom: 5px;">Auditní zpráva: Security Headers</h1>
            <p style="color:#7F8C8D;">Vytvořeno aplikací Nmap Scanner | Verze {VERSION}</p>
            <p>Datum vygenerování: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}</p>
            
            <h3 style="margin-top:40px; border-bottom: 2px solid #3498DB; padding-bottom:10px;">Manažerské shrnutí výsledků</h3>
            <table class="summary-table">
                <tr><th>IP:Port</th><th>Doménové jméno</th><th>Server</th><th style="text-align:center;">Známka</th></tr>"""
        
        for target in selected_targets:
            g, c = self.calculate_grade(target['data']['headers'])
            full_html += f"""
                <tr>
                    <td><strong>{target['name']}</strong></td>
                    <td>{target['data'].get('domain', '-')}</td>
                    <td>{target['settings']}</td>
                    <td style="text-align:center;"><span class="summary-badge" style="background-color:{c};">{g}</span></td>
                </tr>"""
        full_html += "</table><p style='margin-top:30px; font-style:italic; color:#666;'>Poznámka: Detailní analýza a doporučení pro jednotlivé cíle následují na dalších stranách.</p></div>"

        # --- KONFIGURACE PRO DETAILNÍ STRANY ---
        descriptions = {
            "Strict-Transport-Security": "Vynucuje HTTPS a chrání před útoky man-in-the-middle.",
            "Content-Security-Policy": "Prevence XSS útoků striktním povolením zdrojů obsahu.",
            "X-Frame-Options": "Ochrana proti clickjackingu (zákaz vkládání do iframe).",
            "X-Content-Type-Options": "Zabraňuje MIME-sniffingu (vynucuje deklarovaný typ).",
            "Referrer-Policy": "Řídí množství informací předávaných v hlavičce Referer.",
            "Permissions-Policy": "Omezuje přístup prohlížeče k citlivým API (kamera, mikrofon atd.)."
        }
        ordered_headers = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", 
                           "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]
        recommendations = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; (upravte dle potřeb aplikace)",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), camera=(), microphone=()"
        }

        # --- GENEROVÁNÍ DETAILNÍCH STRAN (1 cíl = 1 strana) ---
        for target in selected_targets:
            t_data = target['data']
            grade, color = self.calculate_grade(t_data['headers'])
            server_raw = t_data.get('server', 'Neznámý').lower()
            audit_time = t_data.get('check_time', 'Neprověřeno')
            
            # Generování konfiguračního kódu pro nápravu
            missing = [h for h in ordered_headers if t_data['headers'].get(h) == "CHYBÍ"]
            if not missing:
                fix_code = "<p class='pass'>Gratulujeme! Server má korektně implementovány všechny sledované bezpečnostní hlavičky.</p>"
            elif "nginx" in server_raw:
                fix_code = "<strong>Nginx (.conf):</strong><pre>" + "\n".join([f"add_header {h} \"{recommendations[h]}\" always;" for h in missing]) + "</pre>"
            elif "apache" in server_raw:
                fix_code = "<strong>Apache (.htaccess):</strong><pre>" + "\n".join([f"Header set {h} \"{recommendations[h]}\"" for h in missing]) + "</pre>"
            elif "microsoft" in server_raw or "iis" in server_raw:
                fix_code = "<strong>IIS (web.config):</strong><pre>&lt;customHeaders&gt;\n" + "\n".join([f"  &lt;add name=\"{h}\" value=\"{recommendations[h]}\" /&gt;" for h in missing]) + "\n&lt;/customHeaders&gt;</pre>"
            else:
                fix_code = "<strong>Obecné doporučení:</strong> Přidejte chybějící hlavičky do konfigurace vašeho webového serveru nebo reverzního proxy."

            full_html += f"""
            <div class="page">
                <div class="header">
                    <div class="grade" style="background-color: {color};">{grade}</div>
                    <div>
                        <h2 style="margin:0;">Detailní audit: {target['name']}</h2>
                        <p style="margin:5px 0;">Doména: <strong>{t_data.get('domain', '-')}</strong></p>
                        <p style="margin:5px 0;">Server: <strong>{t_data.get('server', 'Neznámý')}</strong></p>
                        <p style="font-size:10px; color:#999;">Čas měření: {audit_time}</p>
                    </div>
                </div>
                <table>
                    <tr><th style="width:35%;">Hlavička / Popis</th><th style="width:15%;">Stav</th><th>Aktuální hodnota</th></tr>"""
            
            for h in ordered_headers:
                val = t_data['headers'].get(h, "CHYBÍ")
                full_html += f"<tr><td><strong>{h}</strong><span class='desc'>{descriptions[h]}</span></td><td class='{'pass' if val != 'CHYBÍ' else 'fail'}'>{'PŘÍTOMNA' if val != 'CHYBÍ' else 'CHYBÍ'}</td><td><code>{val}</code></td></tr>"
            
            full_html += f"""
                </table>
                <div class="recommendation-box">
                    <h3 style="margin-top:0; color:#2980B9; font-size:14px;">🛠️ Doporučení pro nápravu (OWASP)</h3>
                    {fix_code}
                </div>
                <div class="links-box">
                    <strong>Další zdroje a dokumentace:</strong><br>
                    • OWASP Secure Headers Project: <a href="https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html">HTTP Headers Cheat Sheet</a><br>
                    • Mozilla Web Docs (MDN): <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers">HTTP Headers Documentation</a>
                </div>
            </div>"""

        full_html += "</body></html>"

        # 4. Asynchronní renderování a uložení do PDF
        self.status_label.setText(f"Generuji PDF ({len(selected_targets) + 1} stran)...")
        self.pdf_page = QWebEnginePage()
        self.pdf_page.setHtml(full_html)
        
        def handle_print_finished(ok):
            if ok:
                self.pdf_page.printToPdf(path)
                self.status_label.setText("PDF report uložen.")
                QMessageBox.information(self, "Export", f"Vícestránkový report byl úspěšně vygenerován:\n{path}")
        
        self.pdf_page.loadFinished.connect(handle_print_finished)

class CertificateWorker(QRunnable):
    """
    Worker využívající systémový OpenSSL.
    FIX: Inteligentní detekce typu chyby (Timeout vs Refused vs SSL Error).
    """
    def __init__(self, ip, port, signals):
        super().__init__()
        self.ip = ip
        self.port = str(port)
        self.signals = signals

    def parse_openssl_date(self, date_str):
        month_map = {
            'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
            'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
        }
        try:
            parts = [p for p in date_str.split(' ') if p]
            if len(parts) < 4: return None
            month = month_map.get(parts[0])
            day = int(parts[1])
            time_parts = parts[2].split(':')
            year = int(parts[3])
            if not month: return None
            return datetime(year, month, day, int(time_parts[0]), int(time_parts[1]), int(time_parts[2]))
        except:
            return None

    @Slot()
    def run(self):
        if not shutil.which("openssl"):
            self.signals.result.emit(self.ip, self.port, {'status': 'Chyba', 'error': "OpenSSL chybí", 'cn': 'System Error'})
            self.signals.finished.emit()
            return

        try:
            # 1. Stáhnout certifikát a info o spojení
            # Používáme echo "Q" | openssl ... pro bezpečné ukončení
            cmd_client = [
                "openssl", "s_client",
                "-connect", f"{self.ip}:{self.port}",
                "-showcerts",
                "-servername", self.ip
            ]
            
            process = subprocess.Popen(
                cmd_client,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            try:
                # Pošleme "Q" pro ukončení spojení. Timeout 8s.
                stdout, stderr = process.communicate(input="Q\n", timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                raise Exception("TIMEOUT")
            
            # --- DETEKCE CHYB PŘIPOJENÍ ---
            # Kombinujeme výstupy pro hledání chyb i informací
            full_output_raw = (stdout or "") + (stderr or "")
            
            if "-----BEGIN CERTIFICATE-----" not in full_output_raw:
                err_msg = full_output_raw.strip() if full_output_raw.strip() else "Empty response"
                
                # Klasifikace chyb
                if "Connection refused" in err_msg:
                    raise Exception("REFUSED")
                elif "No route to host" in err_msg:
                    raise Exception("UNREACHABLE")
                elif "getaddrinfo" in err_msg or "Name or service not known" in err_msg:
                    raise Exception("DNS_ERROR")
                elif "unexpected eof" in err_msg.lower() or "ssl handshake failure" in err_msg.lower():
                    raise Exception("SSL_ERROR") 
                elif "alert" in err_msg.lower():
                    raise Exception("SSL_ALERT")
                else:
                    raise Exception(f"OPENSSL_ERR: {err_msg[:50]}")

            # --- EXTRAKCE PROTOKOLU A ŠIFRY (z s_client výstupu) ---
            cipher_info = "Neznámá"
            protocol_info = "Neznámý"
            
            # Hledání v celém výstupu (stdout i stderr)
            # 1. Protokol (hledáme různé varianty výstupu OpenSSL)
            # Varianta A: "Protocol  : TLSv1.2"
            # Varianta B: "SSL-Session: ... Protocol : TLSv1.2"
            proto_matches = re.findall(r'Protocol\s*:\s*([A-Za-z0-9\.]+)', full_output_raw, re.IGNORECASE)
            if proto_matches:
                # Vezmeme poslední nalezený (často ten v SSL-Session sekci je nejpřesnější)
                protocol_info = proto_matches[-1].strip()

            # 2. Šifra
            cipher_match = re.search(r'Cipher\s*(?:is|:)\s*(.*)', full_output_raw, re.IGNORECASE)
            if cipher_match:
                val = cipher_match.group(1).strip()
                if val != "00,00" and "(NONE)" not in val:
                    cipher_info = val

            # --- EXTRAKCE CHAINU ---
            certs = re.findall(r'(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)', full_output_raw, re.DOTALL)
            if not certs: raise Exception("NO_PEM_DATA")
            
            leaf_cert = certs[0]
            full_chain_text = "\n\n".join(certs)
            
            # --- ANALÝZA X509 (Detail certifikátu) ---
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tf:
                tf.write(leaf_cert)
                temp_path = tf.name
            
            text_output = ""
            try:
                # -nameopt utf8,sep_multiline zajistí čitelnost Subject/Issuer
                cmd_x509 = ["openssl", "x509", "-in", temp_path, "-noout", "-text", "-nameopt", "utf8,sep_multiline"]
                res_x509 = subprocess.run(cmd_x509, capture_output=True, text=True)
                text_output = res_x509.stdout
            finally:
                if os.path.exists(temp_path): os.unlink(temp_path)

            # --- PARSOVÁNÍ DETAILŮ ---
            subject_cn = "N/A"
            issuer_cn = "N/A"
            sig_algo = "N/A"
            pub_key = "N/A"
            
            # Subject CN (multiline)
            subj_match = re.search(r'Subject:.*?\n\s+CN\s*=\s*([^\n]+)', text_output, re.DOTALL)
            if subj_match: subject_cn = subj_match.group(1).strip()
            
            # Issuer CN (multiline)
            iss_match = re.search(r'Issuer:.*?\n\s+CN\s*=\s*([^\n]+)', text_output, re.DOTALL)
            if iss_match: issuer_cn = iss_match.group(1).strip()
            
            # Signature Algorithm
            sig_match = re.search(r'Signature Algorithm:\s*(.*)', text_output)
            if sig_match: sig_algo = sig_match.group(1).strip()
            
            # Public Key - OPRAVENÝ REGEX
            # Hledá "Public-Key: (2048 bit)" s libovolnými mezerami
            pk_match = re.search(r'Public-Key:\s*\(\s*(\d+\s*bit)\s*\)', text_output, re.IGNORECASE)
            
            if pk_match:
                bits = pk_match.group(1).strip()
                # Zkusíme určit typ klíče podle algoritmu v textu
                if "rsaEncryption" in text_output:
                    pub_key = f"RSA ({bits})"
                elif "id-ecPublicKey" in text_output or "Ansip192r1" in text_output:
                    pub_key = f"ECC ({bits})"
                else:
                    pub_key = bits
            
            # Expirace
            date_match = re.search(r'Not After\s*:\s*(.*)', text_output)
            expire_str = date_match.group(1).strip() if date_match else ""
            
            days_left = 0
            status = "Validní"
            formatted_date = expire_str
            
            if expire_str:
                dt = self.parse_openssl_date(expire_str)
                if dt:
                    days_left = (dt - datetime.now()).days
                    formatted_date = dt.strftime('%Y-%m-%d')
                    if days_left < 0: status = "Expirovaný"
                    elif days_left < 30: status = "Brzy expiruje"
            
            result_data = {
                'ip': self.ip, 'port': self.port,
                'status': status,
                'cn': subject_cn, 'issuer': issuer_cn,
                'expiry': formatted_date, 'days': days_left,
                'cipher': cipher_info, 'sig_algo': sig_algo,
                'protocol': protocol_info, 'pub_key': pub_key,
                'full_text': text_output, 'chain': full_chain_text
            }
            self.signals.result.emit(self.ip, self.port, result_data)

        except Exception as e:
            # Překlad chyb
            err_raw = str(e)
            
            status = "Chyba"
            desc = err_raw
            
            if "TIMEOUT" in err_raw:
                status = "Timeout"
                desc = "Server neodpovídá (8s)"
            elif "REFUSED" in err_raw:
                status = "Odmítnuto"
                desc = "Connection Refused (Port zavřen)"
            elif "UNREACHABLE" in err_raw:
                status = "Nedostupný"
                desc = "No Route to Host"
            elif "SSL_ERROR" in err_raw:
                status = "SSL Chyba"
                desc = "Handshake Failed (Legacy Protocol?)"
            elif "SSL_ALERT" in err_raw:
                status = "SSL Alert"
                desc = "Server odmítl spojení (Alert)"
            elif "DNS_ERROR" in err_raw:
                status = "DNS Chyba"
                desc = "Host not found"
            
            self.signals.result.emit(self.ip, self.port, {
                'status': status,
                'error': desc,
                'full_error': err_raw
            })
            
        finally:
            self.signals.finished.emit()
            
class CertificateDetailDialog(QDialog):
    """
    Dialog pro zobrazení detailních informací o certifikátu a řetězci důvěry.
    """
    def __init__(self, data, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Detail certifikátu: {data.get('cn', 'N/A')}")
        self.resize(800, 700)
        
        layout = QVBoxLayout(self)
        
        # Textová oblast s reportem
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setFont(QFont("Courier New", 12)) 
        self.text_edit.setStyleSheet("background-color: #2b2b2b; color: #f0f0f0;")
        
        # Sestavení obsahu
        report = []
        report.append("="*60)
        report.append(f" PŘEHLED: {data.get('ip', '')}:{data.get('port', '')}")
        report.append("="*60)
        report.append(f"Stav:       {data.get('status', 'N/A')}")
        report.append(f"Doména (CN):{data.get('cn', 'N/A')}")
        report.append(f"Vydavatel:  {data.get('issuer', 'N/A')}")
        report.append(f"Expirace:   {data.get('expiry', 'N/A')} (Zbývá dní: {data.get('days', 'N/A')})")
        report.append("-" * 60)
        report.append(f"Protokol:   {data.get('protocol', 'N/A')}")
        report.append(f"Šifra:      {data.get('cipher', 'N/A')}")
        report.append(f"Algoritmus: {data.get('sig_algo', 'N/A')}")
        report.append(f"Veř. klíč:  {data.get('pub_key', 'N/A')}")
        
        report.append("\n" + "="*60)
        report.append(" RAW DATA (OpenSSL x509)")
        report.append("="*60)
        report.append(data.get('full_text', 'Detaily nejsou k dispozici.'))
        
        report.append("\n" + "="*60)
        report.append(" TRUST CHAIN (Řetězec důvěry)")
        report.append("="*60)
        report.append(data.get('chain', 'Řetězec nebyl stažen.'))
        
        self.text_edit.setText("\n".join(report))
        layout.addWidget(self.text_edit)
        
        # Tlačítka
        btn_layout = QHBoxLayout()
        btn_copy = QPushButton("Kopírovat do schránky")
        btn_copy.clicked.connect(self.copy_to_clipboard)
        btn_layout.addWidget(btn_copy)
        
        btn_close = QPushButton("Zavřít")
        btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(btn_close)
        
        layout.addLayout(btn_layout)
        
    def copy_to_clipboard(self):
        QApplication.clipboard().setText(self.text_edit.toPlainText())
        
class CertificateExportDialog(QDialog):
    """
    Dialog pro nastavení exportu certifikátů do TXT.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Exportovat výsledky (TXT)")
        self.resize(400, 350)
        self.selected_options = {}
        
        layout = QVBoxLayout(self)
        
        # 1. Popis
        layout.addWidget(QLabel("Popis reportu (volitelné):"))
        self.desc_input = QLineEdit()
        self.desc_input.setPlaceholderText("Např. Audit externí sítě 2023...")
        layout.addWidget(self.desc_input)
        
        layout.addSpacing(10)
        
        # 2. Filtry stavů
        filter_group = QGroupBox("Filtrovat cíle podle stavu")
        filter_layout = QVBoxLayout()
        
        self.cb_valid = QCheckBox("Validní (V pořádku)")
        self.cb_valid.setChecked(False) # Defaultně vypnuto
        
        self.cb_expired = QCheckBox("Expirované / Brzy expirují")
        self.cb_expired.setChecked(True) # Defaultně zapnuto
        
        self.cb_errors = QCheckBox("Chyby (Timeout, SSL Error, Odmítnuto)")
        self.cb_errors.setChecked(True) # Defaultně zapnuto (považujeme za nevalidní)
        
        filter_layout.addWidget(self.cb_valid)
        filter_layout.addWidget(self.cb_expired)
        filter_layout.addWidget(self.cb_errors)
        filter_group.setLayout(filter_layout)
        layout.addWidget(filter_group)
        
        # 3. Obsah
        content_group = QGroupBox("Obsah detailů")
        content_layout = QVBoxLayout()
        
        self.cb_full_text = QCheckBox("Přidat celý obsah certifikátu (Raw OpenSSL text)")
        self.cb_full_text.setChecked(False)
        
        content_layout.addWidget(self.cb_full_text)
        content_group.setLayout(content_layout)
        layout.addWidget(content_group)
        
        layout.addStretch()
        
        # Tlačítka
        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btn_box.accepted.connect(self.accept)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)
        
    def get_options(self):
        return {
            'description': self.desc_input.text(),
            'include_valid': self.cb_valid.isChecked(),
            'include_expired': self.cb_expired.isChecked(),
            'include_errors': self.cb_errors.isChecked(),
            'include_full_text': self.cb_full_text.isChecked()
        }

class CertificateDialog(QDialog):
    """
    Dialog pro kontrolu SSL certifikátů.
    Vylepšeno: Přidány sloupce Protokol a Veřejný klíč.
    """
    def __init__(self, scan_results, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Inspektor SSL/TLS Certifikátů")
        
        # Široké okno pro 10 sloupců
        self.resize(1600, 800)
        
        self.scan_results = scan_results
        self.thread_pool = QThreadPool()
        self.processing_count = 0
        self.item_map = {} 
        
        self.init_ui()
        self.load_targets()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Info panel
        info_layout = QHBoxLayout()
        info_layout.addWidget(QLabel("<b>Nalezené HTTPS/SSL služby:</b>"))
        info_layout.addStretch()
        self.status_label = QLabel("Připraveno")
        info_layout.addWidget(self.status_label)
        layout.addLayout(info_layout)
        
        # --- SURGICAL ADDITION: Filtrační lišta ---
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Zobrazit:"))
        self.filter_valid = QCheckBox("Validní")
        self.filter_valid.setChecked(True)
        self.filter_warning = QCheckBox("Varování/Expirované")
        self.filter_warning.setChecked(True)
        self.filter_error = QCheckBox("Chyby/Ostatní")
        self.filter_error.setChecked(True)
        
        # Propojení signálů pro okamžitou reakci
        self.filter_valid.stateChanged.connect(self.apply_filters)
        self.filter_warning.stateChanged.connect(self.apply_filters)
        self.filter_error.stateChanged.connect(self.apply_filters)
        
        filter_layout.addWidget(self.filter_valid)
        filter_layout.addWidget(self.filter_warning)
        filter_layout.addWidget(self.filter_error)
        filter_layout.addStretch()
        layout.addLayout(filter_layout)
        # ------------------------------------------
        
        # Ovládání stromu
        tree_ctrl_layout = QHBoxLayout()
        btn_expand = QPushButton("Rozbalit vše")
        btn_expand.clicked.connect(lambda: self.tree.expandAll())
        btn_expand.setFixedWidth(100)
        btn_collapse = QPushButton("Sbalit vše")
        btn_collapse.clicked.connect(lambda: self.tree.collapseAll())
        btn_collapse.setFixedWidth(100)
        tree_ctrl_layout.addWidget(btn_expand)
        tree_ctrl_layout.addWidget(btn_collapse)
        tree_ctrl_layout.addStretch()
        layout.addLayout(tree_ctrl_layout)
        
        # Tabulka (Strom)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels([
            "Cíl / Port", "Stav", "Doména (CN)", "Vydavatel", "Protokol", 
            "Šifra", "Algoritmus", "Veř. klíč", "Expirace", "Dny"
        ])
        
        header = self.tree.header()
        for i in range(10):
            header.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        
        self.tree.itemDoubleClicked.connect(self.show_detail)
        layout.addWidget(self.tree)
        
        # Tlačítka dole (zůstávají beze změny)
        btn_layout = QHBoxLayout()
        self.check_btn = QPushButton("🔍 Zkontrolovat certifikáty")
        self.check_btn.clicked.connect(self.start_checks)
        btn_layout.addWidget(self.check_btn)
        
        self.detail_btn = QPushButton("📄 Zobrazit detail")
        self.detail_btn.clicked.connect(lambda: self.show_detail(self.tree.currentItem(), 0))
        btn_layout.addWidget(self.detail_btn)
        
        self.export_csv_btn = QPushButton("💾 CSV")
        self.export_csv_btn.clicked.connect(self.export_results_csv)
        btn_layout.addWidget(self.export_csv_btn)

        self.export_txt_btn = QPushButton("📝 TXT Report")
        self.export_txt_btn.clicked.connect(self.export_results_txt)
        btn_layout.addWidget(self.export_txt_btn)
        
        close_btn = QPushButton("Zavřít")
        close_btn.clicked.connect(self.reject)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)
        
    def apply_filters(self):
        """Projde strom a skryje řádky, které neodpovídají filtrům."""
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            ip_item = root.child(i)
            ip_visible = False
            
            for j in range(ip_item.childCount()):
                port_item = ip_item.child(j)
                status = port_item.text(1)
                
                show = True
                if status == "Validní":
                    show = self.filter_valid.isChecked()
                elif status in ["Brzy expiruje", "Expirovaný"]:
                    show = self.filter_warning.isChecked()
                else:
                    # Chyby, Timeout, Odmítnuto, Čeká...
                    show = self.filter_error.isChecked()
                
                port_item.setHidden(not show)
                if show:
                    ip_visible = True
            
            # Pokud nemá IP žádný viditelný port, skryjeme i celou IP
            ip_item.setHidden(not ip_visible)
        
    def load_targets(self):
        """Načte cíle a seskupí je. Pokud existují uložená data v projektu, aplikuje je."""
        self.tree.clear()
        self.item_map = {} 
        
        targets_dict = {}
        
        # Načtení historie certifikátů z projektu (pokud existuje)
        saved_certs = self.scan_results.get('certificates', {})
        
        # A) Z NMAP
        tcp_data = self.scan_results.get('tcp', {})
        for ip, ports in tcp_data.items():
            if ip not in targets_dict: targets_dict[ip] = set()
            if 'tcp' in ports:
                for port, info in ports['tcp'].items():
                    state = info.get('state')
                    service = info.get('name', '').lower()
                    is_ssl = (str(port) == '443' or str(port) == '8443' or 
                              'ssl' in service or 'https' in service or 
                              info.get('tunnel') == 'ssl')
                    if state == 'open' and is_ssl:
                        targets_dict[ip].add((str(port), "Čeká (Nmap)"))

        # B) Defaultní probe
        all_ips = set()
        for phase in ['online', 'tcp', 'udp']:
            phase_data = self.scan_results.get(phase, {})
            if phase_data: all_ips.update(phase_data.keys())
            
        for ip in all_ips:
            if ip not in targets_dict: targets_dict[ip] = set()
            has_443 = any(p[0] == '443' for p in targets_dict[ip])
            if not has_443:
                targets_dict[ip].add(('443', "Čeká (Probe)"))

        # Řazení IP
        def ip_sort_key(ip):
            try: return tuple(int(part) for part in ip.split('.'))
            except: return (0, 0, 0, 0)
        sorted_ips = sorted(targets_dict.keys(), key=ip_sort_key)
        
        for ip in sorted_ips:
            ports = targets_dict[ip]
            if not ports: continue
            
            ip_item = QTreeWidgetItem(self.tree)
            ip_item.setText(0, ip)
            ip_item.setExpanded(True)
            ip_item.setFont(0, QFont("Arial", 11, QFont.Bold))
            
            header_color = QColor("#3498DB")
            for col in range(self.tree.columnCount()):
                ip_item.setForeground(col, header_color)

            sorted_ports = sorted(list(ports), key=lambda x: int(x[0]))
            
            for port, note in sorted_ports:
                port_item = QTreeWidgetItem(ip_item)
                port_item.setText(0, f"Port {port}")
                
                # Inicializace základních dat (aby columns nebyly prázdné při chybě persistence)
                port_item.setText(1, "Čeká...")
                port_item.setForeground(0, QColor("#E67E22"))
                port_item.setFont(0, QFont("Arial", 10, QFont.Bold))
                
                if "Probe" in note:
                    port_item.setText(1, "Čeká (Probe)")
                    port_item.setForeground(1, QColor("#95A5A6"))
                
                port_item.setData(0, Qt.UserRole, {'ip': ip, 'port': port})
                
                # REGISTRACE DO MAPY (Musí být před update_result!)
                self.item_map[(ip, str(port))] = port_item
                
                # PERSISTENCE: Pokud máme data v projektu, aplikujeme je
                cert_key = f"{ip}:{port}"
                if cert_key in saved_certs:
                    self.update_result(ip, port, saved_certs[cert_key])

        count = len(self.item_map)
        if count == 0:
            QMessageBox.information(self, "Info", "Nebyly nalezeny žádné cíle.")
        else:
            self.status_label.setText(f"Načteno {count} služeb na {len(sorted_ips)} IP adresách.")
            
    @Slot(str, str, dict)
    def update_result(self, ip, port, data):
        """Aktualizace řádku, uložení do projektu a aplikace filtrů."""
        item = self.item_map.get((ip, str(port)))
        if not item: return
        
        # Persistence do hlavního objektu aplikace
        if 'certificates' not in self.scan_results:
            self.scan_results['certificates'] = {}
        self.scan_results['certificates'][f"{ip}:{port}"] = data
        
        stored_data = item.data(0, Qt.UserRole)
        stored_data.update(data)
        item.setData(0, Qt.UserRole, stored_data)
        
        status = data.get('status', 'Neznámý')
        item.setText(1, status)
        
        # Původní barvení stavů (beze změny vzhledu)
        if status == "Timeout":
            item.setForeground(1, QColor("#7F8C8D")) 
            item.setText(2, "-") 
            item.setText(3, "Server neodpovídá") 
        elif status == "Odmítnuto":
            item.setForeground(1, QColor("#E67E22")) 
            item.setText(2, "-")
            item.setText(3, "Connection Refused")
        elif status in ["SSL Chyba", "SSL Alert"]:
            item.setForeground(1, QColor("#E74C3C")) 
            item.setText(2, "Chyba protokolu")
            item.setText(3, data.get('error', ''))
        elif status in ["Nedostupný", "DNS Chyba"]:
            item.setForeground(1, QColor("#9B59B6"))
            item.setText(3, data.get('error', ''))
        elif status == "Validní":
            item.setForeground(1, QColor("#2ECC71")) 
            self._fill_cert_details(item, data)
        elif status == "Brzy expiruje":
            item.setForeground(1, QColor("#F39C12")) 
            self._fill_cert_details(item, data)
        elif status == "Expirovaný":
            item.setForeground(1, QColor("#C0392B")) 
            self._fill_cert_details(item, data)
        else:
            item.setForeground(1, QColor("#E74C3C"))
            item.setText(2, str(data.get('error', 'Chyba')))
            
        # Okamžitá aplikace filtrů po aktualizaci dat
        self.apply_filters()

    def start_checks(self):
        if not self.item_map: return
            
        self.check_btn.setEnabled(False)
        self.processing_count = len(self.item_map)
        self.status_label.setText(f"Zpracovávám {self.processing_count} služeb...")
        
        for (ip, port), item in self.item_map.items():
            item.setText(1, "Ověřuji...")
            item.setForeground(1, QColor("#ECF0F1"))
            item.setIcon(0, QIcon())
            
            signals = WorkerSignals()
            signals.result.connect(self.update_result)
            signals.finished.connect(self.on_worker_finished)
            
            worker = CertificateWorker(ip, port, signals)
            self.thread_pool.start(worker)

    def _fill_cert_details(self, item, data):
        """Vyplnění sloupců (nyní 10)"""
        item.setText(2, data.get('cn', ''))
        item.setText(3, data.get('issuer', ''))
        item.setText(4, data.get('protocol', ''))  # NOVÉ
        item.setText(5, data.get('cipher', ''))
        item.setText(6, data.get('sig_algo', ''))
        item.setText(7, data.get('pub_key', ''))   # NOVÉ
        item.setText(8, data.get('expiry', ''))
        item.setText(9, str(data.get('days', '')))

    @Slot()
    def on_worker_finished(self):
        self.processing_count -= 1
        if self.processing_count <= 0:
            self.status_label.setText("Hotovo.")
            self.check_btn.setEnabled(True)

    def show_detail(self, item, column):
        if not item: return
        if item.childCount() > 0: return # IP řádek
        
        data = item.data(0, Qt.UserRole)
        if not data: return 
        
        if 'full_text' in data:
            dlg = CertificateDetailDialog(data, self)
            dlg.exec()
        elif 'error' in data:
            QMessageBox.warning(self, "Chyba", f"{data['error']}")

    def export_results_csv(self):
        fname, _ = QFileDialog.getSaveFileName(self, "Export CSV", "certifikaty.csv", "CSV Files (*.csv)")
        if fname:
            try:
                with open(fname, 'w', encoding='utf-8') as f:
                    # Aktualizovaná hlavička CSV
                    f.write("IP;Port;Stav;CN;Issuer;Protokol;Cipher;Algoritmus;PubKey;Expiry;DaysLeft\n")
                    
                    root = self.tree.invisibleRootItem()
                    for i in range(root.childCount()):
                        ip_item = root.child(i)
                        ip_addr = ip_item.text(0)
                        
                        for j in range(ip_item.childCount()):
                            port_item = ip_item.child(j)
                            port_str = port_item.text(0).replace("Port ", "")
                            
                            row = [
                                ip_addr, 
                                port_str,
                                port_item.text(1), # Stav
                                port_item.text(2), # CN
                                port_item.text(3), # Issuer
                                port_item.text(4), # Protokol
                                port_item.text(5), # Cipher
                                port_item.text(6), # Algo
                                port_item.text(7), # PubKey
                                port_item.text(8), # Expiry
                                port_item.text(9)  # Days
                            ]
                            safe_row = [str(x).replace(';', ',').replace('\n', ' ') for x in row]
                            f.write(";".join(safe_row) + "\n")
                            
                QMessageBox.information(self, "Export", "Data uložena.")
            except Exception as e:
                QMessageBox.critical(self, "Chyba", str(e))

    def export_results_txt(self):
        """
        Generuje detailní TXT report z výsledků kontroly certifikátů.
        Zahrnuje hlavičku, statistiku, filtrování podle stavu a technické detaily.
        """
        # 1. Zobrazit dialog pro nastavení filtrů a popisu
        dlg = CertificateExportDialog(self)
        if dlg.exec() != QDialog.Accepted:
            return
            
        opts = dlg.get_options()
        
        # 2. Výběr cílového souboru
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        default_name = f"cert_audit_{timestamp}.txt"
        fname, _ = QFileDialog.getSaveFileName(self, "Exportovat TXT Report", default_name, "Text Files (*.txt)")
        
        if not fname:
            return

        try:
            with open(fname, 'w', encoding='utf-8') as f:
                # --- HLAVIČKA REPORTU ---
                f.write("=" * 80 + "\n")
                f.write(f"AUDITNÍ ZPRÁVA: SSL/TLS INSPEKCE\n")
                f.write(f"Vytvořeno: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                if opts['description']:
                    f.write(f"Popis projektu: {opts['description']}\n")
                f.write("=" * 80 + "\n\n")

                # --- PŘÍPRAVA DAT A STATISTIKA ---
                total_scanned = 0
                exported_count = 0
                
                root = self.tree.invisibleRootItem()
                items_to_process = []

                # Projdeme strom (IP -> Porty)
                for i in range(root.childCount()):
                    ip_item = root.child(i)
                    ip_addr = ip_item.text(0)
                    
                    for j in range(ip_item.childCount()):
                        port_item = ip_item.child(j)
                        total_scanned += 1
                        
                        # Získání dat uložených v UserRole
                        data = port_item.data(0, Qt.UserRole)
                        status = data.get('status', 'Neznámý')
                        
                        # Logika filtrování na základě voleb v dialogu
                        should_include = False
                        
                        if status == "Validní" and opts['include_valid']:
                            should_include = True
                        elif status in ["Expirovaný", "Brzy expiruje"] and opts['include_expired']:
                            should_include = True
                        elif status not in ["Validní", "Expirovaný", "Brzy expiruje"] and opts['include_errors']:
                            # Zahrnuje Timeout, Odmítnuto, SSL Chyby atd.
                            should_include = True
                            
                        if should_include:
                            items_to_process.append((ip_addr, data))
                            exported_count += 1

                # Zápis souhrnu
                f.write(f"SOUHRN TESTU:\n")
                f.write(f"- Celkem prověřeno služeb: {total_scanned}\n")
                f.write(f"- Zahrnuto v tomto exportu: {exported_count}\n")
                f.write("-" * 80 + "\n\n")

                if not items_to_process:
                    f.write("Žádné výsledky neodpovídají nastaveným filtrům exportu.\n")

                # --- DETAILNÍ VÝPIS JEDNOTLIVÝCH CÍLŮ ---
                for ip, data in items_to_process:
                    port = data.get('port', 'N/A')
                    status = data.get('status', 'Neznámý').upper()
                    
                    f.write(f"CÍL: {ip}:{port}\n")
                    f.write(f"STAV: {status}\n")
                    f.write("-" * 40 + "\n")
                    
                    # Pokud máme technická data o certifikátu
                    if status in ["VALIDNÍ", "EXPIROVANÝ", "BRZY EXPIRUJE"]:
                        f.write(f"Doména (CN):     {data.get('cn', 'N/A')}\n")
                        f.write(f"Vydavatel:       {data.get('issuer', 'N/A')}\n")
                        f.write(f"Protokol:        {data.get('protocol', 'N/A')}\n")
                        f.write(f"Šifra (Cipher):  {data.get('cipher', 'N/A')}\n")
                        f.write(f"Algoritmus:      {data.get('sig_algo', 'N/A')}\n")
                        f.write(f"Veřejný klíč:    {data.get('pub_key', 'N/A')}\n")
                        f.write(f"Expirace:        {data.get('expiry', 'N/A')} (Zbývá dní: {data.get('days', 'N/A')})\n")
                    else:
                        # Pokud jde o chybu (Timeout, Refused...)
                        error_detail = data.get('error', 'Žádné doplňující informace')
                        f.write(f"Chyba:           {error_detail}\n")
                        if 'full_error' in data:
                            f.write(f"Technický popis: {data['full_error']}\n")

                    # Volitelný export celého OpenSSL výstupu (Raw data)
                    if opts['include_full_text'] and 'full_text' in data:
                        f.write("\n--- KOMPLETNÍ VÝSTUP (OPENSSL) ---\n")
                        f.write(data['full_text'].strip())
                        f.write("\n----------------------------------\n")
                    
                    f.write("\n" + "=" * 60 + "\n\n")

                f.write(f"\n*** Konec reportu ***\n")

            QMessageBox.information(self, "Export", f"Report byl úspěšně vygenerován do souboru:\n{fname}")
            
        except Exception as e:
            QMessageBox.critical(self, "Chyba exportu", f"Během zápisu reportu došlo k chybě:\n{str(e)}")
    
class ScreenshotWorker(QRunnable):
    """
    Asynchronní worker pro pořízení screenshotu webové stránky.
    Musí být volán z hlavního vlákna kvůli QWebEngineView.
    """
    def __init__(self, url, ip, port, path, signals):
        super().__init__()
        self.url = url
        self.ip = ip
        self.port = port
        self.path = path
        self.signals = signals

    @Slot()
    def run(self):
        # Tato funkce je zjednodušená; v praxi je třeba view vytvořit
        # a spravovat v hlavním vlákně. Použijeme signály pro tento účel.
        self.signals.screenshot_request.emit(self.url, self.ip, self.port, self.path)

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

class WorkerSignals(QObject):
    result = Signal(str, str, dict)
    finished = Signal()
    log = Signal(str, str)
    task_started = Signal(str, str)
    screenshot_request = Signal(str, str, int, str) # url, ip, port, path
    screenshot_taken = Signal(str, str) # ip, filepath


class ScanWorker(QRunnable):
    def __init__(self, phase, command, target, signals):
        super().__init__()
        self.phase, self.command, self.target, self.signals = phase, command, target, signals

    @Slot()
    def run(self):
        self.signals.task_started.emit(self.phase, self.target)
        self.signals.log.emit("info", f"🔍 [{self.phase.upper()}] Skenování {self.target} - START")
        self.signals.log.emit("info", f"   Příkaz: {self.command}")
        
        full_command = self.command.split()
        if full_command and full_command[0] != 'sudo':
            full_command.insert(0, 'sudo')
        
        start_time = time.time()
        
        try:
            result = subprocess.run(full_command, capture_output=True, text=True, check=False)
            elapsed = time.time() - start_time
            
            if result.returncode != 0 and "Host seems down" not in result.stderr:
                self.signals.log.emit("error", f"❌ [{self.phase.upper()}] {self.target} - CHYBA (čas: {elapsed:.1f}s)")
                self.signals.log.emit("error", f"   Detail: {result.stderr.strip()[:200]}")
                self.signals.result.emit(self.phase, self.target, {'error': result.stderr.strip()})
            else:
                scanner = nmap.PortScanner()
                scan_data = scanner.analyse_nmap_xml_scan(result.stdout)
                scan_result = scan_data.get('scan', {}).get(self.target, {})
                is_up_now = self.is_host_up_from_xml(result.stdout, self.target)
                
                if self.phase.startswith('online'):
                    scan_result = {'status': {'state': 'up' if is_up_now else 'down'}}
                    status_icon = "✅" if is_up_now else "⚠️"
                    self.signals.log.emit("info", f"{status_icon} [{self.phase.upper()}] {self.target} - {('ONLINE' if is_up_now else 'OFFLINE')} (čas: {elapsed:.1f}s)")
                elif not is_up_now:
                    scan_result = {"status": "skipped"}
                    self.signals.log.emit("info", f"⏭️  [{self.phase.upper()}] {self.target} - PŘESKOČENO (host down, čas: {elapsed:.1f}s)")
                else:
                    # Logování pro TCP/UDP/VULN/OSSCAN
                    port_count = sum(len(scan_result.get(proto, {})) for proto in ['tcp', 'udp'])
                    self.signals.log.emit("info", f"✅ [{self.phase.upper()}] {self.target} - HOTOVO ({port_count} portů, čas: {elapsed:.1f}s)")
                
                self.signals.result.emit(self.phase, self.target, scan_result)
        
        except Exception as e:
            elapsed = time.time() - start_time
            self.signals.log.emit("error", f"❌ [{self.phase.upper()}] {self.target} - VÝJIMKA (čas: {elapsed:.1f}s)")
            self.signals.log.emit("error", f"   Detail: {str(e)[:200]}")
            self.signals.result.emit(self.phase, self.target, {'error': str(e)})
        
        finally:
            self.signals.finished.emit()

    def is_host_up_from_xml(self, xml_string, ip_address):
        try:
            root = ET.fromstring(xml_string)
            for host in root.findall('host'):
                if host.find('address') is not None and host.find('address').get('addr') == ip_address:
                    status_elem = host.find('status')
                    if status_elem is not None and status_elem.get('state') == 'up': return True
                    ports = host.find('ports')
                    if ports is not None:
                        for port in ports.findall('port'):
                            if port.find('state').get('state') == 'open': return True
        except ET.ParseError: return False
        return False

class ScanManager(QObject):
    workflow_finished = Signal()

    def __init__(self, command_templates, signals):
        super().__init__()
        self.command_templates = command_templates
        self.signals = signals
        self.is_running = False
        self.phases = ['online', 'tcp', 'udp', 'vuln', 'osscan']
        self.enabled_phases = {p: True for p in self.phases}
        self.thread_pool = QThreadPool()
        
        # Nová počítadla pro progress
        self.phase_progress = {p: {'total': 0, 'completed': 0} for p in self.phases}

    def set_enabled_phases(self, enabled_phases):
        self.enabled_phases = enabled_phases

    @Slot(list)
    def start_workflow(self, targets):
        self.is_running = True
        self.thread_pool.setMaxThreadCount(20)
        self.signals.log.emit("info", f"Zahajuji paralelní online kontrolu pro {len(targets)} cílů...")
        for target in targets:
            if not self.is_running: break
            if self.enabled_phases.get('online', True):
                self._schedule_task('online', target)
            else:
                self.signals.log.emit("warning", f"Fáze 'online' je přeskočena pro cíl {target}")
                self.signals.result.emit('online', target, {'status': {'state': 'skipped_by_user'}})

    def _schedule_task(self, phase, target, use_pn=False):
        if not self.is_running:
            return
        
        base_phase = phase.replace("-Pn", "")  # OPRAVA: Bez mezery a závorek
        
        if not self.enabled_phases.get(base_phase, True):
            self.signals.log.emit("warning", f"Fáze '{phase}' je zakázána - přeskakuji cíl {target}")
            self.signals.result.emit(phase, target, {'status': 'skipped_by_user'})
            return
        
        command = self.command_templates[base_phase].replace('{target}', target)
        phase_name = phase
        
        if use_pn:
            command += " -Pn"
            phase_name += "-Pn"  # OPRAVA: Bez mezery a bez závorek
        
        # Zvýšit počet celkových úloh pro tuto fázi
        self.phase_progress[base_phase]['total'] += 1
        
        worker = ScanWorker(phase_name, command, target, self.signals)
        self.thread_pool.start(worker)
        
        # Logovat progress
        progress = self.phase_progress[base_phase]
        self.signals.log.emit("info", f"📊 [{base_phase.upper()}] Progress: {progress['completed']}/{progress['total']} úloh")


    @Slot(dict)
    def handle_online_phase_done(self, online_results):
        if not self.is_running:
            return
        
        self.signals.log.emit("info", "Online kontrola dokončena. Spouštím hloubkové skeny...")
        self.thread_pool.setMaxThreadCount(10)
        
        online_targets_count = sum(1 for data in online_results.values() if data.get('status', {}).get('state') == 'up')
        self.signals.log.emit("info", f"Nalezeno {online_targets_count} online cílů.")
        
        if not any(online_results.values()):
            self.workflow_finished.emit()
            return
        
        for target, data in online_results.items():
            is_online = data.get('status', {}).get('state') == 'up'
            skipped_by_user = data.get('status', {}).get('state') == 'skipped_by_user'
            
            # Přidat 'osscan' do seznamu fází
            for phase in ['tcp', 'udp', 'vuln', 'osscan']:
                if not self.is_running:
                    break
                
                if self.enabled_phases.get(phase, True):
                    self._schedule_task(phase, target, use_pn=not is_online and not skipped_by_user)
                else:
                    self.signals.log.emit("warning", f"Fáze '{phase}' přeskočena pro {target}")
                    self.signals.result.emit(phase, target, {'status': 'skipped_by_user'})
            
            if not self.is_running:
                break

    def stop_workflow(self):
        self.is_running = False
        self.thread_pool.clear()
        self.signals.log.emit("warning", "Všechny naplánované skeny byly zrušeny.")
        self.workflow_finished.emit()

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
                pass
                return
            
            phase_idx = self.real_phases.index(base_phase) + 1
            self.ip_items[ip].setText(phase_idx, display_status)
            self.ip_items[ip].setForeground(phase_idx, self.status_colors.get(display_status, QColor('black')))
            
            if base_phase == 'online':
                self.resizeColumnToContents(1)


class StartupDialog(QDialog):
    """Dialog zobrazený při startu aplikace pro výběr projektu."""
    def __init__(self, recent_projects=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Nmap Scanner - Start projektu")
        self.setModal(True)
        self.choice = None  # "import", "new", nebo cesta k projektu
        self.recent_projects = recent_projects or []
        
        layout = QVBoxLayout()
        label = QLabel("Vyberte možnost spuštění:")
        label.setStyleSheet("font-weight: bold; font-size: 12px;")
        layout.addWidget(label)
        
        # Sekce: Poslední projekty
        if self.recent_projects:
            recent_label = QLabel("Poslední projekty:")
            recent_label.setStyleSheet("margin-top: 10px; font-weight: bold;")
            layout.addWidget(recent_label)
            
            for project_path in self.recent_projects[:5]:  # Zobrazit max 5
                if os.path.exists(project_path):
                    # Zkrácený název projektu pro zobrazení
                    project_name = os.path.basename(project_path)
                    if len(project_name) > 50:
                        project_name = project_name[:47] + "..."
                    
                    btn = QPushButton(f"📂 {project_name}")
                    btn.setToolTip(project_path)  # Celá cesta v tooltipu
                    btn.clicked.connect(lambda checked, path=project_path: self.make_choice(path))
                    layout.addWidget(btn)
            
            # Oddělovač
            separator = QLabel("─" * 50)
            separator.setStyleSheet("color: #cccccc; margin-top: 5px; margin-bottom: 5px;")
            layout.addWidget(separator)
        
        # Standardní možnosti
        self.import_btn = QPushButton("📁 Importovat jiný projekt (.nmapproj)")
        self.import_btn.clicked.connect(lambda: self.make_choice("import"))
        layout.addWidget(self.import_btn)
        
        self.new_btn = QPushButton("✨ Vytvořit nový prázdný projekt")
        self.new_btn.clicked.connect(lambda: self.make_choice("new"))
        layout.addWidget(self.new_btn)
        
        self.setLayout(layout)
        self.resize(500, 300)
    
    def make_choice(self, choice):
        self.choice = choice
        self.accept()

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

# ==========================================
# DEFINICE WORDLISTŮ (Ověřená struktura 2026)
# ==========================================
AVAILABLE_WORDLISTS = [
    {
        "name": "Common (SecLists)",
        "filename": "common.txt",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        "desc": "Základní slovník, rychlý a efektivní. (Doporučeno)"
    },
    {
        "name": "Big (SecLists)",
        "filename": "big.txt",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt",
        "desc": "Velký slovník pro důkladné skenování."
    },
    {
        "name": "Directory List 2.3 Medium",
        "filename": "directory-list-2.3-medium.txt",
        "url": "https://raw.githubusercontent.com/daviddias/node-dirbuster/master/lists/directory-list-2.3-medium.txt",
        "desc": "Standardní slovník z nástroje DirBuster."
    },
    {
        "name": "RAFT Medium Directories",
        "filename": "raft-medium-directories.txt",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt",
        "desc": "Velmi populární slovník ze sady RAFT."
    },
    {
        "name": "RAFT Medium Files",
        "filename": "raft-medium-files.txt",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-files.txt",
        "desc": "RAFT slovník zaměřený na konkrétní soubory."
    },
    {
        "name": "Apache Server",
        "filename": "apache.txt",
        # FIX: Velké "A" v názvu souboru (Apache.txt)
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Web-Servers/Apache.txt",
        "desc": "Specifické cesty pro Apache server."
    },
    {
        "name": "IIS Server",
        "filename": "iis.txt",
        # FIX: Velká písmena v názvu souboru (IIS.txt)
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Web-Servers/IIS.txt",
        "desc": "Specifické cesty pro Microsoft IIS."
    },
    {
        "name": "Nginx Server",
        "filename": "nginx.txt",
        # Ponecháno malé "n", protože toto vám fungovalo
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Web-Servers/nginx.txt",
        "desc": "Specifické cesty pro Nginx."
    }
]

class BatchDownloadWorker(QThread):
    """
    Vlákno pro hromadné stahování.
    Upraveno: Nevyhazuje dialogy, sbírá chyby a posílá souhrnný report na konci.
    """
    progress = Signal(str, int) # filename, procenta
    file_finished = Signal(str) # filename hotov (pro odškrtnutí v GUI)
    finished_report = Signal(int, list) # (počet_úspěšných, seznam_chyb)

    def __init__(self, download_list, output_dir):
        super().__init__()
        self.download_list = download_list
        self.output_dir = output_dir
        self.is_running = True

    def run(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)

        total_files = len(self.download_list)
        success_count = 0
        errors = []
        
        for idx, item in enumerate(self.download_list):
            if not self.is_running:
                break
                
            url = item['url']
            filename = item['filename']
            dest_path = os.path.join(self.output_dir, filename)
            
            try:
                self.progress.emit(f"Stahuji: {filename}...", int((idx / total_files) * 100))
                
                # Timeout a stream pro lepší stabilitu
                response = requests.get(url, stream=True, timeout=20)
                
                # Kontrola status kódu - vyhodí výjimku např. u 404
                response.raise_for_status()
                
                with open(dest_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if not self.is_running:
                            break
                        f.write(chunk)
                
                if self.is_running:
                    success_count += 1
                    self.file_finished.emit(filename)
                    
            except Exception as e:
                # Chybu přidáme do seznamu, ale NEZASTAVUJEME vlákno a NEVYHAZUJEME dialog
                clean_err = str(e).replace(url, "...url...") # Zkrácení erroru
                errors.append(f"{filename}: {clean_err}")

        # Na konci pošleme souhrn
        self.finished_report.emit(success_count, errors)

    def stop(self):
        self.is_running = False

class WordlistManagerDialog(QDialog):
    """
    Dialog pro správu a stahování wordlistů.
    Upraveno: Zpracování souhrnného reportu stahování.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Správce slovníků (Wordlists)")
        self.resize(700, 500)
        self.download_dir = os.path.join(os.getcwd(), "wordlists")
        self.worker = None
        
        self.init_ui()
        self.check_existing_files()
    
    def init_ui(self):
        """
        UI rozšířené o sloupec 'Obsah' a tlačítko pro čištění.
        """
        layout = QVBoxLayout(self)
        
        info_label = QLabel("Vyberte slovníky ke stažení (zdroj: SecLists). Soubory se uloží do složky 'wordlists'.")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # --- TABULKA S NOVÝM SLOUPCEM ---
        self.tree = QTreeWidget()
        # Přidán sloupec "Obsah" na index 3
        self.tree.setHeaderLabels(["Název slovníku", "Popis", "Slov", "Obsah", "Stav"])
        
        # Nastavení šířky sloupců
        self.tree.setColumnWidth(0, 200) # Název
        self.tree.setColumnWidth(1, 200) # Popis
        self.tree.setColumnWidth(2, 80)  # Slov
        self.tree.setColumnWidth(3, 100) # Obsah (Nový)
        # Sloupec 4 (Stav) se dopočítá
        
        layout.addWidget(self.tree)
        
        for wl in AVAILABLE_WORDLISTS:
            item = QTreeWidgetItem(self.tree)
            item.setText(0, wl['name'])
            item.setText(1, wl['desc'])
            item.setText(2, "-") 
            item.setText(3, "-") # Placeholder pro Obsah
            item.setText(4, "Zjišťuji...")
            item.setCheckState(0, Qt.CheckState.Unchecked)
            item.setData(0, Qt.UserRole, wl)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("")
        layout.addWidget(self.status_label)
        
        # --- TLAČÍTKA ---
        btn_layout = QHBoxLayout()
        
        self.download_btn = QPushButton("⬇️ Stáhnout vybrané")
        self.download_btn.clicked.connect(self.start_download)
        btn_layout.addWidget(self.download_btn)
        
        # NOVÉ TLAČÍTKO: Čištění
        self.clean_btn = QPushButton("🧹 Vyčistit komentáře (#)")
        self.clean_btn.setToolTip("Odstraní řádky začínající znakem # z vybraných stažených slovníků")
        self.clean_btn.clicked.connect(self.clean_selected_wordlists)
        btn_layout.addWidget(self.clean_btn)
        
        close_btn = QPushButton("Zavřít")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        
        layout.addLayout(btn_layout)

    def check_existing_files(self):
        """
        Ověří existenci, vypočítá slova a zkontroluje přítomnost komentářů.
        """
        if not os.path.exists(self.download_dir):
            os.makedirs(self.download_dir, exist_ok=True)
            
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            data = item.data(0, Qt.UserRole)
            path = os.path.join(self.download_dir, data['filename'])
            
            if os.path.exists(path):
                # 1. Počet slov
                count = 0
                has_comments = False
                
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        # Optimalizovaný průchod souborem (počítá řádky a hledá #)
                        for line in f:
                            count += 1
                            if not has_comments and line.strip().startswith('#'):
                                has_comments = True
                except: 
                    count = 0
                
                # Aktualizace sloupce "Slov"
                item.setText(2, f"{count:,}".replace(",", " "))
                
                # Aktualizace sloupce "Obsah" (NOVÉ)
                if has_comments:
                    item.setText(3, "⚠️ Komentáře")
                    item.setForeground(3, QColor("#F39C12")) # Oranžová
                    item.setToolTip(3, "Slovník obsahuje řádky začínající #. Doporučeno vyčistit.")
                else:
                    item.setText(3, "✅ Čistý")
                    item.setForeground(3, QColor("#2ECC71")) # Zelená
                    item.setToolTip(3, "Slovník je připraven k použití.")

                # Aktualizace sloupce "Stav"
                item.setText(4, "✅ Staženo")
                item.setForeground(4, QColor("#2ECC71"))
                item.setCheckState(0, Qt.CheckState.Unchecked)
            else:
                item.setText(2, "0")
                item.setText(3, "-")
                item.setText(4, "❌ Chybí")
                item.setForeground(4, QColor("#E74C3C"))

    def clean_selected_wordlists(self):
        """
        NOVÁ FUNKCE: Projde vybrané slovníky, odstraní řádky s # a uloží zpět.
        """
        root = self.tree.invisibleRootItem()
        files_cleaned = 0
        total_removed_lines = 0
        errors = []

        # Získat vybrané položky
        selected_items = []
        for i in range(root.childCount()):
            item = root.child(i)
            if item.checkState(0) == Qt.Checked:
                selected_items.append(item)
        
        if not selected_items:
            QMessageBox.warning(self, "Výběr", "Vyberte alespoň jeden slovník k vyčištění.")
            return

        # Potvrzení akce
        reply = QMessageBox.question(
            self, "Potvrzení čištění",
            f"Chystáte se odstranit komentáře (řádky s #) z {len(selected_items)} slovníků.\n\nTato akce přepíše soubory na disku. Pokračovat?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        self.tree.setEnabled(False)
        self.clean_btn.setEnabled(False)
        self.status_label.setText("Probíhá čištění slovníků...")
        QApplication.processEvents() # Překreslit GUI

        for item in selected_items:
            data = item.data(0, Qt.UserRole)
            path = os.path.join(self.download_dir, data['filename'])
            
            if not os.path.exists(path):
                continue # Přeskočit nestáhnuté
                
            try:
                # Načtení a filtrace
                cleaned_lines = []
                removed_in_file = 0
                
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if line.strip().startswith('#'):
                            removed_in_file += 1
                        else:
                            cleaned_lines.append(line)
                
                # Pokud bylo něco odstraněno, uložíme soubor zpět
                if removed_in_file > 0:
                    with open(path, 'w', encoding='utf-8') as f:
                        f.writelines(cleaned_lines)
                    
                    files_cleaned += 1
                    total_removed_lines += removed_in_file
                    
            except Exception as e:
                errors.append(f"{data['name']}: {str(e)}")

        # Aktualizace GUI po dokončení
        self.check_existing_files() # Znovu načte statistiky a stavy
        self.tree.setEnabled(True)
        self.clean_btn.setEnabled(True)
        self.status_label.setText("Čištění dokončeno.")
        
        # Report
        msg = f"Čištění dokončeno.\n\nUpraveno souborů: {files_cleaned}\nOdstraněno řádků: {total_removed_lines}"
        if errors:
            msg += f"\n\nChyby:\n" + "\n".join(errors)
            QMessageBox.warning(self, "Výsledek čištění", msg)
        else:
            QMessageBox.information(self, "Výsledek čištění", msg)

    def start_download(self):
        to_download = []
        root = self.tree.invisibleRootItem()
        
        for i in range(root.childCount()):
            item = root.child(i)
            if item.checkState(0) == Qt.Checked:
                to_download.append(item.data(0, Qt.UserRole))
        
        if not to_download:
            QMessageBox.warning(self, "Výběr", "Vyberte alespoň jeden slovník ke stažení.")
            return

        self.tree.setEnabled(False)
        self.download_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        self.worker = BatchDownloadWorker(to_download, self.download_dir)
        self.worker.progress.connect(self.update_progress)
        self.worker.file_finished.connect(self.on_file_finished)
        # ZMĚNA: Připojíme nový signál finished_report
        self.worker.finished_report.connect(self.on_download_report)
        self.worker.start()

    def update_progress(self, msg, val):
        self.status_label.setText(msg)
        self.progress_bar.setValue(val)

    def on_file_finished(self, filename):
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            data = item.data(0, Qt.UserRole)
            if data['filename'] == filename:
                item.setText(2, "✅ Staženo")
                item.setForeground(2, QColor("#2ECC71"))
                item.setCheckState(0, Qt.CheckState.Unchecked)

    # --- NOVÁ METODA PRO SOUHRNNÉ OKNO ---
    def on_download_report(self, success_count, errors):
        self.tree.setEnabled(True)
        self.download_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText("Akce dokončena.")
        
        if not errors:
            QMessageBox.information(self, "Hotovo", f"Úspěšně staženo {success_count} slovníků.")
        else:
            # Sestavení chybové zprávy
            err_msg = "\n".join(errors[:5]) # Zobrazit max 5 chyb v detailu
            if len(errors) > 5:
                err_msg += f"\n... a {len(errors) - 5} dalších."
                
            QMessageBox.warning(
                self, 
                "Dokončeno s chybami", 
                f"Úspěšně staženo: {success_count}\n"
                f"Chyby: {len(errors)}\n\n"
                f"Detaily chyb:\n{err_msg}"
            )

# ==========================================
# FFUF WORKER S REAL-TIME PROGRESS ČTENÍM
# ==========================================
class StderrReader(QThread):
    """
    Reader s přímým přístupem k signálu.
    """
    def __init__(self, process_stderr, signal_reference):
        super().__init__()
        self.stderr = process_stderr
        self.signal_reference = signal_reference 

    def remove_ansi_codes(self, text):
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)

    def run(self):
        print("DEBUG: [StderrReader] Start")
        # Regex na progress
        progress_re = re.compile(
            r'Progress:\s*\[(\d+)/(\d+)\].*?(\d+)\s*req/sec.*?Duration:\s*\[(.*?)\]', 
            re.IGNORECASE
        )

        while True:
            try:
                # Blokující čtení - pokud je pipe zavřená, vrátí prázdné bytes
                chunk = self.stderr.read(256)
            except (ValueError, OSError):
                # Pipe byla zavřena
                break
                
            if not chunk:
                # EOF
                break
            
            try:
                text_chunk = chunk.decode('utf-8', errors='ignore')
                parts = text_chunk.split('\r')
                
                for part in parts:
                    clean_line = self.remove_ansi_codes(part).strip()
                    if not clean_line or "Progress:" not in clean_line:
                        continue
                        
                    match = progress_re.search(clean_line)
                    if match:
                        current, total, rps, duration = match.groups()
                        data = {
                            'progress': int(current),
                            'total': int(total),
                            'rps': int(rps),
                            'eta': duration
                        }
                        self.signal_reference.emit(data)
                        
            except Exception as e:
                print(f"DEBUG: [StderrReader] Error: {e}")
        
        # Důležité: Zavřít stream pokud je otevřený
        try:
            self.stderr.close()
        except:
            pass
        print("DEBUG: [StderrReader] Finished")
        
class ExportFfufSelectionDialog(QDialog):
    """
    Dialog pro výběr Skenů, Cílů a Status kódů k exportu.
    Obsahuje logiku pro hromadné označování (Rodič -> Děti).
    """
    def __init__(self, source_tree_root, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Výběr dat pro export (FFUF)")
        self.resize(500, 600)
        self.source_root = source_tree_root
        
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Vyberte, co chcete zahrnout do TXT reportu:"))
        
        # Strom pro výběr
        self.tree = QTreeWidget()
        self.tree.setHeaderLabel("Struktura nálezů")
        
        # Propojení kaskádového výběru
        self.tree.itemChanged.connect(self.on_item_changed)
        
        layout.addWidget(self.tree)
        
        # Naplnění stromu
        self.tree.blockSignals(True)
        self.populate_tree()
        self.tree.blockSignals(False)
        
        # --- NOVÉ: Checkbox pro deduplikaci ---
        self.dedup_check = QCheckBox("Deduplikovat výsledky (Case-Insensitive)")
        self.dedup_check.setToolTip("Považuje cesty jako '/admin' a '/ADMIN' za shodné a exportuje pouze první nalezenou.")
        self.dedup_check.setChecked(True) # Defaultně zapnuto, je to užitečné
        layout.addWidget(self.dedup_check)
        # --------------------------------------
        
        # Tlačítka pro výběr
        btn_box = QHBoxLayout()
        btn_all = QPushButton("Vybrat vše")
        btn_none = QPushButton("Zrušit vše")
        btn_all.clicked.connect(self.select_all)
        btn_none.clicked.connect(self.select_none)
        btn_box.addWidget(btn_all)
        btn_box.addWidget(btn_none)
        layout.addLayout(btn_box)
        
        # Dialog tlačítka
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def on_item_changed(self, item, column):
        """
        Kaskádová změna stavu: Pokud změním rodiče, změní se i děti.
        """
        # 1. Zablokujeme signály, aby změna dětí nevyvolala tuto funkci znovu (nekonečná smyčka)
        self.tree.blockSignals(True)
        
        # 2. Zjistíme nový stav rodiče
        new_state = item.checkState(column)
        
        # 3. Aplikujeme na všechny potomky (rekurzivně)
        self._propagate_state(item, new_state)
        
        # 4. Odblokujeme signály
        self.tree.blockSignals(False)

    def _propagate_state(self, parent, state):
        """Rekurzivní pomocná funkce pro nastavení stavu dětí."""
        for i in range(parent.childCount()):
            child = parent.child(i)
            child.setCheckState(0, state)
            # Jdeme hlouběji (např. Session -> Target -> Status)
            self._propagate_state(child, state)
        
    def populate_tree(self):
        """Projder zdrojový strom a vytvoří checkboxy."""
        for i in range(self.source_root.childCount()):
            session_src = self.source_root.child(i)
            session_item = QTreeWidgetItem(self.tree)
            session_item.setText(0, session_src.text(0))
            session_item.setCheckState(0, Qt.CheckState.Checked)
            session_item.setExpanded(True)
            
            for j in range(session_src.childCount()):
                target_src = session_src.child(j)
                target_item = QTreeWidgetItem(session_item)
                target_item.setText(0, target_src.text(0))
                target_item.setCheckState(0, Qt.CheckState.Checked)
                target_item.setExpanded(True)
                
                for k in range(target_src.childCount()):
                    status_src = target_src.child(k)
                    status_text = status_src.text(0)
                    
                    text_lower = status_text.lower()
                    if "status:" in text_lower or "žádné nálezy" in text_lower or "sken dokončen" in text_lower:
                        status_item = QTreeWidgetItem(target_item)
                        status_item.setText(0, status_text)
                        status_item.setCheckState(0, Qt.CheckState.Checked)
                        
    def select_all(self):
        self.tree.blockSignals(True)
        self._set_checked_recursive(self.tree.invisibleRootItem(), Qt.Checked)
        self.tree.blockSignals(False)
        
    def select_none(self):
        self.tree.blockSignals(True)
        self._set_checked_recursive(self.tree.invisibleRootItem(), Qt.Unchecked)
        self.tree.blockSignals(False)
        
    def _set_checked_recursive(self, item, state):
        for i in range(item.childCount()):
            child = item.child(i)
            child.setCheckState(0, state)
            self._set_checked_recursive(child, state)

    def get_selection_map(self):
        result = {}
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            session_item = root.child(i)
            if session_item.checkState(0) == Qt.Unchecked: continue
            session_key = session_item.text(0)
            result[session_key] = {}
            for j in range(session_item.childCount()):
                target_item = session_item.child(j)
                if target_item.checkState(0) == Qt.Unchecked: continue
                target_key = target_item.text(0)
                allowed_statuses = []
                for k in range(target_item.childCount()):
                    status_item = target_item.child(k)
                    if status_item.checkState(0) == Qt.Checked:
                        allowed_statuses.append(status_item.text(0))
                if allowed_statuses:
                    result[session_key][target_key] = allowed_statuses
        return result

class FfufWorker(QThread):
    """
    Worker s podporou pro sledování přesměrování (-r).
    """
    result_found = Signal(dict)
    finished = Signal()
    log = Signal(str)
    progress_update = Signal(dict)

    def __init__(self, target_url, wordlist, options):
        super().__init__()
        self.target_url = target_url
        self.wordlist = wordlist
        self.options = options
        self.is_running = True
        self.process = None
        self.stderr_reader = None

    def run(self):
        print(f"DEBUG: [FfufWorker] Spouštím pro {self.target_url}")
        command = []
        
        ffuf_path = shutil.which("ffuf")
        if not ffuf_path:
            possible_paths = ["/usr/local/bin/ffuf", "/opt/homebrew/bin/ffuf"]
            for p in possible_paths:
                if os.path.exists(p):
                    ffuf_path = p
                    break
        
        if not ffuf_path:
            self.log.emit("❌ Chyba: Nástroj 'ffuf' nebyl nalezen.")
            self.finished.emit()
            return

        command.extend([ffuf_path, "-w", self.wordlist, "-u", f"{self.target_url}/FUZZ", "-json"])
        if self.options.get('extensions'): command.extend(["-e", self.options['extensions']])
        if self.options.get('matcher'): command.extend(["-mc", self.options['matcher']])
        if self.options.get('follow_redirects', False): command.append("-r")

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        try:
            self.process = subprocess.Popen(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, # Musí být PIPE pro reader
                text=False,       
                bufsize=0,        
                env=env
            )
            
            # Start readeru
            self.stderr_reader = StderrReader(self.process.stderr, self.progress_update)
            self.stderr_reader.start()

            # Čtení stdout (výsledky)
            for line in self.process.stdout:
                if not self.is_running: break
                try:
                    line_str = line.decode('utf-8', errors='ignore').strip()
                    if line_str:
                        data = json.loads(line_str)
                        self.result_found.emit(data)
                except json.JSONDecodeError: 
                    pass
            
            print("DEBUG: [FfufWorker] Stdout loop finished, waiting for process...")
            self.process.wait()
            
            # CRITICAL FIX: Musíme počkat, až skončí reader thread!
            if self.stderr_reader and self.stderr_reader.isRunning():
                print("DEBUG: [FfufWorker] Waiting for StderrReader...")
                self.stderr_reader.wait()
            
            print("DEBUG: [FfufWorker] Process and Reader finished.")
            
        except Exception as e:
            self.log.emit(f"❌ Chyba procesu: {str(e)}")
            print(f"DEBUG: [FfufWorker] Exception: {e}")
        finally:
            print(f"DEBUG: [FfufWorker] Emitting finished for {self.target_url}")
            self.finished.emit()

    def stop(self):
        print("DEBUG: [FfufWorker] Stop requested")
        self.is_running = False
        if self.process: 
            self.process.terminate()
            time.sleep(0.5)
            if self.process.poll() is None:
                self.process.kill()
        
        # I při násilném zastavení musíme počkat na reader
        if self.stderr_reader:
            self.stderr_reader.wait()
            
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

class ExportTargetSelectionDialog(QDialog):
    """Mini dialog pro výběr konkrétních cílů k exportu včetně jejich nastavení."""
    def __init__(self, target_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Výběr cílů pro export")
        self.resize(600, 500)
        
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Vyberte konkrétní skeny pro TXT report (Cíl | Konfigurace):"))
        
        # Seznam s checkboxy
        self.list_widget = QListWidget()
        for data in target_data:
            display_text = f"{data['name']}  |  {data['settings']}"
            item = QListWidgetItem(display_text)
            # Uložíme si původní data pro pozdější filtraci
            item.setData(Qt.UserRole, data)
            item.setCheckState(Qt.Unchecked)
            self.list_widget.addItem(item)
        
        layout.addWidget(self.list_widget)
        
        # Tlačítka pro hromadnou manipulaci
        selection_btns = QHBoxLayout()
        btn_all = QPushButton("Vybrat vše")
        btn_none = QPushButton("Zrušit vše")
        btn_all.clicked.connect(self.select_all)
        btn_none.clicked.connect(self.select_none)
        selection_btns.addWidget(btn_all)
        selection_btns.addWidget(btn_none)
        layout.addLayout(selection_btns)
        
        # Potvrzovací tlačítka
        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)

    def select_all(self):
        for i in range(self.list_widget.count()):
            self.list_widget.item(i).setCheckState(Qt.Checked)

    def select_none(self):
        for i in range(self.list_widget.count()):
            self.list_widget.item(i).setCheckState(Qt.Unchecked)

    def get_selected_data(self):
        """Vrátí seznam vybraných dat (název a nastavení)."""
        selected = []
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            if item.checkState() == Qt.Checked:
                selected.append(item.setData(Qt.UserRole))
        return selected

class FfufDialog(QDialog):
    """
    Dialogové okno pro ffuf - FIX CRASH:
    - Opraven odkaz na self.mc_combo v metodě process_next_target.
    """
    def __init__(self, scan_results, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Directory Fuzzing (ffuf)")
        self.resize(1100, 850)
        self.scan_results = scan_results
        self.worker = None
        self.queue = []
        self.is_scanning = False 
        self.json_results = []
        
        # Flagy pro řízení
        self.is_processing_target = False 
        self.current_scan_has_results = False
        self.current_target_url_str = ""
        
        # NOVÉ: Uložení odkazu na aktuální vizuální skupinu (Session)
        self.current_session_item = None
        self.current_scan_timestamp = ""
        
        # Definice skupin přípon pro rychlý výběr
        self.ext_groups = {
            "ASP.NET": [".aspx", ".axd", ".ashx", ".asmx", ".svc"],
            "Java": [".jsp", ".jspx", ".do", ".action"],
            "Config": [".config", ".xml", ".yml", ".yaml", ".json", ".ini", ".env"],
            "Backup": [".bak", ".old", ".zip", ".rar", ".7z", ".tar.gz", ".sql"]
        }
        
        self.init_ui()
        self.load_targets()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(10)
        
        # Cache pro počty řádků v souborech {cesta: pocet}
        self.line_count_cache = {} 

        # --- 1. Konfigurace (Fixní výška) ---
        config_group = QGroupBox("Nastavení skenování")
        config_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        
        config_layout = QGridLayout(config_group)
        config_layout.setContentsMargins(10, 10, 10, 10)
        
        # Řádek 0: Wordlist (ZMĚNĚNO NA CheckableComboBox)
        config_layout.addWidget(QLabel("Slovníky:"), 0, 0)
        self.wordlist_combo = CheckableComboBox() # Nyní Checkable
        self.wordlist_combo.setMinimumWidth(300)
        self.refresh_wordlists()
        config_layout.addWidget(self.wordlist_combo, 0, 1)
        
        wl_btn_layout = QHBoxLayout()
        wl_btn_layout.setContentsMargins(0, 0, 0, 0)
        browse_btn = QPushButton("📂")
        browse_btn.setToolTip("Procházet...")
        browse_btn.setFixedWidth(40)
        browse_btn.clicked.connect(self.browse_wordlist)
        wl_btn_layout.addWidget(browse_btn)
        
        self.manager_btn = QPushButton("📚")
        self.manager_btn.setToolTip("Správce slovníků")
        self.manager_btn.setFixedWidth(40)
        self.manager_btn.clicked.connect(self.open_wordlist_manager)
        wl_btn_layout.addWidget(self.manager_btn)
        wl_btn_layout.addStretch()
        config_layout.addLayout(wl_btn_layout, 0, 2)
        
        self.stats_label = QLabel("Načítám...")
        self.stats_label.setStyleSheet("color: #666; font-size: 11px; font-weight: bold;")
        self.stats_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        config_layout.addWidget(self.stats_label, 0, 3)

        # Řádek 1: Match Codes
        config_layout.addWidget(QLabel("Match Codes:"), 1, 0)
        self.mc_combo = CheckableComboBox()
        codes = [
            ("200", "200 OK", True), ("204", "204 No Content", False),
            ("301", "301 Moved", True), ("302", "302 Found", True),
            ("307", "307 Temp Redirect", False), ("401", "401 Unauthorized", True),
            ("403", "403 Forbidden", True), ("405", "405 Method Not Allowed", False),
            ("500", "500 Server Error", True)
        ]
        for c, t, s in codes: self.mc_combo.add_item(c, t, s)
        config_layout.addWidget(self.mc_combo, 1, 1)
        
        # Přípony
        config_layout.addWidget(QLabel("Přípony (-e):"), 1, 2)
        self.ext_combo = CheckableComboBox()
        self.ext_combo.setMinimumWidth(350)
        self.ext_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        
        defaults = [".php", ".html", ".txt"]
        all_exts = set(defaults)
        for group in self.ext_groups.values():
            all_exts.update(group)
        
        sorted_exts = sorted(list(all_exts))
        for ext in sorted_exts:
            is_checked = ext in defaults
            self.ext_combo.add_item(ext, f"Hledat soubory {ext}", is_checked)
        config_layout.addWidget(self.ext_combo, 1, 3)
        
        # Řádek 2
        self.redirect_check = QCheckBox("Sledovat přesměrování (-r)")
        self.redirect_check.setChecked(True)
        config_layout.addWidget(self.redirect_check, 2, 1)
        
        tech_layout = QHBoxLayout()
        tech_layout.setContentsMargins(0, 0, 0, 0)
        self.chk_asp = QCheckBox("ASP.NET"); self.chk_asp.toggled.connect(lambda s: self.toggle_ext_group("ASP.NET", s))
        self.chk_java = QCheckBox("Java"); self.chk_java.toggled.connect(lambda s: self.toggle_ext_group("Java", s))
        self.chk_config = QCheckBox("Konfig"); self.chk_config.toggled.connect(lambda s: self.toggle_ext_group("Config", s))
        self.chk_backup = QCheckBox("Zálohy"); self.chk_backup.toggled.connect(lambda s: self.toggle_ext_group("Backup", s))
        tech_layout.addWidget(self.chk_asp); tech_layout.addWidget(self.chk_java); tech_layout.addWidget(self.chk_config); tech_layout.addWidget(self.chk_backup); tech_layout.addStretch()
        config_layout.addLayout(tech_layout, 2, 2, 1, 2)

        config_layout.setColumnStretch(4, 1)
        main_layout.addWidget(config_group, 0)
        self.init_ui_rest(main_layout)

        # SIGNÁLY (Opraveno na lineEdit().textChanged pro CheckableComboBox)
        self.wordlist_combo.lineEdit().textChanged.connect(self.update_stats)
        self.ext_combo.lineEdit().textChanged.connect(self.update_stats)
        
        QTimer.singleShot(100, self.update_stats)

    def init_ui_rest(self, main_layout):
        # --- 2. Splitter (Zbytek místa) ---
        splitter = QSplitter(Qt.Horizontal)
        splitter.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        
        # Levá část (Cíle)
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0,0,0,0)
        left_layout.addWidget(QLabel("<b>Webové služby:</b>"))
        self.targets_list = QListWidget()
        self.targets_list.setSelectionMode(QListWidget.MultiSelection)
        left_layout.addWidget(self.targets_list)
        
        target_btns_layout = QHBoxLayout()
        select_all_btn = QPushButton("Vybrat vše")
        select_all_btn.clicked.connect(self.select_all_targets)
        target_btns_layout.addWidget(select_all_btn)
        left_layout.addLayout(target_btns_layout)
        
        left_layout.addSpacing(5)
        left_layout.addWidget(QLabel("Přidat cíl:"))
        manual_add_layout = QHBoxLayout()
        self.manual_target_input = QLineEdit()
        self.manual_target_input.setPlaceholderText("http://cíl:port")
        self.manual_target_input.returnPressed.connect(self.add_manual_target)
        manual_add_layout.addWidget(self.manual_target_input)
        add_btn = QPushButton("➕")
        add_btn.setFixedWidth(30)
        add_btn.clicked.connect(self.add_manual_target)
        manual_add_layout.addWidget(add_btn)
        left_layout.addLayout(manual_add_layout)
        
        left_widget.setMaximumWidth(300)
        splitter.addWidget(left_widget)
        
        # Pravá část (Tabulka výsledků)
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0,0,0,0)
        right_layout.addWidget(QLabel("<b>Nálezy:</b>"))
        
        self.results_tree = QTreeWidget()
        # ZMĚNA: Přejmenování sloupce "Redirect" na "Celá URL"
        self.results_tree.setHeaderLabels(["Cesta", "Status", "Velikost", "Slov", "Celá URL"])
        self.results_tree.setColumnHidden(2, True) # Velikost schovaná
        self.results_tree.setColumnHidden(3, True) # Slov schovaná
        
        header = self.results_tree.header()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setStretchLastSection(True) # Poslední sloupec s URL se roztáhne
        
        self.results_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.results_tree.customContextMenuRequested.connect(self.show_context_menu)
        
        right_layout.addWidget(self.results_tree)
        splitter.addWidget(right_widget)
        
        main_layout.addWidget(splitter, 1)
        
        # --- 3. Panel průběhu (Fixní výška) ---
        progress_frame = QFrame()
        progress_frame.setFrameShape(QFrame.StyledPanel)
        progress_frame.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        
        progress_layout = QVBoxLayout(progress_frame)
        progress_layout.setContentsMargins(5, 5, 5, 5)
        progress_layout.setSpacing(2)
        
        self.scan_progress_bar = QProgressBar()
        self.scan_progress_bar.setVisible(False)
        self.scan_progress_bar.setTextVisible(True)
        self.scan_progress_bar.setFixedHeight(20)
        self.scan_progress_bar.setFormat("%p% - %v / %m")
        progress_layout.addWidget(self.scan_progress_bar)

        stats_layout = QHBoxLayout()
        self.progress_label = QLabel("Postup: -/-")
        self.rps_label = QLabel("Rychlost: -")
        self.eta_label = QLabel("Zbývá: -")
        
        stats_style = "font-size: 11px; color: #888;"
        self.progress_label.setStyleSheet(stats_style)
        self.rps_label.setStyleSheet(stats_style)
        self.eta_label.setStyleSheet(stats_style)
        
        stats_layout.addWidget(self.progress_label)
        stats_layout.addStretch()
        stats_layout.addWidget(self.rps_label)
        stats_layout.addStretch()
        stats_layout.addWidget(self.eta_label)
        progress_layout.addLayout(stats_layout)
        
        main_layout.addWidget(progress_frame, 0)
        
        # --- 4. Spodní panel (Fixní výška) ---
        bottom_widget = QWidget()
        bottom_widget.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        bottom_layout = QHBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 5, 0, 0)
        
        self.total_progress_bar = QProgressBar()
        self.total_progress_bar.setVisible(False)
        self.total_progress_bar.setMaximumWidth(150)
        self.total_progress_bar.setFixedHeight(15)
        self.total_progress_bar.setFormat("Cíle: %v/%m")
        bottom_layout.addWidget(self.total_progress_bar)
        
        self.log_label = QLabel("Připraveno.")
        bottom_layout.addWidget(self.log_label)
        bottom_layout.addStretch()
        
        self.export_json_btn = QPushButton("Uložit JSON")
        self.export_json_btn.setToolTip("Exportovat Raw JSON data")
        self.export_json_btn.clicked.connect(self.export_raw_json)
        self.export_json_btn.setEnabled(False)
        bottom_layout.addWidget(self.export_json_btn)
        
        self.export_txt_btn = QPushButton("Uložit TXT")
        self.export_txt_btn.setToolTip("Exportovat výsledky do strukturovaného TXT")
        self.export_txt_btn.clicked.connect(self.export_results_txt)
        self.export_txt_btn.setEnabled(False) # Aktivuje se až při prvním nálezu
        bottom_layout.addWidget(self.export_txt_btn)

        self.start_btn = QPushButton("Spustit Fuzzing")
        self.start_btn.clicked.connect(self.start_fuzzing)
        bottom_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("Zastavit")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_fuzzing)
        bottom_layout.addWidget(self.stop_btn)
        
        main_layout.addWidget(bottom_widget, 0)
        
    def load_existing_results(self, existing_data):
        """
        Načte výsledky ffuf z projektu.
        OPRAVA: Automaticky přidá historické/manuální cíle do seznamu 'Webové služby'.
        """
        if not existing_data or not isinstance(existing_data, list):
            return
            
        self.log_label.setText("Obnovuji historii skenů...")
        self.json_results = existing_data 
        
        sessions_map = {} 
        targets_map = {}  
        from urllib.parse import urlparse
        
        for data in self.json_results:
            full_url = data.get("url", "")
            if not full_url and data.get('_meta') == 'empty_scan':
                 # Pokusíme se získat URL z metadat, pokud tam je
                 full_url = data.get("url", "") 
            
            if not full_url:
                continue

            # --- NOVÁ LOGIKA: Přidání do seznamu cílů vlevo ---
            try:
                parsed = urlparse(full_url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                
                # Zkontrolujeme, zda už base_url v seznamu targets_list náhodou není
                is_present = False
                for idx in range(self.targets_list.count()):
                    if self.targets_list.item(idx).data(Qt.UserRole) == base_url:
                        is_present = True
                        break
                
                # Pokud v seznamu chybí, přidáme ho (označený jako 'Z historie/Manuální')
                if not is_present:
                    # Pokud byl seznam dříve deaktivován (žádné nmap výsledky), aktivujeme ho
                    self.targets_list.setEnabled(True)
                    new_item = QListWidgetItem(f"{base_url} (Z historie)")
                    new_item.setData(Qt.UserRole, base_url)
                    new_item.setCheckState(Qt.Unchecked)
                    self.targets_list.addItem(new_item)
            except:
                pass
            # --------------------------------------------------

            saved_settings = data.get("_settings", "Načteno z projektu")
            timestamp = data.get("_scan_timestamp", "Historie")
            session_key = f"{timestamp}|{saved_settings}"
            
            if session_key not in sessions_map:
                title = f"SKEN: {timestamp}" if timestamp != "Historie" else "Historie skenování"
                session_item = QTreeWidgetItem([title, "", "", "", saved_settings])
                session_item.setForeground(0, QColor("#34495E")) 
                session_item.setForeground(4, QColor("#7F8C8D"))
                session_item.setFont(0, QFont("Arial", 11, QFont.Bold))
                
                self.results_tree.insertTopLevelItem(0, session_item)
                session_item.setExpanded(True)
                sessions_map[session_key] = session_item
            
            target_key = f"{session_key}|{base_url}"
            if target_key not in targets_map:
                target_item = QTreeWidgetItem(sessions_map[session_key], [f"CÍL: {base_url}", "", "", "", saved_settings])
                target_item.setForeground(0, QColor("#3498DB"))
                target_item.setForeground(4, QColor("#95A5A6"))
                target_item.setFont(0, QFont("Arial", 10, QFont.Bold))
                target_item.setExpanded(True)
                targets_map[target_key] = target_item
            
            if data.get('_meta') == 'empty_scan':
                info_item = QTreeWidgetItem(targets_map[target_key], ["Sken dokončen - žádné nálezy", "", "", "", ""])
                info_item.setForeground(0, QColor("#95A5A6"))
                info_item.setFirstColumnSpanned(True)
                continue

            status = data.get("status", 0)
            path_display = data.get('input', {}).get('FUZZ', 'Unknown')
            if full_url:
                try:
                    parsed = urlparse(full_url)
                    path_display = parsed.path + (f"?{parsed.query}" if parsed.query else "")
                except: pass

            status_group_item = None
            group_label = f"Status: {status}"
            for i in range(targets_map[target_key].childCount()):
                child = targets_map[target_key].child(i)
                if child.text(0) == group_label:
                    status_group_item = child
                    break
            
            if not status_group_item:
                status_group_item = QTreeWidgetItem(targets_map[target_key], [group_label, "", "", "", ""])
                status_group_item.setExpanded(True) # ROZBALENO
                group_color = QColor("#95A5A6")
                if 200 <= status < 300: group_color = QColor("#2ECC71")
                elif 300 <= status < 400: group_color = QColor("#F39C12")
                elif status == 401 or status == 403: group_color = QColor("#E74C3C")
                status_group_item.setForeground(0, group_color)
                status_group_item.setFont(0, QFont("Arial", 10, QFont.Bold))

            res_item = QTreeWidgetItem(status_group_item, [str(path_display), str(status), str(data.get('length', 0)), str(data.get('words', 0)), full_url])
            if 200 <= status < 300: res_item.setForeground(1, QColor("#2ECC71"))
            elif 300 <= status < 400: res_item.setForeground(1, QColor("#F39C12"))
            elif status == 401 or status == 403: res_item.setForeground(1, QColor("#E74C3C"))

        self.results_tree.header().resizeSections(QHeaderView.ResizeToContents)
        
        # NOVÉ: Aktivace tlačítek pro export, pokud máme data
        if self.json_results:
            self.export_txt_btn.setEnabled(True)
            self.export_json_btn.setEnabled(True)
            
        self._refresh_target_list_ui()
        
    def _refresh_target_list_ui(self):
        """
        Pomocná metoda pro seřazení a seskupení cílů.
        OPRAVA: Oddělovače nebudou mít checkboxy a nebudou klikatelné.
        """
        items_data = []
        # Načteme pouze skutečné cíle (přeskočíme staré oddělovače)
        for i in range(self.targets_list.count()):
            item = self.targets_list.item(i)
            url = item.data(Qt.UserRole)
            if url: # Oddělovače nemají UserRole data
                items_data.append({
                    'text': item.text(),
                    'url': url,
                    'checked': item.checkState() == Qt.Checked
                })
        
        if not items_data:
            return

        # Numerické seřazení podle IP adresy
        def sort_key(x):
            try:
                from urllib.parse import urlparse
                netloc = urlparse(x['url']).netloc.split(':')[0]
                return tuple(int(part) for part in netloc.split('.'))
            except:
                return (0, 0, 0, 0)

        items_data.sort(key=sort_key)
        
        self.targets_list.clear()
        last_ip = None
        
        for data in items_data:
            try:
                from urllib.parse import urlparse
                current_ip = urlparse(data['url']).netloc.split(':')[0]
                
                # Přidání oddělovače mezi různé IP adresy
                if last_ip and last_ip != current_ip:
                    separator = QListWidgetItem("───────")
                    # KLÍČOVÁ OPRAVA: Vypnutí všech interakcí a checkboxu
                    separator.setFlags(Qt.NoItemFlags) 
                    separator.setTextAlignment(Qt.AlignCenter)
                    separator.setForeground(QColor("#555555")) # Jemná šedá pro oddělovač
                    self.targets_list.addItem(separator)
                last_ip = current_ip
            except:
                pass

            new_item = QListWidgetItem(data['text'])
            new_item.setData(Qt.UserRole, data['url'])
            # Skutečné cíle mají checkbox povolený
            new_item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            new_item.setCheckState(Qt.Checked if data['checked'] else Qt.Unchecked)
            self.targets_list.addItem(new_item)

    def start_fuzzing(self):
        """
        Spustí proces fuzzingu. 
        Upraveno: Nový sken se vkládá na začátek seznamu (index 0).
        """
        self.export_json_btn.setEnabled(False)

        # Sjednocení slovníků
        selected_paths = []
        model = self.wordlist_combo.model
        for i in range(model.rowCount()):
            item = model.item(i)
            if item.checkState() == Qt.Checked:
                path = item.data(Qt.UserRole)
                if path: selected_paths.append(path)
    
        if not selected_paths:
            QMessageBox.warning(self, "Chyba", "Musíte zaškrtnout alespoň jeden slovník!")
            return

        try:
            unique_words = set()
            for path in selected_paths:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        word = line.strip()
                        if word and not word.startswith('#'):
                            unique_words.add(word)
            
            merged_path = os.path.join(os.getcwd(), "wordlists", "merged_wordlist.tmp")
            with open(merged_path, 'w', encoding='utf-8') as f:
                for word in sorted(list(unique_words)):
                    f.write(f"{word}\n")
            self.current_wordlist = merged_path
        except Exception as e:
            QMessageBox.critical(self, "Chyba", f"Nelze sjednotit slovníky: {e}")
            return

        self.queue = []
        for i in range(self.targets_list.count()):
            item = self.targets_list.item(i)
            if item.checkState() == Qt.Checked:
                self.queue.append(item.data(Qt.UserRole))
        
        if not self.queue:
            QMessageBox.warning(self, "Chyba", "Vyberte alespoň jeden cíl.")
            return

        self.is_scanning = True 
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.scan_progress_bar.setVisible(True)
        self.total_progress_bar.setVisible(True)
        self.total_progress_bar.setRange(0, len(self.queue))
        
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.current_scan_timestamp = timestamp
        
        wls = self.wordlist_combo.lineEdit().text()
        exts = self.ext_combo.get_checked_codes()
        mcs = self.mc_combo.get_checked_codes()
        settings_text = f"Slovníky: {wls} | Přípony: {exts if exts else 'Žádné'} | Match: {mcs}"
        
        # Vytvoření hlavičky relace na indexu 0
        session_title = f"SKEN: {timestamp} (Cílů: {len(self.queue)})"
        self.current_session_item = QTreeWidgetItem([session_title, "", "", "", settings_text])
        
        # ZMĚNA: Design bez pozadí
        self.current_session_item.setForeground(0, QColor("#34495E"))
        self.current_session_item.setForeground(4, QColor("#7F8C8D"))
        self.current_session_item.setFont(0, QFont("Arial", 11, QFont.Bold))
        
        self.results_tree.insertTopLevelItem(0, self.current_session_item)
        self.current_session_item.setExpanded(True)
        
        self.process_next_target(self.current_wordlist)

    def get_line_count(self, filepath):
        """Spočítá řádky v souboru (s jednoduchou cache)."""
        if not filepath or not os.path.isfile(filepath):
            return 0
            
        # Pokud máme v cache a velikost souboru se nezměnila, vrátíme z cache
        try:
            mtime = os.path.getmtime(filepath)
            if filepath in self.line_count_cache:
                cached_mtime, count = self.line_count_cache[filepath]
                if cached_mtime == mtime:
                    return count
        except OSError:
            pass

        # Spočítat řádky (optimalizovaně)
        try:
            with open(filepath, 'rb') as f:
                count = sum(1 for _ in f)
            
            # Uložit do cache
            self.line_count_cache[filepath] = (os.path.getmtime(filepath), count)
            return count
        except Exception:
            return 0

    def update_stats(self):
        """Aktualizuje label se statistikou (Slova x (Přípony + 1) = Celkem)."""
        if not hasattr(self, 'ext_combo') or not hasattr(self, 'wordlist_combo') or not hasattr(self, 'stats_label'):
            return

        # 1. Získat unikátní cesty
        selected_paths = []
        model = self.wordlist_combo.model
        for i in range(model.rowCount()):
            item = model.item(i)
            if item.checkState() == Qt.Checked:
                path = item.data(Qt.UserRole)
                if path and os.path.exists(path):
                    selected_paths.append(path)
        
        if not selected_paths:
            self.stats_label.setText("Žádný slovník nevybrán")
            return

        # 2. Spočítat unikátní slova
        unique_words = set()
        for path in selected_paths:
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        word = line.strip()
                        if word: unique_words.add(word)
            except: pass
        
        word_count = len(unique_words)
        
        # 3. Opravený výpočet multiplieru
        ext_text = self.ext_combo.get_checked_codes()
        extensions = [x for x in ext_text.split(',') if x.strip()]
        
        # ffuf zkouší: slovo + (slovo.ext1, slovo.ext2...) 
        # Tedy multiplier je počet přípon + 1 (pro původní slovo bez přípony)
        multiplier = (len(extensions) + 1) if extensions else 1
        
        total_requests = word_count * multiplier
        
        # 4. Výpis
        wc_str = f"{word_count:,}".replace(",", " ")
        req_str = f"{total_requests:,}".replace(",", " ")
        self.stats_label.setText(f"Slov: {wc_str} | Mult: x{multiplier}\nCelkem: {req_str} reqs")
        
    def show_context_menu(self, position):
        """
        Zobrazí kontextové menu. Nabídne smazání u hlavičky cíle 
        nebo kopírování u konkrétního nálezu.
        """
        item = self.results_tree.itemAt(position)
        if not item: 
            return
        
        menu = QMenu()
        
        # PŘÍPAD A: Kliknutí na modrou hlavičku CÍLE (nemá parenta)
        if item.parent() is None:
            delete_action = menu.addAction("❌ Smazat tento celý sken")
            action = menu.exec(self.results_tree.mapToGlobal(position))
            
            if action == delete_action:
                self.delete_target_scan(item)
                
        # PŘÍPAD B: Kliknutí na konkrétní NÁLEZ (má parenta i grandparenta)
        elif item.parent() is not None and item.parent().parent() is not None:
            copy_word = menu.addAction("Kopírovat řádek slovníku")
            copy_url = menu.addAction("Kopírovat URL adresu")
            
            action = menu.exec(self.results_tree.mapToGlobal(position))
            
            if action == copy_word:
                QApplication.clipboard().setText(item.text(0))
            elif action == copy_url:
                # Sloupec Celá URL je na indexu 4
                QApplication.clipboard().setText(item.text(4))
                
    def delete_target_scan(self, item):
        """
        Odstraní veškerá data spojená s vybraným skenem z paměti i z tabulky.
        Identifikace probíhá pomocí kombinace URL a nastavení.
        """
        # Zjistíme, co mažeme (Session, Target, nebo nested Target)
        target_label = item.text(0) 
        
        # Pokud mažeme celou Session (hlavní skupinu)
        if "SKEN:" in target_label:
            reply = QMessageBox.question(
                self, "Smazat relaci", 
                f"Opravdu smazat celou relaci a všechny její cíle?\n{target_label}",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply != QMessageBox.Yes: return
            
            # Musíme najít všechny děti (Cíle) a smazat jejich data
            # Pro zjednodušení: Projdeme všechny json_results a smažeme ty, 
            # které mají stejný timestamp jako tato session.
            # Timestamp je v titulku "SKEN: 2023-10-10 10:10:10"
            timestamp_str = target_label.replace("SKEN: ", "").split(" (")[0]
            
            self.json_results = [
                d for d in self.json_results 
                if d.get("_scan_timestamp") != timestamp_str
            ]
            
            # Smazat z GUI
            index = self.results_tree.indexOfTopLevelItem(item)
            self.results_tree.takeTopLevelItem(index)
            return

        # Pokud mažeme konkrétní Cíl (Target)
        target_url = target_label.replace("CÍL: ", "").replace("SCAN: ", "").strip()
        settings = item.text(4) # Nastavení je ve sloupci 4

        reply = QMessageBox.question(
            self, "Smazat výsledky",
            f"Opravdu chcete smazat tento sken?\n\nCíl: {target_url}",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            from urllib.parse import urlparse
            
            # Filtrace seznamu json_results - ponecháme jen to, co NEMÁ odpovídat mazanému cíli
            # Musíme filtrovat podle URL (full_url nebo _target_url) a nastavení
            new_results = []
            
            for data in self.json_results:
                # Získat identifikátory dat
                data_url = data.get("url", "")
                data_target = data.get("_target_url", "")
                data_parent = data.get("_parent_url", "")
                data_settings = data.get("_settings", "")
                
                # Logika shody:
                # 1. Pokud data_url odpovídá target_url
                # 2. Pokud data_target odpovídá target_url (pro root skeny)
                # 3. Pokud data_parent odpovídá target_url (pro nested skeny)
                
                # Zjednodušená kontrola: Pokud URL v datech odpovídá mazanému cíli
                # A zároveň sedí nastavení (pokud je dostupné)
                
                match = False
                if data_url == target_url: match = True
                if data_target == target_url: match = True
                
                # Pokud je to shoda A sedí nastavení -> SMAZAT (nepřidat do new)
                if match and (not settings or data_settings == settings):
                    continue
                
                new_results.append(data)
            
            # Aktualizace hlavního seznamu výsledků
            self.json_results = new_results
            
            # Odstranění položky z GUI (musíme najít rodiče)
            parent = item.parent()
            if parent:
                parent.removeChild(item)
            else:
                index = self.results_tree.indexOfTopLevelItem(item)
                self.results_tree.takeTopLevelItem(index)
            
            self.log_label.setText(f"Sken {target_url} byl odstraněn.")

    def toggle_ext_group(self, group_name, checked):
        """Zapne/vypne všechny přípony v dané skupině."""
        if group_name in self.ext_groups:
            extensions = self.ext_groups[group_name]
            for ext in extensions:
                self.ext_combo.set_item_checked(ext, checked)
    
    def refresh_wordlists(self):
        """
        Načte slovníky ze složky 'wordlists' a umožní vícenásobný výběr.
        """
        self.wordlist_combo.blockSignals(True)
        # Vyčistíme model našeho CheckableComboBoxu
        self.wordlist_combo.model.clear()
        
        local_dir = os.path.join(os.getcwd(), "wordlists")
        if not os.path.exists(local_dir):
            os.makedirs(local_dir, exist_ok=True)

        items = []
        for f in os.listdir(local_dir):
            if f.endswith(".txt") and not f.endswith(".tmp"):
                path = os.path.join(local_dir, f)
                count = self.get_line_count(path)
                count_str = f"{count:,}".replace(",", " ")
                display = f"📁 {f} ({count_str} slov)"
                items.append((f.lower(), display, path))

        # Seřadit abecedně
        items.sort(key=lambda x: x[0])

        # Přidání do modelu CheckableComboBoxu
        for _, display, path in items:
            # CheckableComboBox používá vnitřně metodu add_item(text, tooltip, checked)
            self.wordlist_combo.add_item(display, f"Cesta: {path}", False)
            # DŮLEŽITÉ: Uložíme cestu do posledního přidaného řádku v modelu
            last_row = self.wordlist_combo.model.rowCount() - 1
            self.wordlist_combo.model.item(last_row).setData(path, Qt.UserRole)
            
        self.wordlist_combo.blockSignals(False)
        self.wordlist_combo.update_text()
        
        if hasattr(self, 'update_stats'):
            self.update_stats()

    def open_wordlist_manager(self):
        dialog = WordlistManagerDialog(self)
        dialog.exec()
        self.refresh_wordlists()

    def browse_wordlist(self):
        start_dir = os.path.join(os.getcwd(), "wordlists")
        if not os.path.exists(start_dir): start_dir = os.getcwd()
        fname, _ = QFileDialog.getOpenFileName(self, "Vybrat wordlist", start_dir, "Text files (*.txt);;All files (*)")
        if fname:
            self.wordlist_combo.addItem(f"📂 {os.path.basename(fname)}", fname)
            self.wordlist_combo.setCurrentIndex(self.wordlist_combo.count() - 1)

    def load_targets(self):
        self.targets_list.clear()
        found_targets = set()
        phase_data = self.scan_results.get('tcp', {})
        common_web_ports = [80, 443, 8080, 8443, 8000, 8008, 3000, 5000]
        for ip, ip_data in phase_data.items():
            if 'tcp' in ip_data:
                for port, info in ip_data['tcp'].items():
                    if info.get('state') == 'open':
                        service = info.get('name', '').lower()
                        if 'http' in service or 'ssl' in service or int(port) in common_web_ports:
                            proto = "https" if ('ssl' in service or 'https' in service or port == '443') else "http"
                            url = f"{proto}://{ip}:{port}"
                            if url not in found_targets:
                                item = QListWidgetItem(f"{url} ({service})")
                                item.setData(Qt.UserRole, url) 
                                item.setCheckState(Qt.Unchecked)
                                self.targets_list.addItem(item)
                                found_targets.add(url)
        if self.targets_list.count() == 0:
            self.targets_list.addItem("Žádné webové služby (spusťte TCP sken).")
            self.targets_list.setEnabled(False)
        else:
            self.log_label.setText(f"Nalezeno {self.targets_list.count()} webových cílů.")
            
        # Na konec metody:
        if self.targets_list.count() > 0:
            self._refresh_target_list_ui()

    def add_manual_target(self):
        url = self.manual_target_input.text().strip()
        if not url: return
        if not url.startswith("http://") and not url.startswith("https://"): url = "http://" + url
        for i in range(self.targets_list.count()):
            if self.targets_list.item(i).data(Qt.UserRole) == url:
                QMessageBox.warning(self, "Info", "Tento cíl už je v seznamu.")
                return
        item = QListWidgetItem(f"{url} (Manuální)")
        item.setData(Qt.UserRole, url)
        item.setCheckState(Qt.Checked) 
        self.targets_list.addItem(item)
        self.targets_list.setEnabled(True)
        self.log_label.setText(f"Přidán cíl: {url}")
        self.manual_target_input.clear()

    def select_all_targets(self):
        for i in range(self.targets_list.count()):
            self.targets_list.item(i).setCheckState(Qt.Checked)

    def process_next_target(self, wordlist_path=None):
        """Spustí skenování a zapamatuje si aktivní nastavení pro výsledky."""
        # Ochrana proti souběhu
        if self.is_processing_target:
            print("DEBUG: [FfufDialog] process_next_target called but already processing! IGNORING.")
            return

        if not self.queue:
            print("DEBUG: [FfufDialog] Queue empty, finishing.")
            self.fuzzing_finished()
            return
            
        self.is_processing_target = True
        
        if wordlist_path: 
            self.current_wordlist = wordlist_path
            
        current_url = self.queue.pop(0)
        self.current_target_url_str = current_url
        self.current_scan_has_results = False
        
        print(f"DEBUG: [FfufDialog] Processing next target: {current_url}")
        self.log_label.setText(f"Skenuji: {current_url}...")
        
        self.scan_progress_bar.setValue(0)
        self.scan_progress_bar.setFormat("Načítám...")
        self.progress_label.setText("Postup: 0/0")
        
        wls = self.wordlist_combo.lineEdit().text()
        exts = self.ext_combo.get_checked_codes()
        mcs = self.mc_combo.get_checked_codes()
        self.active_settings_for_current_scan = f"WL: {wls} | EXT: {exts if exts else 'žádné'} | MC: {mcs}"

        parent_for_target = self.current_session_item if self.current_session_item else self.results_tree
        
        header = QTreeWidgetItem(parent_for_target, [f"CÍL: {current_url}", "", "", "", self.active_settings_for_current_scan])
        
        # ZMĚNA: Pouze barva textu (modrá), bez barevného pozadí
        header.setForeground(0, QColor("#3498DB"))
        header.setForeground(4, QColor("#95A5A6"))
        header.setFont(0, QFont("Arial", 10, QFont.Bold))
        
        header.setExpanded(True)
        self.current_parent_item = header
        
        options = {
            "matcher": mcs, 
            "extensions": exts,
            "follow_redirects": self.redirect_check.isChecked()
        }
        
        if self.worker:
            try:
                self.worker.result_found.disconnect()
                self.worker.progress_update.disconnect()
                self.worker.finished.disconnect()
            except: pass
        
        self.worker = FfufWorker(current_url, self.current_wordlist, options)
        self.worker.result_found.connect(self.add_result)
        self.worker.progress_update.connect(self.on_progress_update)
        self.worker.finished.connect(self.on_worker_finished, Qt.SingleShotConnection)
        self.worker.start()
        
    def add_result(self, data):
        """
        Zpracuje jeden nález.
        """
        if data.get('_meta') != 'empty_scan':
            self.current_scan_has_results = True
            
        if "_settings" not in data and hasattr(self, "active_settings_for_current_scan"):
            data["_settings"] = self.active_settings_for_current_scan
        
        # NOVÉ: Uložení timestampu skenu do výsledků pro budoucí seskupení
        if "_scan_timestamp" not in data and hasattr(self, "current_scan_timestamp"):
            data["_scan_timestamp"] = self.current_scan_timestamp

        if data not in self.json_results:
            self.json_results.append(data)
        
        if hasattr(self, "export_json_btn"): self.export_json_btn.setEnabled(True)
        if hasattr(self, "export_txt_btn"): self.export_txt_btn.setEnabled(True)
            
        full_url = data.get("url", "")
        if not full_url and data.get('_meta') == 'empty_scan':
             full_url = self.current_target_url_str
        
        # Logika pro vytvoření stromu (pokud se generuje z historie nebo real-time)
        # Zde už předpokládáme, že self.current_parent_item (Cíl) existuje (vytvořen v process_next_target)
        
        if data.get('_meta') == 'empty_scan':
            if self.current_parent_item:
                info_item = QTreeWidgetItem(self.current_parent_item, ["Sken dokončen - žádné nálezy", "", "", "", ""])
                info_item.setForeground(0, QColor("#95A5A6"))
                info_item.setFirstColumnSpanned(True)
            return

        status = data.get("status", 0)
        path_display = ""
        
        if full_url:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(full_url)
                path_display = parsed.path
                if parsed.query: path_display += f"?{parsed.query}"
            except: 
                path_display = full_url
        
        if not path_display: 
            path_display = data.get('input', {}).get('FUZZ', 'Unknown')
            
        status = data.get('status', 0)
        length = data.get('length', 0)
        words = data.get('words', 0)
        
        if self.current_parent_item:
            status_group_item = None
            group_label = f"Status: {status}"
            
            for i in range(self.current_parent_item.childCount()):
                child = self.current_parent_item.child(i)
                if child.text(0) == group_label:
                    status_group_item = child
                    break
                    
            if not status_group_item:
                status_group_item = QTreeWidgetItem(self.current_parent_item, [group_label, "", "", "", ""])
                status_group_item.setExpanded(True)
                group_color = QColor("#95A5A6")
                if 200 <= status < 300: group_color = QColor("#2ECC71")
                elif 300 <= status < 400: group_color = QColor("#F39C12")
                elif status == 401 or status == 403: group_color = QColor("#E74C3C")
                status_group_item.setForeground(0, group_color)
                status_group_item.setFont(0, QFont("Arial", 10, QFont.Bold))
                self.current_parent_item.sortChildren(0, Qt.AscendingOrder)

            item = QTreeWidgetItem(status_group_item, [str(path_display), str(status), str(length), str(words), full_url])
            item.setData(0, Qt.UserRole, full_url)
            
            status_group_item.sortChildren(0, Qt.AscendingOrder)
            
            if 200 <= status < 300: item.setForeground(1, QColor("#2ECC71"))
            elif 300 <= status < 400: item.setForeground(1, QColor("#F39C12"))
            elif status == 401 or status == 403: item.setForeground(1, QColor("#E74C3C"))
            elif status >= 400: item.setForeground(1, QColor("#95A5A6"))
            
            self.results_tree.header().resizeSections(QHeaderView.ResizeToContents)
        
        self.export_txt_btn.setEnabled(True)

    def export_raw_json(self):
        if not self.json_results:
            return

        timestamp = time.strftime("%Y%m%d-%H%M%S")
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Uložit FFUF Raw JSON",
            f"ffuf_raw_results_{timestamp}.json",
            "JSON Files (*.json)"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self.json_results, f, indent=4, ensure_ascii=False)
                QMessageBox.information(self, "Export", f"JSON data uložena do:\n{filename}")
            except Exception as e:
                QMessageBox.critical(self, "Chyba", f"Nepodařilo se uložit soubor: {e}")

    @Slot(dict)
    def on_progress_update(self, data):
        total = data.get('total', 0)
        progress = data.get('progress', 0)
        rps = data.get('rps', 0)
        
        if total > 0:
            self.scan_progress_bar.setRange(0, total)
            self.scan_progress_bar.setValue(progress)
            
            val_str = f"{progress:,}".replace(",", " ")
            tot_str = f"{total:,}".replace(",", " ")
            percent = int((progress / total) * 100) if total > 0 else 0
            self.scan_progress_bar.setFormat(f"{percent}% - {val_str} / {tot_str}")
        
        eta_text = "Výpočet..."
        if rps > 0 and total > progress:
            remaining_items = total - progress
            seconds_left = int(remaining_items / rps)
            
            m, s = divmod(seconds_left, 60)
            h, m = divmod(m, 60)
            if h > 0:
                eta_text = f"{h}h {m}m {s}s"
            else:
                eta_text = f"{m}m {s}s"
        elif progress >= total:
            eta_text = "Hotovo"
        
        self.progress_label.setText(f"Postup: {progress}/{total}")
        self.rps_label.setText(f"Rychlost: {rps} req/sec")
        self.eta_label.setText(f"Zbývá: {eta_text}")
        
        self.scan_progress_bar.update()

    def on_worker_finished(self):
        print("DEBUG: [FfufDialog] Worker finished signal received")
        
        # --- NOVÉ: Pokud nebyly žádné nálezy, vytvoříme placeholder záznam ---
        if not self.current_scan_has_results:
            print("DEBUG: [FfufDialog] No results found, creating placeholder record.")
            empty_record = {
                "url": self.current_target_url_str,
                "status": 0,
                "_settings": self.active_settings_for_current_scan,
                "_meta": "empty_scan" # Značka
            }
            # Zavoláme add_result, aby se to zobrazilo v GUI a uložilo do JSONu
            self.add_result(empty_record)
        # ---------------------------------------------------------------------

        self.total_progress_bar.setValue(self.total_progress_bar.value() + 1)
        
        if self.scan_progress_bar.maximum() > 0:
            self.scan_progress_bar.setValue(self.scan_progress_bar.maximum())
            self.scan_progress_bar.setFormat("100% - Hotovo")

        # Bezpečný úklid starého workeru
        if self.worker:
            # Důkladné odpojení
            try:
                self.worker.result_found.disconnect()
                self.worker.progress_update.disconnect()
                self.worker.finished.disconnect()
            except:
                pass
            
            self.worker.deleteLater()
            self.worker = None

        # Uvolnit zámek těsně před plánováním dalšího
        QTimer.singleShot(500, self._schedule_next)

    def _schedule_next(self):
        """Pomocná metoda volaná časovačem."""
        self.is_processing_target = False  # ODEMKNOUT
        self.process_next_target()

    def stop_fuzzing(self):
        if self.worker: 
            # Odpojit signály aby nedošlo k volání finished
            try:
                self.worker.finished.disconnect()
            except:
                pass
            self.worker.stop()
            
        self.queue = [] 
        self.is_processing_target = False # Reset
        self.log_label.setText("Zastaveno.")
        self.fuzzing_finished()

    def fuzzing_finished(self):
        if not getattr(self, 'is_scanning', False): return
        self.is_scanning = False
        
        # Odstranit dočasný sjednocený slovník
        merged_path = os.path.join(os.getcwd(), "wordlists", "merged_wordlist.tmp")
        if os.path.exists(merged_path):
            try: os.remove(merged_path)
            except: pass

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.targets_list.setEnabled(True)
        self.manager_btn.setEnabled(True)
        self.scan_progress_bar.setVisible(False)
        self.total_progress_bar.setVisible(False)
        self.progress_label.setText("Postup: -/-")
        self.rps_label.setText("Rychlost: -")
        self.eta_label.setText("Zbývá: -")
        if self.log_label.text() != "Zastaveno.":
            self.log_label.setText("Hotovo.")
            QMessageBox.information(self, "Hotovo", "Fuzzing dokončen.")
            
    def export_results_txt(self):
        """
        Exportuje výsledky do TXT.
        Podporuje filtrování a case-insensitive deduplikaci.
        """
        root = self.results_tree.invisibleRootItem()
        if root.childCount() == 0:
            QMessageBox.information(self, "Export", "Nejsou k dispozici žádné výsledky k exportu.")
            return

        sel_dialog = ExportFfufSelectionDialog(root, self)
        if sel_dialog.exec() != QDialog.Accepted:
            return
            
        selection_map = sel_dialog.get_selection_map()
        # Získání stavu checkboxu pro deduplikaci
        deduplicate = sel_dialog.dedup_check.isChecked()
        
        if not selection_map:
            QMessageBox.warning(self, "Export", "Nebyla vybrána žádná data k exportu.")
            return

        timestamp = time.strftime("%Y%m%d-%H%M%S")
        filename, _ = QFileDialog.getSaveFileName(
            self, "Uložit FFUF Report", f"ffuf_report_filtered_{timestamp}.txt", "Text Files (*.txt)"
        )
        
        if not filename: return

        status_map = {
            "200": "OK - Úspěch", "301": "Moved Permanently", "302": "Found",
            "401": "Unauthorized", "403": "Forbidden", "404": "Not Found", "500": "Server Error"
        }

        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("=" * 80 + "\n")
                f.write(f"FFUF SCAN REPORT - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                if deduplicate:
                    f.write("Mód: Deduplikováno (Case-Insensitive)\n")
                f.write("=" * 80 + "\n\n")

                for i in range(root.childCount()):
                    session_item = root.child(i)
                    session_title = session_item.text(0)
                    
                    if session_title not in selection_map: continue
                        
                    session_config = session_item.text(4)
                    f.write("#" * 80 + "\n")
                    f.write(f"{session_title}\n")
                    f.write(f"KONFIGURACE: {session_config}\n")
                    f.write("#" * 80 + "\n\n")
                    
                    for j in range(session_item.childCount()):
                        target_item = session_item.child(j)
                        target_name = target_item.text(0)
                        
                        if target_name not in selection_map[session_title]: continue
                            
                        allowed_statuses = selection_map[session_title][target_name]
                        
                        f.write(f"  [{target_name}]\n")
                        f.write(f"  {'-' * 60}\n")
                        
                        has_data_printed = False
                        target_has_children = target_item.childCount() > 0
                        
                        # --- DEDUPLIKACE: Množina viděných cest pro tento CÍL ---
                        seen_paths = set()
                        
                        for k in range(target_item.childCount()):
                            status_item = target_item.child(k)
                            status_text = status_item.text(0)
                            
                            if status_text not in allowed_statuses: continue
                            
                            # Dočasný buffer pro výsledky v této status skupině
                            # Musíme je bufferovat, abychom zjistili, zda po deduplikaci něco zbylo
                            lines_to_write = []
                            
                            # Zpracování placeholderu "Žádné nálezy"
                            text_lower = status_text.lower()
                            if "žádné nálezy" in text_lower or "sken dokončen" in text_lower:
                                has_data_printed = True
                                f.write(f"    -> {status_text}\n")
                                continue

                            for l in range(status_item.childCount()):
                                result_item = status_item.child(l)
                                path = result_item.text(0) # např. /admin
                                full_url = result_item.text(4)
                                
                                # Logika deduplikace
                                if deduplicate:
                                    path_lower = path.lower()
                                    if path_lower in seen_paths:
                                        continue # Přeskočit duplikát
                                    seen_paths.add(path_lower)
                                
                                lines_to_write.append(f"      - {path:<30} -> {full_url}\n")
                            
                            # Pokud po deduplikaci zbyly nějaké řádky, zapíšeme hlavičku statusu a řádky
                            if lines_to_write:
                                has_data_printed = True
                                status_code = status_text.replace("Status: ", "").strip()
                                note = status_map.get(status_code, "HTTP Stav")
                                f.write(f"\n    STAV {status_code} ({note}):\n")
                                for line in lines_to_write:
                                    f.write(line)
                        
                        if not has_data_printed:
                            if target_has_children:
                                if deduplicate:
                                    f.write("    (Výsledky skryty filtrem nebo deduplikací)\n")
                                else:
                                    f.write("    (Výsledky skryty filtrem)\n")
                            else:
                                f.write("    (Žádná data k dispozici)\n")
                            
                        f.write("\n")
                    f.write("\n")

            QMessageBox.information(self, "Export", f"Report byl úspěšně uložen.")
        except Exception as e:
            QMessageBox.critical(self, "Chyba", f"Chyba při zápisu reportu: {e}")

class NmapScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Finální Nmap Skener - Verze 19.0 (Screenshot Viewer)")
        self.phases = ['online', 'tcp', 'udp', 'vuln', 'osscan']  # ODSTRANĚNA 'screenshot'
        self.scan_results = {}
        self.current_project_path = None
        self.screenshots = {}
        self.loading_project = False
        self.total_tasks = 0
        self.completed_tasks = 0
        
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
        
        # 2. Načteme uložená nastavení (zde se nastaví index ComboBoxu)
        self.load_settings()
        
        # 3. KLÍČOVÝ KROK: Vynutíme aktualizaci šablon podle aktuálního (načteného) stavu ComboBoxu
        self.update_command_templates()
        
        # NOVÉ: Zjistit IP hned po startu
        self.fetch_public_ip()
        
        self.debounce_timer = QTimer(self)
        self.debounce_timer.setSingleShot(True)
        self.debounce_timer.setInterval(500)
        self.debounce_timer.timeout.connect(self.save_settings)
        
        self.raw_input_text.textChanged.connect(self.debounce_timer.start)
        
        # Inicializace command templates podle vybrané intenzity
        intensive = self.intensity_combo.currentIndex() == 0  # 0=Light, 1=Intensive
        initial_templates = {p: self.command_edits[p].text() for p in self.phases}
        
        self.manager_thread = QThread()
        self.worker_signals = WorkerSignals()
        self.scan_manager = ScanManager(initial_templates, self.worker_signals)
        self.scan_manager.moveToThread(self.manager_thread)
        self.manager_thread.start()
        
        self.worker_signals.result.connect(self.handle_single_result)
        self.worker_signals.log.connect(self.log_console.log_message)
        self.worker_signals.task_started.connect(self.on_task_started)
        self.worker_signals.finished.connect(self.task_finished)
        self.worker_signals.screenshot_request.connect(self.handle_screenshot_request)
        self.worker_signals.screenshot_taken.connect(self.on_screenshot_taken)
        self.scan_manager.workflow_finished.connect(self.on_workflow_finished)
        
        self.scan_button.clicked.connect(self.start_workflow_ui)
        self.stop_button.clicked.connect(self.scan_manager.stop_workflow)
        
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


    def calculate_adaptive_sizes(self):
        """Vypočítá adaptivní velikosti panelů podle rozlišení obrazovky."""
        
        # Minimální rozlišení pro plný režim
        FULL_MODE_WIDTH = 3000
        
        if self.screen_width >= FULL_MODE_WIDTH:
            # Velký monitor - původní velikosti
            self.left_panel_width = 400
            self.middle_panel_width = 1000
            self.ip_summary_width = 1200
            self.ip_summary_col0 = 480
            self.ip_summary_col1 = 720
            self.port_summary_width = 300
            self.port_summary_col0 = 144
            self.port_summary_col1 = 155
            self.service_summary_width = 260
            self.service_summary_col0 = 140
            self.service_summary_col1 = 119
            self.font_size = 9  # Normální velikost fontu
            
        elif self.screen_width >= 2560:
            # Střední monitor (2560x1440, 2K) - lehké zmenšení
            self.left_panel_width = 350
            self.middle_panel_width = 900
            self.ip_summary_width = 900
            self.ip_summary_col0 = 360
            self.ip_summary_col1 = 540
            self.port_summary_width = 220
            self.port_summary_col0 = 120
            self.port_summary_col1 = 99
            self.service_summary_width = 280
            self.service_summary_col0 = 175
            self.service_summary_col1 = 104
            self.font_size = 8
            
        elif self.screen_width >= 1920:
            # Full HD (1920x1080) - větší redukce
            self.left_panel_width = 300
            self.middle_panel_width = 700
            self.ip_summary_width = 650
            self.ip_summary_col0 = 260
            self.ip_summary_col1 = 390
            self.port_summary_width = 180
            self.port_summary_col0 = 100
            self.port_summary_col1 = 79
            self.service_summary_width = 220
            self.service_summary_col0 = 140
            self.service_summary_col1 = 79
            self.font_size = 8
            
        else:
            # Malý monitor (1366x768, 1600x900) - maximální komprese
            self.left_panel_width = 250
            self.middle_panel_width = 500
            self.ip_summary_width = 450
            self.ip_summary_col0 = 180
            self.ip_summary_col1 = 270
            self.port_summary_width = 150
            self.port_summary_col0 = 85
            self.port_summary_col1 = 64
            self.service_summary_width = 180
            self.service_summary_col0 = 115
            self.service_summary_col1 = 64
            self.font_size = 7
        
        # Výpočet celkové šířky pravého panelu
        self.right_panel_width = (self.ip_summary_width + 
                                   self.port_summary_width + 
                                   self.service_summary_width)
        
        # Aplikovat globální styl s menším fontem
        if self.font_size < 9:
            self.setStyleSheet(f"QWidget {{ font-size: {self.font_size}pt; }}")

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
        
        # Přidání přepínače intenzity skenování
        intensity_layout = QHBoxLayout()
        intensity_layout.addWidget(QLabel("Intenzita detekce služeb:"))
        self.intensity_combo = QComboBox()
        self.intensity_combo.addItems(["Light (rychlejší)", "Intensive (přesnější)"])
        
        # Připojíme signál pro budoucí změny uživatelem
        self.intensity_combo.currentIndexChanged.connect(self.update_command_templates)
        intensity_layout.addWidget(self.intensity_combo)
        left_panel.addLayout(intensity_layout)
        
        # Přidání checkboxů a command editů
        self.command_edits = {}
        self.phase_checkboxes = {}
        for phase in self.phases:
            phase_layout = QHBoxLayout()
            checkbox = QCheckBox(f"Povolit fázi '{phase.capitalize()}'")
            checkbox.setChecked(True)
            self.phase_checkboxes[phase] = checkbox
            phase_layout.addWidget(checkbox)
            left_panel.addLayout(phase_layout)
            
            left_panel.addWidget(QLabel(f"Šablona příkazu pro fázi '{phase}':"))
            # Inicializujeme prázdné nebo defaultní, update_command_templates to za chvíli v __init__ přepíše správně
            edit = QLineEdit()
            self.command_edits[phase] = edit
            left_panel.addWidget(edit)
        
        btn_layout = QHBoxLayout()
        self.scan_button = QPushButton("Spustit skenování")
        self.stop_button = QPushButton("Zastavit skenování")
        self.stop_button.setEnabled(False)
        btn_layout.addWidget(self.scan_button)
        btn_layout.addWidget(self.stop_button)
        left_panel.addLayout(btn_layout)
        
        # Nový layout pro Export / Import tlačítka
        export_import_layout = QVBoxLayout()
        self.export_btn = QPushButton("Exportovat projekt")
        self.export_btn.clicked.connect(self.export_project_dialog)
        export_import_layout.addWidget(self.export_btn)
        
        self.import_btn = QPushButton("Importovat projekt")
        self.import_btn.clicked.connect(self.import_project_dialog)
        export_import_layout.addWidget(self.import_btn)
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
        middle_panel.addWidget(QLabel("Průběh fází (Matice):"))
        
        self.status_matrix = StatusMatrix(self.phases)
        self.status_matrix.itemClicked.connect(self.on_matrix_ip_clicked)
        
        # PŘIDAT: Reagovat i na změnu výběru (šipky)
        self.status_matrix.currentItemChanged.connect(self.on_matrix_selection_changed)
        
        middle_panel.addWidget(self.status_matrix)
        
        self.tabs = QTabWidget()
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
        
        # Přidat spacer vlevo
        right_side_main_layout.addStretch()
        
        # === Sekce 1: IP Summary (Souhrn vybrané IP) - FIXNÍ 1200px ===
        self.ip_summary_container = QWidget()
        ip_summary_layout = QVBoxLayout(self.ip_summary_container)
        ip_summary_layout.setContentsMargins(0, 0, 0, 0)
        ip_summary_layout.addWidget(QLabel("Souhrn vybrané IP:"))
        
        self.ip_summary_tree = QTreeWidget()
        self.ip_summary_tree.setHeaderLabels(["Atribut", "Hodnota"])
        self.ip_summary_tree.setMinimumWidth(self.ip_summary_width)
        self.ip_summary_tree.setMaximumWidth(self.ip_summary_width)
        
        header_ip = self.ip_summary_tree.header()
        header_ip.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header_ip.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        
        ip_summary_layout.addWidget(self.ip_summary_tree)
        
        default_item = QTreeWidgetItem(self.ip_summary_tree, ["", "Vyberte IP v matici"])
        default_item.setForeground(1, QColor("#999999"))
        
        right_side_main_layout.addWidget(self.ip_summary_container)
        
        # === Sekce 2: Port Summary (Přehled portů) - FIXNÍ ===
        self.port_summary_container = QWidget()
        port_summary_layout = QVBoxLayout(self.port_summary_container)
        port_summary_layout.setContentsMargins(0, 0, 0, 0)
        port_summary_layout.addWidget(QLabel("Přehled portů:"))
        
        self.port_summary_tree = QTreeWidget()
        self.port_summary_tree.setHeaderLabels(["Port/Stav", "Počet IP"])
        self.port_summary_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.port_summary_tree.customContextMenuRequested.connect(self.show_port_context_menu)
        self.port_summary_tree.setMinimumWidth(self.port_summary_width)
        self.port_summary_tree.setMaximumWidth(self.port_summary_width)
        
        header_port = self.port_summary_tree.header()
        header_port.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header_port.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        
        port_summary_layout.addWidget(self.port_summary_tree)
        
        right_side_main_layout.addWidget(self.port_summary_container)
        
        # === Sekce 3: Service Summary (Přehled služeb) - FIXNÍ ===
        self.service_summary_container = QWidget()
        service_summary_layout = QVBoxLayout(self.service_summary_container)
        service_summary_layout.setContentsMargins(0, 0, 0, 0)
        service_summary_layout.addWidget(QLabel("Přehled služeb:"))
        
        self.service_summary_tree = QTreeWidget()
        self.service_summary_tree.setHeaderLabels(["Služba/Port", "Počet IP"])
        self.service_summary_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.service_summary_tree.customContextMenuRequested.connect(self.show_service_context_menu)
        self.service_summary_tree.setMinimumWidth(self.service_summary_width)
        self.service_summary_tree.setMaximumWidth(self.service_summary_width)
        
        header_serv = self.service_summary_tree.header()
        header_serv.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header_serv.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        
        service_summary_layout.addWidget(self.service_summary_tree)
        
        right_side_main_layout.addWidget(self.service_summary_container)
        
        content_splitter.addWidget(right_side_widget)
        
        # Nastavení stretch faktorů pro hlavní content_splitter
        content_splitter.setStretchFactor(0, 0)  # Levý panel - fixní
        content_splitter.setStretchFactor(1, 1)  # Střední panel - PRUŽNÝ
        content_splitter.setStretchFactor(2, 0)  # Pravý panel - fixní
        
        # Defaultní velikosti
        total_right = self.ip_summary_width + self.port_summary_width + self.service_summary_width
        content_splitter.setSizes([400, 1200, total_right])
        
        self.content_splitter = content_splitter  # Uložit referenci
        self.right_side_widget = right_side_widget  # Uložit referenci pro toggle funkce
        
        main_layout.addWidget(content_splitter)
        
    def open_tls_audit_dialog(self):
        """Otevře dialog pro audit TLS a šifer."""
        dialog = TlsAuditDialog(self.scan_results, self)
        dialog.exec()
        
    def open_security_headers_dialog(self):
        """Otevře dialog pro kontrolu Security Headers."""
        if not any(self.scan_results.get('tcp', {}).values()):
            QMessageBox.warning(self, "Žádná data", "Nejdříve spusťte TCP sken portů.")
            return
        dialog = SecurityHeadersDialog(self.scan_results, self)
        dialog.exec()

    def open_certificate_dialog(self):
        """Otevře dialog pro kontrolu certifikátů."""
        if not any(self.scan_results.get(phase, {}) for phase in ['tcp', 'online']):
            QMessageBox.warning(self, "Žádná data", "Nejdříve spusťte skenování (TCP), aby bylo možné detekovat webové služby.")
            return
            
        dialog = CertificateDialog(self.scan_results, self)
        dialog.exec()
        
    def open_ffuf_dialog(self):
        """Otevře ffuf dialog a spravuje předávání dat."""
        if "ffuf" not in self.scan_results:
            self.scan_results["ffuf"] = []

        # Předáváme referenci na naše výsledky
        dialog = FfufDialog(self.scan_results, self)
        
        if self.scan_results["ffuf"]:
            dialog.load_existing_results(self.scan_results["ffuf"])
        
        dialog.exec()
        
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
            self.screenshot_display.setText("Žádné screenshoty k dispozici")
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
    def handle_screenshot_request(self, url, ip, port, path):
        """Vytvoří screenshot v hlavním vlákně."""
        import requests
        from urllib3.exceptions import InsecureRequestWarning
        import warnings
        
        # Potlačit varování o SSL
        warnings.filterwarnings('ignore', category=InsecureRequestWarning)
        
        # Nejprve zkusit HTTP request pro získání status kódu
        try:
            response = requests.get(url, verify=False, timeout=10, allow_redirects=True)
            status_code = response.status_code
            self.worker_signals.log.emit("info", f"📡 HTTP {status_code} pro {url}")
        except Exception as e:
            status_code = None
            self.worker_signals.log.emit("warning", f"⚠️ Chyba HTTP requestu pro {url}: {str(e)[:100]}")
            self.status_matrix.update_status(ip, 'screenshot', 'chyba')
            return
        
        # Pokud je status code OK (2xx nebo 3xx), pokračovat se screenshotem
        if status_code and 200 <= status_code < 400:
            from PySide6.QtWebEngineCore import QWebEngineProfile, QWebEngineSettings, QWebEnginePage
            
            view = QWebEngineView()
            view.resize(1920, 1080)  # Nastavit rozlišení pro screenshot
            
            # Vytvořit vlastní profil s vypnutými SSL kontrolami
            profile = view.page().profile()
            settings = profile.settings()
            settings.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, False)
            settings.setAttribute(QWebEngineSettings.WebAttribute.AllowRunningInsecureContent, True)
            settings.setAttribute(QWebEngineSettings.WebAttribute.ErrorPageEnabled, False)
            
            # Vytvořit vlastní page s ignorováním SSL chyb
            class CustomWebEnginePage(QWebEnginePage):
                def certificateError(self, error):
                    # Ignorovat všechny SSL chyby
                    error.acceptCertificate()
                    return True
            
            custom_page = CustomWebEnginePage(profile, view)
            view.setPage(custom_page)
            
            # Timeout pro načtení stránky
            load_timeout = QTimer()
            load_timeout.setSingleShot(True)
            load_timeout.setInterval(15000)  # 15 sekund
            
            def on_timeout():
                self.worker_signals.log.emit("warning", f"⏱️ Timeout při načítání {url} - pořizuji screenshot i tak...")
                # Pokusit se pořídit screenshot i při timeoutu
                self.capture_and_save(view, self.generate_screenshot_path(ip, port, path), ip, url)
            
            load_timeout.timeout.connect(on_timeout)
            
            def on_load_finished(ok):
                load_timeout.stop()
                
                if ok:
                    # Počkat chvíli na dokončení renderování JavaScriptu
                    QTimer.singleShot(2000, lambda: self.capture_and_save(
                        view, 
                        self.generate_screenshot_path(ip, port, path), 
                        ip, 
                        url
                    ))
                else:
                    # I když načtení "selhalo", zkusit pořídit screenshot
                    self.worker_signals.log.emit("warning", f"⚠️ QWebEngine hlásí chybu načtení {url} (HTTP {status_code}), ale pořizuji screenshot...")
                    QTimer.singleShot(2000, lambda: self.capture_and_save(
                        view, 
                        self.generate_screenshot_path(ip, port, path), 
                        ip, 
                        url
                    ))
            
            view.page().loadFinished.connect(on_load_finished)
            load_timeout.start()
            view.load(url)
        else:
            self.worker_signals.log.emit("warning", f"⚠️ Nečekaný status kód {status_code} pro {url}, screenshot přeskočen.")
            self.status_matrix.update_status(ip, 'screenshot', 'hotovo')
            
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

    
    def generate_screenshot_path(self, ip, port, path):
        """Helper funkce pro generování cesty k souboru screenshotu."""
        now_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        ip_safe = ip.replace('.', '_')
        filename = f"{ip_safe}_{port}_{now_str}.png"
        return os.path.join(path, filename)
    
    def capture_and_save(self, view, filepath, ip, url):
        """Helper funkce pro zachycení a uložení screenshotu."""
        try:
            pixmap = view.grab()
            if not pixmap.isNull():
                pixmap.save(filepath)
                self.worker_signals.log.emit("info", f"📸 Screenshot pro {url} uložen do {filepath}")
                self.worker_signals.screenshot_taken.emit(ip, filepath)
                self.status_matrix.update_status(ip, 'screenshot', 'hotovo')
            else:
                self.worker_signals.log.emit("error", f"❌ Screenshot pro {url} je prázdný (null pixmap)")
                self.status_matrix.update_status(ip, 'screenshot', 'chyba')
        except Exception as e:
            self.worker_signals.log.emit("error", f"❌ Chyba při ukládání screenshotu {url}: {str(e)}")
            self.status_matrix.update_status(ip, 'screenshot', 'chyba')
        finally:
            view.deleteLater()


    def handle_screenshot_request_selenium(self, url, ip, port, path):
        """Alternativní screenshot pomocí Selenium."""
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.common.exceptions import WebDriverException, TimeoutException
        import requests
        
        # HTTP request pro status kód
        try:
            response = requests.get(url, verify=False, timeout=10)
            status_code = response.status_code
            self.worker_signals.log.emit("info", f"📡 HTTP {status_code} pro {url}")
        except Exception as e:
            self.worker_signals.log.emit("warning", f"⚠️ HTTP request selhal: {str(e)[:100]}")
            self.status_matrix.update_status(ip, 'screenshot', 'chyba')
            return
        
        if 200 <= status_code < 400:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--ignore-certificate-errors')
            chrome_options.add_argument('--allow-insecure-localhost')
            
            try:
                driver = webdriver.Chrome(options=chrome_options)
                driver.set_page_load_timeout(15)
                driver.get(url)
                
                now_str = datetime.now().strftime('%Y%m%d_%H%M%S')
                ip_safe = ip.replace('.', '_')
                filename = f"{ip_safe}_{port}_{now_str}.png"
                filepath = os.path.join(path, filename)
                
                driver.save_screenshot(filepath)
                self.worker_signals.log.emit("info", f"📸 Screenshot pro {url} (HTTP {status_code}) uložen")
                self.worker_signals.screenshot_taken.emit(ip, filepath)
                self.status_matrix.update_status(ip, 'screenshot', 'hotovo')
                
                driver.quit()
            except (WebDriverException, TimeoutException) as e:
                self.worker_signals.log.emit("warning", f"⚠️ Screenshot selhal: {str(e)[:100]}")
                self.status_matrix.update_status(ip, 'screenshot', 'chyba')
        else:
            self.worker_signals.log.emit("warning", f"⚠️ Status {status_code}, screenshot přeskočen")
            self.status_matrix.update_status(ip, 'screenshot', 'hotovo')

    @Slot(str, str)
    def on_screenshot_taken(self, ip, filepath):
        """Reaguje na pořízení screenshotu a aktualizuje GUI."""
        if ip not in self.screenshots:
            self.screenshots[ip] = []
        self.screenshots[ip].append(filepath)
        
        # Aktualizovat screenshot viewer
        self.update_screenshot_viewer()

    @Slot(QTreeWidgetItem, int)
    def on_matrix_ip_clicked(self, item, column):
        """Zobrazí souhrn výsledků pro vybranou IP z matici."""
        ip_address = item.text(0)
        
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
        
        # Zranitelnosti - shromáždit z fáze vuln - POUZE POTVRZENÉ
        vulnerabilities = []
        vuln_data = self.scan_results.get('vuln', {}).get(ip_address, {})
        
        # Klíčová slova, která indikují potvrzenou zranitelnost
        confirmed_keywords = [
            'VULNERABLE',
            'EXPLOITABLE',
            'CONFIRMED',
            'State: VULNERABLE',
            'IDS: CVE',
            'Risk factor:'
        ]
        
        # Klíčová slova, která indikují nepotvrcenou/negativní výsledek
        negative_keywords = [
            'NOT vulnerable',
            'Not vulnerable',
            'No vulnerability',
            'not affected',
            'LIKELY NOT vulnerable',
            'false positive',
            'State: NOT VULNERABLE'
        ]
        
        for proto in ['tcp', 'udp']:
            if proto in vuln_data:
                for port, info in vuln_data[proto].items():
                    if 'script' in info:
                        for script_name, script_output in info['script'].items():
                            output_upper = script_output.upper()
                            
                            # Zkontrolovat, zda výstup obsahuje potvrzení zranitelnosti
                            is_confirmed = any(keyword.upper() in output_upper for keyword in confirmed_keywords)
                            is_negative = any(keyword.upper() in output_upper for keyword in negative_keywords)
                            
                            # Přidat pouze pokud je potvrzená a není negativní
                            if is_confirmed and not is_negative:
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

    def start_workflow_ui(self):
        # Zkontrolovat, zda již existují data z předchozího testu
        has_existing_data = any(len(self.scan_results.get(phase, {})) > 0 for phase in self.phases)
        
        if has_existing_data:
            # Zobrazit dialog pro vytvoření nového projektu
            msg_box = QMessageBox(self)
            msg_box.setIcon(QMessageBox.Warning)
            msg_box.setWindowTitle("Upozornění - Existující data")
            msg_box.setText("V aplikaci již existují data z předchozího testování.")
            msg_box.setInformativeText(
                "Chcete vytvořit nový projekt?\n\n"
                "• ANO - Vytvoří nový projekt a smaže aktuální data\n"
                "• NE - Zruší spuštění testu a zachová současný projekt\n"
                "• ULOŽIT A POKRAČOVAT - Uloží aktuální projekt a vytvoří nový"
            )
            
            new_btn = msg_box.addButton("Ano (Smazat a spustit)", QMessageBox.YesRole)
            save_and_new_btn = msg_box.addButton("Uložit a pokračovat", QMessageBox.AcceptRole)
            cancel_btn = msg_box.addButton("Ne (Zrušit)", QMessageBox.NoRole)
            
            msg_box.setDefaultButton(save_and_new_btn)
            msg_box.exec()
            
            clicked_button = msg_box.clickedButton()
            
            if clicked_button == cancel_btn:
                # Zrušit spuštění
                self.worker_signals.log.emit("warning", "Spuštění nového testu zrušeno uživatelem.")
                return
            elif clicked_button == save_and_new_btn:
                # Uložit aktuální projekt před pokračováním
                self.export_project_dialog()
                self.worker_signals.log.emit("info", "Aktuální projekt uložen. Spouštím nový projekt...")
            elif clicked_button == new_btn:
                # Pouze logovat
                self.worker_signals.log.emit("info", "Zahajuji nový projekt, předchozí data budou smazána...")
        
        cleaned_text = self.cleaned_output_text.toPlainText()
        
        # Filtrovat zakomentované řádky (začínající #) a prázdné řádky
        targets = [
            line.strip()
            for line in cleaned_text.splitlines()
            if line.strip() and not line.strip().startswith('#')
        ]
        
        if not targets:
            self.status_label.setText("Žádné cíle k testování (všechny jsou zakomentované nebo prázdné).")
            return
        
        # Zjistit které fáze jsou povoleny
        enabled_phases = {phase: checkbox.isChecked() for phase, checkbox in self.phase_checkboxes.items()}
        self.scan_manager.set_enabled_phases(enabled_phases)
        
        # Aktualizovat command templates
        self.scan_manager.command_templates = {p: self.command_edits[p].text() for p in self.phases}
        
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.log_console.clear()
        
        for tree in self.tree_widgets.values():
            tree.clear()
        
        self.scan_results = {p: {} for p in self.phases}
        self.status_matrix.populate_targets(targets)
        
        # Označit zakázané fáze v matici
        for target in targets:
            for phase in self.phases:
                if not enabled_phases[phase]:
                    self.status_matrix.update_status(target, phase, 'skipped_by_user')
        
        self.total_tasks = len(targets)
        self.completed_tasks = 0
        
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        self.base_export_path = Path.cwd() / f"nmap_scan_results_{timestamp}"
        self.base_export_path.mkdir(parents=True, exist_ok=True)
        
        self.worker_signals.log.emit("info", f"Výsledky se budou ukládat do: {self.base_export_path}")
        
        # NOVÉ: Při startu nového testování vytvořit autosave projekt pokud neexistuje
        if not self.current_project_path:
            home_dir = os.path.expanduser("~")
            autosave_dir = os.path.join(home_dir, ".nmap_scanner_autosave")
            os.makedirs(autosave_dir, exist_ok=True)
            
            project_name = self.project_name_edit.text().replace(" ", "_").replace("/", "_")
            timestamp_auto = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.current_project_path = os.path.join(autosave_dir, f"{project_name}_{timestamp_auto}_autosave.nmapproj")
            
            self.worker_signals.log.emit("info", f"🔄 Vytvořen dočasný autosave projekt: {self.current_project_path}")
        
        self.scan_manager.start_workflow(targets)

    def show_startup_dialog(self):
        """Zobrazí startup dialog pro výběr projektu."""
        last_project_path = self.settings.value("last_project_path", None)
        has_last = last_project_path and os.path.exists(last_project_path)

        dialog = StartupDialog(has_last_project=has_last, parent=self)
        if dialog.exec() == QDialog.Accepted:
            if dialog.choice == "last":
                self.import_project(last_project_path)
            elif dialog.choice == "import":
                self.import_project_dialog()
            # "new" -> nic nedělat, pokračovat s prázdným projektem

    def export_project_dialog(self):
        """Export projektu do JSON (.nmapproj). Povoleno jen, když neběží testování."""
        if self.scan_manager.is_running:
            QMessageBox.warning(self, "Export nelze", "Export není možný během probíhajícího testování.")
            return
        
        path, _ = QFileDialog.getSaveFileName(self, "Exportovat projekt", "", "Nmap Project (*.nmapproj)")
        if not path:
            return
        
        project_data = self.gather_project_data()
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(project_data, f, indent=2, ensure_ascii=False)
            
            self.current_project_path = path  # NOVÉ: Uložit jako aktuální projekt
            self.add_to_recent_projects(path)
            
            self.settings.setValue("last_project_path", path)
            self.status_label.setText(f"Projekt exportován do {path}")
            self.worker_signals.log.emit("export", f"Projekt úspěšně exportován do {path}.")
        except Exception as e:
            QMessageBox.critical(self, "Chyba exportu", f"Nelze uložit projekt: {e}")

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

    def gather_project_data(self):
        """Sestaví dict se stavem projektu pro export. Včetně certifikátů v scan_results."""
        return {
            "project_name": self.project_name_edit.text(),
            "intensity_mode": self.intensity_combo.currentIndex(),
            "raw_input_text": self.raw_input_text.toPlainText(),
            "cleaned_output_text": self.cleaned_output_text.toPlainText(),
            "phase_settings": {
                phase: {
                    "enabled": self.phase_checkboxes[phase].isChecked(),
                    "command": self.command_edits[phase].text()
                }
                for phase in self.phases
            },
            "scan_results": self.scan_results, # Zde jsou již certifikáty uloženy
            "screenshots": self.screenshots
        }

    def apply_project_data(self, data):
        """Načte data z .nmapproj a zajistí persistenci certifikátů."""
        self.loading_project = True
        
        p_name = data.get("project_name") or data.get("name") or "Můj Nmap Projekt"
        self.project_name_edit.setText(p_name)
        
        self.intensity_combo.blockSignals(True)
        idx = int(data.get("intensity_mode", 1))
        self.intensity_combo.setCurrentIndex(idx)
        self.intensity_combo.blockSignals(False)

        phase_settings = data.get("phase_settings", {})
        for phase in self.phases:
            settings = phase_settings.get(phase, {})
            if phase in self.phase_checkboxes:
                self.phase_checkboxes[phase].setChecked(settings.get("enabled", True))
            if phase in self.command_edits:
                cmd_text = settings.get("command", self.get_command_template(phase, intensive=(idx==1)))
                self.command_edits[phase].setText(cmd_text)
    
        # Načtení výsledků skenů
        self.scan_results = data.get("scan_results", {})
        # Inicializace klíče pro certifikáty, pokud v projektu chybí
        if 'certificates' not in self.scan_results:
            self.scan_results['certificates'] = {}
            
        self.raw_input_text.setPlainText(data.get("raw_input_text", ""))
        self.cleaned_output_text.setPlainText(data.get("cleaned_output_text", ""))
        
        if hasattr(self, 'scan_manager'):
            self.scan_manager.command_templates = {p: self.command_edits[p].text() for p in self.phases}

        self.loading_project = False
        self.repopulate_ui_from_results()
        self.status_label.setText(f"Projekt '{p_name}' načten včetně SSL auditů.")

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

    @Slot(str, str)
    def on_task_started(self, phase, target):
        # Pokud fáze obsahuje -Pn, pošli status "probíhá -Pn", jinak jen "probíhá"
        if '-Pn' in phase:
            self.status_matrix.update_status(target, phase, 'probíhá -Pn')
        else:
            self.status_matrix.update_status(target, phase, 'probíhá')


    @Slot(str, str, dict)
    def handle_single_result(self, phase, target, data):
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
            
            status = "hotovo"
            
            if data.get('status') == 'skipped_by_user':
                status = 'zakázáno'
                target_item.setText(1, 'Fáze zakázána uživatelem')
                target_item.setForeground(1, QColor("#95A5A6"))
            
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
                                    
                                    # Kontrola, zda neprobíhá načítání projektu
                                    if not hasattr(self, 'loading_project') or not self.loading_project:
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
                    if base_phase == 'tcp' and not has_http:
                        if not hasattr(self, 'loading_project') or not self.loading_project:
                            self.status_matrix.update_status(target, 'screenshot', 'hotovo')
    
            
            # DŮLEŽITÉ: Aktualizovat status v matici s původním názvem fáze (včetně -Pn)
            self.status_matrix.update_status(target, phase, status)  # Poslat 'phase' místo 'base_phase'
            
            self.sort_tree_by_ip(tree)
            
            # Aktualizace přehledu portů
            if hasattr(self, 'port_summary_tree'):
                self.update_port_summary()
                self.update_service_summary()
                self.update_online_display_with_ports()


    @Slot()
    def task_finished(self):
        with QMutexLocker(output_mutex):
            self.completed_tasks += 1
            
            # Aktualizovat progress pro aktuální fázi
            # (detekce fáze z posledního výsledku)
            phase_completed = None
            for phase in self.phases:
                if phase in self.scan_results and self.scan_results[phase]:
                    if self.scan_manager.phase_progress[phase]['completed'] < self.scan_manager.phase_progress[phase]['total']:
                        self.scan_manager.phase_progress[phase]['completed'] += 1
                        progress = self.scan_manager.phase_progress[phase]
                        percent = (progress['completed'] / progress['total'] * 100) if progress['total'] > 0 else 0
                        self.worker_signals.log.emit("info", f"📈 [{phase.upper()}] Průběh: {progress['completed']}/{progress['total']} ({percent:.1f}%)")
                        
                        # Zjistit, zda byla fáze právě dokončena
                        if progress['completed'] == progress['total']:
                            phase_completed = phase
                        
                        break
            
            # NOVÉ: Automatické uložení projektu po dokončení fáze
            if phase_completed:
                self.worker_signals.log.emit("info", f"✅ Fáze {phase_completed.upper()} dokončena - spouštím autosave...")
                self.auto_save_project()
            
            # Původní logika
            if self.completed_tasks >= self.total_tasks:
                if len(self.scan_results.get('tcp', {})) == 0 and len(self.scan_results.get('udp', {})) == 0:
                    all_targets = list(self.status_matrix.ip_items.keys())
                    self.total_tasks = len(all_targets) * (len(self.phases) - 1)
                    self.completed_tasks = 0
                    
                    if self.scan_manager.is_running:
                        self.scan_manager.handle_online_phase_done(self.scan_results['online'])
                else:
                    if self.scan_manager.is_running:
                        self.on_workflow_finished()

    @Slot()
    def on_workflow_finished(self):
        """Voláno při dokončení celého workflow všech fází."""
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_label.setText("Skenování dokončeno! Připraveno k exportu.")
        self.worker_signals.log.emit("export", "Všechny fáze dokončeny. Výsledky jsou k dispozici pro export.")
        
        # NOVÉ: Finální autosave po dokončení všech fází
        self.worker_signals.log.emit("info", "✅ Všechny fáze dokončeny - spouštím finální autosave...")
        self.auto_save_project()

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

    def get_command_template(self, phase, intensive=True):
        """Vrací šablonu příkazu podle fáze a intenzity."""
        if intensive:
            # Intensive mode - maximální přesnost
            return {
                'online': "nmap -sn -T4 -oX - {target}",
                'tcp': "nmap -T4 -sS -sV --version-intensity 9 -p- -oX - {target}",
                'udp': "nmap -T4 -sU -sV --version-intensity 7 -p- -oX - {target}",
                'vuln': "nmap -T4 -sV --version-intensity 9 --script vuln -oX - {target}",
                'osscan': "nmap -O -T4 -oX - {target}"
            }.get(phase, "")
        else:
            # Light mode - rychlejší
            return {
                'online': "nmap -sn -T4 -oX - {target}",
                'tcp': "nmap -T4 -sS -sV --version-light -p- -oX - {target}",
                'udp': "nmap -T4 -sU -sV --version-light --top-ports 1000 -oX - {target}",
                'vuln': "nmap -T4 -sV --version-light --script vuln -oX - {target}",
                'osscan': "nmap -O -T4 -oX - {target}"
            }.get(phase, "")
        
    @Slot()
    def update_command_templates(self):
        """Aktualizuje šablony příkazů v UI podle vybrané intenzity v ComboBoxu."""
        # Zjištění stavu přímo z ComboBoxu
        is_intensive = self.intensity_combo.currentIndex() == 1
        
        for phase in self.phases:
            new_template = self.get_command_template(phase, intensive=is_intensive)
            if phase in self.command_edits:
                self.command_edits[phase].setText(new_template)
        
        # Synchronizace šablon do manažera skenování, pokud již existuje
        if hasattr(self, 'scan_manager'):
            self.scan_manager.command_templates = {p: self.command_edits[p].text() for p in self.phases}

        # Logování
        if hasattr(self, 'worker_signals') and self.worker_signals:
            mode = "Intensive" if is_intensive else "Light"
            self.worker_signals.log.emit("info", f"🔄 Příkazy synchronizovány s režimem: {mode}")

    def update_cumulative_reports(self, target_ip):
        if not hasattr(self, 'base_export_path'):
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
        """Automaticky uloží projekt na pozadí během testování."""
        if not self.current_project_path:
            # Pokud není otevřený žádný projekt, vytvořit dočasný autosave
            home_dir = os.path.expanduser("~")
            autosave_dir = os.path.join(home_dir, ".nmap_scanner_autosave")
            os.makedirs(autosave_dir, exist_ok=True)
            
            project_name = self.project_name_edit.text().replace(" ", "_").replace("/", "_")
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            autosave_path = os.path.join(autosave_dir, f"{project_name}_{timestamp}_autosave.nmapproj")
            
            self.current_project_path = autosave_path
            self.worker_signals.log.emit("info", f"🔄 Autosave: Vytvořen dočasný projekt {autosave_path}")
        
        try:
            project_data = self.gather_project_data()
            with open(self.current_project_path, 'w', encoding='utf-8') as f:
                json.dump(project_data, f, indent=2, ensure_ascii=False)
            
            self.worker_signals.log.emit("info", f"💾 Autosave: Projekt automaticky uložen do {self.current_project_path}")
        except Exception as e:
            self.worker_signals.log.emit("error", f"⚠️ Autosave: Chyba při automatickém ukládání: {e}")


    def save_settings(self):
        settings = QSettings("UTB", "NmapScannerApp")
        settings.setValue("last_input", self.raw_input_text.toPlainText())
        settings.setValue("cleaned_output", self.cleaned_output_text.toPlainText())
        settings.setValue("intensity_mode", self.intensity_combo.currentIndex())
    
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
        
        # Načtení intenzity (výchozí: 1 = Intensive)
        intensity_index = self.settings.value("intensity_mode", 1, type=int)
        
        # Blokovat signály během načítání nastavení
        self.intensity_combo.blockSignals(True)
        self.intensity_combo.setCurrentIndex(intensity_index)
        self.intensity_combo.blockSignals(False)

    def closeEvent(self, event):
        """Při zavření aplikace nabídnout uložení projektu."""
        self.save_settings()
        
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
        
        elif clicked == save_current_btn and self.current_project_path:
            # Uložit do současného projektu
            try:
                project_data = self.gather_project_data()
                with open(self.current_project_path, 'w', encoding='utf-8') as f:
                    json.dump(project_data, f, indent=2, ensure_ascii=False)
                self.worker_signals.log.emit("export", f"Projekt uložen do {self.current_project_path}")
            except Exception as e:
                QMessageBox.critical(self, "Chyba uložení", f"Nelze uložit projekt: {e}")
                event.ignore()
                return
        
        elif clicked == save_new_btn:
            # Uložit jako nový projekt
            path, _ = QFileDialog.getSaveFileName(
                self,
                "Uložit projekt jako",
                "",
                "Nmap Project (*.nmapproj)"
            )
            if path:
                try:
                    project_data = self.gather_project_data()
                    with open(path, 'w', encoding='utf-8') as f:
                        json.dump(project_data, f, indent=2, ensure_ascii=False)
                    self.worker_signals.log.emit("export", f"Projekt uložen do {path}")
                except Exception as e:
                    QMessageBox.critical(self, "Chyba uložení", f"Nelze uložit projekt: {e}")
                    event.ignore()
                    return
            else:
                # Uživatel zrušil dialog - zeptat se, zda chce pokračovat bez uložení
                reply = QMessageBox.question(
                    self,
                    "Neuloženo",
                    "Projekt nebyl uložen. Opravdu chcete ukončit bez uložení?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                if reply == QMessageBox.No:
                    event.ignore()
                    return
        
        # elif clicked == dont_save_btn - nic nedělat, jen zavřít
        
        # Korektní ukončení vláken
        self.manager_thread.quit()
        self.manager_thread.wait()
        event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = NmapScannerApp()
    window.showMaximized()
    sys.exit(app.exec())
