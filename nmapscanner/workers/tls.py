import os
import shutil
import socket
import subprocess
from datetime import datetime
from xml.etree import ElementTree as ET



from PySide6.QtCore import Slot, QRunnable


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

