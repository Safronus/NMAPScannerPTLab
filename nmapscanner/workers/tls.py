import os
import shutil
import socket
import subprocess
from datetime import datetime
from xml.etree import ElementTree as ET



from PySide6.QtCore import Slot, QRunnable

from ..core.tls_grading import classify_cipher


class TlsAuditWorker(QRunnable):
    """
    Asynchronní worker pro testování TLS verzí a šifer pomocí Nmap (ssl-enum-ciphers).
    Získává detailní seznam Cipher Suites jako Qualys SSL Labs.
    """
    def __init__(self, ip, port, signals, cancel_event=None):
        super().__init__()
        self.ip = ip
        self.port = str(port)
        self.signals = signals
        self.cancel_event = cancel_event

    def _is_cancelled(self):
        return self.cancel_event is not None and self.cancel_event.is_set()

    def evaluate_cipher(self, name):
        """Vyhodnotí sílu šifry dle Qualys SSL Labs. Vrací (label, barva, tag)."""
        return classify_cipher(name)

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
            'engine': 'Nmap',
            'protocols': {},
            'cipher_tree': {},
            'check_time': datetime.now().strftime('%d.%m.%Y %H:%M:%S'),
            'status': "Hotovo"
        }

        try:
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=90)

            if self._is_cancelled():
                scan_data['status'] = "Zrušeno"
                scan_data['error'] = "Prověření zrušeno uživatelem."
                self.signals.result.emit(self.ip, self.port, scan_data)
                self.signals.finished.emit()
                return

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

    Qualys umí scanovat **jen veřejné domény** (přes veřejné DNS + SNI), ne
    interní IP. Pokud je cíl IP, zkusí se reverzní DNS na veřejný hostname;
    interní/privátní IP se odmítne s jasnou hláškou (použij Nmap nebo TestSSL).
    """
    def __init__(self, ip, port, signals, cancel_event=None):
        super().__init__()
        self.ip = ip
        self.port = str(port)
        self.signals = signals
        self.cancel_event = cancel_event
        self.api_url = "https://api.ssllabs.com/api/v3/analyze"

    def _is_cancelled(self):
        return self.cancel_event is not None and self.cancel_event.is_set()

    def _wait_or_cancel(self, seconds):
        """Spí až ``seconds`` s, ale probudí se hned po zrušení (kontrola po 1 s)."""
        import time
        for _ in range(int(seconds)):
            if self._is_cancelled():
                return True
            time.sleep(1)
        return False

    def _resolve_host(self):
        """Vrátí (hostname, error). Pro doménu vrátí ji; pro IP zkusí reverzní DNS."""
        import ipaddress
        target = (self.ip or "").strip()
        try:
            ip_obj = ipaddress.ip_address(target)
        except ValueError:
            # Není to IP → bereme jako doménu (to Qualys umí).
            return target, None
        # Interní/privátní IP Qualys neumí (potřebuje veřejnou dosažitelnost).
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
            return None, ("Qualys SSL Labs skenuje jen veřejné cíle, ne interní/privátní IP "
                          f"({target}). Pro interní cíle použij engine Nmap nebo TestSSL.sh.")
        # Veřejná IP: nejdřív zkus reverzní DNS (lepší shoda s certem), jinak
        # předáme IP přímo Qualysu — ať to zkusí (Qualys u IP vrátí vlastní chybu,
        # když to nejde).
        try:
            return socket.gethostbyaddr(target)[0], None
        except Exception:
            return target, None

    @Slot()
    def run(self):
        scan_data = {
            'ip': self.ip, 'port': self.port, 'domain': self.ip,
            'engine': 'Qualys',
            'protocols': {}, 'cipher_tree': {},
            'check_time': datetime.now().strftime('%d.%m.%Y %H:%M:%S'),
            'status': "Hotovo"
        }

        # Qualys testuje pouze port 443.
        if self.port != "443":
            scan_data['status'] = "Chyba"
            scan_data['error'] = "Qualys SSL Labs podporuje pouze port 443."
            self.signals.result.emit(self.ip, self.port, scan_data)
            self.signals.finished.emit()
            return

        host, host_err = self._resolve_host()
        if host_err:
            scan_data['status'] = "Chyba"
            scan_data['error'] = host_err
            self.signals.result.emit(self.ip, self.port, scan_data)
            self.signals.finished.emit()
            return
        scan_data['domain'] = host

        try:
            import requests
            import time

            base = {'host': host, 'publish': 'off', 'all': 'done', 'ignoreMismatch': 'on'}
            # První dotaz spustí nové hodnocení; další jen pollují stav.
            params = dict(base, startNew='on')
            data = {}
            deadline = time.monotonic() + 300  # max ~5 min

            while True:
                if self._is_cancelled():
                    scan_data['status'] = "Zrušeno"
                    scan_data['error'] = "Prověření zrušeno uživatelem."
                    self.signals.result.emit(self.ip, self.port, scan_data)
                    self.signals.finished.emit()
                    return
                response = requests.get(self.api_url, params=params, timeout=15)
                params = base  # po prvním požadavku už bez startNew
                if response.status_code in (429, 503, 529):
                    scan_data['status'] = "Qualys: API přetížené, čekám…"
                    self.signals.result.emit(self.ip, self.port, scan_data)
                    if time.monotonic() > deadline:
                        raise Exception("Qualys API je přetížené (rate limit). Zkus to později.")
                    self._wait_or_cancel(15)  # zrušení vyřeší kontrola na začátku smyčky
                    continue
                if response.status_code in (400, 441):
                    # Qualys nepřijal cíl — typicky když je to IP bez použitelného
                    # hostname (Qualys umí jen veřejné domény, raw IP odmítá).
                    raise Exception(
                        f"Qualys nepřijal cíl '{host}' (HTTP {response.status_code}). "
                        "Qualys umí jen veřejné domény; tato IP nemá použitelný reverzní "
                        "DNS (PTR). Použij doménu, nebo pro tenhle cíl engine TestSSL.sh.")
                if response.status_code != 200:
                    raise Exception(f"Qualys API vrátilo HTTP {response.status_code}.")

                data = response.json()
                status = data.get('status', 'ERROR')

                if status == 'READY':
                    break
                elif status == 'ERROR':
                    raise Exception(data.get('statusMessage', 'Qualys: cíl není veřejně dostupný.'))
                elif status == 'DNS':
                    scan_data['status'] = "Qualys: překládám DNS…"
                    self.signals.result.emit(self.ip, self.port, scan_data)
                else:  # IN_PROGRESS
                    scan_data['status'] = "Qualys: probíhá hloubkový audit (1–3 min)…"
                    self.signals.result.emit(self.ip, self.port, scan_data)

                if time.monotonic() > deadline:
                    raise Exception("Qualys audit překročil časový limit (5 min).")
                self._wait_or_cancel(10)  # zrušení vyřeší kontrola na začátku smyčky

            # Zpracování výsledků
            endpoints = data.get('endpoints', [])
            if not endpoints:
                raise Exception("Žádné endpointy nenalezeny.")

            endpoint = endpoints[0]
            if 'details' not in endpoint:
                raise Exception(endpoint.get('statusMessage', 'Chybí detailní výsledky.'))

            details = endpoint['details']

            # Oficiální celková známka od Qualysu (A+, A, B, …, T pro nedůvěryhodný cert).
            scan_data['qualys_grade'] = endpoint.get('grade') or endpoint.get('gradeTrustIgnored')

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
    def __init__(self, ip, port, signals, cancel_event=None):
        super().__init__()
        self.ip = ip
        self.port = str(port)
        self.signals = signals
        self.cancel_event = cancel_event

    def _is_cancelled(self):
        return self.cancel_event is not None and self.cancel_event.is_set()

    @Slot()
    def run(self):
        scan_data = {
            'ip': self.ip, 'port': self.port, 'domain': self.ip,
            'engine': 'TestSSL',
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

            if self._is_cancelled():
                try:
                    os.path.exists(json_path) and os.remove(json_path)
                except OSError:
                    pass
                scan_data['status'] = "Zrušeno"
                scan_data['error'] = "Prověření zrušeno uživatelem."
                self.signals.result.emit(self.ip, self.port, scan_data)
                self.signals.finished.emit()
                return

            # Čtení JSON výsledků
            if os.path.exists(json_path):
                with open(json_path, 'r', encoding='utf-8') as f:
                    results = json.load(f)
                os.remove(json_path)
            else:
                raise Exception("Nepodařilo se vygenerovat JSON report.")

            def proto_label(raw):
                """Z id/textu testssl odvodí název protokolu (TLSv1.2 …) nebo None."""
                k = raw.lower().replace(".", "_").replace("-", "_")
                if "tls1_3" in k:
                    return "TLSv1.3"
                if "tls1_2" in k:
                    return "TLSv1.2"
                if "tls1_1" in k:
                    return "TLSv1.1"
                if "ssl3" in k or "sslv3" in k:
                    return "SSLv3"
                if "ssl2" in k or "sslv2" in k:
                    return "SSLv2"
                if "tls1" in k:        # samotné tls1 = TLS 1.0
                    return "TLSv1.0"
                return None

            proto_key_map = {"TLSv1.3": "tls1_3", "TLSv1.2": "tls1_2", "TLSv1.1": "tls1_1",
                             "TLSv1.0": "tls1_0", "SSLv3": "sslv3", "SSLv2": "sslv2"}
            cipher_tree = {}

            for item in results:
                id_val = str(item.get('id', ''))
                finding = str(item.get('finding', ''))
                severity = str(item.get('severity', ''))
                low_id = id_val.lower()

                # Podpora protokolů (id typu SSLv2/SSLv3/TLS1/TLS1_1/TLS1_2/TLS1_3)
                if low_id in ("sslv2", "sslv3", "tls1", "tls1_1", "tls1_2", "tls1_3", "tls1_0"):
                    if "not offered" not in finding.lower() and "offered" in finding.lower():
                        pl = proto_label(id_val)
                        if pl:
                            scan_data['protocols'][proto_key_map[pl]] = True

                # Cipher řádky: id začíná na 'cipher' (cipher-tls1_2_xc02c …).
                # testssl finding má tvar: "<proto>  <hexkód>  <NÁZEV>  <kex/info>",
                # kde NÁZEV je OpenSSL styl (ECDHE-ECDSA-AES256-GCM-SHA384) nebo u
                # TLS 1.3 IANA (TLS_AES_256_GCM_SHA384).
                if low_id.startswith("cipher"):
                    proto_name = proto_label(id_val) or "TLSv1.2"
                    cipher_tree.setdefault(proto_name, [])

                    parts = finding.split()
                    cname = parts[2] if len(parts) >= 3 else finding.strip()
                    kex = " ".join(parts[3:]) if len(parts) > 3 else ""

                    # Qualys-laděná klasifikace (rozumí IANA i OpenSSL názvům).
                    grade_label, grade_color, grade_tag = classify_cipher(cname)

                    cipher_tree[proto_name].append({
                        'name': cname,
                        'grade_label': grade_label,
                        'grade_color': grade_color,
                        'grade_tag': grade_tag,
                        'kex_info': kex,
                    })

            scan_data['cipher_tree'] = cipher_tree
            scan_data['status'] = "Hotovo"

        except Exception as e:
            scan_data['status'] = "Chyba"
            scan_data['error'] = str(e)[:100]

        self.signals.result.emit(self.ip, self.port, scan_data)
        self.signals.finished.emit()

