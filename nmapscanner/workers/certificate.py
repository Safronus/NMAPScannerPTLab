import os
import re
import shutil
import tempfile
import subprocess
from datetime import datetime



from PySide6.QtCore import Slot, QRunnable


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
            
