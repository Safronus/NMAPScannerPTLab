


from PySide6.QtCore import Slot, QRunnable


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

