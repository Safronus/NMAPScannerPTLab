"""Worker: detekce typu webového serveru z HTTP hlaviček (aktivní probe).

Pro webové porty cíle stáhne hlavičky (``Server``, ``X-Powered-By``,
``X-AspNet-Version``) a zkombinuje je s nmap ``product`` (``-sV``). Funguje i pro
interní IP. Nepotřebuje žádnou instalaci navíc (``requests``).
"""
from datetime import datetime

from PySide6.QtCore import Slot, QRunnable

from ..core.webserver_detect import detect_server
from .scan import _safe_emit


class WebServerWorker(QRunnable):
    """Zjistí web server pro zadané porty jednoho cíle a výsledek emituje jako
    ``webserver_result(ip, {port: info})``."""

    def __init__(self, ip, web_ports, signals):
        super().__init__()
        self.ip = ip
        # web_ports: list of (port:int, scheme:str, nmap_product:str)
        self.web_ports = web_ports
        self.signals = signals

    @Slot()
    def run(self):
        import requests
        try:
            import urllib3
            urllib3.disable_warnings()
        except Exception:
            pass

        results = {}
        for port, scheme, nmap_product in self.web_ports:
            url = f"{scheme}://{self.ip}:{port}"
            info = {
                "port": port, "scheme": scheme, "url": url,
                "server": "", "powered_by": "", "family": "neznámý",
                "detail": "", "source": "",
                "time": datetime.now().strftime('%d.%m.%Y %H:%M:%S'),
            }
            try:
                r = requests.get(url, timeout=8, verify=False, allow_redirects=True,
                                 headers={"User-Agent": "NMAPScannerPTLab/1.0"})
                server = r.headers.get("Server", "") or ""
                powered = (r.headers.get("X-Powered-By", "")
                           or r.headers.get("X-AspNet-Version", "") or "")
                fam, detail, src = detect_server(server, powered, nmap_product)
                info.update(server=server, powered_by=powered, family=fam,
                            detail=detail or server or nmap_product, source=src,
                            status=r.status_code)
            except Exception as e:
                # Spojení selhalo → zkus aspoň pasivně z nmap product.
                fam, detail, src = detect_server("", "", nmap_product)
                info.update(family=fam, detail=detail, source=src, error=str(e)[:120])
            results[str(port)] = info

        _safe_emit(self.signals.webserver_result, self.ip, results)
