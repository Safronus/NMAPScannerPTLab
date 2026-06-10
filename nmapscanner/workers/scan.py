import time
import subprocess
from xml.etree import ElementTree as ET

import nmap

from PySide6.QtCore import Slot, QRunnable


class ScanWorker(QRunnable):
    """Spustí JEDNU příčku skenu (jeden nmap příkaz) a nahlásí výsledek.

    Rozhodnutí o de-eskalaci (zmírnění při selhání) dělá ``ScanManager`` podle
    nahlášeného ``outcome``:

    * ``"ok"``        – sken proběhl (i prázdný výsledek je OK)
    * ``"host_down"`` – host neodpovídá / vypadá dole (manager zkusí -Pn nebo zmírní)
    * ``"fail"``      – chyba/timeout (manager zmírní na další příčku)
    """

    def __init__(self, phase, target, rung, command, label, used_pn, timeout, signals):
        super().__init__()
        self.phase = phase
        self.target = target
        self.rung = rung
        self.command = command
        self.label = label
        self.used_pn = used_pn
        self.timeout = timeout
        self.signals = signals

    @Slot()
    def run(self):
        self.signals.task_started.emit(self.phase, self.target, self.label)
        self.signals.log.emit("info", f"🔍 [{self.label}] {self.target} – START")
        self.signals.log.emit("info", f"   Příkaz: {self.command}")

        full_command = self.command.split()
        if full_command and full_command[0] != 'sudo':
            full_command.insert(0, 'sudo')

        start_time = time.time()
        outcome = "ok"
        data = {}

        try:
            result = subprocess.run(
                full_command, capture_output=True, text=True,
                check=False, timeout=self.timeout
            )
            elapsed = time.time() - start_time
            stderr = result.stderr or ""
            host_down_msg = "Host seems down" in stderr

            if result.returncode != 0 and not host_down_msg:
                outcome = "fail"
                detail = stderr.strip()[:400] or f"nmap skončil s kódem {result.returncode}"
                data = {"error": detail}
                self.signals.log.emit(
                    "error", f"❌ [{self.label}] {self.target} – CHYBA ({elapsed:.1f}s): {detail[:160]}")
            else:
                is_up = self.is_host_up_from_xml(result.stdout, self.target)

                if self.phase == "online":
                    if is_up:
                        outcome = "ok"
                        data = {"status": {"state": "up"}}
                        self.signals.log.emit(
                            "info", f"✅ [{self.label}] {self.target} – ONLINE ({elapsed:.1f}s)")
                    else:
                        outcome = "host_down"
                        data = {"status": {"state": "down"}}
                        self.signals.log.emit(
                            "info", f"⚠️ [{self.label}] {self.target} – neodpovídá na ping ({elapsed:.1f}s)")
                else:
                    scanner = nmap.PortScanner()
                    scan_data = scanner.analyse_nmap_xml_scan(result.stdout)
                    scan_result = scan_data.get("scan", {}).get(self.target, {}) or {}

                    if not is_up and not self.used_pn:
                        # Host vypadá dole a -Pn jsme ještě nezkoušeli → ať manager
                        # zopakuje tuto příčku s -Pn (možná jen blokovaný ping).
                        outcome = "host_down"
                        data = scan_result
                        self.signals.log.emit(
                            "info", f"⏭️ [{self.label}] {self.target} – host dole, zkusím -Pn ({elapsed:.1f}s)")
                    else:
                        outcome = "ok"
                        data = scan_result
                        port_count = sum(len(scan_result.get(p, {})) for p in ("tcp", "udp"))
                        self.signals.log.emit(
                            "info", f"✅ [{self.label}] {self.target} – HOTOVO ({port_count} portů, {elapsed:.1f}s)")

        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            outcome = "fail"
            data = {"error": f"timeout po {self.timeout}s"}
            self.signals.log.emit(
                "error", f"⏱️ [{self.label}] {self.target} – TIMEOUT ({elapsed:.1f}s)")
        except Exception as e:
            elapsed = time.time() - start_time
            outcome = "fail"
            data = {"error": str(e)[:400]}
            self.signals.log.emit(
                "error", f"❌ [{self.label}] {self.target} – VÝJIMKA: {str(e)[:160]}")

        finally:
            self.signals.task_outcome.emit(
                self.phase, self.target, self.rung, outcome, data, self.used_pn)
            self.signals.finished.emit()

    def is_host_up_from_xml(self, xml_string, ip_address):
        try:
            root = ET.fromstring(xml_string)
            for host in root.findall('host'):
                if host.find('address') is not None and host.find('address').get('addr') == ip_address:
                    status_elem = host.find('status')
                    if status_elem is not None and status_elem.get('state') == 'up':
                        return True
                    ports = host.find('ports')
                    if ports is not None:
                        for port in ports.findall('port'):
                            if port.find('state').get('state') == 'open':
                                return True
        except ET.ParseError:
            return False
        return False
