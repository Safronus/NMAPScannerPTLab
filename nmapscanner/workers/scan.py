import time
import subprocess
from xml.etree import ElementTree as ET

import nmap


from PySide6.QtCore import Slot, QRunnable


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

