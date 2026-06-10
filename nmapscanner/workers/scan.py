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

    def __init__(self, phase, target, rung, command, label, used_pn, timeout, signals,
                 sudo_password=None, use_sudo=True):
        super().__init__()
        self.phase = phase
        self.target = target
        self.rung = rung
        self.command = command
        self.label = label
        self.used_pn = used_pn
        self.timeout = timeout
        self.signals = signals
        # sudo_password: bytes/bytearray (předá se na stdin přes `sudo -S`) nebo None.
        # use_sudo: zda nmap obalit sudem (False = už běžíme jako root / sudo netřeba).
        self.sudo_password = sudo_password
        self.use_sudo = use_sudo

    def _build_command(self):
        """Sestaví argv pro spuštění (případně obalený sudem) a vstup pro stdin.

        Heslo se NIKDY nedává na příkazovou řádku (nebylo by vidět v `ps`) — jen
        na stdin přes ``sudo -S``. Vrací ``(argv, stdin_bytes_or_None)``.
        """
        parts = self.command.split()
        if not self.use_sudo:
            return parts, None
        if self.sudo_password is not None:
            return (["sudo", "-S", "-p", ""] + parts, bytes(self.sudo_password) + b"\n")
        # sudo bez hesla (NOPASSWD / platná cache); -n = neptat se, raději selhat
        return (["sudo", "-n"] + parts, None)

    @Slot()
    def run(self):
        self.signals.task_started.emit(self.phase, self.target, self.label)
        self.signals.log.emit("info", f"🔍 [{self.label}] {self.target} – START")
        self.signals.log.emit("info", f"   Příkaz: {self.command}")

        full_command, stdin_bytes = self._build_command()

        start_time = time.time()
        outcome = "ok"
        data = {}

        try:
            # Bajtový režim (text=False), ať se heslo drží jen jako bytes a nekopíruje
            # do nemazatelného str; výstup dekódujeme ručně.
            result = subprocess.run(
                full_command, input=stdin_bytes, capture_output=True,
                check=False, timeout=self.timeout
            )
            elapsed = time.time() - start_time
            stdout = (result.stdout or b"").decode("utf-8", "replace")
            stderr = (result.stderr or b"").decode("utf-8", "replace")
            host_down_msg = "Host seems down" in stderr
            sudo_err = result.returncode != 0 and (
                "incorrect password" in stderr.lower()
                or "a password is required" in stderr.lower()
                or "sudo:" in stderr.lower() and "password" in stderr.lower())

            if sudo_err:
                outcome = "fail"
                data = {"error": "sudo: chybné/chybějící heslo nebo nedostatečná oprávnění"}
                self.signals.log.emit(
                    "error", f"🔒 [{self.label}] {self.target} – sudo selhalo (heslo?)")
            elif result.returncode != 0 and not host_down_msg:
                outcome = "fail"
                detail = stderr.strip()[:400] or f"nmap skončil s kódem {result.returncode}"
                data = {"error": detail}
                self.signals.log.emit(
                    "error", f"❌ [{self.label}] {self.target} – CHYBA ({elapsed:.1f}s): {detail[:160]}")
            else:
                is_up = self.is_host_up_from_xml(stdout, self.target)

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
                    scan_data = scanner.analyse_nmap_xml_scan(stdout)
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
