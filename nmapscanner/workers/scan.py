import time
import threading
import subprocess
from xml.etree import ElementTree as ET

import nmap

from PySide6.QtCore import Slot, QRunnable


class ProcessRegistry:
    """Thread-safe registr běžících nmap procesů, aby šly při zastavení/zavření
    aplikace tvrdě ukončit (jinak by se ScanWorker zasekl na ``subprocess`` až do
    timeoutu a thread pool by při ukončení appky zamrzl)."""

    def __init__(self):
        self._procs = set()
        self._lock = threading.Lock()
        self.stopped = False

    def add(self, proc):
        with self._lock:
            self._procs.add(proc)

    def remove(self, proc):
        with self._lock:
            self._procs.discard(proc)

    def terminate_all(self):
        """Označí jako zastavené a zabije všechny běžící procesy (idempotentní)."""
        with self._lock:
            self.stopped = True
            procs = list(self._procs)
            self._procs.clear()
        for p in procs:
            try:
                p.kill()
            except Exception:
                pass

    def reset(self):
        with self._lock:
            self._procs.clear()
            self.stopped = False


def _safe_emit(signal, *args):
    """Emituje signál, ale přežije, když už byl C++ objekt signálů zničen
    (aplikace se zavírá) — jinak by worker spadl na 'Signal source has been deleted'."""
    try:
        signal.emit(*args)
    except RuntimeError:
        pass


class ScanWorker(QRunnable):
    """Spustí JEDNU příčku skenu (jeden nmap příkaz) a nahlásí výsledek.

    * ``"ok"``        – sken proběhl (i prázdný výsledek je OK)
    * ``"host_down"`` – host neodpovídá / vypadá dole (manager zkusí -Pn nebo zmírní)
    * ``"fail"``      – chyba/timeout (manager zmírní na další příčku)
    """

    def __init__(self, phase, target, rung, command, label, used_pn, timeout, signals,
                 sudo_password=None, use_sudo=True, registry=None):
        super().__init__()
        self.phase = phase
        self.target = target
        self.rung = rung
        self.command = command
        self.label = label
        self.used_pn = used_pn
        self.timeout = timeout
        self.signals = signals
        self.sudo_password = sudo_password
        self.use_sudo = use_sudo
        self.registry = registry

    def _build_command(self):
        """Sestaví argv (případně obalený sudem) a vstup pro stdin. Heslo jde jen
        na stdin (``sudo -S``), nikdy ne do argv (nebylo by vidět v ``ps``)."""
        command = self.command
        # Windows bez práv správce: SYN sken (-sS) selže → převést na TCP connect.
        from ..utils import is_windows, is_windows_admin, unprivileged_nmap_command
        if is_windows() and not is_windows_admin():
            command = unprivileged_nmap_command(command)
        parts = command.split()
        if not self.use_sudo:
            return parts, None
        if self.sudo_password is not None:
            return (["sudo", "-S", "-p", ""] + parts, bytes(self.sudo_password) + b"\n")
        return (["sudo", "-n"] + parts, None)

    def _run_process(self, argv, stdin_bytes):
        """Spustí proces tak, aby šel z jiného vlákna zabít. Vrací (rc, stdout, stderr).
        Vyhodí ``subprocess.TimeoutExpired`` při timeoutu."""
        proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if self.registry is not None:
            self.registry.add(proc)
        try:
            out, err = proc.communicate(input=stdin_bytes, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.communicate()
            except Exception:
                pass
            raise
        finally:
            if self.registry is not None:
                self.registry.remove(proc)
        return proc.returncode, out or b"", err or b""

    @Slot()
    def run(self):
        if self.registry is not None and self.registry.stopped:
            return
        _safe_emit(self.signals.task_started, self.phase, self.target, self.label)
        _safe_emit(self.signals.log, "info", f"🔍 [{self.label}] {self.target} – START")
        _safe_emit(self.signals.log, "info", f"   Příkaz: {self.command}")

        full_command, stdin_bytes = self._build_command()
        start_time = time.time()
        outcome = "ok"
        data = {}

        try:
            returncode, out_b, err_b = self._run_process(full_command, stdin_bytes)
            elapsed = time.time() - start_time
            stdout = out_b.decode("utf-8", "replace")
            stderr = err_b.decode("utf-8", "replace")
            host_down_msg = "Host seems down" in stderr
            low_err = stderr.lower()
            sudo_err = returncode != 0 and (
                "incorrect password" in low_err
                or "a password is required" in low_err
                or ("sudo:" in low_err and "password" in low_err))

            if self.registry is not None and self.registry.stopped:
                return  # aplikace/sken se zastavuje — nehlásit nic
            if sudo_err:
                outcome = "fail"
                data = {"error": "sudo: chybné/chybějící heslo nebo nedostatečná oprávnění"}
                _safe_emit(self.signals.log, "error",
                           f"🔒 [{self.label}] {self.target} – sudo selhalo (heslo?)")
            elif returncode != 0 and not host_down_msg:
                outcome = "fail"
                detail = stderr.strip()[:400] or f"nmap skončil s kódem {returncode}"
                data = {"error": detail}
                _safe_emit(self.signals.log, "error",
                           f"❌ [{self.label}] {self.target} – CHYBA ({elapsed:.1f}s): {detail[:160]}")
            else:
                is_up = self.is_host_up_from_xml(stdout, self.target)
                if self.phase == "online":
                    if is_up:
                        outcome = "ok"
                        data = {"status": {"state": "up"}}
                        _safe_emit(self.signals.log, "info",
                                   f"✅ [{self.label}] {self.target} – ONLINE ({elapsed:.1f}s)")
                    else:
                        outcome = "host_down"
                        data = {"status": {"state": "down"}}
                        _safe_emit(self.signals.log, "info",
                                   f"⚠️ [{self.label}] {self.target} – neodpovídá na ping ({elapsed:.1f}s)")
                else:
                    scanner = nmap.PortScanner()
                    scan_data = scanner.analyse_nmap_xml_scan(stdout)
                    scan_result = scan_data.get("scan", {}).get(self.target, {}) or {}
                    if not is_up and not self.used_pn:
                        outcome = "host_down"
                        data = scan_result
                        _safe_emit(self.signals.log, "info",
                                   f"⏭️ [{self.label}] {self.target} – host dole, zkusím -Pn ({elapsed:.1f}s)")
                    else:
                        outcome = "ok"
                        data = scan_result
                        port_count = sum(len(scan_result.get(p, {})) for p in ("tcp", "udp"))
                        _safe_emit(self.signals.log, "info",
                                   f"✅ [{self.label}] {self.target} – HOTOVO ({port_count} portů, {elapsed:.1f}s)")

        except subprocess.TimeoutExpired:
            if self.registry is not None and self.registry.stopped:
                return
            elapsed = time.time() - start_time
            outcome = "fail"
            data = {"error": f"timeout po {self.timeout}s"}
            _safe_emit(self.signals.log, "error",
                       f"⏱️ [{self.label}] {self.target} – TIMEOUT ({elapsed:.1f}s)")
        except Exception as e:
            if self.registry is not None and self.registry.stopped:
                return
            outcome = "fail"
            data = {"error": str(e)[:400]}
            _safe_emit(self.signals.log, "error",
                       f"❌ [{self.label}] {self.target} – VÝJIMKA: {str(e)[:160]}")

        finally:
            if not (self.registry is not None and self.registry.stopped):
                _safe_emit(self.signals.task_outcome,
                           self.phase, self.target, self.rung, outcome, data, self.used_pn)
                _safe_emit(self.signals.finished)

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
