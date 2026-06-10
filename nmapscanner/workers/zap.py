"""OWASP ZAP scan worker — řídí lokální daemon + spider + active scan.

Spustí (nebo využije běžící) ZAP daemon, pro každý cíl proběhne Spider a Active
Scan se sledováním postupu a na konci sebere alerty. Pokud worker daemon spustil,
na konci ho i zastaví. Komunikace přes signály (jako ostatní workery).
"""

import time
import subprocess

from PySide6.QtCore import QThread, Signal

from ..core.zap_runner import find_zap, daemon_command


class ZapScanWorker(QThread):
    # phase: 'init'|'spider'|'ascan'|'collect'; data: dict s percent/target/index/total
    progress_update = Signal(dict)
    target_done = Signal(str, list)     # (target_url, alerts[])
    log = Signal(str)
    error = Signal(str)
    finished = Signal()

    def __init__(self, targets, options=None):
        super().__init__()
        self.targets = list(targets or [])
        self.options = options or {}
        self.is_running = True
        self.proc = None          # daemon proces, pokud jsme ho spustili my
        self._zap = None

    # ------------------------------------------------------------------
    def _emit(self, phase, **kw):
        d = {"phase": phase}
        d.update(kw)
        self.progress_update.emit(d)

    def _connect_client(self, host, port, api_key):
        from zapv2 import ZAPv2
        base = f"http://{host}:{port}"
        proxies = {"http": base, "https": base}
        return ZAPv2(apikey=api_key or None, proxies=proxies)

    def _api_ready(self, zap):
        try:
            _ = zap.core.version
            return True
        except Exception:
            return False

    def _ensure_daemon(self, host, port, api_key):
        """Vrátí připojeného ZAPv2 klienta; daemon spustí, jen když neběží."""
        zap = self._connect_client(host, port, api_key)
        if self._api_ready(zap):
            self.log.emit(f"✅ Připojeno k běžícímu ZAP na {host}:{port}.")
            return zap

        if self.options.get("use_existing", False):
            raise RuntimeError(f"Na {host}:{port} neběží ZAP daemon (a 'použít běžící' je zapnuto).")

        zap_path = self.options.get("zap_path") or find_zap()
        if not zap_path:
            raise RuntimeError("ZAP launcher nenalezen. Nainstaluj ZAP (viz nápověda).")

        cmd = daemon_command(zap_path, host=host, port=port, api_key=api_key)
        self.log.emit(f"🚀 Spouštím ZAP daemon: {zap_path} (port {port})…")
        self.proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        # Čekat na nastartování API (ZAP + JVM může chvíli trvat)
        timeout = int(self.options.get("startup_timeout", 90))
        for i in range(timeout):
            if not self.is_running:
                raise RuntimeError("Přerušeno uživatelem během startu daemonu.")
            if self.proc.poll() is not None:
                raise RuntimeError("ZAP daemon se neočekávaně ukončil při startu.")
            if self._api_ready(zap):
                self.log.emit("✅ ZAP daemon je připraven.")
                return zap
            self._emit("init", percent=min(99, int(i / timeout * 100)))
            time.sleep(1)
        raise RuntimeError(f"ZAP daemon nenaběhl do {timeout} s.")

    def _poll(self, status_fn, scan_id, phase, target, index, total):
        """Polluje status (0–100) dané scan operace, dokud nedoběhne / nezruší se."""
        last = -1
        while self.is_running:
            try:
                pct = int(status_fn(scan_id))
            except Exception:
                pct = 100
            if pct != last:
                self._emit(phase, percent=pct, target=target, index=index, total=total)
                last = pct
            if pct >= 100:
                break
            time.sleep(1)

    # ------------------------------------------------------------------
    def run(self):
        host = self.options.get("host", "127.0.0.1")
        port = int(self.options.get("port", 8090))
        api_key = self.options.get("api_key", "")
        do_spider = self.options.get("spider", True)
        do_ascan = self.options.get("active_scan", True)

        try:
            zap = self._ensure_daemon(host, port, api_key)
            self._zap = zap
        except Exception as e:  # noqa: BLE001
            self.error.emit(str(e))
            self._shutdown_daemon()
            self.finished.emit()
            return

        total = len(self.targets)
        for i, target in enumerate(self.targets, start=1):
            if not self.is_running:
                break
            try:
                self.log.emit(f"🔎 [{i}/{total}] {target}")
                # Seed – otevřít cíl přes proxy, ať je v ZAP stromu
                try:
                    zap.urlopen(target)
                    time.sleep(1)
                except Exception:
                    pass

                if do_spider and self.is_running:
                    sid = zap.spider.scan(target)
                    self._poll(zap.spider.status, sid, "spider", target, i, total)

                if do_ascan and self.is_running:
                    aid = zap.ascan.scan(target)
                    self._poll(zap.ascan.status, aid, "ascan", target, i, total)

                self._emit("collect", target=target, index=i, total=total)
                alerts = []
                try:
                    alerts = zap.core.alerts(baseurl=target) or []
                except Exception:
                    alerts = []
                self.target_done.emit(target, alerts)
                self.log.emit(f"✅ {target}: {len(alerts)} alertů")
            except Exception as e:  # noqa: BLE001
                self.error.emit(f"{target}: {e}")

        self._shutdown_daemon()
        self.finished.emit()

    def _shutdown_daemon(self):
        """Zastaví daemon, jen pokud jsme ho spustili my."""
        if self.proc is not None:
            try:
                if self._zap is not None and self.options.get("shutdown_when_done", True):
                    try:
                        self._zap.core.shutdown()
                        time.sleep(1)
                    except Exception:
                        pass
                if self.proc.poll() is None:
                    self.proc.terminate()
                    time.sleep(1)
                    if self.proc.poll() is None:
                        self.proc.kill()
            except Exception:
                pass
            self.proc = None

    def stop(self):
        self.is_running = False
        # Pokusit se zastavit běžící scany (rychlejší přerušení)
        if self._zap is not None:
            try:
                self._zap.spider.stop_all_scans()
            except Exception:
                pass
            try:
                self._zap.ascan.stop_all_scans()
            except Exception:
                pass
