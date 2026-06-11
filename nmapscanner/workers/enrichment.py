"""Worker obohacení klasifikace z internetu (NVD CVE + EOL endoflife.date).

Pro vybrané cíle projde detekované služby (produkt+verze → EOL) a nalezené CVE
(nmap vuln + ZAP → NVD CVSS) a vrátí obohacení, které se uloží do
``scan_results['enrichment']`` a promítne do klasifikace.
"""

import re

from PySide6.QtCore import QThread, Signal

from ..core import enrichment as enr

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class EnrichmentWorker(QThread):
    progress = Signal(str, int, int)   # popis, hotovo, celkem
    finished = Signal(dict)            # {'cve': {...}, 'eol': {...}}
    log = Signal(str)

    def __init__(self, targets, scan_results, nvd_api_key=None):
        super().__init__()
        self.targets = list(targets or [])
        self.scan_results = scan_results or {}
        self.nvd_api_key = nvd_api_key
        self.is_running = True

    def _collect_jobs(self):
        services = []  # (key, product, version)
        cves = set()
        tcp = self.scan_results.get("tcp", {}) or {}
        for ip in self.targets:
            ipd = (tcp.get(ip, {}) or {}).get("tcp", {}) or {}
            for port, info in ipd.items():
                if not isinstance(info, dict) or info.get("state") != "open":
                    continue
                product = (info.get("product") or "").strip()
                version = (info.get("version") or "").strip()
                if product and version:
                    services.append((f"{ip}:{port}", product, version))
        # CVE z vuln skriptů
        vuln = self.scan_results.get("vuln", {}) or {}
        for ip in self.targets:
            ipd = vuln.get(ip, {}) or {}
            for proto in ("tcp", "udp"):
                for port, info in (ipd.get(proto, {}) or {}).items():
                    for out in ((info or {}).get("script", {}) or {}).values():
                        for m in _CVE_RE.findall(out or ""):
                            cves.add(m.upper())
        # CVE ze ZAP alertů cílů
        zap = self.scan_results.get("zap", {}) or {}
        if isinstance(zap, dict):
            for tgt, alerts in zap.items():
                if not any(ip in str(tgt) for ip in self.targets):
                    continue
                for a in (alerts or []):
                    blob = " ".join(str(a.get(k, "")) for k in ("alert", "name", "description", "reference"))
                    for m in _CVE_RE.findall(blob):
                        cves.add(m.upper())
        return services, sorted(cves)

    def run(self):
        services, cves = self._collect_jobs()
        total = len(services) + len(cves)
        result = {"cve": {}, "eol": {}}
        done = 0
        if total == 0:
            self.log.emit("Žádné služby s verzí ani CVE k obohacení.")
            self.finished.emit(result)
            return

        for key, product, version in services:
            if not self.is_running:
                break
            self.progress.emit(f"EOL: {product} {version}", done, total)
            try:
                info = enr.eol_lookup(product, version)
                if info:
                    result["eol"][key] = info
            except Exception as e:  # noqa: BLE001
                self.log.emit(f"EOL {product}: {e}")
            done += 1

        for cve in cves:
            if not self.is_running:
                break
            self.progress.emit(f"NVD: {cve}", done, total)
            try:
                info = enr.nvd_lookup(cve, api_key=self.nvd_api_key)
                if info:
                    result["cve"][cve] = info
            except Exception as e:  # noqa: BLE001
                self.log.emit(f"NVD {cve}: {e}")
            done += 1

        self.finished.emit(result)

    def stop(self):
        self.is_running = False
