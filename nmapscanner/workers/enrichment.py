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

    def __init__(self, targets, scan_results, nvd_api_key=None, use_searchsploit=False,
                 vulners_api_key=None, discover_version_cves=True):
        super().__init__()
        self.targets = list(targets or [])
        self.scan_results = scan_results or {}
        self.nvd_api_key = nvd_api_key
        self.vulners_api_key = vulners_api_key
        self.discover_version_cves = discover_version_cves
        self.use_searchsploit = use_searchsploit
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
        cves = set(cves)
        total = len(services) + len(cves)
        result = {"cve": {}, "eol": {}, "version_cve": {}}
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
            # CVE podle verze služby (NVD CPE + Vulners) — i bez vuln skriptu
            if self.discover_version_cves:
                try:
                    found = enr.version_cve_lookup(
                        product, version, nvd_api_key=self.nvd_api_key,
                        vulners_api_key=self.vulners_api_key)
                    if found:
                        result["version_cve"][key] = []
                        for r in found:
                            cid = r["cve"]
                            result["version_cve"][key].append(cid)
                            # přednačíst severity/cvss do mapy CVE
                            result["cve"].setdefault(cid, {}).update(
                                {k: r[k] for k in ("cvss", "severity", "description")
                                 if k in r})
                            cves.add(cid)
                        self.log.emit(
                            f"🔎 {product} {version}: nalezeno {len(found)} CVE dle verze")
                except Exception as e:  # noqa: BLE001
                    self.log.emit(f"CVE dle verze {product}: {e}")
            done += 1

        total = len(services) + len(cves)  # přepočet (přibyly CVE z verzí)
        for cve in sorted(cves):
            if not self.is_running:
                break
            self.progress.emit(f"NVD + exploity: {cve}", done, total)
            info = dict(result["cve"].get(cve, {}))  # zachovat data z verze
            try:
                if not info.get("severity"):
                    nvd = enr.nvd_lookup(cve, api_key=self.nvd_api_key)
                    if nvd:
                        info.update(nvd)
            except Exception as e:  # noqa: BLE001
                self.log.emit(f"NVD {cve}: {e}")
            try:
                expl = enr.exploit_lookup(cve, use_searchsploit=self.use_searchsploit)
                info["exploit"] = expl
                if expl.get("kev"):
                    self.log.emit(f"⚠️ {cve}: aktivně zneužíváno (CISA KEV)")
                elif expl.get("has_exploit"):
                    self.log.emit(f"⚠️ {cve}: existuje exploit / vysoká EPSS")
            except Exception as e:  # noqa: BLE001
                self.log.emit(f"Exploit {cve}: {e}")
            if info:
                result["cve"][cve] = info
            done += 1

        self.finished.emit(result)

    def stop(self):
        self.is_running = False
