"""Startup průvodce — kontrola aktuálnosti před testováním.

Při spuštění (volitelně) zkontroluje:
* **Aplikace** — je na GitHubu novější verze?
* **Nástroje** — nmap / ffuf / ZAP / TLS … nainstalované + verze.
* **Data (DB)** — čerstvost CVE/DB cache: CISA KEV, EOL, NVD, EPSS.

Cíl: ať uživatel ví, že netestuje na zastaralých datech. Síťové/pomalé části
běží na pozadí; z dialogu vede rovnou odkaz do Správce aktualizací.
"""

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QCheckBox,
    QDialogButtonBox, QScrollArea, QWidget,
)


class _StartupCheckWorker(QThread):
    done = Signal(dict)

    def run(self):
        res = {}
        try:
            from .. import VERSION as local
        except Exception:
            local = "?"
        remote = None
        try:
            import requests
            from .updates import GH_RAW_VER, _parse_version
            txt = requests.get(GH_RAW_VER, timeout=12,
                               headers={"User-Agent": "NMAPScanner-PTLab"}).text
            remote = _parse_version(txt) or None
        except Exception:
            remote = None
        res["app"] = {"local": local, "remote": remote}
        try:
            from ..core import toolcheck
            res["tools"] = [
                (s["name"], bool(st.get("installed")), st.get("version") or "",
                 bool(st.get("needs_restart")), toolcheck.installable_here(s))
                for s, st in toolcheck.detect_all()]
        except Exception:
            res["tools"] = []
        try:
            from ..core import enrichment
            res["data"] = enrichment.cache_status()
        except Exception:
            res["data"] = {}
        self.done.emit(res)


def _age_txt(d):
    if d is None:
        return "neznámé stáří"
    if d < 1:
        return "dnes"
    if d < 2:
        return "1 den"
    return f"{int(d)} dní"


class StartupCheckDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Kontrola aktuálnosti — než začneš testovat")
        self.resize(640, 560)
        self._parent_app = parent
        lay = QVBoxLayout(self)

        self.banner = QLabel("⏳ Kontroluji aktuálnost aplikace, nástrojů a dat…")
        self.banner.setStyleSheet("font-size: 15px; font-weight: bold; padding: 6px;")
        self.banner.setWordWrap(True)
        lay.addWidget(self.banner)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        self.body = QLabel("")
        self.body.setWordWrap(True)
        self.body.setTextFormat(Qt.RichText)
        self.body.setAlignment(Qt.AlignTop)
        self.body.setTextInteractionFlags(Qt.TextBrowserInteraction)
        self.body.setOpenExternalLinks(True)
        holder = QWidget()
        hl = QVBoxLayout(holder)
        hl.addWidget(self.body)
        hl.addStretch(1)
        scroll.setWidget(holder)
        lay.addWidget(scroll, 1)

        from PySide6.QtCore import QSettings
        self._settings = QSettings("UTB", "NmapScannerApp")
        self.chk = QCheckBox("Zobrazovat tuto kontrolu při každém startu")
        self.chk.setChecked(self._settings.value("startup_check", True, type=bool))
        self.chk.toggled.connect(
            lambda on: self._settings.setValue("startup_check", bool(on)))
        lay.addWidget(self.chk)

        row = QHBoxLayout()
        self.mgr_btn = QPushButton("🔄 Otevřít Správce aktualizací")
        self.mgr_btn.clicked.connect(self._open_manager)
        row.addWidget(self.mgr_btn)
        row.addStretch(1)
        bb = QDialogButtonBox(QDialogButtonBox.Close)
        bb.rejected.connect(self.accept)
        bb.accepted.connect(self.accept)
        row.addWidget(bb)
        lay.addLayout(row)

        self._worker = _StartupCheckWorker(self)
        self._worker.done.connect(self._render)
        self._worker.start()

    def _open_manager(self):
        try:
            from .updates import UpdateManagerDialog
            UpdateManagerDialog(self).exec()
        except Exception:
            pass

    def _render(self, res):
        app = res.get("app", {})
        tools = res.get("tools", [])
        data = res.get("data", {})
        problems = 0
        parts = []

        # --- Aplikace ---
        local = app.get("local", "?")
        remote = app.get("remote")
        if remote is None:
            app_line = f"ℹ️ Aplikace: verze <b>{local}</b> — nejnovější na GitHubu se nezdařilo zjistit (offline?)."
        elif remote == local:
            app_line = f"✅ Aplikace je aktuální (verze <b>{local}</b>)."
        else:
            problems += 1
            app_line = (f"⚠️ Aplikace: máš <b>{local}</b>, na GitHubu je <b>{remote}</b> — "
                        "aktualizuj (Správce aktualizací → Aplikace).")
        parts.append(f"<h3>Aplikace</h3>{app_line}")

        # --- Nástroje ---
        rows = []
        missing_req = False
        for name, inst, ver, restart, installable in tools:
            if inst and restart:
                rows.append(f"⚠️ {name} — nainstalováno, ale restartuj aplikaci (PATH)")
            elif inst:
                rows.append(f"✅ {name} {('· ' + ver) if ver else ''}")
            elif not installable:
                rows.append(f"➖ {name} — není pro tuto platformu")
            else:
                mark = "❌" if name.lower().startswith("nmap") else "—"
                rows.append(f"{mark} {name} — chybí")
                if name.lower().startswith("nmap"):
                    missing_req = True
        if missing_req:
            problems += 1
        parts.append("<h3>Nástroje</h3>" + "<br>".join(rows))
        if missing_req:
            parts.append("<span style='color:#C00000'><b>Nmap chybí</b> — je nutný pro skenování.</span>")

        # --- Data / DB ---
        drows = []
        def _d(key, label, ttl_txt):
            d = data.get(key, {})
            if not d.get("present"):
                return f"⚠️ {label}: zatím nestaženo"
            age = _age_txt(d.get("age_days"))
            cnt = d.get("count")
            base = f"{label}: {age}" + (f", {cnt} záznamů" if cnt else "")
            if d.get("stale"):
                return f"⚠️ {base} — zastaralé ({ttl_txt})"
            return f"✅ {base}"
        # zastaralost KEV/EOL/EPSS počítáme do problémů
        for key in ("kev", "eol", "epss"):
            if data.get(key, {}).get("stale"):
                problems += 1
        drows.append(_d("kev", "CISA KEV (aktivně zneužívané)", "obnov denně"))
        drows.append(_d("eol", "End-of-Life (verze)", "TTL 14 dní"))
        drows.append(_d("nvd", "NVD CVE cache", ""))
        drows.append(_d("epss", "EPSS (pravděpodobnost zneužití)", "TTL 3 dny"))
        parts.append("<h3>Data / DB (CVE apod.)</h3>" + "<br>".join(drows))
        parts.append("<i>Data se obnovují ve Správci aktualizací → Datové zdroje; "
                     "„Automaticky obohatit po skenu“ zapneš ve Správci knihovny (📚).</i>")

        self.body.setText("<br>".join(parts))
        if problems == 0:
            self.banner.setText("✅ Vše vypadá aktuální — můžeš testovat.")
            self.banner.setStyleSheet("font-size:15px; font-weight:bold; color:#1F9E4F; padding:6px;")
        else:
            self.banner.setText(f"⚠️ {problems} věcí je zastaralých / chybí — "
                                "doporučuji aktualizovat před testováním.")
            self.banner.setStyleSheet("font-size:15px; font-weight:bold; color:#BF9000; padding:6px;")

    def closeEvent(self, ev):
        try:
            if self._worker.isRunning():
                self._worker.wait(1500)
        except Exception:
            pass
        super().closeEvent(ev)
