"""Podokno OWASP ZAP — spider + active scan vybraných webových cílů.

Spustí lokální ZAP daemon (nebo využije běžící), proběhne Spider a Active Scan
a alerty zobrazí ve stromu dle rizika. Výsledky se ukládají do
``scan_results['zap']`` a zapojí do souhrnného PDF reportu.
"""

import secrets

from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QGridLayout, QGroupBox, QLabel, QLineEdit,
    QListWidget, QListWidgetItem, QTreeWidget, QTreeWidgetItem, QHeaderView,
    QCheckBox, QSpinBox, QPushButton, QProgressBar, QSplitter, QWidget,
    QMessageBox, QApplication, QFileDialog,
)
import json
import time

from ..core.zap_runner import find_zap, install_hint, client_missing_hint
from ..workers.zap import ZapScanWorker
from ..utils import register_project_report

RISK_COLOR = {
    "High": "#c0392b",
    "Medium": "#e67e22",
    "Low": "#f1c40f",
    "Informational": "#2980b9",
    "Info": "#2980b9",
}
RISK_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3, "Info": 3}


class ZapDialog(QDialog):
    def __init__(self, scan_results, parent=None):
        super().__init__(parent)
        self.setWindowTitle("OWASP ZAP — aktivní sken")
        self.resize(1000, 760)
        self.scan_results = scan_results if scan_results is not None else {}
        self.worker = None
        self.results = {}  # target -> [alerts]

        self._build_ui()
        self._load_targets()

    # ------------------------------------------------------------------
    def _build_ui(self):
        layout = QVBoxLayout(self)

        # --- Konfigurace ---
        cfg = QGroupBox("Nastavení ZAP")
        grid = QGridLayout(cfg)
        grid.addWidget(QLabel("Host:"), 0, 0)
        self.host_edit = QLineEdit("127.0.0.1")
        self.host_edit.setFixedWidth(120)
        grid.addWidget(self.host_edit, 0, 1)
        grid.addWidget(QLabel("Port:"), 0, 2)
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(8090)
        grid.addWidget(self.port_spin, 0, 3)
        grid.addWidget(QLabel("API klíč:"), 0, 4)
        self.apikey_edit = QLineEdit(secrets.token_hex(8))
        self.apikey_edit.setToolTip("Náhodný klíč pro lokální daemon (necháš-li prázdné, klíč se vypne).")
        grid.addWidget(self.apikey_edit, 0, 5)

        self.chk_spider = QCheckBox("Spider (procházení)")
        self.chk_spider.setChecked(True)
        self.chk_ascan = QCheckBox("Active scan (útočné testy)")
        self.chk_ascan.setChecked(True)
        self.chk_existing = QCheckBox("Použít běžící daemon")
        self.chk_existing.setToolTip("Nezakládat nový daemon, připojit se k už běžícímu na host:port.")
        self.chk_shutdown = QCheckBox("Po dokončení ukončit daemon")
        self.chk_shutdown.setChecked(True)
        grid.addWidget(self.chk_spider, 1, 0, 1, 2)
        grid.addWidget(self.chk_ascan, 1, 2, 1, 2)
        grid.addWidget(self.chk_existing, 1, 4)
        grid.addWidget(self.chk_shutdown, 1, 5)
        layout.addWidget(cfg)

        # --- Splitter: cíle | alerty ---
        splitter = QSplitter(Qt.Horizontal)

        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.addWidget(QLabel("<b>Webové cíle:</b>"))
        self.targets_list = QListWidget()
        self.targets_list.setSelectionMode(QListWidget.MultiSelection)
        ll.addWidget(self.targets_list)
        trow = QHBoxLayout()
        sa = QPushButton("Vybrat vše")
        sa.clicked.connect(self._select_all)
        trow.addWidget(sa)
        ll.addLayout(trow)
        man = QHBoxLayout()
        self.manual_edit = QLineEdit()
        self.manual_edit.setPlaceholderText("http://cíl:port")
        self.manual_edit.returnPressed.connect(self._add_manual)
        man.addWidget(self.manual_edit)
        addb = QPushButton("➕")
        addb.setFixedWidth(32)
        addb.clicked.connect(self._add_manual)
        man.addWidget(addb)
        ll.addLayout(man)
        left.setMaximumWidth(300)
        splitter.addWidget(left)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.addWidget(QLabel("<b>Alerty:</b>"))
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Alert / cíl", "Riziko", "URL", "Parametr"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tree.header().setStretchLastSection(True)
        rl.addWidget(self.tree)
        splitter.addWidget(right)
        layout.addWidget(splitter, 1)

        # --- Progres ---
        self.phase_label = QLabel("Připraveno.")
        layout.addWidget(self.phase_label)
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        # --- Spodní lišta ---
        bottom = QHBoxLayout()
        self.status_label = QLabel("")
        bottom.addWidget(self.status_label)
        bottom.addStretch()
        self.export_btn = QPushButton("Uložit alerty (JSON)")
        self.export_btn.setToolTip("Exportovat ZAP alerty do JSON a přidat do manažeru reportů")
        self.export_btn.clicked.connect(self._export_json)
        bottom.addWidget(self.export_btn)
        self.start_btn = QPushButton("Spustit ZAP sken")
        self.start_btn.clicked.connect(self._start)
        bottom.addWidget(self.start_btn)
        self.stop_btn = QPushButton("Zastavit")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)
        bottom.addWidget(self.stop_btn)
        layout.addLayout(bottom)

    # ------------------------------------------------------------------
    def _load_targets(self):
        self.targets_list.clear()
        found = set()
        tcp = self.scan_results.get("tcp", {}) or {}
        web_ports = [80, 443, 8080, 8000, 8008, 8443, 8081, 8888, 9443, 3000, 5000]
        entries = []   # (ip, pnum, scheme, name, url)
        for ip, ip_data in tcp.items():
            for port, info in (ip_data.get("tcp", {}) or {}).items():
                if not isinstance(info, dict) or info.get("state") != "open":
                    continue
                name = (info.get("name") or "").lower()
                try:
                    pnum = int(port)
                except (TypeError, ValueError):
                    continue
                if pnum in web_ports or "http" in name:
                    scheme = "https" if ("https" in name or "ssl" in name or pnum in (443, 8443, 9443)) else "http"
                    url = f"{scheme}://{ip}:{pnum}"
                    if url not in found:
                        found.add(url)
                        entries.append((ip, pnum, scheme, name, url))

        def _ipkey(ip):
            try:
                return tuple(int(x) for x in ip.split("."))
            except Exception:
                return (0, 0, 0, 0)
        entries.sort(key=lambda e: (_ipkey(e[0]), e[1]))   # dle IP (číselně), pak portu

        last_ip = None
        for ip, pnum, scheme, name, url in entries:
            if ip != last_ip:                              # hlavička skupiny IP
                head = QListWidgetItem(f"■ {ip}")
                head.setFlags(Qt.NoItemFlags)
                head.setForeground(QColor("#4EA1FF"))
                f = QFont(); f.setBold(True); head.setFont(f)
                self.targets_list.addItem(head)
                last_ip = ip
            it = QListWidgetItem(f"    {scheme}://…:{pnum} ({name or 'http'})")
            it.setData(Qt.UserRole, url)
            it.setToolTip(url)
            it.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            it.setCheckState(Qt.Unchecked)
            self.targets_list.addItem(it)

        if not entries:
            self.targets_list.addItem("Žádné webové cíle (spusť nejdřív TCP sken).")
            self.targets_list.setEnabled(False)

    def _select_all(self):
        for i in range(self.targets_list.count()):
            it = self.targets_list.item(i)
            if not (it.flags() & Qt.ItemIsUserCheckable):   # přeskočit hlavičky skupin
                continue
            if it.data(Qt.UserRole):
                it.setCheckState(Qt.Checked)

    def _add_manual(self):
        url = self.manual_edit.text().strip()
        if not url:
            return
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        it = QListWidgetItem(f"{url} (manuální)")
        it.setData(Qt.UserRole, url)
        it.setCheckState(Qt.Checked)
        self.targets_list.setEnabled(True)
        self.targets_list.addItem(it)
        self.manual_edit.clear()

    def _checked_targets(self):
        out = []
        for i in range(self.targets_list.count()):
            it = self.targets_list.item(i)
            if it.data(Qt.UserRole) and it.checkState() == Qt.Checked:
                out.append(it.data(Qt.UserRole))
        return out

    # ------------------------------------------------------------------
    def _start(self):
        # Kontrola dostupnosti ZAP (binárka + klient), pokud nepoužíváme jen běžící daemon
        try:
            import zapv2  # noqa: F401
        except Exception:
            QMessageBox.warning(self, "OWASP ZAP", client_missing_hint())
            return
        if not self.chk_existing.isChecked() and find_zap() is None:
            QMessageBox.warning(self, "OWASP ZAP", install_hint())
            return

        targets = self._checked_targets()
        if not targets:
            QMessageBox.warning(self, "OWASP ZAP", "Vyber alespoň jeden cíl.")
            return
        if not self.chk_spider.isChecked() and not self.chk_ascan.isChecked():
            QMessageBox.warning(self, "OWASP ZAP", "Zapni Spider nebo Active scan.")
            return

        options = {
            "host": self.host_edit.text().strip() or "127.0.0.1",
            "port": self.port_spin.value(),
            "api_key": self.apikey_edit.text().strip(),
            "spider": self.chk_spider.isChecked(),
            "active_scan": self.chk_ascan.isChecked(),
            "use_existing": self.chk_existing.isChecked(),
            "shutdown_when_done": self.chk_shutdown.isChecked(),
            "zap_path": find_zap(),
        }

        self.results = {}
        self.tree.clear()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress.setVisible(True)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.phase_label.setText("Spouštím ZAP…")

        self.worker = ZapScanWorker(targets, options)
        self.worker.progress_update.connect(self._on_progress)
        self.worker.target_done.connect(self._on_target_done)
        self.worker.log.connect(lambda m: self.status_label.setText(m))
        self.worker.error.connect(self._on_error)
        self.worker.finished.connect(self._on_finished, Qt.SingleShotConnection)
        self.worker.start()

    def _stop(self):
        if self.worker:
            self.status_label.setText("Zastavuji ZAP sken…")
            self.worker.stop()
        self.stop_btn.setEnabled(False)

    @Slot(dict)
    def _on_progress(self, data):
        phase = data.get("phase", "")
        pct = data.get("percent", 0)
        target = data.get("target", "")
        idx = data.get("index")
        total = data.get("total")
        names = {"init": "Start daemonu", "spider": "Spider", "ascan": "Active scan",
                 "collect": "Sběr alertů"}
        label = names.get(phase, phase)
        scope = f" [{idx}/{total}]" if idx and total else ""
        self.phase_label.setText(f"{label}{scope}: {target}  —  {pct}%")
        self.progress.setValue(int(pct))

    @Slot(str, list)
    def _on_target_done(self, target, alerts):
        self.results[target] = alerts
        # Skupina cíle
        tnode = QTreeWidgetItem(self.tree, [f"CÍL: {target} ({len(alerts)})", "", "", ""])
        tnode.setFont(0, QFont("Arial", 10, QFont.Bold))
        tnode.setForeground(0, QColor("#16233f"))
        tnode.setExpanded(True)

        # Seskupit dle rizika
        by_risk = {}
        for a in alerts:
            by_risk.setdefault(a.get("risk", "Informational"), []).append(a)
        for risk in sorted(by_risk.keys(), key=lambda r: RISK_ORDER.get(r, 9)):
            rnode = QTreeWidgetItem(tnode, [f"{risk} ({len(by_risk[risk])})", risk, "", ""])
            rnode.setForeground(1, QColor(RISK_COLOR.get(risk, "#777")))
            rnode.setFont(0, QFont("Arial", 9, QFont.Bold))
            rnode.setExpanded(True)
            for a in by_risk[risk]:
                name = a.get("alert") or a.get("name") or "Alert"
                item = QTreeWidgetItem(rnode, [name, risk, a.get("url", ""), a.get("param", "")])
                item.setForeground(1, QColor(RISK_COLOR.get(risk, "#777")))

    @Slot(str)
    def _on_error(self, msg):
        self.status_label.setText(f"⚠️ {msg}")

    def _on_finished(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress.setVisible(False)
        # Uložit do scan_results pro report/persistenci
        if self.results:
            self.scan_results["zap"] = dict(self.results)
        total_alerts = sum(len(v) for v in self.results.values())
        self.phase_label.setText(f"Hotovo. Cílů: {len(self.results)}, alertů: {total_alerts}.")
        self.worker = None

    def _export_json(self):
        data = self.results or (self.scan_results.get("zap", {}) or {})
        if not data:
            QMessageBox.information(self, "OWASP ZAP", "Žádné alerty k exportu (nejdřív spusť sken).")
            return
        default = f"PTLab_zap_{time.strftime('%Y%m%d-%H%M%S')}.json"
        path, _ = QFileDialog.getSaveFileName(self, "Uložit ZAP alerty", default,
                                              "JSON soubory (*.json)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            QMessageBox.critical(self, "OWASP ZAP", f"Uložení selhalo: {e}")
            return
        register_project_report(self, path, "zap", "json")
        QMessageBox.information(self, "OWASP ZAP", f"Alerty uloženy a přidány do projektu:\n{path}")

    def closeEvent(self, event):
        if self.worker is not None:
            self.worker.stop()
            self.worker.wait(3000)
        super().closeEvent(event)
