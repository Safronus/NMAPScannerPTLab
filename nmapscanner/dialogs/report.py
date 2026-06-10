"""Dialog souhrnného PDF reportu — výběr obsahu + generování přes QtWebEngine.

Agreguje výsledky celého běhu (porty, služby, zranitelnosti, TLS, hlavičky,
ffuf, webserver), klasifikuje je dle CVSS v4.0 / OWASP Top 10:2025 a vytiskne
PDF ve stylu PT Lab. Defaultně zapnuto vše, co má data.
"""

import os
import time

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QGridLayout, QGroupBox, QLabel, QLineEdit,
    QCheckBox, QComboBox, QPushButton, QDialogButtonBox, QFileDialog, QMessageBox,
    QFrame,
)
from PySide6.QtWebEngineCore import QWebEnginePage

from ..core.report_classify import (
    build_findings, ALL_SECTIONS, SECTION_TITLES, SEVERITIES,
)
from ..core.report_html import build_html


class ReportDialog(QDialog):
    """Konfigurace a generování souhrnného PDF reportu."""

    def __init__(self, scan_results, meta_defaults=None, reports_dir=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Souhrnný report (PDF)")
        self.resize(640, 720)
        self.scan_results = scan_results or {}
        self.meta_defaults = meta_defaults or {}
        self.reports_dir = reports_dir or os.getcwd()
        self._pdf_page = None  # reference, ať GC nesebere během tisku

        # Počet nálezů pro každou sekci → zobrazí se u checkboxů a řídí jejich aktivaci
        self._section_counts = {
            s: build_findings(self.scan_results, sections=[s])["total"]
            for s in ALL_SECTIONS
        }

        self._build_ui()

    # ------------------------------------------------------------------
    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # --- Metadata ---
        meta_box = QGroupBox("Hlavička reportu")
        meta_grid = QGridLayout(meta_box)
        self.title_edit = QLineEdit(self.meta_defaults.get("title", "Zpráva z penetračního testu"))
        self.project_edit = QLineEdit(self.meta_defaults.get("project_name", ""))
        self.client_edit = QLineEdit(self.meta_defaults.get("client", ""))
        self.author_edit = QLineEdit(self.meta_defaults.get("author", ""))
        meta_grid.addWidget(QLabel("Název:"), 0, 0)
        meta_grid.addWidget(self.title_edit, 0, 1)
        meta_grid.addWidget(QLabel("Projekt:"), 1, 0)
        meta_grid.addWidget(self.project_edit, 1, 1)
        meta_grid.addWidget(QLabel("Klient / rozsah:"), 2, 0)
        meta_grid.addWidget(self.client_edit, 2, 1)
        meta_grid.addWidget(QLabel("Zpracoval:"), 3, 0)
        meta_grid.addWidget(self.author_edit, 3, 1)
        layout.addWidget(meta_box)

        # --- Sekce ---
        sec_box = QGroupBox("Co zahrnout do reportu")
        sec_layout = QVBoxLayout(sec_box)
        self.section_checks = {}
        for s in ALL_SECTIONS:
            n = self._section_counts.get(s, 0)
            cb = QCheckBox(f"{SECTION_TITLES[s]}  ({n} nálezů)")
            cb.setChecked(n > 0)
            cb.setEnabled(n > 0)
            self.section_checks[s] = cb
            sec_layout.addWidget(cb)
        layout.addWidget(sec_box)

        # --- Možnosti ---
        opt_box = QGroupBox("Možnosti")
        opt_grid = QGridLayout(opt_box)

        opt_grid.addWidget(QLabel("Minimální závažnost:"), 0, 0)
        self.sev_combo = QComboBox()
        for s in SEVERITIES:
            self.sev_combo.addItem(s, s)
        self.sev_combo.setCurrentText("INFO")  # vše
        self.sev_combo.setToolTip("Nálezy nižší závažnosti se do reportu nezahrnou.")
        opt_grid.addWidget(self.sev_combo, 0, 1)

        opt_grid.addWidget(QLabel("Seskupit nálezy:"), 1, 0)
        self.group_combo = QComboBox()
        self.group_combo.addItem("Podle závažnosti", "severity")
        self.group_combo.addItem("Podle oblasti", "category")
        opt_grid.addWidget(self.group_combo, 1, 1)

        self.chk_evidence = QCheckBox("Zahrnout důkazy (evidence)")
        self.chk_evidence.setChecked(True)
        self.chk_reco = QCheckBox("Zahrnout doporučení")
        self.chk_reco.setChecked(True)
        self.chk_method = QCheckBox("Zahrnout metodiku (CVSS / OWASP)")
        self.chk_method.setChecked(True)
        self.chk_charts = QCheckBox("Zahrnout grafy a souhrn")
        self.chk_charts.setChecked(True)
        opt_grid.addWidget(self.chk_evidence, 2, 0, 1, 2)
        opt_grid.addWidget(self.chk_reco, 3, 0, 1, 2)
        opt_grid.addWidget(self.chk_method, 4, 0, 1, 2)
        opt_grid.addWidget(self.chk_charts, 5, 0, 1, 2)
        layout.addWidget(opt_box)

        # --- Stav + tlačítka ---
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color:#6b7686;")
        layout.addWidget(self.status_label)

        line = QFrame(); line.setFrameShape(QFrame.HLine); line.setStyleSheet("color:#ddd;")
        layout.addWidget(line)

        btn_row = QHBoxLayout()
        preview_btn = QPushButton("👁 Náhled (HTML)")
        preview_btn.clicked.connect(self.preview_html)
        btn_row.addWidget(preview_btn)
        btn_row.addStretch()
        self.generate_btn = QPushButton("📄 Vytvořit PDF")
        self.generate_btn.setDefault(True)
        self.generate_btn.clicked.connect(self.generate_pdf)
        btn_row.addWidget(self.generate_btn)
        close_btn = QPushButton("Zavřít")
        close_btn.clicked.connect(self.reject)
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)

    # ------------------------------------------------------------------
    def _selected_sections(self):
        return [s for s in ALL_SECTIONS
                if self.section_checks[s].isEnabled() and self.section_checks[s].isChecked()]

    def _options(self):
        return {
            "include_evidence": self.chk_evidence.isChecked(),
            "include_recommendations": self.chk_reco.isChecked(),
            "include_methodology": self.chk_method.isChecked(),
            "include_charts": self.chk_charts.isChecked(),
            "group_by": self.group_combo.currentData(),
        }

    def _meta(self):
        return {
            "title": self.title_edit.text().strip() or "Zpráva z penetračního testu",
            "project_name": self.project_edit.text().strip() or "—",
            "client": self.client_edit.text().strip() or "—",
            "author": self.author_edit.text().strip() or "—",
            "date": time.strftime("%Y-%m-%d %H:%M"),
            "run_info": self.meta_defaults.get("run_info", "—"),
            "tool": self.meta_defaults.get("tool", "NMAP Scanner — PT Lab"),
        }

    def _build_html(self):
        sections = self._selected_sections()
        min_sev = self.sev_combo.currentData()
        result = build_findings(self.scan_results, sections=sections, min_severity=min_sev)
        return build_html(self._meta(), result, self._options()), result

    # ------------------------------------------------------------------
    def preview_html(self):
        if not self._selected_sections():
            QMessageBox.warning(self, "Report", "Vyber alespoň jednu oblast.")
            return
        html, _ = self._build_html()
        path = os.path.join(self.reports_dir, "report_preview.html")
        try:
            os.makedirs(self.reports_dir, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
        except Exception as e:
            QMessageBox.critical(self, "Náhled", f"Nelze uložit náhled: {e}")
            return
        from PySide6.QtGui import QDesktopServices
        from PySide6.QtCore import QUrl
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))
        self.status_label.setText(f"Náhled otevřen: {path}")

    def generate_pdf(self):
        if not self._selected_sections():
            QMessageBox.warning(self, "Report", "Vyber alespoň jednu oblast.")
            return
        html, result = self._build_html()

        default_name = f"PTLab_report_{time.strftime('%Y%m%d-%H%M%S')}.pdf"
        os.makedirs(self.reports_dir, exist_ok=True)
        path, _ = QFileDialog.getSaveFileName(
            self, "Uložit PDF report", os.path.join(self.reports_dir, default_name),
            "PDF soubory (*.pdf)")
        if not path:
            return

        self.generate_btn.setEnabled(False)
        self.status_label.setText(f"Generuji PDF ({result['total']} nálezů)…")

        self._pdf_page = QWebEnginePage(self)

        def on_load(ok):
            if ok:
                self._pdf_page.printToPdf(path)
            else:
                self._finish_pdf(False, path)

        def on_pdf(out_path, ok):
            self._finish_pdf(ok, out_path)

        self._pdf_page.loadFinished.connect(on_load)
        self._pdf_page.pdfPrintingFinished.connect(on_pdf)
        self._pdf_page.setHtml(html)

    def _finish_pdf(self, ok, path):
        self.generate_btn.setEnabled(True)
        if not ok:
            self.status_label.setText("Generování PDF selhalo.")
            QMessageBox.critical(self, "Report", "Nepodařilo se vytvořit PDF.")
            return
        self.status_label.setText(f"Hotovo: {path}")
        reply = QMessageBox.question(
            self, "Report hotov",
            f"PDF report byl uložen:\n{path}\n\nOtevřít ho?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if reply == QMessageBox.Yes:
            from PySide6.QtGui import QDesktopServices
            from PySide6.QtCore import QUrl
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))
