"""Dialog souhrnného PDF reportu — výběr typu/jazyka + editovatelná pole.

Většina obsahu je generovaná (klasifikace OWASP/CVSS), ale klíčové texty
(úvod, rozsah, shrnutí, závěr, doporučení, metadata) jsou **předgenerované a
editovatelné**, plus volitelné **komentáře k jednotlivým nálezům**. Hotový
report se vytiskne do PDF (QtWebEngine) ve stylu PT Lab a zaregistruje do
projektu (manažer reportů). Konfigurace se ukládá do projektu.
"""

import os
import time

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QGridLayout, QGroupBox, QLabel, QLineEdit,
    QCheckBox, QComboBox, QPushButton, QFileDialog, QMessageBox, QFrame, QTabWidget,
    QWidget, QPlainTextEdit, QTableWidget, QTableWidgetItem, QHeaderView, QScrollArea,
)
from PySide6.QtWebEngineCore import QWebEnginePage

from ..core.report_classify import (
    build_findings, ALL_SECTIONS, section_title, SEVERITIES,
)
from ..core.report_html import build_report, T as RT
from ..core import report_store
from ..core.report_tools import detect_tool_versions

# Editovatelná volná pole: klíč -> (CZ label, EN label, i18n default key v report_html)
FREE_FIELDS = [
    ("intro", "Úvod / omezení reportu", "Introduction / limitation", "limitation_default"),
    ("scope", "Rozsah / náplň testu", "Scope / objectives", "scope_default"),
    ("summary", "Shrnutí", "Summary", "summary_default"),
    ("conclusion", "Závěr", "Conclusion", "conclusion_default"),
    ("recommendation", "Souhrnné doporučení", "Overall recommendation", "recommendation_default"),
]


class ReportDialog(QDialog):
    """Konfigurace a generování souhrnného PDF reportu (technický / manažerský)."""

    def __init__(self, scan_results, meta_defaults=None, reports_dir=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Souhrnný report (PDF)")
        self.resize(720, 820)
        self.scan_results = scan_results or {}
        self.meta_defaults = meta_defaults or {}
        self.reports_dir = reports_dir or os.getcwd()
        self._pdf_page = None

        # Uložená konfigurace z projektu (pokud existuje)
        self._cfg = dict(self.scan_results.get("report_config", {}) or {})

        # Počet nálezů pro každou sekci (CZ jazyk pro počty)
        self._section_counts = {
            s: build_findings(self.scan_results, sections=[s])["total"]
            for s in ALL_SECTIONS
        }
        # Detekce verzí nástrojů (jednorázově)
        try:
            self._tools = detect_tool_versions(self.scan_results, lang="cs")
        except Exception:
            self._tools = []

        self._build_ui()
        self._load_cfg()

    # ------------------------------------------------------------------
    def _build_ui(self):
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)

        self.tabs.addTab(self._tab_general(), "Report")
        self.tabs.addTab(self._tab_texts(), "Texty")
        self.tabs.addTab(self._tab_comments(), "Komentáře")

        # stav + tlačítka
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color:#6b7686;")
        layout.addWidget(self.status_label)
        line = QFrame(); line.setFrameShape(QFrame.HLine); layout.addWidget(line)
        row = QHBoxLayout()
        prev = QPushButton("👁 Náhled (HTML)"); prev.clicked.connect(self.preview_html)
        row.addWidget(prev); row.addStretch()
        self.generate_btn = QPushButton("📄 Vytvořit PDF"); self.generate_btn.setDefault(True)
        self.generate_btn.clicked.connect(self.generate_pdf)
        row.addWidget(self.generate_btn)
        close = QPushButton("Zavřít"); close.clicked.connect(self.reject)
        row.addWidget(close)
        layout.addLayout(row)

    def _tab_general(self):
        w = QWidget(); v = QVBoxLayout(w)

        # Typ + jazyk
        tl = QGroupBox("Typ a jazyk"); g = QGridLayout(tl)
        g.addWidget(QLabel("Typ reportu:"), 0, 0)
        self.type_combo = QComboBox()
        self.type_combo.addItem("Technický (podrobný)", "technical")
        self.type_combo.addItem("Manažerský (bez technikálií)", "management")
        g.addWidget(self.type_combo, 0, 1)
        g.addWidget(QLabel("Jazyk:"), 0, 2)
        self.lang_combo = QComboBox()
        self.lang_combo.addItem("Čeština", "cs")
        self.lang_combo.addItem("English", "en")
        self.lang_combo.currentIndexChanged.connect(self._on_lang_changed)
        g.addWidget(self.lang_combo, 0, 3)
        g.addWidget(QLabel("Min. závažnost:"), 1, 0)
        self.sev_combo = QComboBox()
        for s in SEVERITIES:
            self.sev_combo.addItem(s, s)
        self.sev_combo.setCurrentText("INFO")
        g.addWidget(self.sev_combo, 1, 1)
        v.addWidget(tl)

        # Sekce
        sec = QGroupBox("Co zahrnout (oblasti)"); sv = QVBoxLayout(sec)
        self.section_checks = {}
        for s in ALL_SECTIONS:
            n = self._section_counts.get(s, 0)
            cb = QCheckBox(f"{section_title(s, 'cs')}  ({n} nálezů)")
            cb.setChecked(n > 0); cb.setEnabled(n > 0)
            self.section_checks[s] = cb
            sv.addWidget(cb)
        v.addWidget(sec)

        # Možnosti
        opt = QGroupBox("Možnosti"); og = QGridLayout(opt)
        self.chk_exec = QCheckBox("Executive summary"); self.chk_exec.setChecked(True)
        self.chk_toc = QCheckBox("Obsah (TOC) s čísly stran"); self.chk_toc.setChecked(True)
        self.chk_evidence = QCheckBox("Důkazy (evidence)"); self.chk_evidence.setChecked(True)
        self.chk_reco = QCheckBox("Doporučení"); self.chk_reco.setChecked(True)
        self.chk_method = QCheckBox("Metodika (OWASP/CVSS)"); self.chk_method.setChecked(True)
        self.chk_charts = QCheckBox("Souhrn nálezů / oblasti"); self.chk_charts.setChecked(True)
        self.chk_tools = QCheckBox("Použité nástroje + verze"); self.chk_tools.setChecked(True)
        og.addWidget(self.chk_exec, 0, 0); og.addWidget(self.chk_toc, 0, 1)
        og.addWidget(self.chk_evidence, 1, 0); og.addWidget(self.chk_reco, 1, 1)
        og.addWidget(self.chk_method, 2, 0); og.addWidget(self.chk_charts, 2, 1)
        og.addWidget(self.chk_tools, 3, 0)
        v.addWidget(opt)
        v.addStretch()
        return w

    def _tab_texts(self):
        w = QWidget(); outer = QVBoxLayout(w)
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        inner = QWidget(); v = QVBoxLayout(inner)

        # Metadata
        meta = QGroupBox("Hlavička"); g = QGridLayout(meta)
        self.title_edit = QLineEdit(self.meta_defaults.get("title", "Pentest Report"))
        self.project_edit = QLineEdit(self.meta_defaults.get("project_name", ""))
        self.client_edit = QLineEdit(self.meta_defaults.get("client", ""))
        self.author_edit = QLineEdit(self.meta_defaults.get("author", ""))
        self.engagement_edit = QLineEdit(self.meta_defaults.get("engagement", ""))
        for i, (lab, ed) in enumerate([
            ("Název:", self.title_edit), ("Projekt:", self.project_edit),
            ("Klient / rozsah:", self.client_edit), ("Zpracoval (autoři):", self.author_edit),
            ("Zaměření (engagement):", self.engagement_edit),
        ]):
            g.addWidget(QLabel(lab), i, 0); g.addWidget(ed, i, 1)
        v.addWidget(meta)

        # Volná pole (předgenerovaná, editovatelná)
        self.free_edits = {}
        for key, lab_cs, lab_en, _dk in FREE_FIELDS:
            box = QGroupBox(lab_cs); bv = QVBoxLayout(box)
            te = QPlainTextEdit(); te.setFixedHeight(80)
            self.free_edits[key] = te
            bv.addWidget(te)
            reset = QPushButton("↺ Předvyplnit výchozí text")
            reset.clicked.connect(lambda _=False, k=key: self._reset_field(k))
            bv.addWidget(reset, 0, Qt.AlignRight)
            v.addWidget(box)

        scroll.setWidget(inner)
        outer.addWidget(scroll)
        return w

    def _tab_comments(self):
        w = QWidget(); v = QVBoxLayout(w)
        v.addWidget(QLabel("Volitelné komentáře k jednotlivým nálezům "
                           "(zobrazí se u nálezu v reportu):"))
        self.comments_table = QTableWidget(0, 4)
        self.comments_table.setHorizontalHeaderLabels(["Záv.", "Cíl", "Nález", "Komentář"])
        hh = self.comments_table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.Stretch)
        hh.setSectionResizeMode(3, QHeaderView.Stretch)
        v.addWidget(self.comments_table)
        refresh = QPushButton("↻ Načíst nálezy dle aktuálního výběru")
        refresh.clicked.connect(self._refresh_comments_table)
        v.addWidget(refresh, 0, Qt.AlignRight)
        return w

    # ------------------------------------------------------------------
    def _lang(self):
        return self.lang_combo.currentData()

    def _reset_field(self, key):
        dk = next(dk for k, _a, _b, dk in FREE_FIELDS if k == key)
        self.free_edits[key].setPlainText(RT(dk, self._lang()))

    def _on_lang_changed(self):
        # Předvyplnit volná pole výchozím textem v novém jazyce, pokud jsou prázdná
        for key, _a, _b, dk in FREE_FIELDS:
            te = self.free_edits.get(key)
            if te is not None and not te.toPlainText().strip():
                te.setPlainText(RT(dk, self._lang()))

    def _selected_sections(self):
        return [s for s in ALL_SECTIONS
                if self.section_checks[s].isEnabled() and self.section_checks[s].isChecked()]

    def _refresh_comments_table(self):
        result = build_findings(self.scan_results, sections=self._selected_sections(),
                                min_severity=self.sev_combo.currentData(), lang=self._lang())
        saved = dict(self._cfg.get("comments", {}))
        self._comment_keys = []
        findings = result["findings"]
        self.comments_table.setRowCount(len(findings))
        for i, f in enumerate(findings):
            ckey = self._comment_key(f)
            self._comment_keys.append(ckey)
            for col, val in enumerate([f["severity"], f["target"], f["title"]]):
                it = QTableWidgetItem(val)
                it.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                self.comments_table.setItem(i, col, it)
            cit = QTableWidgetItem(saved.get(ckey, ""))
            self.comments_table.setItem(i, 3, cit)

    @staticmethod
    def _comment_key(f):
        # jazykově co nejstabilnější klíč
        return f"{f.get('target','')}|{f.get('section','')}|{f.get('owasp','')}|{f.get('id','')}"

    def _collect_comments(self):
        out = {}
        if getattr(self, "_comment_keys", None):
            for i, ckey in enumerate(self._comment_keys):
                it = self.comments_table.item(i, 3)
                txt = it.text().strip() if it else ""
                if txt:
                    out[ckey] = txt
        else:
            out = dict(self._cfg.get("comments", {}))
        return out

    # ------------------------------------------------------------------
    def _options(self, comments):
        # komentáře přemapovat z _comment_key na finding id pro aktuální build
        return {
            "report_type": self.type_combo.currentData(),
            "lang": self._lang(),
            "include_exec": self.chk_exec.isChecked(),
            "include_toc": self.chk_toc.isChecked(),
            "include_evidence": self.chk_evidence.isChecked(),
            "include_recommendations": self.chk_reco.isChecked(),
            "include_methodology": self.chk_method.isChecked(),
            "include_charts": self.chk_charts.isChecked(),
            "scan_results": self.scan_results,
            "tools": self._tools if self.chk_tools.isChecked() else [],
            "human": {k: self.free_edits[k].toPlainText().strip() for k in self.free_edits},
            "_comments_by_key": comments,
        }

    def _meta(self):
        return {
            "title": self.title_edit.text().strip() or "Pentest Report",
            "project_name": self.project_edit.text().strip() or "—",
            "client": self.client_edit.text().strip() or "—",
            "author": self.author_edit.text().strip() or "—",
            "engagement": self.engagement_edit.text().strip() or "",
            "date": time.strftime("%Y-%m-%d %H:%M"),
            "run_info": self.meta_defaults.get("run_info", "—"),
            "tool": self.meta_defaults.get("tool", "NMAP Scanner — PT Lab"),
        }

    def _build_html(self):
        lang = self._lang()
        sections = self._selected_sections()
        comments_by_key = self._collect_comments()
        result = build_findings(self.scan_results, sections=sections,
                                min_severity=self.sev_combo.currentData(), lang=lang)
        # přemapovat komentáře na id nálezů aktuálního buildu
        comments_by_id = {}
        for f in result["findings"]:
            ck = self._comment_key(f)
            if ck in comments_by_key:
                comments_by_id[f["id"]] = comments_by_key[ck]
        opts = self._options(comments_by_key)
        opts["comments"] = comments_by_id
        html = build_report(self._meta(), result, opts)
        return html, result

    def _save_cfg(self, comments_by_key):
        cfg = {
            "type": self.type_combo.currentData(),
            "lang": self._lang(),
            "min_severity": self.sev_combo.currentData(),
            "sections": {s: self.section_checks[s].isChecked() for s in ALL_SECTIONS},
            "options": {
                "exec": self.chk_exec.isChecked(),
                "toc": self.chk_toc.isChecked(),
                "evidence": self.chk_evidence.isChecked(),
                "recommendations": self.chk_reco.isChecked(),
                "methodology": self.chk_method.isChecked(),
                "charts": self.chk_charts.isChecked(),
                "tools": self.chk_tools.isChecked(),
            },
            "meta": {
                "title": self.title_edit.text(), "project": self.project_edit.text(),
                "client": self.client_edit.text(), "author": self.author_edit.text(),
                "engagement": self.engagement_edit.text(),
            },
            "human": {k: self.free_edits[k].toPlainText() for k in self.free_edits},
            "comments": comments_by_key,
        }
        self.scan_results["report_config"] = cfg
        self._cfg = cfg

    def _load_cfg(self):
        cfg = self._cfg
        if not cfg:
            # předvyplnit volná pole výchozími texty
            for key, _a, _b, dk in FREE_FIELDS:
                self.free_edits[key].setPlainText(RT(dk, self._lang()))
            self._refresh_comments_table()
            return
        idx = self.type_combo.findData(cfg.get("type", "technical"))
        if idx >= 0:
            self.type_combo.setCurrentIndex(idx)
        lidx = self.lang_combo.findData(cfg.get("lang", "cs"))
        if lidx >= 0:
            self.lang_combo.setCurrentIndex(lidx)
        self.sev_combo.setCurrentText(cfg.get("min_severity", "INFO"))
        for s, on in (cfg.get("sections", {}) or {}).items():
            if s in self.section_checks and self.section_checks[s].isEnabled():
                self.section_checks[s].setChecked(bool(on))
        o = cfg.get("options", {})
        self.chk_exec.setChecked(o.get("exec", True))
        self.chk_toc.setChecked(o.get("toc", True))
        self.chk_evidence.setChecked(o.get("evidence", True))
        self.chk_reco.setChecked(o.get("recommendations", True))
        self.chk_method.setChecked(o.get("methodology", True))
        self.chk_charts.setChecked(o.get("charts", True))
        self.chk_tools.setChecked(o.get("tools", True))
        m = cfg.get("meta", {})
        self.title_edit.setText(m.get("title", self.title_edit.text()))
        self.project_edit.setText(m.get("project", self.project_edit.text()))
        self.client_edit.setText(m.get("client", self.client_edit.text()))
        self.author_edit.setText(m.get("author", self.author_edit.text()))
        self.engagement_edit.setText(m.get("engagement", ""))
        human = cfg.get("human", {})
        for key, _a, _b, dk in FREE_FIELDS:
            self.free_edits[key].setPlainText(human.get(key) or RT(dk, self._lang()))
        self._refresh_comments_table()

    # ------------------------------------------------------------------
    def preview_html(self):
        if not self._selected_sections():
            QMessageBox.warning(self, "Report", "Vyber alespoň jednu oblast.")
            return
        html, _ = self._build_html()
        self._save_cfg(self._collect_comments())
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
        self.status_label.setText(f"Náhled: {path}")

    def generate_pdf(self):
        if not self._selected_sections():
            QMessageBox.warning(self, "Report", "Vyber alespoň jednu oblast.")
            return
        html, result = self._build_html()
        self._save_cfg(self._collect_comments())

        rtype = self.type_combo.currentData()
        lang = self._lang()
        default_name = report_store.suggested_filename("report_full", rtype, lang, "pdf")
        os.makedirs(self.reports_dir, exist_ok=True)
        path, _ = QFileDialog.getSaveFileName(
            self, "Uložit PDF report", os.path.join(self.reports_dir, default_name),
            "PDF soubory (*.pdf)")
        if not path:
            return

        self.generate_btn.setEnabled(False)
        self.status_label.setText(f"Generuji PDF ({result['total']} nálezů)…")
        # Render do dočasného PDF, pak razítko hlavičky/patičky/čísel stran do finálního.
        # Okraje MUSÍ být přes QPageLayout — QtWebEngine ignoruje CSS @page margin.
        from PySide6.QtGui import QPageLayout, QPageSize
        from PySide6.QtCore import QMarginsF
        layout = QPageLayout(QPageSize(QPageSize.A4), QPageLayout.Portrait,
                             QMarginsF(16, 30, 16, 18), QPageLayout.Millimeter)
        # TOC: seznam nadpisů (dohledá se v textu stran při post-processingu)
        from ..core.report_html import toc_headings, toc_title
        toc_opts = {"report_type": rtype, "include_exec": self.chk_exec.isChecked(),
                    "include_methodology": self.chk_method.isChecked(),
                    "tools": self._tools if self.chk_tools.isChecked() else []}
        headings = toc_headings(result, toc_opts, lang) if self.chk_toc.isChecked() else None

        raw_path = path + ".raw.pdf"
        self._pdf_meta = (path, raw_path, rtype, lang, headings, toc_title(lang))
        self._pdf_page = QWebEnginePage(self)
        self._pdf_page.loadFinished.connect(
            lambda ok: self._pdf_page.printToPdf(raw_path, layout) if ok else self._finish_pdf(False, path))
        self._pdf_page.pdfPrintingFinished.connect(lambda p, ok: self._on_raw_pdf(ok))
        self._pdf_page.setHtml(html)

    def _on_raw_pdf(self, ok):
        path, raw_path, rtype, lang, headings, toc_title_str = self._pdf_meta
        if not ok:
            self._finish_pdf(False, path)
            return
        # 1) volitelně vložit Obsah (TOC), 2) dokreslit hlavičku/patičku/čísla stran
        try:
            from ..core.report_pdf import stamp_report, assemble_with_toc
            src = raw_path
            toc_tmp = None
            if headings:
                toc_tmp = path + ".toc.pdf"
                assemble_with_toc(raw_path, toc_tmp, lang, headings, toc_title_str)
                src = toc_tmp
            stamp_report(src, path, lang)
            for tmp in (raw_path, toc_tmp):
                if tmp:
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass
        except Exception as e:
            # Razítkování selhalo → použít aspoň nerazítkovaný render
            print(f"DEBUG: stamp_report selhalo: {e}")
            try:
                os.replace(raw_path, path)
            except OSError:
                self._finish_pdf(False, path)
                return
        self._finish_pdf(True, path)

    def _finish_pdf(self, ok, path):
        self.generate_btn.setEnabled(True)
        if not ok:
            self.status_label.setText("Generování PDF selhalo.")
            QMessageBox.critical(self, "Report", "Nepodařilo se vytvořit PDF.")
            return
        # Registrovat do manažeru reportů
        try:
            meta_t = getattr(self, "_pdf_meta", (path, "", "technical", "cs", None, ""))
            rtype, lang = meta_t[2], meta_t[3]
            title = f"{self.title_edit.text().strip() or 'Pentest Report'} " \
                    f"({'manažerský' if rtype == 'management' else 'technický'}, {lang.upper()})"
            report_store.register_report(self.reports_dir, path, "report_full", rtype, lang, title)
        except Exception:
            pass
        self.status_label.setText(f"Hotovo: {path}")
        reply = QMessageBox.question(
            self, "Report hotov", f"PDF report byl uložen a přidán do projektu:\n{path}\n\nOtevřít?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if reply == QMessageBox.Yes:
            from PySide6.QtGui import QDesktopServices
            from PySide6.QtCore import QUrl
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))
