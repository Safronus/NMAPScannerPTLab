"""Dialogy klasifikace: per-případ editace nálezu + správce knihovny klasifikací.

* ``FindingEditDialog`` — úprava jednoho nálezu pro daný případ (severity, OWASP,
  doporučení, dopad, komentář). Uloží se jako override do projektu; lze odsud
  otevřít i globální správce knihovny.
* ``ClassificationManagerDialog`` — prohlížení a editace pravidel knihovny
  (porty / TLS / hlavičky / certifikáty / CVE) pro penetrační testery. Ukládá do
  uživatelské override knihovny (``~/.nmapscanner/classification_library.json``).
"""

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QComboBox, QPlainTextEdit,
    QLineEdit, QPushButton, QTreeWidget, QTreeWidgetItem, QHeaderView, QMessageBox,
    QDialogButtonBox, QWidget, QTabWidget,
)

from ..core.report_classify import SEVERITIES, SEVERITY_COLOR, OWASP_2025
from ..core import classification_library as lib


class FindingEditDialog(QDialog):
    """Úprava jednoho nálezu pro tento případ (per-IP override)."""

    def __init__(self, finding, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Úprava nálezu (pro tento případ)")
        self.resize(560, 560)
        self.finding = finding
        self.open_manager_requested = False

        v = QVBoxLayout(self)
        head = QLabel(f"<b>{finding.get('title','')}</b><br>"
                      f"<span style='color:#666'>{finding.get('target','')} · "
                      f"{finding.get('category','')}</span>")
        head.setWordWrap(True)
        v.addWidget(head)

        # Klikací CVE odkazy (NVD / MITRE), pokud nález CVE obsahuje
        import re as _re
        blob = " ".join([finding.get("title", ""), finding.get("evidence", ""),
                         finding.get("recommendation", "")])
        cves = sorted(set(_re.findall(r"CVE-\d{4}-\d{4,7}", blob, _re.IGNORECASE)))
        if cves:
            links = " &nbsp; ".join(
                f'<a href="{lib.cve_link("nvd", c.upper())}">{c.upper()} (NVD)</a> · '
                f'<a href="{lib.cve_link("mitre", c.upper())}">MITRE</a>' for c in cves)
            cve_lbl = QLabel(f"<b>CVE:</b> {links}")
            cve_lbl.setOpenExternalLinks(True)
            cve_lbl.setWordWrap(True)
            v.addWidget(cve_lbl)

        g = QGridLayout()
        g.addWidget(QLabel("Závažnost:"), 0, 0)
        self.sev = QComboBox()
        self.sev.addItems(SEVERITIES)
        self.sev.setCurrentText(finding.get("severity", "INFO"))
        g.addWidget(self.sev, 0, 1)
        g.addWidget(QLabel("OWASP:"), 0, 2)
        self.owasp = QComboBox()
        for code, name in OWASP_2025.items():
            self.owasp.addItem(f"{code} — {name}", code)
        idx = self.owasp.findData(finding.get("owasp", "A02"))
        if idx >= 0:
            self.owasp.setCurrentIndex(idx)
        g.addWidget(self.owasp, 0, 3)
        v.addLayout(g)

        v.addWidget(QLabel("Název:"))
        self.title = QLineEdit(finding.get("title", ""))
        v.addWidget(self.title)
        v.addWidget(QLabel("Dopad:"))
        self.impact = QPlainTextEdit(finding.get("impact", ""))
        self.impact.setFixedHeight(60)
        v.addWidget(self.impact)
        v.addWidget(QLabel("Doporučení:"))
        self.rec = QPlainTextEdit(finding.get("recommendation", ""))
        self.rec.setFixedHeight(80)
        v.addWidget(self.rec)
        v.addWidget(QLabel("Komentář (jen pro tento report):"))
        self.comment = QPlainTextEdit(finding.get("comment", ""))
        self.comment.setFixedHeight(60)
        v.addWidget(self.comment)

        row = QHBoxLayout()
        mgr = QPushButton("⚙ Otevřít správce knihovny (globálně)")
        mgr.clicked.connect(self._open_manager)
        row.addWidget(mgr)
        row.addStretch()
        save = QPushButton("Uložit pro tento případ")
        save.setDefault(True)
        save.clicked.connect(self.accept)
        row.addWidget(save)
        cancel = QPushButton("Zrušit")
        cancel.clicked.connect(self.reject)
        row.addWidget(cancel)
        v.addLayout(row)

    def _open_manager(self):
        self.open_manager_requested = True
        self.accept()

    def get_override(self):
        """Vrátí dict override pro tento nález."""
        return {
            "severity": self.sev.currentText(),
            "owasp": self.owasp.currentData(),
            "title": self.title.text().strip(),
            "impact": self.impact.toPlainText().strip(),
            "recommendation": self.rec.toPlainText().strip(),
            "comment": self.comment.toPlainText().strip(),
        }


# ---------------------------------------------------------------------------
class RuleEditDialog(QDialog):
    """Editace jednoho pravidla knihovny (severity, OWASP, doporučení/dopad CZ+EN)."""

    def __init__(self, title, rule, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Pravidlo: {title}")
        self.resize(620, 620)
        self.rule = dict(rule or {})

        v = QVBoxLayout(self)
        v.addWidget(QLabel(f"<b>{title}</b>"))
        g = QGridLayout()
        g.addWidget(QLabel("Závažnost:"), 0, 0)
        self.sev = QComboBox(); self.sev.addItems(SEVERITIES)
        self.sev.setCurrentText(self.rule.get("severity", "INFO"))
        g.addWidget(self.sev, 0, 1)
        g.addWidget(QLabel("OWASP:"), 0, 2)
        self.owasp = QComboBox()
        for code, name in OWASP_2025.items():
            self.owasp.addItem(f"{code} — {name}", code)
        i = self.owasp.findData(self.rule.get("owasp", "A02"))
        if i >= 0:
            self.owasp.setCurrentIndex(i)
        g.addWidget(self.owasp, 0, 3)
        v.addLayout(g)

        def _pair(label, key):
            v.addWidget(QLabel(label))
            cur = self.rule.get(key, {})
            cs = cur.get("cs", "") if isinstance(cur, dict) else (cur or "")
            en = cur.get("en", "") if isinstance(cur, dict) else ""
            te_cs = QPlainTextEdit(cs); te_cs.setFixedHeight(54)
            te_en = QPlainTextEdit(en); te_en.setFixedHeight(54)
            v.addWidget(QLabel("  CZ:")); v.addWidget(te_cs)
            v.addWidget(QLabel("  EN:")); v.addWidget(te_en)
            return te_cs, te_en

        self.rec_cs, self.rec_en = _pair("Doporučení:", "recommendation")
        self.imp_cs, self.imp_en = _pair("Dopad:", "impact")

        bb = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        v.addWidget(bb)

    def get_rule(self):
        out = dict(self.rule)
        out["severity"] = self.sev.currentText()
        out["owasp"] = self.owasp.currentData()
        out["recommendation"] = {"cs": self.rec_cs.toPlainText().strip(),
                                 "en": self.rec_en.toPlainText().strip()}
        out["impact"] = {"cs": self.imp_cs.toPlainText().strip(),
                         "en": self.imp_en.toPlainText().strip()}
        return out


class ClassificationManagerDialog(QDialog):
    """Správce knihovny klasifikací — editace pravidel (ukládá do user override)."""

    # editovatelné dict-kategorie (klíč → pravidlo)
    DICT_CATEGORIES = [
        ("ports", "Porty"), ("service_keywords", "Služby (klíčová slova)"),
        ("tls_grade", "TLS známky"), ("headers", "Bezpečnostní hlavičky"),
        ("certificate", "Certifikáty"), ("ffuf", "Cesty/soubory (ffuf)"), ("cve", "CVE"),
    ]
    # nápověda ke klíči pro nové pravidlo dle kategorie
    KEY_HINT = {
        "ports": "číslo portu (např. 3306)",
        "service_keywords": "klíčové slovo služby (např. redis)",
        "tls_grade": "známka A/B/C/F",
        "headers": "název hlavičky (např. X-Frame-Options)",
        "certificate": "typ (expired / expiring / self_signed)",
        "ffuf": "cesta/soubor (např. .git, /admin, .env)",
        "cve": "CVE id (např. CVE-2021-44228)",
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Správce knihovny klasifikací")
        self.resize(900, 620)

        v = QVBoxLayout(self)
        info = QLabel("Pravidla referenční knihovny (severity + OWASP + doporučení + dopad). "
                      "Změny se ukládají do uživatelské knihovny a překrývají výchozí. "
                      "Dvojklik na pravidlo = editace.")
        info.setWordWrap(True)
        v.addWidget(info)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Klíč / pravidlo", "Závažnost", "OWASP", "Doporučení"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tree.header().setSectionResizeMode(3, QHeaderView.Stretch)
        self.tree.itemDoubleClicked.connect(self._edit_item)
        v.addWidget(self.tree, 1)

        # NVD API klíč (volitelné) — rychlejší obohacení bez rate-limitu
        from PySide6.QtCore import QSettings
        from PySide6.QtWidgets import QLineEdit
        nvd_row = QHBoxLayout()
        nvd_row.addWidget(QLabel("NVD API klíč (volitelné, rychlejší obohacení):"))
        self._nvd_settings = QSettings("UTB", "NmapScannerApp")
        self.nvd_key_edit = QLineEdit(self._nvd_settings.value("nvd_api_key", "") or "")
        self.nvd_key_edit.setPlaceholderText("získáš zdarma na nvd.nist.gov/developers/request-an-api-key")
        self.nvd_key_edit.setEchoMode(QLineEdit.Password)
        nvd_row.addWidget(self.nvd_key_edit, 1)
        save_key = QPushButton("Uložit klíč")
        save_key.clicked.connect(self._save_nvd_key)
        nvd_row.addWidget(save_key)
        self.nvd_test_btn = QPushButton("Otestovat")
        self.nvd_test_btn.setToolTip("Ověří klíč dotazem na NVD")
        self.nvd_test_btn.clicked.connect(self._test_nvd_key)
        nvd_row.addWidget(self.nvd_test_btn)
        self.nvd_status = QLabel()
        nvd_row.addWidget(self.nvd_status)
        v.addLayout(nvd_row)
        self._set_nvd_status(None)

        vulners_row = QHBoxLayout()
        vulners_row.addWidget(QLabel("Vulners API klíč (volitelné, CVE dle verze):"))
        self.vulners_key_edit = QLineEdit(self._nvd_settings.value("vulners_api_key", "") or "")
        self.vulners_key_edit.setPlaceholderText("získáš na vulners.com (free tier)")
        self.vulners_key_edit.setEchoMode(QLineEdit.Password)
        vulners_row.addWidget(self.vulners_key_edit, 1)
        save_vk = QPushButton("Uložit klíč")
        save_vk.clicked.connect(self._save_vulners_key)
        vulners_row.addWidget(save_vk)
        v.addLayout(vulners_row)

        from PySide6.QtWidgets import QCheckBox
        self.discover_cve_chk = QCheckBox(
            "Hledat známá CVE i podle verze služby (NVD CPE + Vulners) — i bez vuln skriptu")
        self.discover_cve_chk.setChecked(
            self._nvd_settings.value("discover_version_cves", True, type=bool))
        self.discover_cve_chk.toggled.connect(
            lambda on: self._nvd_settings.setValue("discover_version_cves", bool(on)))
        v.addWidget(self.discover_cve_chk)

        self.auto_enrich_chk = QCheckBox(
            "Automaticky obohatit z internetu po dokončení skenu (CVE z NVD + EOL + exploity)")
        self.auto_enrich_chk.setChecked(
            self._nvd_settings.value("auto_enrich", False, type=bool))
        self.auto_enrich_chk.toggled.connect(
            lambda on: self._nvd_settings.setValue("auto_enrich", bool(on)))
        v.addWidget(self.auto_enrich_chk)

        row = QHBoxLayout()
        add = QPushButton("➕ Přidat pravidlo")
        add.clicked.connect(self._add_rule)
        row.addWidget(add)
        reset = QPushButton("↺ Reset na výchozí (smazat moje změny)")
        reset.clicked.connect(self._reset)
        row.addWidget(reset)
        row.addStretch()
        close = QPushButton("Zavřít")
        close.clicked.connect(self.accept)
        row.addWidget(close)
        v.addLayout(row)

        self._info = info
        self._reload()

    def _save_nvd_key(self):
        self._nvd_settings.setValue("nvd_api_key", self.nvd_key_edit.text().strip())
        self._nvd_settings.setValue("nvd_key_prompted", True)
        self._set_nvd_status(None)
        QMessageBox.information(self, "NVD", "API klíč uložen.")

    def _set_nvd_status(self, ok, msg=""):
        """ok=None → neověřeno/nezadáno; True → platný; False → chyba."""
        key = self.nvd_key_edit.text().strip()
        if ok is True:
            self.nvd_status.setText("✅ platný")
            self.nvd_status.setStyleSheet("color: #1F9E4F; font-weight: bold;")
        elif ok is False:
            self.nvd_status.setText("❌ neplatný")
            self.nvd_status.setStyleSheet("color: #C00000; font-weight: bold;")
        elif not key:
            self.nvd_status.setText("○ nezadán")
            self.nvd_status.setStyleSheet("color: #888;")
        else:
            self.nvd_status.setText("● neověřeno")
            self.nvd_status.setStyleSheet("color: #BF9000;")
        if msg:
            self.nvd_status.setToolTip(msg)

    def _test_nvd_key(self):
        key = self.nvd_key_edit.text().strip()
        if not key:
            self._set_nvd_status(None)
            QMessageBox.information(self, "NVD", "Nejprve zadej API klíč.")
            return
        self.nvd_test_btn.setEnabled(False)
        self.nvd_status.setText("⏳ ověřuji…")
        self.nvd_status.setStyleSheet("color: #888;")

        class _Check(QThread):
            done = Signal(bool, str)

            def __init__(self, k):
                super().__init__()
                self.k = k

            def run(self):
                from ..core.enrichment import validate_nvd_key
                ok, m = validate_nvd_key(self.k)
                self.done.emit(ok, m)

        self._nvd_check = _Check(key)
        self._nvd_check.done.connect(self._on_nvd_checked)
        self._nvd_check.start()

    def _on_nvd_checked(self, ok, msg):
        self.nvd_test_btn.setEnabled(True)
        self._set_nvd_status(ok, msg)
        if not ok:
            QMessageBox.warning(self, "NVD", msg)

    def _save_vulners_key(self):
        self._nvd_settings.setValue("vulners_api_key", self.vulners_key_edit.text().strip())
        QMessageBox.information(self, "Vulners", "API klíč uložen.")

    def _reload(self):
        self.tree.clear()
        data = lib.library(force_reload=True)
        total = sum(len(data.get(cat, {}) or {}) for cat, _ in self.DICT_CATEGORIES)
        if getattr(self, "_info", None):
            self._info.setText(f"Pravidla referenční knihovny — celkem {total}. "
                               "Severity + OWASP + doporučení + dopad. Změny se ukládají do "
                               "uživatelské knihovny a překrývají výchozí. Dvojklik = editace, "
                               "➕ přidá vlastní pravidlo.")
        for cat, label in self.DICT_CATEGORIES:
            rules = data.get(cat, {}) or {}
            if not rules:
                continue
            head = QTreeWidgetItem(self.tree, [f"{label}  ({len(rules)})"])
            f = QFont("Arial", 10, QFont.Bold)
            head.setFont(0, f)
            # čitelné v tmavém i světlém režimu (PT Lab akcent + zvýrazněné pozadí)
            head.setForeground(0, QColor("#E2231A"))
            for c in range(4):
                head.setBackground(c, QColor(226, 35, 26, 28))
            head.setExpanded(True)
            head.setFirstColumnSpanned(True)
            for key in sorted(rules.keys(), key=lambda k: (len(k), k)):
                rule = rules[key]
                sev = rule.get("severity", "")
                child = QTreeWidgetItem(head, [
                    str(key), sev, rule.get("owasp", ""),
                    lib.pick(rule.get("recommendation", ""), "cs")[:90]])
                if sev in SEVERITY_COLOR:
                    child.setForeground(1, QColor(SEVERITY_COLOR[sev]))
                child.setData(0, Qt.UserRole, (cat, str(key)))

    def _edit_item(self, item, col):
        data = item.data(0, Qt.UserRole)
        if not data:
            return
        cat, key = data
        rule = (lib.library().get(cat, {}) or {}).get(key, {})
        dlg = RuleEditDialog(f"{cat} / {key}", rule, self)
        if dlg.exec() != QDialog.Accepted:
            return
        new_rule = dlg.get_rule()
        # zapsat do uživatelské knihovny (jen tento záznam)
        user = lib.user_library()
        user.setdefault(cat, {})
        # zachovat ostatní pole pravidla (name, recommended_value…) z efektivní knihovny
        merged = dict(rule)
        merged.update(new_rule)
        user[cat][key] = merged
        lib.save_user_library(user)
        self._reload()

    def _add_rule(self):
        """Přidá vlastní pravidlo do uživatelské knihovny."""
        from PySide6.QtWidgets import QInputDialog
        cats = self.DICT_CATEGORIES
        labels = [l for _, l in cats]
        label, ok = QInputDialog.getItem(self, "Nové pravidlo", "Kategorie:", labels, 0, False)
        if not ok:
            return
        cat = next(c for c, l in cats if l == label)
        hint = self.KEY_HINT.get(cat, "klíč")
        key, ok = QInputDialog.getText(self, "Nové pravidlo", f"Klíč ({hint}):")
        key = (key or "").strip()
        if not ok or not key:
            return
        existing = (lib.library().get(cat, {}) or {})
        if key in existing:
            if QMessageBox.question(self, "Pravidlo existuje",
                                    f"Pravidlo '{key}' v kategorii už existuje. Přepsat?",
                                    QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
                return
        rule = {"severity": "MEDIUM", "owasp": "A02",
                "recommendation": {"cs": "", "en": ""}, "impact": {"cs": "", "en": ""}}
        dlg = RuleEditDialog(f"{cat} / {key}", rule, self)
        if dlg.exec() != QDialog.Accepted:
            return
        user = lib.user_library()
        user.setdefault(cat, {})[key] = dlg.get_rule()
        lib.save_user_library(user)
        self._reload()

    def _reset(self):
        if QMessageBox.question(self, "Reset knihovny",
                                "Opravdu smazat všechny vlastní úpravy a vrátit knihovnu na "
                                "výchozí stav?",
                                QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes:
            lib.reset_user_library()
            self._reload()
