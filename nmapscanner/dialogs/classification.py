"""Dialogy klasifikace: per-případ editace nálezu + správce knihovny klasifikací.

* ``FindingEditDialog`` — úprava jednoho nálezu pro daný případ (severity, OWASP,
  doporučení, dopad, komentář). Uloží se jako override do projektu; lze odsud
  otevřít i globální správce knihovny.
* ``ClassificationManagerDialog`` — prohlížení a editace pravidel knihovny
  (porty / TLS / hlavičky / certifikáty / CVE) pro penetrační testery. Ukládá do
  uživatelské override knihovny (``~/.nmapscanner/classification_library.json``).
"""

from PySide6.QtCore import Qt
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
        ("ports", "Porty"), ("tls_grade", "TLS známky"), ("headers", "Bezpečnostní hlavičky"),
        ("certificate", "Certifikáty"), ("cve", "CVE"),
    ]

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

        row = QHBoxLayout()
        reset = QPushButton("↺ Reset na výchozí (smazat moje změny)")
        reset.clicked.connect(self._reset)
        row.addWidget(reset)
        row.addStretch()
        close = QPushButton("Zavřít")
        close.clicked.connect(self.accept)
        row.addWidget(close)
        v.addLayout(row)

        self._reload()

    def _reload(self):
        self.tree.clear()
        data = lib.library(force_reload=True)
        for cat, label in self.DICT_CATEGORIES:
            rules = data.get(cat, {}) or {}
            if not rules:
                continue
            head = QTreeWidgetItem(self.tree, [f"{label}  ({len(rules)})"])
            head.setFont(0, QFont("Arial", 10, QFont.Bold))
            head.setForeground(0, QColor("#16233f"))
            head.setExpanded(cat in ("tls_grade", "certificate"))
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

    def _reset(self):
        if QMessageBox.question(self, "Reset knihovny",
                                "Opravdu smazat všechny vlastní úpravy a vrátit knihovnu na "
                                "výchozí stav?",
                                QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes:
            lib.reset_user_library()
            self._reload()
