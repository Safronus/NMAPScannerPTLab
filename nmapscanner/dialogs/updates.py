"""Správce aktualizací — nástroje, datové zdroje a knihovna klasifikací.

Tři oblasti:
* **Nástroje** — nmap, ffuf, OWASP ZAP, testssl/sslscan/sslyze, searchsploit:
  detekce nainstalované verze + spuštění instalace/aktualizace (brew/apt/pip).
* **Datové zdroje** — obnova online cache: CISA KEV, EPSS, endoflife.date (EOL),
  NVD CVE. To je „živá" část klasifikace (nové zranitelnosti / konce podpory).
* **Aplikace & knihovna** — kontrola novější verze přes git + počet pravidel
  referenční knihovny klasifikací.

Příkazy nástrojů se spouští až na výslovné kliknutí; nic se nedělá automaticky.
"""

import os

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QWidget, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QPlainTextEdit, QMessageBox,
    QGroupBox, QAbstractItemView,
)

from ..core import toolcheck
from ..core import enrichment as enr
from ..workers.command import CommandWorker


def _repo_root():
    here = os.path.abspath(__file__)
    return os.path.dirname(os.path.dirname(os.path.dirname(here)))


class _FeedWorker(QThread):
    """Obnova online cache (KEV/EPSS/EOL/NVD) na pozadí."""
    line = Signal(str)
    done = Signal()

    def __init__(self, action, parent=None):
        super().__init__(parent)
        self.action = action

    def run(self):
        try:
            if self.action == "kev":
                self.line.emit("Stahuji katalog CISA KEV…")
                cat = enr.kev_catalog(force=True)
                self.line.emit(f"✅ CISA KEV obnoveno — {len(cat)} aktivně zneužívaných CVE.")
            elif self.action == "eol":
                self.line.emit("Mažu cache End-of-Life (znovu se stáhne při dalším obohacení)…")
                try:
                    if os.path.exists(enr._EOL_CACHE):
                        os.remove(enr._EOL_CACHE)
                    self.line.emit("✅ EOL cache vyprázdněna.")
                except Exception as e:  # noqa: BLE001
                    self.line.emit(f"⚠️ {e}")
            elif self.action == "nvd":
                self.line.emit("Mažu cache NVD CVE a CVE-dle-verze…")
                try:
                    for p in (enr._NVD_CACHE, enr._VCVE_CACHE):
                        if os.path.exists(p):
                            os.remove(p)
                    self.line.emit("✅ NVD cache vyprázdněna (nové dotazy půjdou znovu na NVD).")
                except Exception as e:  # noqa: BLE001
                    self.line.emit(f"⚠️ {e}")
            elif self.action == "epss":
                self.line.emit("Mažu cache EPSS…")
                try:
                    if os.path.exists(enr._EPSS_CACHE):
                        os.remove(enr._EPSS_CACHE)
                    self.line.emit("✅ EPSS cache vyprázdněna.")
                except Exception as e:  # noqa: BLE001
                    self.line.emit(f"⚠️ {e}")
        finally:
            self.done.emit()


class UpdateManagerDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Správce aktualizací — nástroje, data a knihovna")
        self.resize(820, 620)
        self._worker = None
        self._feed = None

        root = QVBoxLayout(self)
        tabs = QTabWidget()
        root.addWidget(tabs, 1)
        tabs.addTab(self._tools_tab(), "🛠 Nástroje")
        tabs.addTab(self._data_tab(), "🌐 Datové zdroje")
        tabs.addTab(self._app_tab(), "📦 Aplikace & knihovna")

        # Sdílená konzole výstupu
        out_box = QGroupBox("Výstup")
        ol = QVBoxLayout(out_box)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setMaximumBlockCount(5000)
        self.output.setStyleSheet("font-family: monospace; font-size: 12px;")
        ol.addWidget(self.output)
        root.addWidget(out_box, 1)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        close = QPushButton("Zavřít")
        close.clicked.connect(self.accept)
        btn_row.addWidget(close)
        root.addLayout(btn_row)

        self._refresh_tools()

    # ------------------------------------------------------------------ tools
    def _tools_tab(self):
        import sys as _sys
        if _sys.platform.startswith("win"):
            _hint = ("tlačítkem (vyžaduje winget, může vyskočit potvrzení UAC). "
                     "Pozn.: brew na Windows není — Python knihovny řeší install_windows.bat.")
        elif _sys.platform == "darwin":
            _hint = "tlačítkem (vyžaduje Homebrew / pip)."
        else:
            _hint = "tlačítkem (vyžaduje apt / pip, může chtít heslo sudo)."
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.addWidget(QLabel(
            "Detekce nainstalovaných nástrojů a jejich verzí. Aktualizaci spustíš "
            + _hint))
        self.tools_table = QTableWidget(0, 5)
        self.tools_table.setHorizontalHeaderLabels(
            ["Nástroj", "Účel", "Stav", "Verze", "Akce"])
        self.tools_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tools_table.setSelectionMode(QAbstractItemView.NoSelection)
        hh = self.tools_table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.Stretch)
        hh.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        lay.addWidget(self.tools_table, 1)

        row = QHBoxLayout()
        rescan = QPushButton("🔄 Znovu zkontrolovat")
        rescan.clicked.connect(self._refresh_tools)
        row.addWidget(rescan)
        row.addStretch(1)
        lay.addLayout(row)
        return w

    def _refresh_tools(self):
        results = toolcheck.detect_all()
        self.tools_table.setRowCount(len(results))
        for i, (spec, st) in enumerate(results):
            self.tools_table.setItem(i, 0, QTableWidgetItem(spec["name"]))
            self.tools_table.setItem(i, 1, QTableWidgetItem(spec["kind"]))
            if st["installed"]:
                cell = QTableWidgetItem("✅ nainstalováno")
                cell.setForeground(Qt.darkGreen)
            else:
                cell = QTableWidgetItem("— chybí")
                cell.setForeground(Qt.red)
            self.tools_table.setItem(i, 2, cell)
            self.tools_table.setItem(i, 3, QTableWidgetItem(st["version"] or "—"))
            cmd = toolcheck.update_command(spec)
            holder = QWidget()
            hl = QHBoxLayout(holder)
            hl.setContentsMargins(2, 1, 2, 1)
            label = "⬆️ Aktualizovat" if st["installed"] else "⬇️ Instalovat"
            run_btn = QPushButton(label)
            run_btn.setEnabled(bool(cmd) and self._worker is None)
            run_btn.clicked.connect(lambda _=False, c=cmd, n=spec["name"]: self._run_cmd(c, n))
            hl.addWidget(run_btn)
            copy_btn = QPushButton("⧉")
            copy_btn.setToolTip(cmd or spec["homepage"])
            copy_btn.setFixedWidth(34)
            copy_btn.clicked.connect(
                lambda _=False, c=(cmd or spec["homepage"]): self._copy(c))
            hl.addWidget(copy_btn)
            self.tools_table.setCellWidget(i, 4, holder)

    # ------------------------------------------------------------------- data
    def _data_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.addWidget(QLabel(
            "Online zdroje, ze kterých aplikace obohacuje klasifikaci. Obnova stáhne "
            "aktuální data / vyprázdní cache, aby se příště načetla čerstvá."))

        def feed_row(title, desc, action, btn_text):
            box = QGroupBox(title)
            bl = QVBoxLayout(box)
            bl.addWidget(QLabel(desc))
            b = QPushButton(btn_text)
            b.clicked.connect(lambda _=False, a=action: self._run_feed(a))
            bl.addWidget(b, 0, Qt.AlignLeft)
            return box

        lay.addWidget(feed_row(
            "CISA KEV — aktivně zneužívané zranitelnosti",
            "Katalog CVE s potvrzeným zneužitím ve volné přírodě (denně aktualizovaný).",
            "kev", "🔄 Stáhnout aktuální katalog KEV"))
        lay.addWidget(feed_row(
            "End-of-Life (endoflife.date)",
            "Konce podpory produktů dle verze. Obnoví se vyprázdněním cache (TTL 14 dní).",
            "eol", "🗑 Vyprázdnit EOL cache"))
        lay.addWidget(feed_row(
            "NVD CVE (CVSS)",
            "Skóre a popisy CVE z NVD. Vyprázdnění vynutí znovustažení při dalším obohacení.",
            "nvd", "🗑 Vyprázdnit NVD cache"))
        lay.addWidget(feed_row(
            "EPSS (FIRST)",
            "Pravděpodobnost zneužití CVE. Obnoví se vyprázdněním cache (TTL 3 dny).",
            "epss", "🗑 Vyprázdnit EPSS cache"))
        lay.addStretch(1)
        return w

    def _run_feed(self, action):
        if self._feed is not None:
            return
        self._feed = _FeedWorker(action, self)
        self._feed.line.connect(self._log)
        self._feed.done.connect(self._feed_done)
        QGuiApplication.setOverrideCursor(Qt.BusyCursor)
        self._feed.start()

    def _feed_done(self):
        QGuiApplication.restoreOverrideCursor()
        self._feed = None

    # -------------------------------------------------------------- app & lib
    def _app_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)

        from .. import VERSION
        try:
            from ..core import classification_library as clib
            n_rules = clib.rule_count() if hasattr(clib, "rule_count") else None
        except Exception:
            n_rules = None
        rules_txt = f"{n_rules} pravidel" if n_rules is not None else "knihovna načtena"

        app_box = QGroupBox("Aplikace (git)")
        al = QVBoxLayout(app_box)
        al.addWidget(QLabel(f"Aktuální verze: <b>{VERSION}</b>"))
        al.addWidget(QLabel(
            "Aktualizace aplikace i referenční knihovny klasifikací se distribuují "
            "přes git (knihovna je součástí repozitáře)."))
        brow = QHBoxLayout()
        chk = QPushButton("🔍 Zkontrolovat aktualizaci (git fetch)")
        chk.clicked.connect(self._check_app_update)
        pull = QPushButton("⬇️ Stáhnout aktualizaci (git pull)")
        pull.clicked.connect(self._pull_app_update)
        brow.addWidget(chk)
        brow.addWidget(pull)
        brow.addStretch(1)
        al.addLayout(brow)
        lay.addWidget(app_box)

        lib_box = QGroupBox("Knihovna klasifikací")
        ll = QVBoxLayout(lib_box)
        ll.addWidget(QLabel(
            f"Referenční knihovna: <b>{rules_txt}</b> (závažnost, OWASP, doporučení, dopady).<br>"
            "„Živá“ data (CVE/EOL/exploit) se aktualizují v záložce Datové zdroje; "
            "kurátorská pravidla v záložce Aplikace přes git. Vlastní pravidla "
            "spravuješ ve Správci knihovny klasifikací (📚)."))
        lay.addWidget(lib_box)
        lay.addStretch(1)
        return w

    def _check_app_update(self):
        repo = _repo_root()
        self._run_cmd(
            f'git -C "{repo}" fetch --quiet && '
            f'echo "Lokální:  $(git -C \\"{repo}\\" rev-parse --short HEAD)" && '
            f'echo "Vzdálený: $(git -C \\"{repo}\\" rev-parse --short @{{u}} 2>/dev/null || echo n/a)" && '
            f'AHEAD=$(git -C "{repo}" rev-list --count HEAD..@{{u}} 2>/dev/null || echo 0) && '
            f'if [ "$AHEAD" -gt 0 ]; then echo "⬇️ K dispozici $AHEAD nových commitů — použij git pull."; '
            f'else echo "✅ Aplikace je aktuální."; fi',
            "Kontrola aktualizace")

    def _pull_app_update(self):
        repo = _repo_root()
        if QMessageBox.question(
                self, "Aktualizovat aplikaci",
                "Stáhnout nejnovější verzi přes 'git pull'? Po dokončení aplikaci restartuj.",
                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        self._run_cmd(f'git -C "{repo}" pull --ff-only', "Aktualizace aplikace")

    # ----------------------------------------------------------------- common
    def _run_cmd(self, command, name):
        if not command:
            return
        if self._worker is not None:
            QMessageBox.information(self, "Probíhá akce",
                                    "Počkej na dokončení aktuální operace.")
            return
        self._log(f"\n=== {name} ===")
        self._worker = CommandWorker(command, self)
        self._worker.line.connect(self._log)
        self._worker.finished.connect(self._cmd_done)
        self._refresh_tools()  # zašedne tlačítka (worker != None)
        self._worker.start()

    def _cmd_done(self, code):
        self._log(f"[hotovo, návratový kód {code}]")
        self._worker = None
        self._refresh_tools()

    def _copy(self, text):
        QGuiApplication.clipboard().setText(text or "")
        self._log(f"⧉ Zkopírováno: {text}")

    def _log(self, text):
        self.output.appendPlainText(text)

    def closeEvent(self, ev):
        for wk in (self._worker, self._feed):
            try:
                if wk is not None and wk.isRunning():
                    if hasattr(wk, "stop"):
                        wk.stop()
                    wk.wait(2000)
            except Exception:
                pass
        super().closeEvent(ev)
