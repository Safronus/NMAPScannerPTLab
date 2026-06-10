import os
import time
import json



from PySide6.QtWidgets import (
    QApplication, QWidget, QLineEdit, QPushButton, QVBoxLayout, QTreeWidget,
    QTreeWidgetItem, QLabel, QGroupBox, QHeaderView, QMenu, QFileDialog,
    QHBoxLayout, QSplitter, QCheckBox, QDialog, QMessageBox, QDialogButtonBox, QListWidget, QListWidgetItem, QGridLayout,
    QProgressBar, QSizePolicy, QFrame, QSpinBox, QScrollArea
)
from PySide6.QtCore import Slot, QTimer, Qt, QSettings, Signal
from PySide6.QtGui import QColor, QFont
from ..workers.ffuf import FfufWorker, BatchDownloadWorker
from ..widgets.checkable_combo import CheckableComboBox


# ==========================================
# DEFINICE WORDLISTŮ (Ověřená struktura 2026)
# ==========================================
AVAILABLE_WORDLISTS = [
    {
        "name": "Common (SecLists)",
        "filename": "common.txt",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        "desc": "Základní slovník, rychlý a efektivní. (Doporučeno)"
    },
    {
        "name": "Big (SecLists)",
        "filename": "big.txt",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt",
        "desc": "Velký slovník pro důkladné skenování."
    },
    {
        "name": "Directory List 2.3 Medium",
        "filename": "directory-list-2.3-medium.txt",
        "url": "https://raw.githubusercontent.com/daviddias/node-dirbuster/master/lists/directory-list-2.3-medium.txt",
        "desc": "Standardní slovník z nástroje DirBuster."
    },
    {
        "name": "RAFT Medium Directories",
        "filename": "raft-medium-directories.txt",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt",
        "desc": "Velmi populární slovník ze sady RAFT."
    },
    {
        "name": "RAFT Medium Files",
        "filename": "raft-medium-files.txt",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-files.txt",
        "desc": "RAFT slovník zaměřený na konkrétní soubory."
    },
    {
        "name": "Apache Server",
        "filename": "apache.txt",
        # FIX: Velké "A" v názvu souboru (Apache.txt)
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Web-Servers/Apache.txt",
        "desc": "Specifické cesty pro Apache server."
    },
    {
        "name": "IIS Server",
        "filename": "iis.txt",
        # FIX: Velká písmena v názvu souboru (IIS.txt)
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Web-Servers/IIS.txt",
        "desc": "Specifické cesty pro Microsoft IIS."
    },
    {
        "name": "Nginx Server",
        "filename": "nginx.txt",
        # Ponecháno malé "n", protože toto vám fungovalo
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Web-Servers/nginx.txt",
        "desc": "Specifické cesty pro Nginx."
    }
]


class WordlistManagerDialog(QDialog):
    """
    Dialog pro správu a stahování wordlistů.
    Upraveno: Zpracování souhrnného reportu stahování.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Správce slovníků (Wordlists)")
        self.resize(700, 500)
        self.download_dir = os.path.join(os.getcwd(), "wordlists")
        self.worker = None
        
        self.init_ui()
        self.check_existing_files()
    
    def init_ui(self):
        """
        UI rozšířené o sloupec 'Obsah' a tlačítko pro čištění.
        """
        layout = QVBoxLayout(self)
        
        info_label = QLabel("Vyberte slovníky ke stažení (zdroj: SecLists). Soubory se uloží do složky 'wordlists'.")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # --- TABULKA S NOVÝM SLOUPCEM ---
        self.tree = QTreeWidget()
        # Přidán sloupec "Obsah" na index 3
        self.tree.setHeaderLabels(["Název slovníku", "Popis", "Slov", "Obsah", "Stav"])
        
        # Nastavení šířky sloupců
        self.tree.setColumnWidth(0, 200) # Název
        self.tree.setColumnWidth(1, 200) # Popis
        self.tree.setColumnWidth(2, 80)  # Slov
        self.tree.setColumnWidth(3, 100) # Obsah (Nový)
        # Sloupec 4 (Stav) se dopočítá
        
        layout.addWidget(self.tree)
        
        for wl in AVAILABLE_WORDLISTS:
            item = QTreeWidgetItem(self.tree)
            item.setText(0, wl['name'])
            item.setText(1, wl['desc'])
            item.setText(2, "-") 
            item.setText(3, "-") # Placeholder pro Obsah
            item.setText(4, "Zjišťuji...")
            item.setCheckState(0, Qt.CheckState.Unchecked)
            item.setData(0, Qt.UserRole, wl)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("")
        layout.addWidget(self.status_label)
        
        # --- TLAČÍTKA ---
        btn_layout = QHBoxLayout()
        
        self.download_btn = QPushButton("⬇️ Stáhnout vybrané")
        self.download_btn.clicked.connect(self.start_download)
        btn_layout.addWidget(self.download_btn)
        
        # NOVÉ TLAČÍTKO: Čištění
        self.clean_btn = QPushButton("🧹 Vyčistit komentáře (#)")
        self.clean_btn.setToolTip("Odstraní řádky začínající znakem # z vybraných stažených slovníků")
        self.clean_btn.clicked.connect(self.clean_selected_wordlists)
        btn_layout.addWidget(self.clean_btn)
        
        close_btn = QPushButton("Zavřít")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        
        layout.addLayout(btn_layout)

    def check_existing_files(self):
        """
        Ověří existenci, vypočítá slova a zkontroluje přítomnost komentářů.
        """
        if not os.path.exists(self.download_dir):
            os.makedirs(self.download_dir, exist_ok=True)
            
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            data = item.data(0, Qt.UserRole)
            path = os.path.join(self.download_dir, data['filename'])
            
            if os.path.exists(path):
                # 1. Počet slov
                count = 0
                has_comments = False
                
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        # Optimalizovaný průchod souborem (počítá řádky a hledá #)
                        for line in f:
                            count += 1
                            if not has_comments and line.strip().startswith('#'):
                                has_comments = True
                except: 
                    count = 0
                
                # Aktualizace sloupce "Slov"
                item.setText(2, f"{count:,}".replace(",", " "))
                
                # Aktualizace sloupce "Obsah" (NOVÉ)
                if has_comments:
                    item.setText(3, "⚠️ Komentáře")
                    item.setForeground(3, QColor("#F39C12")) # Oranžová
                    item.setToolTip(3, "Slovník obsahuje řádky začínající #. Doporučeno vyčistit.")
                else:
                    item.setText(3, "✅ Čistý")
                    item.setForeground(3, QColor("#2ECC71")) # Zelená
                    item.setToolTip(3, "Slovník je připraven k použití.")

                # Aktualizace sloupce "Stav"
                item.setText(4, "✅ Staženo")
                item.setForeground(4, QColor("#2ECC71"))
                item.setCheckState(0, Qt.CheckState.Unchecked)
            else:
                item.setText(2, "0")
                item.setText(3, "-")
                item.setText(4, "❌ Chybí")
                item.setForeground(4, QColor("#E74C3C"))

    def clean_selected_wordlists(self):
        """
        NOVÁ FUNKCE: Projde vybrané slovníky, odstraní řádky s # a uloží zpět.
        """
        root = self.tree.invisibleRootItem()
        files_cleaned = 0
        total_removed_lines = 0
        errors = []

        # Získat vybrané položky
        selected_items = []
        for i in range(root.childCount()):
            item = root.child(i)
            if item.checkState(0) == Qt.Checked:
                selected_items.append(item)
        
        if not selected_items:
            QMessageBox.warning(self, "Výběr", "Vyberte alespoň jeden slovník k vyčištění.")
            return

        # Potvrzení akce
        reply = QMessageBox.question(
            self, "Potvrzení čištění",
            f"Chystáte se odstranit komentáře (řádky s #) z {len(selected_items)} slovníků.\n\nTato akce přepíše soubory na disku. Pokračovat?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        self.tree.setEnabled(False)
        self.clean_btn.setEnabled(False)
        self.status_label.setText("Probíhá čištění slovníků...")
        QApplication.processEvents() # Překreslit GUI

        for item in selected_items:
            data = item.data(0, Qt.UserRole)
            path = os.path.join(self.download_dir, data['filename'])
            
            if not os.path.exists(path):
                continue # Přeskočit nestáhnuté
                
            try:
                # Načtení a filtrace
                cleaned_lines = []
                removed_in_file = 0
                
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if line.strip().startswith('#'):
                            removed_in_file += 1
                        else:
                            cleaned_lines.append(line)
                
                # Pokud bylo něco odstraněno, uložíme soubor zpět
                if removed_in_file > 0:
                    with open(path, 'w', encoding='utf-8') as f:
                        f.writelines(cleaned_lines)
                    
                    files_cleaned += 1
                    total_removed_lines += removed_in_file
                    
            except Exception as e:
                errors.append(f"{data['name']}: {str(e)}")

        # Aktualizace GUI po dokončení
        self.check_existing_files() # Znovu načte statistiky a stavy
        self.tree.setEnabled(True)
        self.clean_btn.setEnabled(True)
        self.status_label.setText("Čištění dokončeno.")
        
        # Report
        msg = f"Čištění dokončeno.\n\nUpraveno souborů: {files_cleaned}\nOdstraněno řádků: {total_removed_lines}"
        if errors:
            msg += f"\n\nChyby:\n" + "\n".join(errors)
            QMessageBox.warning(self, "Výsledek čištění", msg)
        else:
            QMessageBox.information(self, "Výsledek čištění", msg)

    def start_download(self):
        to_download = []
        root = self.tree.invisibleRootItem()
        
        for i in range(root.childCount()):
            item = root.child(i)
            if item.checkState(0) == Qt.Checked:
                to_download.append(item.data(0, Qt.UserRole))
        
        if not to_download:
            QMessageBox.warning(self, "Výběr", "Vyberte alespoň jeden slovník ke stažení.")
            return

        self.tree.setEnabled(False)
        self.download_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        self.worker = BatchDownloadWorker(to_download, self.download_dir)
        self.worker.progress.connect(self.update_progress)
        self.worker.file_finished.connect(self.on_file_finished)
        # ZMĚNA: Připojíme nový signál finished_report
        self.worker.finished_report.connect(self.on_download_report)
        self.worker.start()

    def update_progress(self, msg, val):
        self.status_label.setText(msg)
        self.progress_bar.setValue(val)

    def on_file_finished(self, filename):
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            data = item.data(0, Qt.UserRole)
            if data['filename'] == filename:
                item.setText(2, "✅ Staženo")
                item.setForeground(2, QColor("#2ECC71"))
                item.setCheckState(0, Qt.CheckState.Unchecked)

    # --- NOVÁ METODA PRO SOUHRNNÉ OKNO ---
    def on_download_report(self, success_count, errors):
        self.tree.setEnabled(True)
        self.download_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText("Akce dokončena.")
        
        if not errors:
            QMessageBox.information(self, "Hotovo", f"Úspěšně staženo {success_count} slovníků.")
        else:
            # Sestavení chybové zprávy
            err_msg = "\n".join(errors[:5]) # Zobrazit max 5 chyb v detailu
            if len(errors) > 5:
                err_msg += f"\n... a {len(errors) - 5} dalších."
                
            QMessageBox.warning(
                self, 
                "Dokončeno s chybami", 
                f"Úspěšně staženo: {success_count}\n"
                f"Chyby: {len(errors)}\n\n"
                f"Detaily chyb:\n{err_msg}"
            )

# ==========================================
# FFUF WORKER S REAL-TIME PROGRESS ČTENÍM
# ==========================================


class ExportFfufSelectionDialog(QDialog):
    """
    Dialog pro výběr Skenů, Cílů a Status kódů k exportu.
    Obsahuje logiku pro hromadné označování (Rodič -> Děti).
    """
    def __init__(self, source_tree_root, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Výběr dat pro export (FFUF)")
        self.resize(500, 600)
        self.source_root = source_tree_root
        
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Vyberte, co chcete zahrnout do TXT reportu:"))
        
        # Strom pro výběr
        self.tree = QTreeWidget()
        self.tree.setHeaderLabel("Struktura nálezů")
        
        # Propojení kaskádového výběru
        self.tree.itemChanged.connect(self.on_item_changed)
        
        layout.addWidget(self.tree)
        
        # Naplnění stromu
        self.tree.blockSignals(True)
        self.populate_tree()
        self.tree.blockSignals(False)
        
        # --- NOVÉ: Checkbox pro deduplikaci ---
        self.dedup_check = QCheckBox("Deduplikovat výsledky (Case-Insensitive)")
        self.dedup_check.setToolTip("Považuje cesty jako '/admin' a '/ADMIN' za shodné a exportuje pouze první nalezenou.")
        self.dedup_check.setChecked(True) # Defaultně zapnuto, je to užitečné
        layout.addWidget(self.dedup_check)
        # --------------------------------------
        
        # Tlačítka pro výběr
        btn_box = QHBoxLayout()
        btn_all = QPushButton("Vybrat vše")
        btn_none = QPushButton("Zrušit vše")
        btn_all.clicked.connect(self.select_all)
        btn_none.clicked.connect(self.select_none)
        btn_box.addWidget(btn_all)
        btn_box.addWidget(btn_none)
        layout.addLayout(btn_box)
        
        # Dialog tlačítka
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def on_item_changed(self, item, column):
        """
        Kaskádová změna stavu: Pokud změním rodiče, změní se i děti.
        """
        # 1. Zablokujeme signály, aby změna dětí nevyvolala tuto funkci znovu (nekonečná smyčka)
        self.tree.blockSignals(True)
        
        # 2. Zjistíme nový stav rodiče
        new_state = item.checkState(column)
        
        # 3. Aplikujeme na všechny potomky (rekurzivně)
        self._propagate_state(item, new_state)
        
        # 4. Odblokujeme signály
        self.tree.blockSignals(False)

    def _propagate_state(self, parent, state):
        """Rekurzivní pomocná funkce pro nastavení stavu dětí."""
        for i in range(parent.childCount()):
            child = parent.child(i)
            child.setCheckState(0, state)
            # Jdeme hlouběji (např. Session -> Target -> Status)
            self._propagate_state(child, state)
        
    def populate_tree(self):
        """Projder zdrojový strom a vytvoří checkboxy."""
        for i in range(self.source_root.childCount()):
            session_src = self.source_root.child(i)
            session_item = QTreeWidgetItem(self.tree)
            session_item.setText(0, session_src.text(0))
            session_item.setCheckState(0, Qt.CheckState.Checked)
            session_item.setExpanded(True)
            
            for j in range(session_src.childCount()):
                target_src = session_src.child(j)
                target_item = QTreeWidgetItem(session_item)
                target_item.setText(0, target_src.text(0))
                target_item.setCheckState(0, Qt.CheckState.Checked)
                target_item.setExpanded(True)
                
                for k in range(target_src.childCount()):
                    status_src = target_src.child(k)
                    status_text = status_src.text(0)
                    
                    text_lower = status_text.lower()
                    if "status:" in text_lower or "žádné nálezy" in text_lower or "sken dokončen" in text_lower:
                        status_item = QTreeWidgetItem(target_item)
                        status_item.setText(0, status_text)
                        status_item.setCheckState(0, Qt.CheckState.Checked)
                        
    def select_all(self):
        self.tree.blockSignals(True)
        self._set_checked_recursive(self.tree.invisibleRootItem(), Qt.Checked)
        self.tree.blockSignals(False)
        
    def select_none(self):
        self.tree.blockSignals(True)
        self._set_checked_recursive(self.tree.invisibleRootItem(), Qt.Unchecked)
        self.tree.blockSignals(False)
        
    def _set_checked_recursive(self, item, state):
        for i in range(item.childCount()):
            child = item.child(i)
            child.setCheckState(0, state)
            self._set_checked_recursive(child, state)

    def get_selection_map(self):
        result = {}
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            session_item = root.child(i)
            if session_item.checkState(0) == Qt.Unchecked: continue
            session_key = session_item.text(0)
            result[session_key] = {}
            for j in range(session_item.childCount()):
                target_item = session_item.child(j)
                if target_item.checkState(0) == Qt.Unchecked: continue
                target_key = target_item.text(0)
                allowed_statuses = []
                for k in range(target_item.childCount()):
                    status_item = target_item.child(k)
                    if status_item.checkState(0) == Qt.Checked:
                        allowed_statuses.append(status_item.text(0))
                if allowed_statuses:
                    result[session_key][target_key] = allowed_statuses
        return result



class ExportTargetSelectionDialog(QDialog):
    """Mini dialog pro výběr konkrétních cílů k exportu včetně jejich nastavení."""
    def __init__(self, target_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Výběr cílů pro export")
        self.resize(600, 500)
        
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Vyberte konkrétní skeny pro TXT report (Cíl | Konfigurace):"))
        
        # Seznam s checkboxy
        self.list_widget = QListWidget()
        for data in target_data:
            display_text = f"{data['name']}  |  {data['settings']}"
            item = QListWidgetItem(display_text)
            # Uložíme si původní data pro pozdější filtraci
            item.setData(Qt.UserRole, data)
            item.setCheckState(Qt.Unchecked)
            self.list_widget.addItem(item)
        
        layout.addWidget(self.list_widget)
        
        # Tlačítka pro hromadnou manipulaci
        selection_btns = QHBoxLayout()
        btn_all = QPushButton("Vybrat vše")
        btn_none = QPushButton("Zrušit vše")
        btn_all.clicked.connect(self.select_all)
        btn_none.clicked.connect(self.select_none)
        selection_btns.addWidget(btn_all)
        selection_btns.addWidget(btn_none)
        layout.addLayout(selection_btns)
        
        # Potvrzovací tlačítka
        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)

    def select_all(self):
        for i in range(self.list_widget.count()):
            self.list_widget.item(i).setCheckState(Qt.Checked)

    def select_none(self):
        for i in range(self.list_widget.count()):
            self.list_widget.item(i).setCheckState(Qt.Unchecked)

    def get_selected_data(self):
        """Vrátí seznam vybraných dat (název a nastavení)."""
        selected = []
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            if item.checkState() == Qt.Checked:
                selected.append(item.setData(Qt.UserRole))
        return selected



# Klíče pro QSettings (sdílí org/app s hlavní aplikací)
SETTINGS_ORG = "UTB"
SETTINGS_APP = "NmapScannerApp"
# Horní strop paralelních skenů (ochrana cíle i lokálního stroje)
MAX_PARALLEL = 4


def _fmt_int(n):
    return f"{int(n):,}".replace(",", " ")


def _fmt_secs(seconds):
    seconds = max(0, int(seconds))
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    if h > 0:
        return f"{h}h {m}m {s}s"
    if m > 0:
        return f"{m}m {s}s"
    return f"{s}s"


class ScanProgressRow(QWidget):
    """
    Jeden řádek průběhu pro jeden běžící cíl: název + progress bar (%, v/m) +
    zbývající requesty + čas (ETA) + tlačítko zrušení tohoto skenu.
    """
    def __init__(self, target_url, on_cancel=None, parent=None):
        super().__init__(parent)
        self.target_url = target_url
        self._on_cancel = on_cancel
        self._cancelled = False

        layout = QHBoxLayout(self)
        layout.setContentsMargins(2, 1, 2, 1)
        layout.setSpacing(8)

        # Zkrácený název (bez schématu), plná URL v tooltipu
        short = target_url.split("://", 1)[-1]
        self.title = QLabel(short)
        self.title.setToolTip(target_url)
        self.title.setMinimumWidth(150)
        self.title.setMaximumWidth(200)
        self.title.setStyleSheet("font-size: 11px; font-weight: bold;")
        layout.addWidget(self.title)

        self.bar = QProgressBar()
        self.bar.setFixedHeight(18)
        self.bar.setTextVisible(True)
        self.bar.setFormat("Načítám...")
        self.bar.setRange(0, 0)  # indeterminate „busy", než přijde první progress
        layout.addWidget(self.bar, 1)

        # Zbývá: počet requestů
        self.remaining = QLabel("–")
        self.remaining.setStyleSheet("font-size: 11px; color: #888;")
        self.remaining.setFixedWidth(120)
        self.remaining.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.remaining.setToolTip("Zbývající počet requestů")
        layout.addWidget(self.remaining)

        self.rps = QLabel("-")
        self.rps.setStyleSheet("font-size: 11px; color: #888;")
        self.rps.setFixedWidth(90)
        self.rps.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        layout.addWidget(self.rps)

        self.eta = QLabel("Zbývá: -")
        self.eta.setStyleSheet("font-size: 11px; color: #888;")
        self.eta.setFixedWidth(100)
        self.eta.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        layout.addWidget(self.eta)

        # Zrušit tento sken
        self.cancel_btn = QPushButton("✕")
        self.cancel_btn.setToolTip("Zrušit tento sken")
        self.cancel_btn.setFixedSize(22, 18)
        self.cancel_btn.setStyleSheet("QPushButton { color:#C0392B; font-weight:bold; }")
        self.cancel_btn.clicked.connect(self._cancel_clicked)
        layout.addWidget(self.cancel_btn)

    def _cancel_clicked(self):
        if self._cancelled:
            return
        self._cancelled = True
        self.cancel_btn.setEnabled(False)
        self.bar.setFormat("Ruším…")
        self.eta.setText("Zbývá: –")
        if callable(self._on_cancel):
            self._on_cancel()

    def apply_progress(self, progress, total, rps):
        if self._cancelled:
            return
        remaining = max(0, total - progress) if total > 0 else 0
        if total > 0:
            self.bar.setRange(0, total)
            self.bar.setValue(progress)
            percent = int((progress / total) * 100)
            self.bar.setFormat(f"{percent}% - {_fmt_int(progress)} / {_fmt_int(total)}")
            self.remaining.setText(f"zbývá {_fmt_int(remaining)} req")

        self.rps.setText(f"{rps} req/sec")

        if rps > 0 and remaining > 0:
            eta = _fmt_secs(remaining / rps)
        elif total > 0 and progress >= total:
            eta = "Hotovo"
        else:
            eta = "výpočet…"
        self.eta.setText(f"Zbývá: {eta}")

    def mark_done(self):
        self.cancel_btn.setEnabled(False)
        if self.bar.maximum() > 0:
            self.bar.setValue(self.bar.maximum())
            self.bar.setFormat("100% - Hotovo")
        else:
            self.bar.setRange(0, 1)
            self.bar.setValue(1)
            self.bar.setFormat("Hotovo")
        self.remaining.setText("zbývá 0 req")
        self.eta.setText("Zbývá: Hotovo")


class FfufDialog(QDialog):
    """
    Dialogové okno pro ffuf.
    - Paralelní skenování více cílů najednou (až MAX_PARALLEL), každý cíl má
      vlastní progress řádek (% , v/m, req/sec, ETA) + tlačítko zrušení.
    - Může běžet na pozadí (nemodální okno) — skeny běží dál, okno lze zavřít
      a znovu otevřít přes tlačítko ffuf.
    - Poslední použité nastavení se pamatuje přes QSettings.
    """
    # Emituje se po každé synchronizaci výsledků do projektu (pro autosave v app)
    results_changed = Signal()

    def __init__(self, scan_results, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Directory Fuzzing (ffuf)")
        self.resize(1100, 850)
        self.scan_results = scan_results
        self.queue = []            # čekající cíle (URL)
        self.active_ctxs = []      # běžící kontexty skenů (paralelně)
        self.is_scanning = False
        self.json_results = []

        # Počítadla pro celkový progress bar
        self.total_targets = 0
        self.completed_targets = 0

        # Uložení odkazu na aktuální vizuální skupinu (Session) a její čas
        self.current_session_item = None
        self.current_scan_timestamp = ""
        
        # Definice skupin přípon pro rychlý výběr
        self.ext_groups = {
            "ASP.NET": [".aspx", ".axd", ".ashx", ".asmx", ".svc"],
            "Java": [".jsp", ".jspx", ".do", ".action"],
            "Config": [".config", ".xml", ".yml", ".yaml", ".json", ".ini", ".env"],
            "Backup": [".bak", ".old", ".zip", ".rar", ".7z", ".tar.gz", ".sql"]
        }
        
        self.init_ui()
        self.load_targets()
        self._restore_ffuf_settings()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(10)
        
        # Cache pro počty řádků v souborech {cesta: pocet}
        self.line_count_cache = {} 

        # --- 1. Konfigurace (Fixní výška) ---
        config_group = QGroupBox("Nastavení skenování")
        config_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        
        config_layout = QGridLayout(config_group)
        config_layout.setContentsMargins(10, 10, 10, 10)
        
        # Řádek 0: Wordlist (ZMĚNĚNO NA CheckableComboBox)
        config_layout.addWidget(QLabel("Slovníky:"), 0, 0)
        self.wordlist_combo = CheckableComboBox() # Nyní Checkable
        self.wordlist_combo.setMinimumWidth(300)
        self.refresh_wordlists()
        config_layout.addWidget(self.wordlist_combo, 0, 1)
        
        wl_btn_layout = QHBoxLayout()
        wl_btn_layout.setContentsMargins(0, 0, 0, 0)
        browse_btn = QPushButton("📂")
        browse_btn.setToolTip("Procházet...")
        browse_btn.setFixedWidth(40)
        browse_btn.clicked.connect(self.browse_wordlist)
        wl_btn_layout.addWidget(browse_btn)
        
        self.manager_btn = QPushButton("📚")
        self.manager_btn.setToolTip("Správce slovníků")
        self.manager_btn.setFixedWidth(40)
        self.manager_btn.clicked.connect(self.open_wordlist_manager)
        wl_btn_layout.addWidget(self.manager_btn)
        wl_btn_layout.addStretch()
        config_layout.addLayout(wl_btn_layout, 0, 2)
        
        self.stats_label = QLabel("Načítám...")
        self.stats_label.setStyleSheet("color: #666; font-size: 11px; font-weight: bold;")
        self.stats_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        config_layout.addWidget(self.stats_label, 0, 3)

        # Řádek 1: Match Codes
        config_layout.addWidget(QLabel("Match Codes:"), 1, 0)
        self.mc_combo = CheckableComboBox()
        codes = [
            ("200", "200 OK", True), ("204", "204 No Content", False),
            ("301", "301 Moved", True), ("302", "302 Found", True),
            ("307", "307 Temp Redirect", False), ("401", "401 Unauthorized", True),
            ("403", "403 Forbidden", True), ("405", "405 Method Not Allowed", False),
            ("500", "500 Server Error", True)
        ]
        for c, t, s in codes: self.mc_combo.add_item(c, t, s)
        config_layout.addWidget(self.mc_combo, 1, 1)
        
        # Přípony
        config_layout.addWidget(QLabel("Přípony (-e):"), 1, 2)
        self.ext_combo = CheckableComboBox()
        self.ext_combo.setMinimumWidth(350)
        self.ext_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        
        defaults = [".php", ".html", ".txt"]
        all_exts = set(defaults)
        for group in self.ext_groups.values():
            all_exts.update(group)
        
        sorted_exts = sorted(list(all_exts))
        for ext in sorted_exts:
            is_checked = ext in defaults
            self.ext_combo.add_item(ext, f"Hledat soubory {ext}", is_checked)
        config_layout.addWidget(self.ext_combo, 1, 3)
        
        # Řádek 2: paralelní skeny
        parallel_layout = QHBoxLayout()
        parallel_layout.setContentsMargins(0, 0, 0, 0)
        parallel_layout.addWidget(QLabel("Paralelně:"))
        self.parallel_spin = QSpinBox()
        self.parallel_spin.setRange(1, MAX_PARALLEL)
        self.parallel_spin.setValue(1)
        self.parallel_spin.setFixedWidth(50)
        self.parallel_spin.setToolTip(
            f"Kolik cílů skenovat současně (1–{MAX_PARALLEL}). Zrychlejší, "
            "ale vyšší zátěž sítě i lokálního stroje."
        )
        parallel_layout.addWidget(self.parallel_spin)
        parallel_layout.addStretch()
        config_layout.addLayout(parallel_layout, 2, 0)

        self.redirect_check = QCheckBox("Sledovat přesměrování (-r)")
        self.redirect_check.setChecked(True)
        config_layout.addWidget(self.redirect_check, 2, 1)
        
        tech_layout = QHBoxLayout()
        tech_layout.setContentsMargins(0, 0, 0, 0)
        self.chk_asp = QCheckBox("ASP.NET"); self.chk_asp.toggled.connect(lambda s: self.toggle_ext_group("ASP.NET", s))
        self.chk_java = QCheckBox("Java"); self.chk_java.toggled.connect(lambda s: self.toggle_ext_group("Java", s))
        self.chk_config = QCheckBox("Konfig"); self.chk_config.toggled.connect(lambda s: self.toggle_ext_group("Config", s))
        self.chk_backup = QCheckBox("Zálohy"); self.chk_backup.toggled.connect(lambda s: self.toggle_ext_group("Backup", s))
        tech_layout.addWidget(self.chk_asp); tech_layout.addWidget(self.chk_java); tech_layout.addWidget(self.chk_config); tech_layout.addWidget(self.chk_backup); tech_layout.addStretch()
        config_layout.addLayout(tech_layout, 2, 2, 1, 2)

        config_layout.setColumnStretch(4, 1)
        main_layout.addWidget(config_group, 0)
        self.init_ui_rest(main_layout)

        # SIGNÁLY (Opraveno na lineEdit().textChanged pro CheckableComboBox)
        self.wordlist_combo.lineEdit().textChanged.connect(self.update_stats)
        self.ext_combo.lineEdit().textChanged.connect(self.update_stats)
        
        QTimer.singleShot(100, self.update_stats)

    def init_ui_rest(self, main_layout):
        # --- 2. Splitter (Zbytek místa) ---
        splitter = QSplitter(Qt.Horizontal)
        splitter.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        
        # Levá část (Cíle)
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0,0,0,0)
        left_layout.addWidget(QLabel("<b>Webové služby:</b>"))
        self.targets_list = QListWidget()
        self.targets_list.setSelectionMode(QListWidget.MultiSelection)
        left_layout.addWidget(self.targets_list)
        
        target_btns_layout = QHBoxLayout()
        select_all_btn = QPushButton("Vybrat vše")
        select_all_btn.clicked.connect(self.select_all_targets)
        target_btns_layout.addWidget(select_all_btn)
        left_layout.addLayout(target_btns_layout)
        
        left_layout.addSpacing(5)
        left_layout.addWidget(QLabel("Přidat cíl:"))
        manual_add_layout = QHBoxLayout()
        self.manual_target_input = QLineEdit()
        self.manual_target_input.setPlaceholderText("http://cíl:port")
        self.manual_target_input.returnPressed.connect(self.add_manual_target)
        manual_add_layout.addWidget(self.manual_target_input)
        add_btn = QPushButton("➕")
        add_btn.setFixedWidth(30)
        add_btn.clicked.connect(self.add_manual_target)
        manual_add_layout.addWidget(add_btn)
        left_layout.addLayout(manual_add_layout)
        
        left_widget.setMaximumWidth(300)
        splitter.addWidget(left_widget)
        
        # Pravá část (Tabulka výsledků)
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0,0,0,0)
        right_layout.addWidget(QLabel("<b>Nálezy:</b>"))
        
        self.results_tree = QTreeWidget()
        # ZMĚNA: Přejmenování sloupce "Redirect" na "Celá URL"
        self.results_tree.setHeaderLabels(["Cesta", "Status", "Velikost", "Slov", "Celá URL"])
        self.results_tree.setColumnHidden(2, True) # Velikost schovaná
        self.results_tree.setColumnHidden(3, True) # Slov schovaná
        
        header = self.results_tree.header()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setStretchLastSection(True) # Poslední sloupec s URL se roztáhne
        
        self.results_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.results_tree.customContextMenuRequested.connect(self.show_context_menu)
        
        right_layout.addWidget(self.results_tree)
        splitter.addWidget(right_widget)
        
        main_layout.addWidget(splitter, 1)
        
        # --- 3. Panel průběhu (Fixní výška) ---
        progress_frame = QFrame()
        progress_frame.setFrameShape(QFrame.StyledPanel)
        progress_frame.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        
        progress_layout = QVBoxLayout(progress_frame)
        progress_layout.setContentsMargins(5, 5, 5, 5)
        progress_layout.setSpacing(2)

        # Dynamický kontejner: jeden ScanProgressRow na běžící cíl.
        # Ve scroll area, aby se i 4 paralelní řádky vešly bez roztažení okna.
        self.progress_scroll = QScrollArea()
        self.progress_scroll.setWidgetResizable(True)
        self.progress_scroll.setFrameShape(QFrame.NoFrame)
        self.progress_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.progress_scroll.setFixedHeight(MAX_PARALLEL * 26 + 6)
        self.progress_scroll.setVisible(False)

        progress_container = QWidget()
        self.progress_rows_layout = QVBoxLayout(progress_container)
        self.progress_rows_layout.setContentsMargins(0, 0, 0, 0)
        self.progress_rows_layout.setSpacing(2)
        self.progress_rows_layout.addStretch()
        self.progress_scroll.setWidget(progress_container)
        progress_layout.addWidget(self.progress_scroll)

        # Mapování běžícího kontextu -> jeho progress řádek
        self.progress_rows = {}

        main_layout.addWidget(progress_frame, 0)
        
        # --- 4. Spodní panel (Fixní výška) ---
        bottom_widget = QWidget()
        bottom_widget.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        bottom_layout = QHBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 5, 0, 0)
        
        self.total_progress_bar = QProgressBar()
        self.total_progress_bar.setVisible(False)
        self.total_progress_bar.setMaximumWidth(150)
        self.total_progress_bar.setFixedHeight(15)
        self.total_progress_bar.setFormat("Cíle: %v/%m")
        bottom_layout.addWidget(self.total_progress_bar)
        
        self.log_label = QLabel("Připraveno.")
        bottom_layout.addWidget(self.log_label)
        bottom_layout.addStretch()
        
        self.export_json_btn = QPushButton("Uložit JSON")
        self.export_json_btn.setToolTip("Exportovat Raw JSON data")
        self.export_json_btn.clicked.connect(self.export_raw_json)
        self.export_json_btn.setEnabled(False)
        bottom_layout.addWidget(self.export_json_btn)
        
        self.export_txt_btn = QPushButton("Uložit TXT")
        self.export_txt_btn.setToolTip("Exportovat výsledky do strukturovaného TXT")
        self.export_txt_btn.clicked.connect(self.export_results_txt)
        self.export_txt_btn.setEnabled(False) # Aktivuje se až při prvním nálezu
        bottom_layout.addWidget(self.export_txt_btn)

        self.background_btn = QPushButton("⬇ Na pozadí")
        self.background_btn.setToolTip("Skrýt okno a nechat skeny běžet na pozadí "
                                       "(znovu otevřeš tlačítkem ffuf).")
        self.background_btn.clicked.connect(self.send_to_background)
        bottom_layout.addWidget(self.background_btn)

        self.start_btn = QPushButton("Spustit Fuzzing")
        self.start_btn.clicked.connect(self.start_fuzzing)
        bottom_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Zastavit")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_fuzzing)
        bottom_layout.addWidget(self.stop_btn)
        
        main_layout.addWidget(bottom_widget, 0)
        
    def load_existing_results(self, existing_data):
        """
        Načte výsledky ffuf z projektu.
        OPRAVA: Automaticky přidá historické/manuální cíle do seznamu 'Webové služby'.
        """
        if not existing_data or not isinstance(existing_data, list):
            return
            
        self.log_label.setText("Obnovuji historii skenů...")
        self.json_results = existing_data 
        
        sessions_map = {} 
        targets_map = {}  
        from urllib.parse import urlparse
        
        for data in self.json_results:
            full_url = data.get("url", "")
            if not full_url and data.get('_meta') == 'empty_scan':
                 # Pokusíme se získat URL z metadat, pokud tam je
                 full_url = data.get("url", "") 
            
            if not full_url:
                continue

            # --- NOVÁ LOGIKA: Přidání do seznamu cílů vlevo ---
            try:
                parsed = urlparse(full_url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                
                # Zkontrolujeme, zda už base_url v seznamu targets_list náhodou není
                is_present = False
                for idx in range(self.targets_list.count()):
                    if self.targets_list.item(idx).data(Qt.UserRole) == base_url:
                        is_present = True
                        break
                
                # Pokud v seznamu chybí, přidáme ho (označený jako 'Z historie/Manuální')
                if not is_present:
                    # Pokud byl seznam dříve deaktivován (žádné nmap výsledky), aktivujeme ho
                    self.targets_list.setEnabled(True)
                    new_item = QListWidgetItem(f"{base_url} (Z historie)")
                    new_item.setData(Qt.UserRole, base_url)
                    new_item.setCheckState(Qt.Unchecked)
                    self.targets_list.addItem(new_item)
            except:
                pass
            # --------------------------------------------------

            saved_settings = data.get("_settings", "Načteno z projektu")
            timestamp = data.get("_scan_timestamp", "Historie")
            session_key = f"{timestamp}|{saved_settings}"
            
            if session_key not in sessions_map:
                title = f"SKEN: {timestamp}" if timestamp != "Historie" else "Historie skenování"
                session_item = QTreeWidgetItem([title, "", "", "", saved_settings])
                session_item.setForeground(0, QColor("#34495E")) 
                session_item.setForeground(4, QColor("#7F8C8D"))
                session_item.setFont(0, QFont("Arial", 11, QFont.Bold))
                
                self.results_tree.insertTopLevelItem(0, session_item)
                session_item.setExpanded(True)
                sessions_map[session_key] = session_item
            
            target_key = f"{session_key}|{base_url}"
            if target_key not in targets_map:
                target_item = QTreeWidgetItem(sessions_map[session_key], [f"CÍL: {base_url}", "", "", "", saved_settings])
                target_item.setForeground(0, QColor("#3498DB"))
                target_item.setForeground(4, QColor("#95A5A6"))
                target_item.setFont(0, QFont("Arial", 10, QFont.Bold))
                target_item.setExpanded(True)
                targets_map[target_key] = target_item
            
            if data.get('_meta') == 'empty_scan':
                info_item = QTreeWidgetItem(targets_map[target_key], ["Sken dokončen - žádné nálezy", "", "", "", ""])
                info_item.setForeground(0, QColor("#95A5A6"))
                info_item.setFirstColumnSpanned(True)
                continue

            status = data.get("status", 0)
            path_display = data.get('input', {}).get('FUZZ', 'Unknown')
            if full_url:
                try:
                    parsed = urlparse(full_url)
                    path_display = parsed.path + (f"?{parsed.query}" if parsed.query else "")
                except: pass

            status_group_item = None
            group_label = f"Status: {status}"
            for i in range(targets_map[target_key].childCount()):
                child = targets_map[target_key].child(i)
                if child.text(0) == group_label:
                    status_group_item = child
                    break
            
            if not status_group_item:
                status_group_item = QTreeWidgetItem(targets_map[target_key], [group_label, "", "", "", ""])
                status_group_item.setExpanded(True) # ROZBALENO
                group_color = QColor("#95A5A6")
                if 200 <= status < 300: group_color = QColor("#2ECC71")
                elif 300 <= status < 400: group_color = QColor("#F39C12")
                elif status == 401 or status == 403: group_color = QColor("#E74C3C")
                status_group_item.setForeground(0, group_color)
                status_group_item.setFont(0, QFont("Arial", 10, QFont.Bold))

            res_item = QTreeWidgetItem(status_group_item, [str(path_display), str(status), str(data.get('length', 0)), str(data.get('words', 0)), full_url])
            if 200 <= status < 300: res_item.setForeground(1, QColor("#2ECC71"))
            elif 300 <= status < 400: res_item.setForeground(1, QColor("#F39C12"))
            elif status == 401 or status == 403: res_item.setForeground(1, QColor("#E74C3C"))

        self.results_tree.header().resizeSections(QHeaderView.ResizeToContents)
        
        # NOVÉ: Aktivace tlačítek pro export, pokud máme data
        if self.json_results:
            self.export_txt_btn.setEnabled(True)
            self.export_json_btn.setEnabled(True)
            
        self._refresh_target_list_ui()
        
    def _refresh_target_list_ui(self):
        """
        Pomocná metoda pro seřazení a seskupení cílů.
        OPRAVA: Oddělovače nebudou mít checkboxy a nebudou klikatelné.
        """
        items_data = []
        # Načteme pouze skutečné cíle (přeskočíme staré oddělovače)
        for i in range(self.targets_list.count()):
            item = self.targets_list.item(i)
            url = item.data(Qt.UserRole)
            if url: # Oddělovače nemají UserRole data
                items_data.append({
                    'text': item.text(),
                    'url': url,
                    'checked': item.checkState() == Qt.Checked
                })
        
        if not items_data:
            return

        # Numerické seřazení podle IP adresy
        def sort_key(x):
            try:
                from urllib.parse import urlparse
                netloc = urlparse(x['url']).netloc.split(':')[0]
                return tuple(int(part) for part in netloc.split('.'))
            except:
                return (0, 0, 0, 0)

        items_data.sort(key=sort_key)
        
        self.targets_list.clear()
        last_ip = None
        
        for data in items_data:
            try:
                from urllib.parse import urlparse
                current_ip = urlparse(data['url']).netloc.split(':')[0]
                
                # Přidání oddělovače mezi různé IP adresy
                if last_ip and last_ip != current_ip:
                    separator = QListWidgetItem("───────")
                    # KLÍČOVÁ OPRAVA: Vypnutí všech interakcí a checkboxu
                    separator.setFlags(Qt.NoItemFlags) 
                    separator.setTextAlignment(Qt.AlignCenter)
                    separator.setForeground(QColor("#555555")) # Jemná šedá pro oddělovač
                    self.targets_list.addItem(separator)
                last_ip = current_ip
            except:
                pass

            new_item = QListWidgetItem(data['text'])
            new_item.setData(Qt.UserRole, data['url'])
            # Skutečné cíle mají checkbox povolený
            new_item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            new_item.setCheckState(Qt.Checked if data['checked'] else Qt.Unchecked)
            self.targets_list.addItem(new_item)

    def start_fuzzing(self):
        """
        Spustí proces fuzzingu. 
        Upraveno: Nový sken se vkládá na začátek seznamu (index 0).
        """
        self.export_json_btn.setEnabled(False)

        # Sjednocení slovníků
        selected_paths = []
        model = self.wordlist_combo.model
        for i in range(model.rowCount()):
            item = model.item(i)
            if item.checkState() == Qt.Checked:
                path = item.data(Qt.UserRole)
                if path: selected_paths.append(path)
    
        if not selected_paths:
            QMessageBox.warning(self, "Chyba", "Musíte zaškrtnout alespoň jeden slovník!")
            return

        try:
            unique_words = set()
            for path in selected_paths:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        word = line.strip()
                        if word and not word.startswith('#'):
                            unique_words.add(word)
            
            merged_path = os.path.join(os.getcwd(), "wordlists", "merged_wordlist.tmp")
            with open(merged_path, 'w', encoding='utf-8') as f:
                for word in sorted(list(unique_words)):
                    f.write(f"{word}\n")
            self.current_wordlist = merged_path
        except Exception as e:
            QMessageBox.critical(self, "Chyba", f"Nelze sjednotit slovníky: {e}")
            return

        self.queue = []
        for i in range(self.targets_list.count()):
            item = self.targets_list.item(i)
            if item.checkState() == Qt.Checked:
                self.queue.append(item.data(Qt.UserRole))
        
        if not self.queue:
            QMessageBox.warning(self, "Chyba", "Vyberte alespoň jeden cíl.")
            return

        # Zapamatovat poslední použité nastavení
        self._save_ffuf_settings()

        self.parallel_count = self.parallel_spin.value()
        self.total_targets = len(self.queue)
        self.completed_targets = 0

        self.is_scanning = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.parallel_spin.setEnabled(False)
        self.progress_scroll.setVisible(True)
        self.total_progress_bar.setVisible(True)
        self.total_progress_bar.setRange(0, self.total_targets)
        self.total_progress_bar.setValue(0)

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.current_scan_timestamp = timestamp
        
        wls = self.wordlist_combo.lineEdit().text()
        exts = self.ext_combo.get_checked_codes()
        mcs = self.mc_combo.get_checked_codes()
        settings_text = f"Slovníky: {wls} | Přípony: {exts if exts else 'Žádné'} | Match: {mcs}"
        
        # Vytvoření hlavičky relace na indexu 0
        session_title = f"SKEN: {timestamp} (Cílů: {len(self.queue)})"
        self.current_session_item = QTreeWidgetItem([session_title, "", "", "", settings_text])
        
        # ZMĚNA: Design bez pozadí
        self.current_session_item.setForeground(0, QColor("#34495E"))
        self.current_session_item.setForeground(4, QColor("#7F8C8D"))
        self.current_session_item.setFont(0, QFont("Arial", 11, QFont.Bold))
        
        self.results_tree.insertTopLevelItem(0, self.current_session_item)
        self.current_session_item.setExpanded(True)

        # Naplnit volné sloty (spustí až self.parallel_count cílů najednou)
        self._fill_slots()

    def get_line_count(self, filepath):
        """Spočítá řádky v souboru (s jednoduchou cache)."""
        if not filepath or not os.path.isfile(filepath):
            return 0
            
        # Pokud máme v cache a velikost souboru se nezměnila, vrátíme z cache
        try:
            mtime = os.path.getmtime(filepath)
            if filepath in self.line_count_cache:
                cached_mtime, count = self.line_count_cache[filepath]
                if cached_mtime == mtime:
                    return count
        except OSError:
            pass

        # Spočítat řádky (optimalizovaně)
        try:
            with open(filepath, 'rb') as f:
                count = sum(1 for _ in f)
            
            # Uložit do cache
            self.line_count_cache[filepath] = (os.path.getmtime(filepath), count)
            return count
        except Exception:
            return 0

    def update_stats(self):
        """Aktualizuje label se statistikou (Slova x (Přípony + 1) = Celkem)."""
        if not hasattr(self, 'ext_combo') or not hasattr(self, 'wordlist_combo') or not hasattr(self, 'stats_label'):
            return

        # 1. Získat unikátní cesty
        selected_paths = []
        model = self.wordlist_combo.model
        for i in range(model.rowCount()):
            item = model.item(i)
            if item.checkState() == Qt.Checked:
                path = item.data(Qt.UserRole)
                if path and os.path.exists(path):
                    selected_paths.append(path)
        
        if not selected_paths:
            self.stats_label.setText("Žádný slovník nevybrán")
            return

        # 2. Spočítat unikátní slova
        unique_words = set()
        for path in selected_paths:
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        word = line.strip()
                        if word: unique_words.add(word)
            except: pass
        
        word_count = len(unique_words)
        
        # 3. Opravený výpočet multiplieru
        ext_text = self.ext_combo.get_checked_codes()
        extensions = [x for x in ext_text.split(',') if x.strip()]
        
        # ffuf zkouší: slovo + (slovo.ext1, slovo.ext2...) 
        # Tedy multiplier je počet přípon + 1 (pro původní slovo bez přípony)
        multiplier = (len(extensions) + 1) if extensions else 1
        
        total_requests = word_count * multiplier
        
        # 4. Výpis
        wc_str = f"{word_count:,}".replace(",", " ")
        req_str = f"{total_requests:,}".replace(",", " ")
        self.stats_label.setText(f"Slov: {wc_str} | Mult: x{multiplier}\nCelkem: {req_str} reqs")
        
    def show_context_menu(self, position):
        """
        Zobrazí kontextové menu. Nabídne smazání u hlavičky cíle 
        nebo kopírování u konkrétního nálezu.
        """
        item = self.results_tree.itemAt(position)
        if not item: 
            return
        
        menu = QMenu()
        
        # PŘÍPAD A: Kliknutí na modrou hlavičku CÍLE (nemá parenta)
        if item.parent() is None:
            delete_action = menu.addAction("❌ Smazat tento celý sken")
            action = menu.exec(self.results_tree.mapToGlobal(position))
            
            if action == delete_action:
                self.delete_target_scan(item)
                
        # PŘÍPAD B: Kliknutí na konkrétní NÁLEZ (má parenta i grandparenta)
        elif item.parent() is not None and item.parent().parent() is not None:
            copy_word = menu.addAction("Kopírovat řádek slovníku")
            copy_url = menu.addAction("Kopírovat URL adresu")
            
            action = menu.exec(self.results_tree.mapToGlobal(position))
            
            if action == copy_word:
                QApplication.clipboard().setText(item.text(0))
            elif action == copy_url:
                # Sloupec Celá URL je na indexu 4
                QApplication.clipboard().setText(item.text(4))
                
    def delete_target_scan(self, item):
        """
        Odstraní veškerá data spojená s vybraným skenem z paměti i z tabulky.
        Identifikace probíhá pomocí kombinace URL a nastavení.
        """
        # Zjistíme, co mažeme (Session, Target, nebo nested Target)
        target_label = item.text(0) 
        
        # Pokud mažeme celou Session (hlavní skupinu)
        if "SKEN:" in target_label:
            reply = QMessageBox.question(
                self, "Smazat relaci", 
                f"Opravdu smazat celou relaci a všechny její cíle?\n{target_label}",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply != QMessageBox.Yes: return
            
            # Musíme najít všechny děti (Cíle) a smazat jejich data
            # Pro zjednodušení: Projdeme všechny json_results a smažeme ty, 
            # které mají stejný timestamp jako tato session.
            # Timestamp je v titulku "SKEN: 2023-10-10 10:10:10"
            timestamp_str = target_label.replace("SKEN: ", "").split(" (")[0]
            
            self.json_results = [
                d for d in self.json_results 
                if d.get("_scan_timestamp") != timestamp_str
            ]
            
            # Smazat z GUI
            index = self.results_tree.indexOfTopLevelItem(item)
            self.results_tree.takeTopLevelItem(index)
            return

        # Pokud mažeme konkrétní Cíl (Target)
        target_url = target_label.replace("CÍL: ", "").replace("SCAN: ", "").strip()
        settings = item.text(4) # Nastavení je ve sloupci 4

        reply = QMessageBox.question(
            self, "Smazat výsledky",
            f"Opravdu chcete smazat tento sken?\n\nCíl: {target_url}",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            pass
            
            # Filtrace seznamu json_results - ponecháme jen to, co NEMÁ odpovídat mazanému cíli
            # Musíme filtrovat podle URL (full_url nebo _target_url) a nastavení
            new_results = []
            
            for data in self.json_results:
                # Získat identifikátory dat
                data_url = data.get("url", "")
                data_target = data.get("_target_url", "")
                data_parent = data.get("_parent_url", "")
                data_settings = data.get("_settings", "")
                
                # Logika shody:
                # 1. Pokud data_url odpovídá target_url
                # 2. Pokud data_target odpovídá target_url (pro root skeny)
                # 3. Pokud data_parent odpovídá target_url (pro nested skeny)
                
                # Zjednodušená kontrola: Pokud URL v datech odpovídá mazanému cíli
                # A zároveň sedí nastavení (pokud je dostupné)
                
                match = False
                if data_url == target_url: match = True
                if data_target == target_url: match = True
                
                # Pokud je to shoda A sedí nastavení -> SMAZAT (nepřidat do new)
                if match and (not settings or data_settings == settings):
                    continue
                
                new_results.append(data)
            
            # Aktualizace hlavního seznamu výsledků
            self.json_results = new_results
            
            # Odstranění položky z GUI (musíme najít rodiče)
            parent = item.parent()
            if parent:
                parent.removeChild(item)
            else:
                index = self.results_tree.indexOfTopLevelItem(item)
                self.results_tree.takeTopLevelItem(index)
            
            self.log_label.setText(f"Sken {target_url} byl odstraněn.")

    def toggle_ext_group(self, group_name, checked):
        """Zapne/vypne všechny přípony v dané skupině."""
        if group_name in self.ext_groups:
            extensions = self.ext_groups[group_name]
            for ext in extensions:
                self.ext_combo.set_item_checked(ext, checked)
    
    def refresh_wordlists(self):
        """
        Načte slovníky ze složky 'wordlists' a umožní vícenásobný výběr.
        """
        self.wordlist_combo.blockSignals(True)
        # Vyčistíme model našeho CheckableComboBoxu
        self.wordlist_combo.model.clear()
        
        local_dir = os.path.join(os.getcwd(), "wordlists")
        if not os.path.exists(local_dir):
            os.makedirs(local_dir, exist_ok=True)

        items = []
        for f in os.listdir(local_dir):
            if f.endswith(".txt") and not f.endswith(".tmp"):
                path = os.path.join(local_dir, f)
                count = self.get_line_count(path)
                count_str = f"{count:,}".replace(",", " ")
                display = f"📁 {f} ({count_str} slov)"
                items.append((f.lower(), display, path))

        # Seřadit abecedně
        items.sort(key=lambda x: x[0])

        # Přidání do modelu CheckableComboBoxu
        for _, display, path in items:
            # CheckableComboBox používá vnitřně metodu add_item(text, tooltip, checked)
            self.wordlist_combo.add_item(display, f"Cesta: {path}", False)
            # DŮLEŽITÉ: Uložíme cestu do posledního přidaného řádku v modelu
            last_row = self.wordlist_combo.model.rowCount() - 1
            self.wordlist_combo.model.item(last_row).setData(path, Qt.UserRole)
            
        self.wordlist_combo.blockSignals(False)
        self.wordlist_combo.update_text()
        
        if hasattr(self, 'update_stats'):
            self.update_stats()

    def open_wordlist_manager(self):
        dialog = WordlistManagerDialog(self)
        dialog.exec()
        self.refresh_wordlists()

    def browse_wordlist(self):
        start_dir = os.path.join(os.getcwd(), "wordlists")
        if not os.path.exists(start_dir): start_dir = os.getcwd()
        fname, _ = QFileDialog.getOpenFileName(self, "Vybrat wordlist", start_dir, "Text files (*.txt);;All files (*)")
        if fname:
            self.wordlist_combo.addItem(f"📂 {os.path.basename(fname)}", fname)
            self.wordlist_combo.setCurrentIndex(self.wordlist_combo.count() - 1)

    def load_targets(self):
        self.targets_list.clear()
        found_targets = set()
        phase_data = self.scan_results.get('tcp', {})
        common_web_ports = [80, 443, 8080, 8443, 8000, 8008, 3000, 5000]
        for ip, ip_data in phase_data.items():
            if 'tcp' in ip_data:
                for port, info in ip_data['tcp'].items():
                    if info.get('state') == 'open':
                        service = info.get('name', '').lower()
                        if 'http' in service or 'ssl' in service or int(port) in common_web_ports:
                            proto = "https" if ('ssl' in service or 'https' in service or port == '443') else "http"
                            url = f"{proto}://{ip}:{port}"
                            if url not in found_targets:
                                item = QListWidgetItem(f"{url} ({service})")
                                item.setData(Qt.UserRole, url) 
                                item.setCheckState(Qt.Unchecked)
                                self.targets_list.addItem(item)
                                found_targets.add(url)
        if self.targets_list.count() == 0:
            self.targets_list.addItem("Žádné webové služby (spusťte TCP sken).")
            self.targets_list.setEnabled(False)
        else:
            self.log_label.setText(f"Nalezeno {self.targets_list.count()} webových cílů.")
            
        # Na konec metody:
        if self.targets_list.count() > 0:
            self._refresh_target_list_ui()

    def add_manual_target(self):
        url = self.manual_target_input.text().strip()
        if not url: return
        if not url.startswith("http://") and not url.startswith("https://"): url = "http://" + url
        for i in range(self.targets_list.count()):
            if self.targets_list.item(i).data(Qt.UserRole) == url:
                QMessageBox.warning(self, "Info", "Tento cíl už je v seznamu.")
                return
        item = QListWidgetItem(f"{url} (Manuální)")
        item.setData(Qt.UserRole, url)
        item.setCheckState(Qt.Checked) 
        self.targets_list.addItem(item)
        self.targets_list.setEnabled(True)
        self.log_label.setText(f"Přidán cíl: {url}")
        self.manual_target_input.clear()

    def select_all_targets(self):
        for i in range(self.targets_list.count()):
            self.targets_list.item(i).setCheckState(Qt.Checked)

    def _fill_slots(self):
        """Spustí cíle z fronty, dokud nejsou obsazené všechny paralelní sloty."""
        if not self.is_scanning:
            return
        while self.queue and len(self.active_ctxs) < self.parallel_count:
            self._start_target(self.queue.pop(0))

        # Pokud nic neběží ani nečeká, sken skončil
        if not self.active_ctxs and not self.queue:
            self.fuzzing_finished()

    def _start_target(self, current_url):
        """Spustí jeden cíl ve vlastním workeru + kontextu (paralelně bezpečné)."""
        print(f"DEBUG: [FfufDialog] Starting target: {current_url}")

        wls = self.wordlist_combo.lineEdit().text()
        exts = self.ext_combo.get_checked_codes()
        mcs = self.mc_combo.get_checked_codes()
        settings_text = f"WL: {wls} | EXT: {exts if exts else 'žádné'} | MC: {mcs}"

        parent_for_target = self.current_session_item if self.current_session_item else self.results_tree
        header = QTreeWidgetItem(parent_for_target, [f"CÍL: {current_url}", "", "", "", settings_text])
        header.setForeground(0, QColor("#3498DB"))
        header.setForeground(4, QColor("#95A5A6"))
        header.setFont(0, QFont("Arial", 10, QFont.Bold))
        header.setExpanded(True)

        options = {
            "matcher": mcs,
            "extensions": exts,
            "follow_redirects": self.redirect_check.isChecked(),
        }

        worker = FfufWorker(current_url, self.current_wordlist, options)

        ctx = {
            "url": current_url,
            "tree_item": header,
            "settings": settings_text,
            "has_results": False,
            "worker": worker,
            "row": None,
            "cancelled": False,
        }

        # Progress řádek pro tento cíl s tlačítkem zrušení tohoto skenu
        row = ScanProgressRow(current_url, on_cancel=lambda c=ctx: self._cancel_ctx(c))
        ctx["row"] = row
        self.progress_rows_layout.insertWidget(self.progress_rows_layout.count() - 1, row)
        self.active_ctxs.append(ctx)

        # Signály vážeme přes uzávěr s konkrétním kontextem (paralelně bezpečné)
        worker.result_found.connect(lambda data, c=ctx: self.add_result(data, c))
        worker.progress_update.connect(lambda data, c=ctx: self.on_progress_update(data, c))
        worker.finished.connect(lambda c=ctx: self.on_worker_finished(c), Qt.SingleShotConnection)
        worker.start()

        running = len(self.active_ctxs)
        self.log_label.setText(f"Skenuji {running} cíl(ů) paralelně…")

    def add_result(self, data, ctx):
        """
        Zpracuje jeden nález pro daný kontext (cíl).
        """
        if data.get('_meta') != 'empty_scan':
            ctx["has_results"] = True

        if "_settings" not in data:
            data["_settings"] = ctx["settings"]

        # NOVÉ: Uložení timestampu skenu do výsledků pro budoucí seskupení
        if "_scan_timestamp" not in data and hasattr(self, "current_scan_timestamp"):
            data["_scan_timestamp"] = self.current_scan_timestamp

        if data not in self.json_results:
            self.json_results.append(data)
        
        if hasattr(self, "export_json_btn"): self.export_json_btn.setEnabled(True)
        if hasattr(self, "export_txt_btn"): self.export_txt_btn.setEnabled(True)
            
        full_url = data.get("url", "")
        if not full_url and data.get('_meta') == 'empty_scan':
             full_url = ctx["url"]

        # Cílová hlavička pro tento kontext (vytvořená v _start_target)
        parent_item = ctx["tree_item"]

        if data.get('_meta') == 'empty_scan':
            if parent_item:
                info_item = QTreeWidgetItem(parent_item, ["Sken dokončen - žádné nálezy", "", "", "", ""])
                info_item.setForeground(0, QColor("#95A5A6"))
                info_item.setFirstColumnSpanned(True)
            return

        status = data.get("status", 0)
        path_display = ""
        
        if full_url:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(full_url)
                path_display = parsed.path
                if parsed.query: path_display += f"?{parsed.query}"
            except: 
                path_display = full_url
        
        if not path_display: 
            path_display = data.get('input', {}).get('FUZZ', 'Unknown')
            
        status = data.get('status', 0)
        length = data.get('length', 0)
        words = data.get('words', 0)
        
        if parent_item:
            status_group_item = None
            group_label = f"Status: {status}"

            for i in range(parent_item.childCount()):
                child = parent_item.child(i)
                if child.text(0) == group_label:
                    status_group_item = child
                    break

            if not status_group_item:
                status_group_item = QTreeWidgetItem(parent_item, [group_label, "", "", "", ""])
                status_group_item.setExpanded(True)
                group_color = QColor("#95A5A6")
                if 200 <= status < 300: group_color = QColor("#2ECC71")
                elif 300 <= status < 400: group_color = QColor("#F39C12")
                elif status == 401 or status == 403: group_color = QColor("#E74C3C")
                status_group_item.setForeground(0, group_color)
                status_group_item.setFont(0, QFont("Arial", 10, QFont.Bold))
                parent_item.sortChildren(0, Qt.AscendingOrder)

            item = QTreeWidgetItem(status_group_item, [str(path_display), str(status), str(length), str(words), full_url])
            item.setData(0, Qt.UserRole, full_url)
            
            status_group_item.sortChildren(0, Qt.AscendingOrder)
            
            if 200 <= status < 300: item.setForeground(1, QColor("#2ECC71"))
            elif 300 <= status < 400: item.setForeground(1, QColor("#F39C12"))
            elif status == 401 or status == 403: item.setForeground(1, QColor("#E74C3C"))
            elif status >= 400: item.setForeground(1, QColor("#95A5A6"))
            
            self.results_tree.header().resizeSections(QHeaderView.ResizeToContents)
        
        self.export_txt_btn.setEnabled(True)

    def export_raw_json(self):
        if not self.json_results:
            return

        timestamp = time.strftime("%Y%m%d-%H%M%S")
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Uložit FFUF Raw JSON",
            f"ffuf_raw_results_{timestamp}.json",
            "JSON Files (*.json)"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self.json_results, f, indent=4, ensure_ascii=False)
                QMessageBox.information(self, "Export", f"JSON data uložena do:\n{filename}")
            except Exception as e:
                QMessageBox.critical(self, "Chyba", f"Nepodařilo se uložit soubor: {e}")

    @Slot(dict, dict)
    def on_progress_update(self, data, ctx):
        row = ctx.get("row")
        if row is None:
            return
        row.apply_progress(
            data.get('progress', 0),
            data.get('total', 0),
            data.get('rps', 0),
        )

    def _cancel_ctx(self, ctx):
        """Zruší JEN tento jeden běžící sken; uvolněný slot zabere další z fronty.
        Ostatní paralelní skeny běží dál."""
        if ctx.get("cancelled"):
            return
        ctx["cancelled"] = True
        worker = ctx.get("worker")
        if worker:
            worker.stop()   # ukončí ffuf proces → worker emitne finished → on_worker_finished
        self.log_label.setText(f"Ruším sken: {ctx['url']}…")

    def on_worker_finished(self, ctx):
        print(f"DEBUG: [FfufDialog] Worker finished: {ctx['url']}")

        # Pokud nebyly žádné nálezy, vytvoříme placeholder záznam
        if not ctx["has_results"]:
            empty_record = {
                "url": ctx["url"],
                "status": 0,
                "_settings": ctx["settings"],
                "_meta": "empty_scan",
            }
            self.add_result(empty_record, ctx)

        # Celkový postup
        self.completed_targets += 1
        self.total_progress_bar.setValue(self.completed_targets)

        # Označit a odstranit progress řádek tohoto cíle
        row = ctx.get("row")
        if row is not None:
            row.mark_done()
            self.progress_rows_layout.removeWidget(row)
            row.deleteLater()

        # Úklid workeru (finished je SingleShotConnection → už odpojen, neodpojovat znovu)
        worker = ctx.get("worker")
        if worker:
            try:
                worker.result_found.disconnect()
                worker.progress_update.disconnect()
            except Exception:
                pass
            worker.deleteLater()
        ctx["worker"] = None

        if ctx in self.active_ctxs:
            self.active_ctxs.remove(ctx)

        # Naplnit uvolněný slot dalším cílem (nebo dokončit)
        self._fill_slots()

    def stop_fuzzing(self):
        # Zastavit všechny běžící workery
        for ctx in list(self.active_ctxs):
            worker = ctx.get("worker")
            if worker:
                try:
                    worker.finished.disconnect()
                except Exception:
                    pass
                worker.stop()
                worker.deleteLater()
            row = ctx.get("row")
            if row is not None:
                self.progress_rows_layout.removeWidget(row)
                row.deleteLater()

        self.active_ctxs = []
        self.queue = []
        self.log_label.setText("Zastaveno.")
        self.fuzzing_finished()

    def fuzzing_finished(self):
        if not getattr(self, 'is_scanning', False): return
        self.is_scanning = False

        # Odstranit dočasný sjednocený slovník
        merged_path = os.path.join(os.getcwd(), "wordlists", "merged_wordlist.tmp")
        if os.path.exists(merged_path):
            try: os.remove(merged_path)
            except: pass

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.parallel_spin.setEnabled(True)
        self.targets_list.setEnabled(True)
        self.manager_btn.setEnabled(True)
        self.progress_scroll.setVisible(False)
        self.total_progress_bar.setVisible(False)

        # Synchronizovat výsledky do projektu (i když okno běží na pozadí)
        self._sync_results()

        if self.log_label.text() != "Zastaveno.":
            self.log_label.setText("Hotovo.")
            # Modální „Hotovo" jen když je okno viditelné — na pozadí by kradlo focus
            if self.isVisible():
                QMessageBox.information(self, "Hotovo", "Fuzzing dokončen.")

    def _sync_results(self):
        """Zapíše aktuální nálezy do sdíleného scan_results a oznámí appce (autosave)."""
        try:
            self.scan_results["ffuf"] = list(self.json_results)
            self.results_changed.emit()
        except Exception:
            pass

    def send_to_background(self):
        """Skryje okno; běžící skeny pokračují. Znovu se otevře tlačítkem ffuf."""
        self._sync_results()
        self.hide()

    # --- Uložení / obnova posledního nastavení skenu ---
    def _save_ffuf_settings(self):
        s = QSettings(SETTINGS_ORG, SETTINGS_APP)
        # Slovníky ukládáme podle názvu souboru (cesta se může lišit)
        wl_names = []
        model = self.wordlist_combo.model
        for i in range(model.rowCount()):
            item = model.item(i)
            if item.checkState() == Qt.Checked:
                path = item.data(Qt.UserRole)
                if path:
                    wl_names.append(os.path.basename(path))
        s.setValue("ffuf/wordlists", ",".join(wl_names))
        s.setValue("ffuf/match_codes", self.mc_combo.get_checked_codes())
        s.setValue("ffuf/extensions", self.ext_combo.get_checked_codes())
        s.setValue("ffuf/follow_redirects", self.redirect_check.isChecked())
        s.setValue("ffuf/parallel", self.parallel_spin.value())

    def _restore_ffuf_settings(self):
        s = QSettings(SETTINGS_ORG, SETTINGS_APP)

        try:
            self.parallel_spin.setValue(int(s.value("ffuf/parallel", 1)))
        except (TypeError, ValueError):
            pass

        wl_names = [x for x in str(s.value("ffuf/wordlists", "")).split(",") if x]
        if wl_names:
            model = self.wordlist_combo.model
            for i in range(model.rowCount()):
                item = model.item(i)
                path = item.data(Qt.UserRole)
                base = os.path.basename(path) if path else ""
                item.setCheckState(Qt.Checked if base in wl_names else Qt.Unchecked)
            self.wordlist_combo.update_text()

        mcs = s.value("ffuf/match_codes", None)
        if mcs is not None:
            codes = [c for c in str(mcs).split(",") if c]
            for i in range(self.mc_combo.model.rowCount()):
                item = self.mc_combo.model.item(i)
                item.setCheckState(Qt.Checked if item.text() in codes else Qt.Unchecked)
            self.mc_combo.update_text()

        exts = s.value("ffuf/extensions", None)
        if exts is not None:
            ext_list = [e for e in str(exts).split(",") if e]
            for i in range(self.ext_combo.model.rowCount()):
                item = self.ext_combo.model.item(i)
                item.setCheckState(Qt.Checked if item.text() in ext_list else Qt.Unchecked)
            self.ext_combo.update_text()

        r = s.value("ffuf/follow_redirects", True)
        self.redirect_check.setChecked(r in (True, "true", "True", 1, "1"))

        if hasattr(self, "update_stats"):
            self.update_stats()

    def closeEvent(self, event):
        # Při zavření okna zapamatovat aktuální nastavení
        try:
            self._save_ffuf_settings()
        except Exception:
            pass

        app = QApplication.instance()
        shutting_down = bool(app and app.closingDown())

        # Běží sken a nezavírá se celá aplikace → nabídnout běh na pozadí
        if self.is_scanning and not shutting_down:
            box = QMessageBox(self)
            box.setWindowTitle("Fuzzing běží")
            box.setText("Skenování stále běží. Co chceš udělat?")
            bg = box.addButton("Nechat běžet na pozadí", QMessageBox.AcceptRole)
            stop = box.addButton("Zastavit a zavřít", QMessageBox.DestructiveRole)
            box.addButton("Zrušit", QMessageBox.RejectRole)
            box.exec()
            clicked = box.clickedButton()
            if clicked is bg:
                self._sync_results()
                event.ignore()
                self.hide()       # okno zmizí, skeny běží dál
                return
            if clicked is stop:
                self.stop_fuzzing()
                # propadne dolů → super().closeEvent (vyemituje finished)
            else:
                event.ignore()    # Zrušit — nic
                return

        # Zavírá se aplikace nebo sken neběží → uklidit a synchronizovat
        if self.is_scanning:
            self.stop_fuzzing()
        self._sync_results()
        super().closeEvent(event)
            
    def export_results_txt(self):
        """
        Exportuje výsledky do TXT.
        Podporuje filtrování a case-insensitive deduplikaci.
        """
        root = self.results_tree.invisibleRootItem()
        if root.childCount() == 0:
            QMessageBox.information(self, "Export", "Nejsou k dispozici žádné výsledky k exportu.")
            return

        sel_dialog = ExportFfufSelectionDialog(root, self)
        if sel_dialog.exec() != QDialog.Accepted:
            return
            
        selection_map = sel_dialog.get_selection_map()
        # Získání stavu checkboxu pro deduplikaci
        deduplicate = sel_dialog.dedup_check.isChecked()
        
        if not selection_map:
            QMessageBox.warning(self, "Export", "Nebyla vybrána žádná data k exportu.")
            return

        timestamp = time.strftime("%Y%m%d-%H%M%S")
        filename, _ = QFileDialog.getSaveFileName(
            self, "Uložit FFUF Report", f"ffuf_report_filtered_{timestamp}.txt", "Text Files (*.txt)"
        )
        
        if not filename: return

        status_map = {
            "200": "OK - Úspěch", "301": "Moved Permanently", "302": "Found",
            "401": "Unauthorized", "403": "Forbidden", "404": "Not Found", "500": "Server Error"
        }

        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("=" * 80 + "\n")
                f.write(f"FFUF SCAN REPORT - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                if deduplicate:
                    f.write("Mód: Deduplikováno (Case-Insensitive)\n")
                f.write("=" * 80 + "\n\n")

                for i in range(root.childCount()):
                    session_item = root.child(i)
                    session_title = session_item.text(0)
                    
                    if session_title not in selection_map: continue
                        
                    session_config = session_item.text(4)
                    f.write("#" * 80 + "\n")
                    f.write(f"{session_title}\n")
                    f.write(f"KONFIGURACE: {session_config}\n")
                    f.write("#" * 80 + "\n\n")
                    
                    for j in range(session_item.childCount()):
                        target_item = session_item.child(j)
                        target_name = target_item.text(0)
                        
                        if target_name not in selection_map[session_title]: continue
                            
                        allowed_statuses = selection_map[session_title][target_name]
                        
                        f.write(f"  [{target_name}]\n")
                        f.write(f"  {'-' * 60}\n")
                        
                        has_data_printed = False
                        target_has_children = target_item.childCount() > 0
                        
                        # --- DEDUPLIKACE: Množina viděných cest pro tento CÍL ---
                        seen_paths = set()
                        
                        for k in range(target_item.childCount()):
                            status_item = target_item.child(k)
                            status_text = status_item.text(0)
                            
                            if status_text not in allowed_statuses: continue
                            
                            # Dočasný buffer pro výsledky v této status skupině
                            # Musíme je bufferovat, abychom zjistili, zda po deduplikaci něco zbylo
                            lines_to_write = []
                            
                            # Zpracování placeholderu "Žádné nálezy"
                            text_lower = status_text.lower()
                            if "žádné nálezy" in text_lower or "sken dokončen" in text_lower:
                                has_data_printed = True
                                f.write(f"    -> {status_text}\n")
                                continue

                            for l in range(status_item.childCount()):
                                result_item = status_item.child(l)
                                path = result_item.text(0) # např. /admin
                                full_url = result_item.text(4)
                                
                                # Logika deduplikace
                                if deduplicate:
                                    path_lower = path.lower()
                                    if path_lower in seen_paths:
                                        continue # Přeskočit duplikát
                                    seen_paths.add(path_lower)
                                
                                lines_to_write.append(f"      - {path:<30} -> {full_url}\n")
                            
                            # Pokud po deduplikaci zbyly nějaké řádky, zapíšeme hlavičku statusu a řádky
                            if lines_to_write:
                                has_data_printed = True
                                status_code = status_text.replace("Status: ", "").strip()
                                note = status_map.get(status_code, "HTTP Stav")
                                f.write(f"\n    STAV {status_code} ({note}):\n")
                                for line in lines_to_write:
                                    f.write(line)
                        
                        if not has_data_printed:
                            if target_has_children:
                                if deduplicate:
                                    f.write("    (Výsledky skryty filtrem nebo deduplikací)\n")
                                else:
                                    f.write("    (Výsledky skryty filtrem)\n")
                            else:
                                f.write("    (Žádná data k dispozici)\n")
                            
                        f.write("\n")
                    f.write("\n")

            QMessageBox.information(self, "Export", f"Report byl úspěšně uložen.")
        except Exception as e:
            QMessageBox.critical(self, "Chyba", f"Chyba při zápisu reportu: {e}")

