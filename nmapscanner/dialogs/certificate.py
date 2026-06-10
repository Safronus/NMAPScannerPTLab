from datetime import datetime



from PySide6.QtWidgets import (
    QApplication, QTextEdit, QLineEdit, QPushButton, QVBoxLayout, QTreeWidget,
    QTreeWidgetItem, QLabel, QGroupBox, QHeaderView, QFileDialog, QHBoxLayout,
    QCheckBox, QDialog, QMessageBox, QDialogButtonBox
)
from PySide6.QtCore import Slot, Qt, QThreadPool
from PySide6.QtGui import QColor, QFont, QIcon
from ..workers.certificate import CertificateWorker
from ..signals import WorkerSignals


class CertificateDetailDialog(QDialog):
    """
    Dialog pro zobrazení detailních informací o certifikátu a řetězci důvěry.
    """
    def __init__(self, data, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Detail certifikátu: {data.get('cn', 'N/A')}")
        self.resize(800, 700)
        
        layout = QVBoxLayout(self)
        
        # Textová oblast s reportem
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setFont(QFont("Courier New", 12)) 
        self.text_edit.setStyleSheet("background-color: #2b2b2b; color: #f0f0f0;")
        
        # Sestavení obsahu
        report = []
        report.append("="*60)
        report.append(f" PŘEHLED: {data.get('ip', '')}:{data.get('port', '')}")
        report.append("="*60)
        report.append(f"Stav:       {data.get('status', 'N/A')}")
        report.append(f"Doména (CN):{data.get('cn', 'N/A')}")
        report.append(f"Vydavatel:  {data.get('issuer', 'N/A')}")
        report.append(f"Expirace:   {data.get('expiry', 'N/A')} (Zbývá dní: {data.get('days', 'N/A')})")
        report.append("-" * 60)
        report.append(f"Protokol:   {data.get('protocol', 'N/A')}")
        report.append(f"Šifra:      {data.get('cipher', 'N/A')}")
        report.append(f"Algoritmus: {data.get('sig_algo', 'N/A')}")
        report.append(f"Veř. klíč:  {data.get('pub_key', 'N/A')}")
        
        report.append("\n" + "="*60)
        report.append(" RAW DATA (OpenSSL x509)")
        report.append("="*60)
        report.append(data.get('full_text', 'Detaily nejsou k dispozici.'))
        
        report.append("\n" + "="*60)
        report.append(" TRUST CHAIN (Řetězec důvěry)")
        report.append("="*60)
        report.append(data.get('chain', 'Řetězec nebyl stažen.'))
        
        self.text_edit.setText("\n".join(report))
        layout.addWidget(self.text_edit)
        
        # Tlačítka
        btn_layout = QHBoxLayout()
        btn_copy = QPushButton("Kopírovat do schránky")
        btn_copy.clicked.connect(self.copy_to_clipboard)
        btn_layout.addWidget(btn_copy)
        
        btn_close = QPushButton("Zavřít")
        btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(btn_close)
        
        layout.addLayout(btn_layout)
        
    def copy_to_clipboard(self):
        QApplication.clipboard().setText(self.text_edit.toPlainText())
        
class CertificateExportDialog(QDialog):
    """
    Dialog pro nastavení exportu certifikátů do TXT.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Exportovat výsledky (TXT)")
        self.resize(400, 350)
        self.selected_options = {}
        
        layout = QVBoxLayout(self)
        
        # 1. Popis
        layout.addWidget(QLabel("Popis reportu (volitelné):"))
        self.desc_input = QLineEdit()
        self.desc_input.setPlaceholderText("Např. Audit externí sítě 2023...")
        layout.addWidget(self.desc_input)
        
        layout.addSpacing(10)
        
        # 2. Filtry stavů
        filter_group = QGroupBox("Filtrovat cíle podle stavu")
        filter_layout = QVBoxLayout()
        
        self.cb_valid = QCheckBox("Validní (V pořádku)")
        self.cb_valid.setChecked(False) # Defaultně vypnuto
        
        self.cb_expired = QCheckBox("Expirované / Brzy expirují")
        self.cb_expired.setChecked(True) # Defaultně zapnuto
        
        self.cb_errors = QCheckBox("Chyby (Timeout, SSL Error, Odmítnuto)")
        self.cb_errors.setChecked(True) # Defaultně zapnuto (považujeme za nevalidní)
        
        filter_layout.addWidget(self.cb_valid)
        filter_layout.addWidget(self.cb_expired)
        filter_layout.addWidget(self.cb_errors)
        filter_group.setLayout(filter_layout)
        layout.addWidget(filter_group)
        
        # 3. Obsah
        content_group = QGroupBox("Obsah detailů")
        content_layout = QVBoxLayout()
        
        self.cb_full_text = QCheckBox("Přidat celý obsah certifikátu (Raw OpenSSL text)")
        self.cb_full_text.setChecked(False)
        
        content_layout.addWidget(self.cb_full_text)
        content_group.setLayout(content_layout)
        layout.addWidget(content_group)
        
        layout.addStretch()
        
        # Tlačítka
        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btn_box.accepted.connect(self.accept)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)
        
    def get_options(self):
        return {
            'description': self.desc_input.text(),
            'include_valid': self.cb_valid.isChecked(),
            'include_expired': self.cb_expired.isChecked(),
            'include_errors': self.cb_errors.isChecked(),
            'include_full_text': self.cb_full_text.isChecked()
        }

class CertificateDialog(QDialog):
    """
    Dialog pro kontrolu SSL certifikátů.
    Vylepšeno: Přidány sloupce Protokol a Veřejný klíč.
    """
    def __init__(self, scan_results, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Inspektor SSL/TLS Certifikátů")
        
        # Široké okno pro 10 sloupců
        self.resize(1600, 800)
        
        self.scan_results = scan_results
        # Globální pool (ne vlastní): vlastní QThreadPool by při zavření dialogu
        # v destruktoru volal waitForDone() a zamrazil GUI, dokud nedoběhne worker.
        self.thread_pool = QThreadPool.globalInstance()
        self.processing_count = 0
        self.item_map = {} 
        
        self.init_ui()
        self.load_targets()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Info panel
        info_layout = QHBoxLayout()
        info_layout.addWidget(QLabel("<b>Nalezené HTTPS/SSL služby:</b>"))
        info_layout.addStretch()
        self.status_label = QLabel("Připraveno")
        info_layout.addWidget(self.status_label)
        layout.addLayout(info_layout)
        
        # --- SURGICAL ADDITION: Filtrační lišta ---
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Zobrazit:"))
        self.filter_valid = QCheckBox("Validní")
        self.filter_valid.setChecked(True)
        self.filter_warning = QCheckBox("Varování/Expirované")
        self.filter_warning.setChecked(True)
        self.filter_error = QCheckBox("Chyby/Ostatní")
        self.filter_error.setChecked(True)
        
        # Propojení signálů pro okamžitou reakci
        self.filter_valid.stateChanged.connect(self.apply_filters)
        self.filter_warning.stateChanged.connect(self.apply_filters)
        self.filter_error.stateChanged.connect(self.apply_filters)
        
        filter_layout.addWidget(self.filter_valid)
        filter_layout.addWidget(self.filter_warning)
        filter_layout.addWidget(self.filter_error)
        filter_layout.addStretch()
        layout.addLayout(filter_layout)
        # ------------------------------------------
        
        # Ovládání stromu
        tree_ctrl_layout = QHBoxLayout()
        btn_expand = QPushButton("Rozbalit vše")
        btn_expand.clicked.connect(lambda: self.tree.expandAll())
        btn_expand.setFixedWidth(100)
        btn_collapse = QPushButton("Sbalit vše")
        btn_collapse.clicked.connect(lambda: self.tree.collapseAll())
        btn_collapse.setFixedWidth(100)
        tree_ctrl_layout.addWidget(btn_expand)
        tree_ctrl_layout.addWidget(btn_collapse)
        tree_ctrl_layout.addStretch()
        layout.addLayout(tree_ctrl_layout)
        
        # Tabulka (Strom)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels([
            "Cíl / Port", "Stav", "Doména (CN)", "Vydavatel", "Protokol", 
            "Šifra", "Algoritmus", "Veř. klíč", "Expirace", "Dny"
        ])
        
        header = self.tree.header()
        for i in range(10):
            header.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        
        self.tree.itemDoubleClicked.connect(self.show_detail)
        layout.addWidget(self.tree)
        
        # Tlačítka dole (zůstávají beze změny)
        btn_layout = QHBoxLayout()
        self.check_btn = QPushButton("🔍 Zkontrolovat certifikáty")
        self.check_btn.clicked.connect(self.start_checks)
        btn_layout.addWidget(self.check_btn)
        
        self.detail_btn = QPushButton("📄 Zobrazit detail")
        self.detail_btn.clicked.connect(lambda: self.show_detail(self.tree.currentItem(), 0))
        btn_layout.addWidget(self.detail_btn)
        
        self.export_csv_btn = QPushButton("💾 CSV")
        self.export_csv_btn.clicked.connect(self.export_results_csv)
        btn_layout.addWidget(self.export_csv_btn)

        self.export_txt_btn = QPushButton("📝 TXT Report")
        self.export_txt_btn.clicked.connect(self.export_results_txt)
        btn_layout.addWidget(self.export_txt_btn)
        
        close_btn = QPushButton("Zavřít")
        close_btn.clicked.connect(self.reject)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)
        
    def apply_filters(self):
        """Projde strom a skryje řádky, které neodpovídají filtrům."""
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            ip_item = root.child(i)
            ip_visible = False
            
            for j in range(ip_item.childCount()):
                port_item = ip_item.child(j)
                status = port_item.text(1)
                
                show = True
                if status == "Validní":
                    show = self.filter_valid.isChecked()
                elif status in ["Brzy expiruje", "Expirovaný"]:
                    show = self.filter_warning.isChecked()
                else:
                    # Chyby, Timeout, Odmítnuto, Čeká...
                    show = self.filter_error.isChecked()
                
                port_item.setHidden(not show)
                if show:
                    ip_visible = True
            
            # Pokud nemá IP žádný viditelný port, skryjeme i celou IP
            ip_item.setHidden(not ip_visible)
        
    def load_targets(self):
        """Načte cíle a seskupí je. Pokud existují uložená data v projektu, aplikuje je."""
        self.tree.clear()
        self.item_map = {} 
        
        targets_dict = {}
        
        # Načtení historie certifikátů z projektu (pokud existuje)
        saved_certs = self.scan_results.get('certificates', {})
        
        # A) Z NMAP
        tcp_data = self.scan_results.get('tcp', {})
        for ip, ports in tcp_data.items():
            if ip not in targets_dict: targets_dict[ip] = set()
            if 'tcp' in ports:
                for port, info in ports['tcp'].items():
                    state = info.get('state')
                    service = info.get('name', '').lower()
                    is_ssl = (str(port) == '443' or str(port) == '8443' or 
                              'ssl' in service or 'https' in service or 
                              info.get('tunnel') == 'ssl')
                    if state == 'open' and is_ssl:
                        targets_dict[ip].add((str(port), "Čeká (Nmap)"))

        # B) Defaultní probe
        all_ips = set()
        for phase in ['online', 'tcp', 'udp']:
            phase_data = self.scan_results.get(phase, {})
            if phase_data: all_ips.update(phase_data.keys())
            
        for ip in all_ips:
            if ip not in targets_dict: targets_dict[ip] = set()
            has_443 = any(p[0] == '443' for p in targets_dict[ip])
            if not has_443:
                targets_dict[ip].add(('443', "Čeká (Probe)"))

        # Řazení IP
        def ip_sort_key(ip):
            try: return tuple(int(part) for part in ip.split('.'))
            except: return (0, 0, 0, 0)
        sorted_ips = sorted(targets_dict.keys(), key=ip_sort_key)
        
        for ip in sorted_ips:
            ports = targets_dict[ip]
            if not ports: continue
            
            ip_item = QTreeWidgetItem(self.tree)
            ip_item.setText(0, ip)
            ip_item.setExpanded(True)
            ip_item.setFont(0, QFont("Arial", 11, QFont.Bold))
            
            header_color = QColor("#3498DB")
            for col in range(self.tree.columnCount()):
                ip_item.setForeground(col, header_color)

            sorted_ports = sorted(list(ports), key=lambda x: int(x[0]))
            
            for port, note in sorted_ports:
                port_item = QTreeWidgetItem(ip_item)
                port_item.setText(0, f"Port {port}")
                
                # Inicializace základních dat (aby columns nebyly prázdné při chybě persistence)
                port_item.setText(1, "Čeká...")
                port_item.setForeground(0, QColor("#E67E22"))
                port_item.setFont(0, QFont("Arial", 10, QFont.Bold))
                
                if "Probe" in note:
                    port_item.setText(1, "Čeká (Probe)")
                    port_item.setForeground(1, QColor("#95A5A6"))
                
                port_item.setData(0, Qt.UserRole, {'ip': ip, 'port': port})
                
                # REGISTRACE DO MAPY (Musí být před update_result!)
                self.item_map[(ip, str(port))] = port_item
                
                # PERSISTENCE: Pokud máme data v projektu, aplikujeme je
                cert_key = f"{ip}:{port}"
                if cert_key in saved_certs:
                    self.update_result(ip, port, saved_certs[cert_key])

        count = len(self.item_map)
        if count == 0:
            QMessageBox.information(self, "Info", "Nebyly nalezeny žádné cíle.")
        else:
            self.status_label.setText(f"Načteno {count} služeb na {len(sorted_ips)} IP adresách.")
            
    @Slot(str, str, dict)
    def update_result(self, ip, port, data):
        """Aktualizace řádku, uložení do projektu a aplikace filtrů."""
        item = self.item_map.get((ip, str(port)))
        if not item: return
        
        # Persistence do hlavního objektu aplikace
        if 'certificates' not in self.scan_results:
            self.scan_results['certificates'] = {}
        self.scan_results['certificates'][f"{ip}:{port}"] = data
        
        stored_data = item.data(0, Qt.UserRole)
        stored_data.update(data)
        item.setData(0, Qt.UserRole, stored_data)
        
        status = data.get('status', 'Neznámý')
        item.setText(1, status)
        
        # Původní barvení stavů (beze změny vzhledu)
        if status == "Timeout":
            item.setForeground(1, QColor("#7F8C8D")) 
            item.setText(2, "-") 
            item.setText(3, "Server neodpovídá") 
        elif status == "Odmítnuto":
            item.setForeground(1, QColor("#E67E22")) 
            item.setText(2, "-")
            item.setText(3, "Connection Refused")
        elif status in ["SSL Chyba", "SSL Alert"]:
            item.setForeground(1, QColor("#E74C3C")) 
            item.setText(2, "Chyba protokolu")
            item.setText(3, data.get('error', ''))
        elif status in ["Nedostupný", "DNS Chyba"]:
            item.setForeground(1, QColor("#9B59B6"))
            item.setText(3, data.get('error', ''))
        elif status == "Validní":
            item.setForeground(1, QColor("#2ECC71")) 
            self._fill_cert_details(item, data)
        elif status == "Brzy expiruje":
            item.setForeground(1, QColor("#F39C12")) 
            self._fill_cert_details(item, data)
        elif status == "Expirovaný":
            item.setForeground(1, QColor("#C0392B")) 
            self._fill_cert_details(item, data)
        else:
            item.setForeground(1, QColor("#E74C3C"))
            item.setText(2, str(data.get('error', 'Chyba')))
            
        # Okamžitá aplikace filtrů po aktualizaci dat
        self.apply_filters()

    def start_checks(self):
        if not self.item_map: return
            
        self.check_btn.setEnabled(False)
        self.processing_count = len(self.item_map)
        self.status_label.setText(f"Zpracovávám {self.processing_count} služeb...")
        
        for (ip, port), item in self.item_map.items():
            item.setText(1, "Ověřuji...")
            item.setForeground(1, QColor("#ECF0F1"))
            item.setIcon(0, QIcon())
            
            signals = WorkerSignals()
            signals.result.connect(self.update_result)
            signals.finished.connect(self.on_worker_finished)
            
            worker = CertificateWorker(ip, port, signals)
            self.thread_pool.start(worker)

    def _fill_cert_details(self, item, data):
        """Vyplnění sloupců (nyní 10)"""
        item.setText(2, data.get('cn', ''))
        item.setText(3, data.get('issuer', ''))
        item.setText(4, data.get('protocol', ''))  # NOVÉ
        item.setText(5, data.get('cipher', ''))
        item.setText(6, data.get('sig_algo', ''))
        item.setText(7, data.get('pub_key', ''))   # NOVÉ
        item.setText(8, data.get('expiry', ''))
        item.setText(9, str(data.get('days', '')))

    @Slot()
    def on_worker_finished(self):
        self.processing_count -= 1
        if self.processing_count <= 0:
            self.status_label.setText("Hotovo.")
            self.check_btn.setEnabled(True)

    def show_detail(self, item, column):
        if not item: return
        if item.childCount() > 0: return # IP řádek
        
        data = item.data(0, Qt.UserRole)
        if not data: return 
        
        if 'full_text' in data:
            dlg = CertificateDetailDialog(data, self)
            dlg.exec()
        elif 'error' in data:
            QMessageBox.warning(self, "Chyba", f"{data['error']}")

    def export_results_csv(self):
        fname, _ = QFileDialog.getSaveFileName(self, "Export CSV", "certifikaty.csv", "CSV Files (*.csv)")
        if fname:
            try:
                with open(fname, 'w', encoding='utf-8') as f:
                    # Aktualizovaná hlavička CSV
                    f.write("IP;Port;Stav;CN;Issuer;Protokol;Cipher;Algoritmus;PubKey;Expiry;DaysLeft\n")
                    
                    root = self.tree.invisibleRootItem()
                    for i in range(root.childCount()):
                        ip_item = root.child(i)
                        ip_addr = ip_item.text(0)
                        
                        for j in range(ip_item.childCount()):
                            port_item = ip_item.child(j)
                            port_str = port_item.text(0).replace("Port ", "")
                            
                            row = [
                                ip_addr, 
                                port_str,
                                port_item.text(1), # Stav
                                port_item.text(2), # CN
                                port_item.text(3), # Issuer
                                port_item.text(4), # Protokol
                                port_item.text(5), # Cipher
                                port_item.text(6), # Algo
                                port_item.text(7), # PubKey
                                port_item.text(8), # Expiry
                                port_item.text(9)  # Days
                            ]
                            safe_row = [str(x).replace(';', ',').replace('\n', ' ') for x in row]
                            f.write(";".join(safe_row) + "\n")
                            
                QMessageBox.information(self, "Export", "Data uložena.")
            except Exception as e:
                QMessageBox.critical(self, "Chyba", str(e))

    def export_results_txt(self):
        """
        Generuje detailní TXT report z výsledků kontroly certifikátů.
        Zahrnuje hlavičku, statistiku, filtrování podle stavu a technické detaily.
        """
        # 1. Zobrazit dialog pro nastavení filtrů a popisu
        dlg = CertificateExportDialog(self)
        if dlg.exec() != QDialog.Accepted:
            return
            
        opts = dlg.get_options()
        
        # 2. Výběr cílového souboru
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        default_name = f"cert_audit_{timestamp}.txt"
        fname, _ = QFileDialog.getSaveFileName(self, "Exportovat TXT Report", default_name, "Text Files (*.txt)")
        
        if not fname:
            return

        try:
            with open(fname, 'w', encoding='utf-8') as f:
                # --- HLAVIČKA REPORTU ---
                f.write("=" * 80 + "\n")
                f.write(f"AUDITNÍ ZPRÁVA: SSL/TLS INSPEKCE\n")
                f.write(f"Vytvořeno: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                if opts['description']:
                    f.write(f"Popis projektu: {opts['description']}\n")
                f.write("=" * 80 + "\n\n")

                # --- PŘÍPRAVA DAT A STATISTIKA ---
                total_scanned = 0
                exported_count = 0
                
                root = self.tree.invisibleRootItem()
                items_to_process = []

                # Projdeme strom (IP -> Porty)
                for i in range(root.childCount()):
                    ip_item = root.child(i)
                    ip_addr = ip_item.text(0)
                    
                    for j in range(ip_item.childCount()):
                        port_item = ip_item.child(j)
                        total_scanned += 1
                        
                        # Získání dat uložených v UserRole
                        data = port_item.data(0, Qt.UserRole)
                        status = data.get('status', 'Neznámý')
                        
                        # Logika filtrování na základě voleb v dialogu
                        should_include = False
                        
                        if status == "Validní" and opts['include_valid']:
                            should_include = True
                        elif status in ["Expirovaný", "Brzy expiruje"] and opts['include_expired']:
                            should_include = True
                        elif status not in ["Validní", "Expirovaný", "Brzy expiruje"] and opts['include_errors']:
                            # Zahrnuje Timeout, Odmítnuto, SSL Chyby atd.
                            should_include = True
                            
                        if should_include:
                            items_to_process.append((ip_addr, data))
                            exported_count += 1

                # Zápis souhrnu
                f.write(f"SOUHRN TESTU:\n")
                f.write(f"- Celkem prověřeno služeb: {total_scanned}\n")
                f.write(f"- Zahrnuto v tomto exportu: {exported_count}\n")
                f.write("-" * 80 + "\n\n")

                if not items_to_process:
                    f.write("Žádné výsledky neodpovídají nastaveným filtrům exportu.\n")

                # --- DETAILNÍ VÝPIS JEDNOTLIVÝCH CÍLŮ ---
                for ip, data in items_to_process:
                    port = data.get('port', 'N/A')
                    status = data.get('status', 'Neznámý').upper()
                    
                    f.write(f"CÍL: {ip}:{port}\n")
                    f.write(f"STAV: {status}\n")
                    f.write("-" * 40 + "\n")
                    
                    # Pokud máme technická data o certifikátu
                    if status in ["VALIDNÍ", "EXPIROVANÝ", "BRZY EXPIRUJE"]:
                        f.write(f"Doména (CN):     {data.get('cn', 'N/A')}\n")
                        f.write(f"Vydavatel:       {data.get('issuer', 'N/A')}\n")
                        f.write(f"Protokol:        {data.get('protocol', 'N/A')}\n")
                        f.write(f"Šifra (Cipher):  {data.get('cipher', 'N/A')}\n")
                        f.write(f"Algoritmus:      {data.get('sig_algo', 'N/A')}\n")
                        f.write(f"Veřejný klíč:    {data.get('pub_key', 'N/A')}\n")
                        f.write(f"Expirace:        {data.get('expiry', 'N/A')} (Zbývá dní: {data.get('days', 'N/A')})\n")
                    else:
                        # Pokud jde o chybu (Timeout, Refused...)
                        error_detail = data.get('error', 'Žádné doplňující informace')
                        f.write(f"Chyba:           {error_detail}\n")
                        if 'full_error' in data:
                            f.write(f"Technický popis: {data['full_error']}\n")

                    # Volitelný export celého OpenSSL výstupu (Raw data)
                    if opts['include_full_text'] and 'full_text' in data:
                        f.write("\n--- KOMPLETNÍ VÝSTUP (OPENSSL) ---\n")
                        f.write(data['full_text'].strip())
                        f.write("\n----------------------------------\n")
                    
                    f.write("\n" + "=" * 60 + "\n\n")

                f.write(f"\n*** Konec reportu ***\n")

            QMessageBox.information(self, "Export", f"Report byl úspěšně vygenerován do souboru:\n{fname}")
            
        except Exception as e:
            QMessageBox.critical(self, "Chyba exportu", f"Během zápisu reportu došlo k chybě:\n{str(e)}")
    
