from datetime import datetime



from PySide6.QtWidgets import (
    QLineEdit, QPushButton, QVBoxLayout, QTreeWidget, QTreeWidgetItem, QLabel,
    QHeaderView, QMenu, QFileDialog, QHBoxLayout, QCheckBox, QDialog,
    QMessageBox, QDialogButtonBox, QListWidget, QListWidgetItem
)
from PySide6.QtCore import Slot, Qt, QThreadPool
from PySide6.QtGui import QColor, QFont
from ..workers.security_headers import SecurityHeadersWorker
from ..signals import WorkerSignals
from .. import VERSION
from PySide6.QtWebEngineCore import QWebEnginePage


class SecurityHeadersDialog(QDialog):
    """Dialog pro kontrolu Security Headers - Vizuální shoda s SSL Inspektorem."""
    def __init__(self, scan_results, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Inspektor Security Headers")
        self.resize(1400, 750)
        self.scan_results = scan_results
        self.thread_pool = QThreadPool()
        self.item_map = {}
        
        self.init_ui()
        self.load_targets()

    def init_ui(self):
        """
        Inicializace UI s automaticky aktivovaným filtrem chyb.
        Verze 2.1.4c: Checkbox "Skrýt chyby" je nyní ve výchozím stavu zaškrtnut.
        """
        layout = QVBoxLayout(self)
        
        # Horní panel
        info_layout = QHBoxLayout()
        info_layout.addWidget(QLabel("<b>Webové hlavičky cílů:</b>"))
        info_layout.addStretch()
        
        # Filtry
        self.filter_missing = QCheckBox("Skrýt plně zabezpečené (A)")
        self.filter_missing.stateChanged.connect(self.apply_filters)
        
        # SURGICAL FIX: Checkbox pro chyby je nyní automaticky zaškrtnut
        self.filter_error = QCheckBox("Skrýt chyby")
        self.filter_error.setChecked(True) 
        self.filter_error.stateChanged.connect(self.apply_filters)
        
        info_layout.addWidget(self.filter_missing)
        info_layout.addWidget(self.filter_error)
        
        self.status_label = QLabel("Připraveno")
        info_layout.addWidget(self.status_label)
        layout.addLayout(info_layout)

        # Správa cílů (Add)
        add_layout = QHBoxLayout()
        add_layout.addWidget(QLabel("Přidat cíl:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("IP adresa")
        self.port_input = QLineEdit()
        self.port_input.setFixedWidth(60)
        self.port_input.setText("443")
        self.add_btn = QPushButton("➕ Přidat")
        self.add_btn.clicked.connect(self.add_target)
        add_layout.addWidget(self.target_input)
        add_layout.addWidget(self.port_input)
        add_layout.addWidget(self.add_btn)
        layout.addLayout(add_layout)

        # Tabulka - 8 sloupců
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels([
            "Cíl / Port / Server / Čas", "Známka", "HSTS", "CSP", "X-Frame", "X-Content", "Referrer", "Permissions"
        ])
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_context_menu)
        
        header = self.tree.header()
        header.setStretchLastSection(False)
        
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents) 
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.tree.headerItem().setTextAlignment(1, Qt.AlignCenter)
        
        font_metrics = self.tree.fontMetrics()
        target_width = font_metrics.horizontalAdvance("Permissions") + 5
        
        for i in range(2, 8):
            header.setSectionResizeMode(i, QHeaderView.Fixed)
            header.resizeSection(i, target_width)
            self.tree.headerItem().setTextAlignment(i, Qt.AlignCenter)
            
        layout.addWidget(self.tree)

        # Spodní tlačítka
        btn_layout = QHBoxLayout()
        self.check_all_btn = QPushButton("🛡️ Prověřit vše")
        self.check_all_btn.clicked.connect(lambda: self.start_checks(only_new=False))
        btn_layout.addWidget(self.check_all_btn)

        self.check_new_btn = QPushButton("⏳ Prověřit neprověřené")
        self.check_new_btn.clicked.connect(lambda: self.start_checks(only_new=True))
        btn_layout.addWidget(self.check_new_btn)
        
        self.export_pdf_btn = QPushButton("📄 Exportovat PDF")
        self.export_pdf_btn.clicked.connect(self.export_to_pdf)
        btn_layout.addWidget(self.export_pdf_btn)
        
        close_btn = QPushButton("Zavřít")
        close_btn.clicked.connect(self.reject)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)
        
        self.resize(1050, 600)

    def load_targets(self):
        """Načte cíle z Nmapu a vytvoří automatické HTTPS sondy pro všechny online IP."""
        self.tree.clear()
        self.item_map = {}
        saved_data = self.scan_results.get('security_headers', {})
        
        targets_dict = {}
        web_ports = ['80', '443', '8080', '8443']
        
        # A) Z NMAP (Identifikované otevřené porty)
        tcp_data = self.scan_results.get('tcp', {})
        for ip, ports in tcp_data.items():
            if ip not in targets_dict: targets_dict[ip] = set()
            if 'tcp' in ports:
                for port, info in ports['tcp'].items():
                    state = info.get('state')
                    if state == 'open' and str(port) in web_ports:
                        targets_dict[ip].add((str(port), "Čeká (Nmap)"))

        # B) AUTOMATICKÁ SONDA (Pro každou online IP zkusíme HTTPS)
        all_ips = set()
        for phase in ['online', 'tcp', 'udp']:
            phase_data = self.scan_results.get(phase, {})
            if phase_data: all_ips.update(phase_data.keys())
            
        for ip in all_ips:
            if ip not in targets_dict: targets_dict[ip] = set()
            # Pokud IP nemá z Nmapu port 80 nebo 443, přidáme sondu na 443
            has_web = any(p[0] in ['80', '443'] for p in targets_dict[ip])
            if not has_web:
                targets_dict[ip].add(('443', "Čeká (Sonda)"))

        # Řazení IP adres
        def ip_sort_key(ip):
            try: return tuple(int(part) for part in ip.split('.'))
            except: return (0, 0, 0, 0)
        sorted_ips = sorted(targets_dict.keys(), key=ip_sort_key)

        # Vykreslení (Vizuální shoda s certifikáty)
        for ip in sorted_ips:
            ports = targets_dict[ip]
            if not ports: continue
            
            # DESIGN: Modrá hlavička IP
            ip_item = QTreeWidgetItem(self.tree, [ip])
            ip_item.setFont(0, QFont("Arial", 11, QFont.Bold))
            ip_item.setForeground(0, QColor("#3498DB"))
            ip_item.setExpanded(True)
            
            # Seřadit porty numericky
            sorted_ports = sorted(list(ports), key=lambda x: int(x[0]))
            
            for port, note in sorted_ports:
                # DESIGN: Oranžový port
                port_item = QTreeWidgetItem(ip_item, [f"Port {port}", note])
                port_item.setFont(0, QFont("Arial", 10, QFont.Bold))
                port_item.setForeground(0, QColor("#E67E22"))
                
                # Pokud je to sonda, označíme status šedě
                if "Sonda" in note:
                    port_item.setForeground(1, QColor("#95A5A6"))
                
                self.item_map[(ip, port)] = port_item
                
                # PERSISTENCE: Načtení dříve uložených výsledků z projektu
                if f"{ip}:{port}" in saved_data:
                    self.update_result(ip, port, saved_data[f"{ip}:{port}"])

        count = len(self.item_map)
        if count == 0:
            self.status_label.setText("Nebyly nalezeny žádné webové služby.")
        else:
            self.status_label.setText(f"Načteno {count} služeb na {len(sorted_ips)} IP adresách.")

    def apply_filters(self):
        """
        Projde strom a skryje řádky podle nastavení filtrů (Zabezpečené / Chyby).
        """
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            ip_item = root.child(i)
            ip_visible = False
            
            for j in range(ip_item.childCount()):
                port_item = ip_item.child(j)
                status_val = port_item.text(1) # Sloupec "Známka"
                
                hide_secure = (status_val == "A" and self.filter_missing.isChecked())
                # Skrýváme pokud text obsahuje "Chyba" (Chyba spojení) a je zaškrtnut filtr
                hide_error = ("Chyba" in status_val and self.filter_error.isChecked())
                
                should_hide = hide_secure or hide_error
                
                port_item.setHidden(should_hide)
                if not should_hide: 
                    ip_visible = True
                    
            # Celou IP adresu skryjeme pouze, pokud jsou skryty všechny její porty
            ip_item.setHidden(not ip_visible)

    def start_checks(self, only_new=False):
        """Spustí prověření. Pokud only_new=True, přeskočí již prověřené cíle."""
        tasks = []
        for (ip, port), item in self.item_map.items():
            current_status = item.text(1)
            # Neprověřené jsou ty, co mají "Čeká..." nebo "Chyba spojení" (pokud chceme retry)
            if only_new:
                if "Čeká" in current_status:
                    tasks.append((ip, port))
            else:
                tasks.append((ip, port))

        if not tasks:
            self.status_label.setText("Žádné nové cíle k prověření.")
            return

        self.check_all_btn.setEnabled(False)
        self.check_new_btn.setEnabled(False)
        self.status_label.setText(f"Prověřuji ({len(tasks)})...")
        self.processing_count = len(tasks)
        
        for (ip, port) in tasks:
            signals = WorkerSignals()
            signals.result.connect(self.update_result)
            signals.finished.connect(self.on_worker_finished)
            self.thread_pool.start(SecurityHeadersWorker(ip, port, signals))

    @Slot(str, str, dict)
    def update_result(self, ip, port, data):
        """
        Aktualizuje řádek s fixem pro zobrazení času i u chybových stavů.
        Verze 2.1.4a: Timestamp se generuje vždy při dokončení testu.
        """
        item = self.item_map.get((ip, port))
        if not item:
            return
        
        # 1. SURGICAL FIX: Časové razítko se generuje pro KAŽDÝ výsledek z workeru
        if 'check_time' not in data:
            data['check_time'] = datetime.now().strftime('%d.%m.%Y %H:%M:%S')

        # 2. Persistence
        if 'security_headers' not in self.scan_results: 
            self.scan_results['security_headers'] = {}
        self.scan_results['security_headers'][f"{ip}:{port}"] = data
        
        # 3. Doména v hlavičce (rodič)
        domain = data.get('domain', '-')
        parent = item.parent()
        if parent:
            parent.setText(0, f"{ip} ({domain})" if domain != "-" else ip)

        # 4. Sloučení informací (Port / Server / Čas) - Čas je nyní vždy přítomen
        server = data.get('server', '-')
        check_time = data.get('check_time', 'Čeká...')
        item.setText(0, f"Port {port} | Server: {server} | {check_time}")

        # 5. Známka (Grade) nebo Stav chyby
        status_text = data.get('status', 'Neznámý')
        item.setTextAlignment(1, Qt.AlignCenter)
        
        if 'headers' in data:
            grade, color = self.calculate_grade(data['headers'])
            item.setText(1, grade)
            item.setForeground(1, QColor(color))
            item.setFont(1, QFont("Arial", 12, QFont.Bold))
        else:
            # Pokud je to chyba, zobrazíme ji, ale čas v sloupci 0 už bude správný
            display_status = "Chyba" if status_text == "Chyba spojení" else status_text
            item.setText(1, display_status)
            item.setForeground(1, QColor("#E74C3C") if display_status == "Chyba" else QColor("#95A5A6"))
            item.setFont(1, QFont("Arial", 10))

        # 6. Vyplnění technických sloupců (jen pokud máme data)
        if 'headers' in data:
            h = data['headers']
            mapping = [
                ("Strict-Transport-Security", 2), ("Content-Security-Policy", 3),
                ("X-Frame-Options", 4), ("X-Content-Type-Options", 5),
                ("Referrer-Policy", 6), ("Permissions-Policy", 7)
            ]
            for h_name, col_idx in mapping:
                val = h.get(h_name, "CHYBÍ")
                item.setText(col_idx, "✅" if val != "CHYBÍ" else "❌")
                item.setTextAlignment(col_idx, Qt.AlignCenter)
        
        self.apply_filters()

    def on_worker_finished(self):
        self.processing_count -= 1
        if self.processing_count <= 0: 
            self.check_all_btn.setEnabled(True)
            self.check_new_btn.setEnabled(True)
            self.status_label.setText("Hotovo.")
            
    def add_target(self):
        """Manuálně přidá cíl do auditu hlaviček."""
        ip = self.target_input.text().strip()
        port = self.port_input.text().strip()
        
        if not ip or not port:
            return

        # Kontrola, zda už neexistuje
        if (ip, port) in self.item_map:
            QMessageBox.warning(self, "Info", "Tento cíl již v seznamu existuje.")
            return

        # Najít nebo vytvořit IP uzel (Modrý design)
        ip_item = None
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            if root.child(i).text(0) == ip:
                ip_item = root.child(i)
                break
        
        if not ip_item:
            ip_item = QTreeWidgetItem(self.tree, [ip])
            ip_item.setFont(0, QFont("Arial", 11, QFont.Bold))
            ip_item.setForeground(0, QColor("#3498DB"))
            ip_item.setExpanded(True)

        # Přidat port (Oranžový design)
        port_item = QTreeWidgetItem(ip_item, [f"Port {port}", "Čeká (Manuální)"])
        port_item.setFont(0, QFont("Arial", 10, QFont.Bold))
        port_item.setForeground(0, QColor("#E67E22"))
        
        self.item_map[(ip, port)] = port_item
        self.target_input.clear()
        self.status_label.setText(f"Přidán cíl: {ip}:{port}")

    def show_context_menu(self, position):
        """Zobrazí menu pro odstranění cíle."""
        item = self.tree.itemAt(position)
        if not item:
            return
            
        menu = QMenu()
        remove_action = menu.addAction("❌ Odstranit vybrané")
        action = menu.exec(self.tree.mapToGlobal(position))
        
        if action == remove_action:
            self.remove_target(item)

    def remove_target(self, item):
        """Odstraní cíl z UI, mapy i persistence."""
        # Pokud je to IP (rodič)
        if item.childCount() > 0 or not item.parent():
            ip = item.text(0)
            # Odstranit všechny porty dané IP z mapy a persistence
            keys_to_remove = [k for k in self.item_map.keys() if k[0] == ip]
            for k in keys_to_remove:
                del self.item_map[k]
                if 'security_headers' in self.scan_results:
                    self.scan_results['security_headers'].pop(f"{k[0]}:{k[1]}", None)
            
            index = self.tree.indexOfTopLevelItem(item)
            self.tree.takeTopLevelItem(index)
            
        # Pokud je to konkrétní port (dítě)
        else:
            ip = item.parent().text(0)
            port = item.text(0).replace("Port ", "")
            
            self.item_map.pop((ip, port), None)
            if 'security_headers' in self.scan_results:
                self.scan_results['security_headers'].pop(f"{ip}:{port}", None)
            
            parent = item.parent()
            parent.removeChild(item)
            
            # Pokud IP už nemá porty, smažeme i ji
            if parent.childCount() == 0:
                index = self.tree.indexOfTopLevelItem(parent)
                self.tree.takeTopLevelItem(index)
        
        self.status_label.setText("Cíl byl odstraněn.")
        
    def calculate_grade(self, headers):
        """Vypočítá známku (A-F) na základě přítomnosti hlaviček."""
        score = 100
        # Váhy jednotlivých chybějících hlaviček
        penalties = {
            "Strict-Transport-Security": 25,
            "Content-Security-Policy": 25,
            "X-Frame-Options": 15,
            "X-Content-Type-Options": 10,
            "Referrer-Policy": 10,
            "Permissions-Policy": 10
        }
        
        for header, penalty in penalties.items():
            if headers.get(header) == "CHYBÍ":
                score -= penalty
        
        if score >= 90: return "A", "#2ECC71"
        if score >= 75: return "B", "#27AE60"
        if score >= 60: return "C", "#F1C40F"
        if score >= 40: return "D", "#E67E22"
        return "F", "#E74C3C"
    
    def export_to_pdf(self):
        """
        Vygeneruje profesionální vícestránkový PDF report.
        Obsahuje: Úvodní souhrn (TOC), Detailní analýzu, OWASP Remediation a MDN odkazy.
        """
        # 1. Příprava dat pro výběrový dialog
        available_data = []
        saved_data = self.scan_results.get('security_headers', {})
        for key, data in saved_data.items():
            if 'headers' in data:
                available_data.append({
                    'name': key, 
                    'settings': data.get('server', 'Neznámý'), 
                    'data': data
                })
        
        if not available_data:
            QMessageBox.warning(self, "Export", "Nejsou k dispozici žádná data z auditů pro export.")
            return

        # 2. Mini-dialog pro výběr cílů k exportu
        selector = QDialog(self)
        selector.setWindowTitle("Výběr cílů pro PDF Report")
        selector.resize(450, 550)
        sel_layout = QVBoxLayout(selector)
        sel_layout.addWidget(QLabel("<b>Vyberte cíle pro zahrnutí do auditní zprávy:</b>"))
        
        list_widget = QListWidget()
        for d in available_data:
            domain_info = f" [{d['data'].get('domain', '-')}]" if d['data'].get('domain') != "-" else ""
            it = QListWidgetItem(f"{d['name']}{domain_info}")
            it.setCheckState(Qt.Checked)
            it.setData(Qt.UserRole, d)
            list_widget.addItem(it)
        sel_layout.addWidget(list_widget)
        
        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(selector.accept)
        btns.rejected.connect(selector.reject)
        sel_layout.addWidget(btns)
        
        if selector.exec() != QDialog.Accepted:
            return
            
        selected_targets = [list_widget.item(i).data(Qt.UserRole) for i in range(list_widget.count()) 
                            if list_widget.item(i).checkState() == Qt.Checked]
                
        if not selected_targets:
            return

        path, _ = QFileDialog.getSaveFileName(self, "Uložit PDF Report", "Security_Audit_Report.pdf", "PDF Files (*.pdf)")
        if not path:
            return

        # 3. Sestavení vícestránkového HTML šablony
        full_html = "<html><head><style>"
        full_html += """
                body { font-family: Arial, sans-serif; color: #333; line-height: 1.4; padding: 0; margin: 0; }
                .page { page-break-after: always; padding: 40px; box-sizing: border-box; position: relative; min-height: 980px; }
                .page:last-child { page-break-after: auto; }
                .header { display: flex; align-items: center; border-bottom: 2px solid #eee; padding-bottom: 15px; margin-bottom: 20px; }
                .grade { font-size: 60px; font-weight: bold; color: white; width: 100px; height: 100px; 
                         display: flex; align-items: center; justify-content: center; border-radius: 10px; 
                         margin-right: 25px; flex-shrink: 0; }
                .summary-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                .summary-table th, .summary-table td { padding: 12px; border: 1px solid #eee; text-align: left; font-size: 12px; }
                .summary-badge { padding: 4px 10px; border-radius: 4px; color: white; font-weight: bold; }
                table { width: 100%; border-collapse: collapse; margin-top: 15px; table-layout: fixed; }
                th, td { padding: 8px; text-align: left; border-bottom: 1px solid #eee; font-size: 11px; word-wrap: break-word; }
                th { background-color: #f8f9fa; }
                pre { background: #f4f4f4; padding: 10px; border-radius: 5px; font-size: 10px; border: 1px solid #ddd; white-space: pre-wrap; }
                .fail { color: #e74c3c; font-weight: bold; }
                .pass { color: #2ecc71; font-weight: bold; }
                .recommendation-box { margin-top: 20px; padding: 15px; border: 1px solid #3498DB; 
                                     border-left: 5px solid #3498DB; background: #f0f7fb; }
                .links-box { margin-top: 30px; padding-top: 15px; border-top: 1px solid #eee; font-size: 11px; color: #555; }
                .links-box a { color: #3498DB; text-decoration: none; font-weight: bold; }
                .desc { font-size: 9px; color: #777; display: block; margin-top: 2px; }
        """
        full_html += "</style></head><body>"

        # --- STRANA 1: SOUHRNNÉ MANAŽERSKÉ SHRNUTÍ ---
        full_html += f"""
        <div class="page">
            <h1 style="color:#2C3E50; margin-bottom: 5px;">Auditní zpráva: Security Headers</h1>
            <p style="color:#7F8C8D;">Vytvořeno aplikací Nmap Scanner | Verze {VERSION}</p>
            <p>Datum vygenerování: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}</p>
            
            <h3 style="margin-top:40px; border-bottom: 2px solid #3498DB; padding-bottom:10px;">Manažerské shrnutí výsledků</h3>
            <table class="summary-table">
                <tr><th>IP:Port</th><th>Doménové jméno</th><th>Server</th><th style="text-align:center;">Známka</th></tr>"""
        
        for target in selected_targets:
            g, c = self.calculate_grade(target['data']['headers'])
            full_html += f"""
                <tr>
                    <td><strong>{target['name']}</strong></td>
                    <td>{target['data'].get('domain', '-')}</td>
                    <td>{target['settings']}</td>
                    <td style="text-align:center;"><span class="summary-badge" style="background-color:{c};">{g}</span></td>
                </tr>"""
        full_html += "</table><p style='margin-top:30px; font-style:italic; color:#666;'>Poznámka: Detailní analýza a doporučení pro jednotlivé cíle následují na dalších stranách.</p></div>"

        # --- KONFIGURACE PRO DETAILNÍ STRANY ---
        descriptions = {
            "Strict-Transport-Security": "Vynucuje HTTPS a chrání před útoky man-in-the-middle.",
            "Content-Security-Policy": "Prevence XSS útoků striktním povolením zdrojů obsahu.",
            "X-Frame-Options": "Ochrana proti clickjackingu (zákaz vkládání do iframe).",
            "X-Content-Type-Options": "Zabraňuje MIME-sniffingu (vynucuje deklarovaný typ).",
            "Referrer-Policy": "Řídí množství informací předávaných v hlavičce Referer.",
            "Permissions-Policy": "Omezuje přístup prohlížeče k citlivým API (kamera, mikrofon atd.)."
        }
        ordered_headers = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", 
                           "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]
        recommendations = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; (upravte dle potřeb aplikace)",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), camera=(), microphone=()"
        }

        # --- GENEROVÁNÍ DETAILNÍCH STRAN (1 cíl = 1 strana) ---
        for target in selected_targets:
            t_data = target['data']
            grade, color = self.calculate_grade(t_data['headers'])
            server_raw = t_data.get('server', 'Neznámý').lower()
            audit_time = t_data.get('check_time', 'Neprověřeno')
            
            # Generování konfiguračního kódu pro nápravu
            missing = [h for h in ordered_headers if t_data['headers'].get(h) == "CHYBÍ"]
            if not missing:
                fix_code = "<p class='pass'>Gratulujeme! Server má korektně implementovány všechny sledované bezpečnostní hlavičky.</p>"
            elif "nginx" in server_raw:
                fix_code = "<strong>Nginx (.conf):</strong><pre>" + "\n".join([f"add_header {h} \"{recommendations[h]}\" always;" for h in missing]) + "</pre>"
            elif "apache" in server_raw:
                fix_code = "<strong>Apache (.htaccess):</strong><pre>" + "\n".join([f"Header set {h} \"{recommendations[h]}\"" for h in missing]) + "</pre>"
            elif "microsoft" in server_raw or "iis" in server_raw:
                fix_code = "<strong>IIS (web.config):</strong><pre>&lt;customHeaders&gt;\n" + "\n".join([f"  &lt;add name=\"{h}\" value=\"{recommendations[h]}\" /&gt;" for h in missing]) + "\n&lt;/customHeaders&gt;</pre>"
            else:
                fix_code = "<strong>Obecné doporučení:</strong> Přidejte chybějící hlavičky do konfigurace vašeho webového serveru nebo reverzního proxy."

            full_html += f"""
            <div class="page">
                <div class="header">
                    <div class="grade" style="background-color: {color};">{grade}</div>
                    <div>
                        <h2 style="margin:0;">Detailní audit: {target['name']}</h2>
                        <p style="margin:5px 0;">Doména: <strong>{t_data.get('domain', '-')}</strong></p>
                        <p style="margin:5px 0;">Server: <strong>{t_data.get('server', 'Neznámý')}</strong></p>
                        <p style="font-size:10px; color:#999;">Čas měření: {audit_time}</p>
                    </div>
                </div>
                <table>
                    <tr><th style="width:35%;">Hlavička / Popis</th><th style="width:15%;">Stav</th><th>Aktuální hodnota</th></tr>"""
            
            for h in ordered_headers:
                val = t_data['headers'].get(h, "CHYBÍ")
                full_html += f"<tr><td><strong>{h}</strong><span class='desc'>{descriptions[h]}</span></td><td class='{'pass' if val != 'CHYBÍ' else 'fail'}'>{'PŘÍTOMNA' if val != 'CHYBÍ' else 'CHYBÍ'}</td><td><code>{val}</code></td></tr>"
            
            full_html += f"""
                </table>
                <div class="recommendation-box">
                    <h3 style="margin-top:0; color:#2980B9; font-size:14px;">🛠️ Doporučení pro nápravu (OWASP)</h3>
                    {fix_code}
                </div>
                <div class="links-box">
                    <strong>Další zdroje a dokumentace:</strong><br>
                    • OWASP Secure Headers Project: <a href="https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html">HTTP Headers Cheat Sheet</a><br>
                    • Mozilla Web Docs (MDN): <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers">HTTP Headers Documentation</a>
                </div>
            </div>"""

        full_html += "</body></html>"

        # 4. Asynchronní renderování a uložení do PDF
        self.status_label.setText(f"Generuji PDF ({len(selected_targets) + 1} stran)...")
        self.pdf_page = QWebEnginePage()
        self.pdf_page.setHtml(full_html)
        
        def handle_print_finished(ok):
            if ok:
                self.pdf_page.printToPdf(path)
                self.status_label.setText("PDF report uložen.")
                QMessageBox.information(self, "Export", f"Vícestránkový report byl úspěšně vygenerován:\n{path}")
        
        self.pdf_page.loadFinished.connect(handle_print_finished)

