from datetime import datetime



from PySide6.QtWidgets import (
    QLineEdit, QPushButton, QVBoxLayout, QTreeWidget, QTreeWidgetItem, QLabel,
    QHeaderView, QMenu, QFileDialog, QHBoxLayout, QCheckBox, QDialog,
    QMessageBox, QDialogButtonBox, QComboBox, QListWidget, QListWidgetItem
)
from PySide6.QtCore import Slot, Qt, QThreadPool
from PySide6.QtGui import QColor, QFont
from ..workers.tls import (
    TlsAuditWorker, SslLabsWorker, TestSslWorker, SslyzeWorker, SslscanWorker
)
from ..core.tls_grading import calculate_grade as tls_calculate_grade
from ..signals import WorkerSignals
from PySide6.QtWebEngineCore import QWebEnginePage


class TlsAuditDialog(QDialog):
    """Dialog pro audit TLS a šifer - Vizuální shoda s verzí 2.1.4c."""
    def __init__(self, scan_results, parent=None, project_name="", project_path=None):
        super().__init__(parent)
        self.setWindowTitle("Inspektor TLS & Cipher Suites (Qualys Style)")
        self.resize(1150, 700) # Zvětšeno pro detaily
        self.scan_results = scan_results
        self.project_name = project_name or ""    # pro verzovaný název PDF reportu
        self.project_path = project_path          # cesta k .nmapproj → složka reports/
        # Globální pool (ne vlastní): vlastní QThreadPool by při zavření dialogu
        # v destruktoru volal waitForDone() a zamrazil GUI, dokud nedoběhne worker.
        self.thread_pool = QThreadPool.globalInstance()
        self.item_map = {}            # (ip, port) -> port řádek
        self.engine_items = {}        # (ip, port, engine) -> řádek enginu pod portem
        self._active = 0              # počet všech právě běžících workerů (napříč dávkami)
        self._cancel_events = []      # threading.Event tokeny běžících dávek (pro Zastavit)
        self.init_ui()
        self.load_targets()

    def init_ui(self):
        """
        Inicializace UI dialogu pro TLS Audit.
        Pět nezávislých enginů (Nmap, Qualys, TestSSL, SSLyze, sslscan) + možnost
        „Prověřit všemi". Každý engine píše do vlastního pod-řádku pod portem.
        """
        layout = QVBoxLayout(self)
        info_layout = QHBoxLayout()
        info_layout.addWidget(QLabel("<b>SSL/TLS Audit cílů (včetně Cipher Suites):</b>"))
        
        info_layout.addSpacing(15)
        info_layout.addWidget(QLabel("Engine:"))
        self.engine_combo = QComboBox()
        self.engine_combo.addItems([
            "Nmap (Rychlý lokální sken)",
            "Qualys SSL Labs API (Veřejné cíle, detailní)",
            "TestSSL.sh (Detailní, pro lokální i veřejné)",
            "SSLyze (Detailní lokální analýza)",
            "sslscan (Rychlý lokální sken)",
        ])
        info_layout.addWidget(self.engine_combo)
        
        info_layout.addStretch()
        
        self.filter_secure = QCheckBox("Skrýt bezpečné (A)")
        self.filter_secure.stateChanged.connect(self.apply_filters)
        self.filter_error = QCheckBox("Skrýt chyby")
        self.filter_error.setChecked(True)
        self.filter_error.stateChanged.connect(self.apply_filters)
        
        info_layout.addWidget(self.filter_secure)
        info_layout.addWidget(self.filter_error)
        self.status_label = QLabel("Připraveno")
        info_layout.addWidget(self.status_label)
        layout.addLayout(info_layout)

        # Manuální přidání cíle
        add_layout = QHBoxLayout()
        add_layout.addWidget(QLabel("Přidat cíl:"))
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("IP adresa nebo doména")
        
        self.port_input = QLineEdit()
        self.port_input.setFixedWidth(60)
        self.port_input.setText("443")
        self.port_input.setPlaceholderText("Port")
        
        self.add_btn = QPushButton("➕ Přidat")
        self.add_btn.clicked.connect(self.add_manual_target)
        
        add_layout.addWidget(self.target_input)
        add_layout.addWidget(self.port_input)
        add_layout.addWidget(self.add_btn)
        layout.addLayout(add_layout)

        # Tabulka
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels([
            "Cíl / Port / Protokol / Šifra", "Známka", 
            "SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"
        ])
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_context_menu)
        
        header = self.tree.header()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        
        for i in range(2, 8):
            header.setSectionResizeMode(i, QHeaderView.Fixed)
            header.resizeSection(i, 65)
            self.tree.headerItem().setTextAlignment(i, Qt.AlignCenter)
        
        layout.addWidget(self.tree)

        # Spodní tlačítka
        btn_layout = QHBoxLayout()
        
        self.check_all_btn = QPushButton("🔐 Prověřit vše")
        self.check_all_btn.clicked.connect(lambda: self.start_checks(False))
        btn_layout.addWidget(self.check_all_btn)

        self.check_new_btn = QPushButton("⏳ Prověřit neprověřené")
        self.check_new_btn.clicked.connect(lambda: self.start_checks(True))
        btn_layout.addWidget(self.check_new_btn)

        self.check_all_engines_btn = QPushButton("🧪 Prověřit VŠEMI enginy")
        self.check_all_engines_btn.setToolTip(
            "Spustí pro všechny cíle Nmap, Qualys, TestSSL, SSLyze i sslscan naráz "
            "(každý do svého pod-řádku).")
        self.check_all_engines_btn.clicked.connect(self.start_all_engines)
        btn_layout.addWidget(self.check_all_engines_btn)

        self.stop_btn = QPushButton("⏹ Zastavit")
        self.stop_btn.clicked.connect(self.stop_checks)
        self.stop_btn.setEnabled(False)
        btn_layout.addWidget(self.stop_btn)

        self.export_pdf_btn = QPushButton("📄 Exportovat PDF")
        self.export_pdf_btn.clicked.connect(self.export_to_pdf)
        btn_layout.addWidget(self.export_pdf_btn)
        
        close_btn = QPushButton("Zavřít")
        close_btn.clicked.connect(self.reject)
        btn_layout.addWidget(close_btn)
        
        layout.addLayout(btn_layout)

    def start_checks(self, only_new=False):
        """Spustí prověření VYBRANÝM enginem (combo). Výsledek jde do samostatného
        řádku enginu pod portem — ostatní enginy se nepřepíšou. ``only_new``
        prověří jen cíle, které vybraným enginem ještě prověřené nebyly."""
        engine_idx = self.engine_combo.currentIndex()
        engine = self.ENGINES[engine_idx] if engine_idx < len(self.ENGINES) else "Nmap"
        if only_new:
            tasks = [k for k in self.item_map if (k[0], k[1], engine) not in self.engine_items]
        else:
            tasks = list(self.item_map.keys())
        if not tasks:
            self.status_label.setText(f"Nic k prověření enginem {engine}.")
            return
        self._start_engine(engine_idx, tasks)
        self.status_label.setText(f"Prověřuji enginem {engine}… (lze Zastavit)")

    def start_all_engines(self):
        """Spustí VŠECHNY enginy pro všechny cíle naráz (každý do svého pod-řádku).
        Qualys u interních/bezdoménových cílů jen vrátí chybu — ostatní projdou."""
        tasks = list(self.item_map.keys())
        if not tasks:
            self.status_label.setText("Nejsou žádné cíle k prověření.")
            return
        for idx in range(len(self.ENGINES)):
            self._start_engine(idx, tasks)
        self.status_label.setText(
            f"Prověřuji všemi enginy ({len(self.ENGINES)}× {len(tasks)} cílů)… (lze Zastavit)")

    def _start_engine(self, engine_idx, tasks):
        """Nastartuje workery jednoho enginu pro zadané cíle. Nic NEzamyká — každý
        engine píše do vlastního pod-řádku per cíl, takže běhy se nepřepisují a lze
        spustit i víc enginů souběžně. Jediný indikátor aktivity je tlačítko Zastavit."""
        import threading
        engine = self.ENGINES[engine_idx]
        WorkerClass = self.WORKERS[engine_idx]
        cancel_event = threading.Event()
        self._cancel_events.append(cancel_event)
        self._active += len(tasks)
        self.stop_btn.setEnabled(True)
        icon = self.ICONS.get(engine, "•")

        for (ip, port) in tasks:
            port_item = self.item_map[(ip, port)]
            eitem = self._engine_item(ip, port, engine, port_item)
            eitem.takeChildren()
            eitem.setText(0, f"{icon} {engine} — Prověřuji…")
            eitem.setText(1, "…")
            eitem.setForeground(1, QColor("#7f8c8d"))
            port_item.setExpanded(True)
            eitem.setExpanded(True)

            signals = WorkerSignals()
            signals.result.connect(self.update_result)
            signals.finished.connect(self.on_worker_finished)
            self.thread_pool.start(WorkerClass(ip, port, signals, cancel_event))

    def on_worker_finished(self):
        """Spočítá doběhlé workery. Když doběhnou všechny, zhasne Zastavit."""
        self._active -= 1
        if self._active <= 0:
            self._active = 0
            stopped = any(ev.is_set() for ev in self._cancel_events)
            self._cancel_events.clear()
            self.stop_btn.setEnabled(False)
            self.status_label.setText("Zastaveno." if stopped else "Hotovo.")

    def stop_checks(self):
        """Zruší všechny rozběhnuté dávky. Workery se ukončí při nejbližší
        kontrole (Qualys čeká mezi dotazy a kontroluje zrušení po 1 s)."""
        for ev in self._cancel_events:
            ev.set()
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Zastavuji… (dokončuji probíhající dotaz)")

    def done(self, result):
        """Zavření dialogu (OK/Zavřít/křížek) zruší vše rozběhnuté, aby
        Qualys/TestSSL zbytečně nepokračovaly na pozadí."""
        for ev in self._cancel_events:
            ev.set()
        super().done(result)

    def load_targets(self):
        """Načte cíle a vytvoří automatické sondy pro TLS audit."""
        self.tree.clear()
        self.item_map = {}
        saved_data = self.scan_results.get('tls_audit', {})
        
        targets_dict = {}
        tls_ports = ['443', '8443', '993', '995', '465', '587']
        
        # A) Z NMAP výsledků (TCP)
        tcp_data = self.scan_results.get('tcp', {})
        for ip, ports in tcp_data.items():
            if ip not in targets_dict: targets_dict[ip] = set()
            if 'tcp' in ports:
                for port, info in ports['tcp'].items():
                    if info.get('state') == 'open' and str(port) in tls_ports:
                        targets_dict[ip].add((str(port), "Čeká (Nmap)"))

        # B) AUTOMATICKÁ SONDA (Online hosti)
        all_ips = set()
        for phase in ['online', 'tcp', 'udp']:
            phase_data = self.scan_results.get(phase, {})
            if phase_data: all_ips.update(phase_data.keys())
            
        for ip in all_ips:
            if ip not in targets_dict: targets_dict[ip] = set()
            if not any(p[0] == '443' for p in targets_dict[ip]):
                targets_dict[ip].add(('443', "Čeká (Sonda)"))

        # C) Z HISTORIE / MANUÁLNÍ CÍLE (NOVÉ - FIX PERSISTENCE)
        # Projdeme uložené výsledky a přidáme ty, které nejsou v Nmapu (manuálně přidané)
        for key in saved_data.keys():
            try:
                # Klíč je ve formátu "IP:PORT"
                if ':' in key:
                    saved_ip, saved_port = key.split(':')
                    
                    if saved_ip not in targets_dict:
                        targets_dict[saved_ip] = set()
                    
                    # Zkontrolujeme, zda už tento port není v seznamu z Nmapu
                    is_present = any(p[0] == saved_port for p in targets_dict[saved_ip])
                    
                    if not is_present:
                        # Pokud není, přidáme ho jako "Načteno"
                        targets_dict[saved_ip].add((saved_port, "Načteno (Historie)"))
            except:
                continue

        # Řazení a vykreslení
        def ip_sort_key(ip):
            try: return tuple(int(part) for part in ip.split('.'))
            except: return (0, 0, 0, 0)
        
        for ip in sorted(targets_dict.keys(), key=ip_sort_key):
            ports = targets_dict[ip]
            if not ports: continue
            
            # IP Hlavička (Modrá)
            ip_item = QTreeWidgetItem(self.tree, [ip])
            ip_item.setFont(0, QFont("Arial", 11, QFont.Bold))
            ip_item.setForeground(0, QColor("#3498DB"))
            ip_item.setExpanded(True)
            
            for port, note in sorted(list(ports), key=lambda x: int(x[0])):
                # Port řádek (Oranžový)
                port_item = QTreeWidgetItem(ip_item)
                port_item.setText(0, f"Port {port} | {note}")
                port_item.setFont(0, QFont("Arial", 10, QFont.Bold))
                port_item.setForeground(0, QColor("#E67E22"))
                
                self.item_map[(ip, port)] = port_item

                # Načtení uložených výsledků — per engine (nový formát) i starý single-dict.
                saved = saved_data.get(f"{ip}:{port}")
                if isinstance(saved, dict) and saved and all(k in self.ENGINES for k in saved.keys()):
                    for eng, rec in saved.items():
                        rec = dict(rec)
                        rec.setdefault('engine', eng)
                        self.update_result(ip, port, rec)
                elif isinstance(saved, dict):
                    self.update_result(ip, port, saved)

        self.apply_filters()

    def add_manual_target(self):
        """Manuálně přidá cíl do seznamu (čeká na spuštění tlačítkem)."""
        target = self.target_input.text().strip()
        port = self.port_input.text().strip()
        
        if not target or not port:
            return

        # Kontrola duplicit
        if (target, port) in self.item_map:
            QMessageBox.warning(self, "Info", "Tento cíl již v seznamu existuje.")
            return

        # 1. Najít nebo vytvořit IP uzel (Modrý design)
        ip_item = None
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            existing_text = root.child(i).text(0).split(' ')[0]
            if existing_text == target:
                ip_item = root.child(i)
                break
        
        if not ip_item:
            ip_item = QTreeWidgetItem(self.tree, [target])
            ip_item.setFont(0, QFont("Arial", 11, QFont.Bold))
            ip_item.setForeground(0, QColor("#3498DB"))
            ip_item.setExpanded(True)

        # 2. Přidat port (Oranžový design) - STAV ČEKÁ
        port_item = QTreeWidgetItem(ip_item)
        port_item.setText(0, f"Port {port} | Čeká (Manuální)") # Důležité: Text obsahuje "Čeká"
        port_item.setFont(0, QFont("Arial", 10, QFont.Bold))
        port_item.setForeground(0, QColor("#E67E22"))
        
        # Přidání do mapy, aby ho našla metoda start_checks()
        self.item_map[(target, port)] = port_item
        
        self.target_input.clear()
        
        # UPRAVENO: Nespouštíme hned worker.
        # Uživatel musí kliknout na "Prověřit neprověřené", což zavolá start_checks(),
        # která najde všechny položky s textem "Čeká" v item_map.
        self.status_label.setText(f"Přidán cíl: {target}:{port}. Klikněte na 'Prověřit neprověřené'.")

    def calculate_grade(self, protocols, cipher_tree=None):
        """Celková TLS známka (A/B/C/F) dle Qualys SSL Labs stropů — viz
        ``nmapscanner.core.tls_grading.calculate_grade`` (bere v potaz protokoly
        i klasifikaci šifer)."""
        return tls_calculate_grade(protocols, cipher_tree)

    def _grade_for_data(self, data):
        """Vrátí (známka, barva) pro výsledek: upřednostní oficiální Qualys grade,
        jinak spočítá lokální známku z protokolů + klasifikace šifer."""
        qg = data.get('qualys_grade')
        if qg:
            first = qg[0].upper()
            color = {"A": "#2ECC71", "B": "#27AE60", "C": "#F39C12",
                     "D": "#E67E22", "E": "#E67E22", "F": "#E74C3C",
                     "T": "#E67E22", "M": "#95A5A6"}.get(first, "#95A5A6")
            return qg, color
        return self.calculate_grade(data.get('protocols', {}), data.get('cipher_tree', {}))

    # Pořadí musí sedět s položkami engine_combo. Přidání nového enginu = doplnit
    # combo (init_ui), ENGINES, WORKERS a ICONS na stejný index.
    ENGINES = ("Nmap", "Qualys", "TestSSL", "Sslyze", "Sslscan")
    WORKERS = (TlsAuditWorker, SslLabsWorker, TestSslWorker, SslyzeWorker, SslscanWorker)
    ICONS = {"Nmap": "🛰", "Qualys": "🌐", "TestSSL": "🔬", "Sslyze": "🧪", "Sslscan": "📡"}

    @Slot(str, str, dict)
    def update_result(self, ip, port, data):
        """Aktualizuje výsledek JEN pro daný engine — ostatní enginy zůstanou.
        Pod portem je samostatný řádek pro každý engine + historie prověření."""
        port_item = self.item_map.get((ip, port))
        if not port_item:
            return
        engine = data.get('engine', 'Nmap')
        key = f"{ip}:{port}"

        # Zrušený pokus NEUKLÁDÁME (nepolutuje výsledky) — jen vizuálně označíme.
        if data.get('status') == "Zrušeno":
            eitem = self._engine_item(ip, port, engine, port_item)
            eitem.takeChildren()
            icon = self.ICONS.get(engine, "•")
            eitem.setText(0, f"{icon} {engine} — zrušeno uživatelem")
            eitem.setText(1, "—")
            eitem.setForeground(1, QColor("#95A5A6"))
            eitem.setTextAlignment(1, Qt.AlignCenter)
            for col in range(2, 8):
                eitem.setText(col, "")
            self.apply_filters()
            return

        # --- uložení per engine + historie (bez přepisu jiných enginů) ---
        store = self.scan_results.setdefault('tls_audit', {})
        entry = store.get(key)
        if not (isinstance(entry, dict) and entry and all(k in self.ENGINES for k in entry.keys())):
            migrated = {}
            if isinstance(entry, dict) and ('protocols' in entry or 'engine' in entry):
                migrated[entry.get('engine', 'Nmap')] = entry
            entry = migrated
            store[key] = entry

        grade, color = self._grade_for_data(data)
        has_proto = any((data.get('protocols') or {}).values())
        status = data.get('status', '')
        in_progress = (status not in ("Hotovo", "Chyba", "Chyba spojení")
                       and not has_proto and 'error' not in data)

        history = list((entry.get(engine) or {}).get('history', []))
        if not in_progress and (has_proto or 'error' in data):
            history.append({'time': data.get('check_time', ''), 'grade': grade})
        rec = dict(data)
        rec['history'] = history
        entry[engine] = rec

        domain = data.get('domain', '-')
        ip_parent = port_item.parent()
        if ip_parent and domain not in ('-', ip, ''):
            ip_parent.setText(0, f"{ip} ({domain})")
        port_item.setText(0, f"Port {port}")
        port_item.setExpanded(True)

        # --- řádek enginu pod portem ---
        eitem = self._engine_item(ip, port, engine, port_item)
        eitem.takeChildren()
        icon = self.ICONS.get(engine, "•")
        when = data.get('check_time', '')
        eitem.setText(0, f"{icon} {engine}   ·   {len(history)}× prověřeno"
                      + (f"   ·   {when}" if when else ""))
        eitem.setFont(0, QFont("Arial", 10, QFont.Bold))
        eitem.setExpanded(True)

        if in_progress:
            # Místo zavádějícího „0× prověřeno" ukaž skutečný stav (Qualys umí
            # běžet i pár minut — uživatel pak vidí, že to žije, ne že je zaseklé).
            eitem.setText(0, f"{icon} {engine} — {status or 'Prověřuji…'}")
            eitem.setText(1, "…")
            eitem.setForeground(1, QColor("#7f8c8d"))
            eitem.setToolTip(1, status)
            for col in range(2, 8):
                eitem.setText(col, "")
            self.apply_filters()
            return

        if 'error' in data or status == "Chyba spojení" or not has_proto:
            eitem.setText(1, "Chyba")
            eitem.setForeground(1, QColor("#E74C3C"))
            eitem.setTextAlignment(1, Qt.AlignCenter)
            err = data.get('error') or "Chyba spojení / žádná data"
            child = QTreeWidgetItem(eitem, [f"⚠️ {err}", ""])
            child.setForeground(0, QColor("#E74C3C"))
            child.setFirstColumnSpanned(True)
            for col in range(2, 8):
                eitem.setText(col, "-")
                eitem.setForeground(col, QColor("#95A5A6"))
                eitem.setTextAlignment(col, Qt.AlignCenter)
            self.apply_filters()
            return

        eitem.setText(1, grade)
        eitem.setFont(1, QFont("Arial", 11, QFont.Bold))
        eitem.setForeground(1, QColor(color))
        eitem.setTextAlignment(1, Qt.AlignCenter)
        self._render_engine_row(eitem, data)
        self.apply_filters()

    def _engine_item(self, ip, port, engine, port_item):
        k = (ip, port, engine)
        it = self.engine_items.get(k)
        if it is None or it.parent() is not port_item:
            it = QTreeWidgetItem(port_item)
            self.engine_items[k] = it
        return it

    def _render_engine_row(self, eitem, data):
        """Vykreslí protokolové sloupce + strom šifer na řádek enginu."""
        p = data.get('protocols', {})
        for key, col in [("sslv2", 2), ("sslv3", 3), ("tls1_0", 4),
                         ("tls1_1", 5), ("tls1_2", 6), ("tls1_3", 7)]:
            supported = p.get(key)
            eitem.setText(col, "✅" if supported else "❌")
            eitem.setTextAlignment(col, Qt.AlignCenter)
            if key in ("sslv2", "sslv3", "tls1_0", "tls1_1") and supported:
                eitem.setForeground(col, QColor("#E74C3C"))
            else:
                eitem.setForeground(col, QColor("#bdc3c7"))

        cipher_tree = data.get('cipher_tree', {})
        proto_safety = {
            "TLSv1.3": ("SECURE", "#2ECC71", "🔒"), "TLSv1.2": ("SECURE", "#27AE60", "🔒"),
            "TLSv1.1": ("INSECURE", "#E67E22", "🔓"), "TLSv1.0": ("INSECURE", "#C0392B", "🔓"),
            "SSLv3": ("INSECURE", "#C0392B", "🔓"), "SSLv2": ("INSECURE", "#C0392B", "🔓"),
        }
        rank_map = {"SECURE": 0, "WEAK": 1, "INSECURE": 2}
        for proto in sorted(cipher_tree.keys(), reverse=True):
            ciphers = sorted(cipher_tree[proto],
                             key=lambda x: (rank_map.get(x.get('grade_label', 'INSECURE'), 3),
                                            x.get('name', '')))
            counts = {}
            for c in ciphers:
                lbl = c.get('grade_label', 'INSECURE')
                counts[lbl] = counts.get(lbl, 0) + 1
            slabel, scolor, sicon = proto_safety.get(proto, ("UNKNOWN", "#95A5A6", "?"))
            proto_item = QTreeWidgetItem(eitem)
            proto_item.setText(0, f"{sicon} {proto}   [{slabel}]")
            proto_item.setFont(0, QFont("Arial", 10, QFont.Bold))
            proto_item.setForeground(0, QColor(scolor))
            proto_item.setExpanded(True)
            last_group = None
            for c in ciphers:
                grp = c.get('grade_label', 'INSECURE')
                if grp != last_group:
                    title = {"SECURE": "Strong / Secure Suites", "WEAK": "Weak Suites",
                             "INSECURE": "Insecure Suites"}.get(grp, grp)
                    gcolor = {"SECURE": "#27AE60", "WEAK": "#F39C12",
                              "INSECURE": "#E74C3C"}.get(grp, "#999")
                    sep = QTreeWidgetItem(proto_item)
                    sep.setText(0, f"▼ {title} ({counts.get(grp, 0)})")
                    sep.setForeground(0, QColor(gcolor))
                    sep.setFont(0, QFont("Arial", 9, QFont.Bold))
                    sep.setFirstColumnSpanned(True)
                    sep.setFlags(Qt.ItemIsEnabled)
                    last_group = grp
                name_display = f"  {c.get('name', 'Unknown')}"
                if c.get('kex_info'):
                    name_display += f" ({c['kex_info']})"
                if c.get('grade_tag'):
                    name_display += f" {c['grade_tag']}"
                citem = QTreeWidgetItem(proto_item)
                citem.setText(0, name_display)
                citem.setForeground(0, QColor(c.get('grade_color') or "#95A5A6"))
                citem.setFont(0, QFont("Consolas", 9))

    def apply_filters(self):
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()):
            ip_item = root.child(i)
            ip_visible = False
            for j in range(ip_item.childCount()):
                port_item = ip_item.child(j)
                port_visible = port_item.childCount() == 0  # port bez prověření necháme vidět
                for e in range(port_item.childCount()):
                    erow = port_item.child(e)
                    grade = erow.text(1)
                    hide = (grade == "A" and self.filter_secure.isChecked()) or \
                           ("Chyba" in grade and self.filter_error.isChecked())
                    erow.setHidden(hide)
                    if not hide:
                        port_visible = True
                port_item.setHidden(not port_visible)
                if port_visible:
                    ip_visible = True
            ip_item.setHidden(not ip_visible)

    def show_context_menu(self, position):
        item = self.tree.itemAt(position)
        if not item: return
        menu = QMenu()
        
        if item.parent() and not item.parent().parent(): # Je to Port položka
             remove_action = menu.addAction("❌ Odstranit vybrané")
             if menu.exec(self.tree.mapToGlobal(position)) == remove_action:
                self.remove_target(item)
        elif not item.parent(): # IP položka
             remove_action = menu.addAction("❌ Odstranit vybrané")
             if menu.exec(self.tree.mapToGlobal(position)) == remove_action:
                self.remove_target(item)

    def remove_target(self, item):
        if item.parent(): # Je to port
            ip = item.parent().text(0).split(' ')[0]
            port = item.text(0).split('|')[0].replace("Port ", "").strip()
            self.item_map.pop((ip, port), None)
            for ek in [k for k in self.engine_items if k[0] == ip and k[1] == port]:
                self.engine_items.pop(ek, None)
            if 'tls_audit' in self.scan_results:
                self.scan_results['tls_audit'].pop(f"{ip}:{port}", None)
            item.parent().removeChild(item)
        else: # Je to IP
            ip = item.text(0).split(' ')[0]
            keys_to_remove = [k for k in self.item_map.keys() if k[0] == ip]
            for k in keys_to_remove: self.item_map.pop(k, None)
            for ek in [k for k in self.engine_items if k[0] == ip]:
                self.engine_items.pop(ek, None)
            if 'tls_audit' in self.scan_results:
                for k in keys_to_remove: self.scan_results['tls_audit'].pop(f"{k[0]}:{k[1]}", None)
            self.tree.takeTopLevelItem(self.tree.indexOfTopLevelItem(item))
            
    def _default_report_path(self):
        """Verzovaný název reportu: ``<projekt>_TLS_Audit_<YYYYMMDD_HHMMSS>.pdf``.
        Když je projekt uložený, předvyplní se do jeho složky ``reports/``,
        jinak jen název v aktuálním adresáři."""
        from ..core.project import safe_name, ProjectPaths
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        fname = f"{safe_name(self.project_name or 'projekt')}_TLS_Audit_{ts}.pdf"
        if self.project_path:
            try:
                return str(ProjectPaths.from_project_file(self.project_path).reports_dir / fname)
            except Exception:
                pass
        return fname

    def export_to_pdf(self):
        """
        Vygeneruje profesionální vícestránkový PDF report pro TLS Audit.
        Inspirováno Qualys SSL Labs reportem.
        UPRAVENO: Přidáno vizuální seskupování Cipher Suites (Secure/Weak/Insecure).
        """
        # 1. Sběr dat pro výběrový dialog s aplikací filtrů
        available_data = []
        saved_data = self.scan_results.get('tls_audit', {})
        
        # Získání stavu filtrů
        hide_secure = self.filter_secure.isChecked()
        hide_errors = self.filter_error.isChecked()

        for key, entry in saved_data.items():
            # entry je engine-mapa {engine: rec}; starý formát = jeden dict.
            if isinstance(entry, dict) and entry and all(k in self.ENGINES for k in entry.keys()):
                items = list(entry.items())
            elif isinstance(entry, dict):
                items = [(entry.get('engine', 'Nmap'), entry)]
            else:
                continue

            for engine, data in items:
                if not isinstance(data, dict):
                    continue
                is_connection_error = data.get('status') == "Chyba spojení"
                if 'protocols' in data and not is_connection_error:
                    grade_val, _ = self._grade_for_data(data)
                    grade = "Chyba" if grade_val == "ERR" else grade_val
                else:
                    grade = "Chyba"

                if grade == "A" and hide_secure:
                    continue
                if "Chyba" in grade and hide_errors:
                    continue
                available_data.append({'name': f"{key} · {engine}", 'data': data})
        
        if not available_data:
            QMessageBox.warning(self, "Export", "Nejsou k dispozici žádná data (nebo jsou všechna skryta filtry).")
            return

        # 2. Mini-dialog pro výběr cílů
        selector = QDialog(self)
        selector.setWindowTitle("Výběr cílů pro TLS Report")
        selector.resize(450, 550)
        sel_layout = QVBoxLayout(selector)
        sel_layout.addWidget(QLabel("<b>Vyberte cíle pro zahrnutí do SSL/TLS reportu:</b>"))
        
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
        
        if selector.exec() != QDialog.Accepted: return
            
        selected_targets = [list_widget.item(i).data(Qt.UserRole) for i in range(list_widget.count()) 
                            if list_widget.item(i).checkState() == Qt.Checked]
                
        if not selected_targets: return

        path, _ = QFileDialog.getSaveFileName(self, "Uložit TLS Report",
                                              self._default_report_path(), "PDF Files (*.pdf)")
        if not path: return

        # 3. HTML Šablona
        full_html = "<html><head><style>"
        full_html += """
                body { font-family: Arial, sans-serif; color: #333; line-height: 1.4; padding: 0; margin: 0; }
                .page { page-break-after: always; padding: 40px; box-sizing: border-box; min-height: 980px; }
                .page:last-child { page-break-after: auto; }
                .header { display: flex; align-items: center; border-bottom: 2px solid #eee; padding-bottom: 15px; margin-bottom: 20px; }
                .grade { font-size: 70px; font-weight: bold; color: white; width: 120px; height: 120px; 
                         display: flex; align-items: center; justify-content: center; border-radius: 10px; 
                         margin-right: 30px; flex-shrink: 0; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
                .summary-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                .summary-table th, .summary-table td { padding: 12px; border: 1px solid #eee; text-align: left; font-size: 12px; }
                .summary-badge { padding: 4px 10px; border-radius: 4px; color: white; font-weight: bold; }
                
                .proto-table { width: 100%; border-collapse: collapse; margin-top: 15px; margin-bottom: 25px; }
                .proto-table td { padding: 8px; border-bottom: 1px solid #eee; font-size: 13px; }
                .proto-table .label { font-weight: bold; width: 200px; }
                
                .cipher-table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 11px; }
                .cipher-table th { background: #f8f9fa; padding: 6px; text-align: left; border-bottom: 2px solid #ddd; }
                .cipher-table td { padding: 4px 6px; border-bottom: 1px solid #f1f1f1; }
                .proto-header { background-color: #eef4f9; color: #2980B9; font-weight: bold; padding: 8px !important; }
                
                .status-yes { color: #27AE60; font-weight: bold; }
                .status-no { color: #BDC3C7; }
                .status-weak { color: #E74C3C; font-weight: bold; }
                
                .cipher-secure { color: #27AE60; }
                .cipher-weak { color: #F39C12; }
                .cipher-insecure { color: #E74C3C; font-weight: bold; }
                
                .recommendation-box { margin-top: 30px; padding: 20px; border: 1px solid #3498DB; 
                                     border-left: 10px solid #3498DB; background: #f0f7fb; }
                .links-box { margin-top: 30px; padding-top: 15px; border-top: 1px solid #eee; font-size: 11px; color: #555; }
        """
        full_html += "</style></head><body>"

        # --- STRANA 1: MANAŽERSKÉ SHRNUTÍ ---
        full_html += f"""
        <div class="page">
            <h1 style="color:#2C3E50;">SSL/TLS Security Audit Report</h1>
            <p>Datum vygenerování: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}</p>
            <h3 style="margin-top:40px; border-bottom: 2px solid #3498DB; padding-bottom:10px;">Souhrnné hodnocení cílů</h3>
            <table class="summary-table">
                <tr><th>IP:Port</th><th>Doménové jméno</th><th style="text-align:center;">Známka</th></tr>"""
        
        for target in selected_targets:
            if 'protocols' in target['data']:
                g, c = self._grade_for_data(target['data'])
                if g == "ERR":
                    g, c = "ERR", "#95A5A6"
            else:
                 g, c = "ERR", "#95A5A6"

            full_html += f"""
                <tr>
                    <td><strong>{target['name']}</strong></td>
                    <td>{target['data'].get('domain', '-')}</td>
                    <td style="text-align:center;"><span class="summary-badge" style="background-color:{c};">{g}</span></td>
                </tr>"""
        full_html += "</table><p style='margin-top:40px; color:#666;'>Tento report hodnotí podporu TLS protokolů a kvalitu šifrovacích sad (Cipher Suites).</p></div>"

        # --- DETAILNÍ STRANY ---
        for target in selected_targets:
            t_data = target['data']
            protocols = t_data.get('protocols', {})
            cipher_tree = t_data.get('cipher_tree', {})
            
            grade, color = "ERR", "#95A5A6"
            if protocols:
                grade, color = self._grade_for_data(t_data)
            
            # --- Generování tabulky Cipher Suites ---
            ciphers_html = ""
            if cipher_tree:
                ciphers_html += """
                <h3 style="color:#2980B9; margin-top:30px; border-bottom:1px solid #eee;">Cipher Suites (Šifrovací sady)</h3>
                <table class="cipher-table">
                """
                sorted_protos = sorted(cipher_tree.keys(), reverse=True)
                
                # Mapa pro řazení šifer (nejdříve SECURE, pak WEAK, pak INSECURE)
                rank_map = {"SECURE": 0, "WEAK": 1, "INSECURE": 2}

                for proto in sorted_protos:
                    ciphers = cipher_tree[proto]
                    
                    # 1. Seřadit šifry podle síly a pak podle jména
                    ciphers.sort(key=lambda x: (
                        rank_map.get(x.get('grade_label', 'INSECURE'), 3), 
                        x.get('name', '')
                    ))

                    # 2. Hlavička protokolu
                    ciphers_html += f"<tr><td colspan='2' class='proto-header'>{proto}</td></tr>"
                    
                    # 3. Iterace a vkládání vizuálních oddělovačů (Headers)
                    last_group = None
                    
                    for c in ciphers:
                        current_group = c.get('grade_label', 'INSECURE')
                        
                        # Pokud se změnila skupina, vložíme řádek s nadpisem
                        if current_group != last_group:
                            group_color = "#777"
                            if current_group == "SECURE": group_color = "#27AE60"
                            elif current_group == "WEAK": group_color = "#F39C12"
                            elif current_group == "INSECURE": group_color = "#E74C3C"
                            
                            group_title = current_group
                            if current_group == "SECURE": group_title = "Strong / Secure Suites"
                            elif current_group == "WEAK": group_title = "Weak Suites"
                            elif current_group == "INSECURE": group_title = "Insecure Suites"
                            
                            ciphers_html += f"""
                            <tr><td colspan='2' style='background:#fafafa; color:{group_color}; font-size:10px; font-weight:bold; border-bottom:1px solid #eee; padding-top:8px; padding-left:8px;'>
                                ▼ {group_title}
                            </td></tr>
                            """
                            last_group = current_group

                        # Styl řádku šifry
                        style_class = "cipher-secure"
                        if current_group == "WEAK": style_class = "cipher-weak"
                        elif current_group == "INSECURE": style_class = "cipher-insecure"
                        
                        name_display = c.get('name', 'Unknown')
                        c_kex = c.get('kex_info', '')
                        if c_kex:
                            name_display += f" <span style='color:#777;'>({c_kex})</span>"
                            
                        # Zobrazení tagu (např. WEAK - No FS)
                        grade_display = current_group
                        tag = c.get('grade_tag', '')
                        if tag:
                            grade_display = f"{current_group} {tag}"
                            
                        ciphers_html += f"""
                        <tr>
                            <td style="width:75%; font-family:monospace; padding-left:20px;">{name_display}</td>
                            <td class="{style_class}" style="text-align:right;">{grade_display}</td>
                        </tr>
                        """
                ciphers_html += "</table>"
            else:
                ciphers_html = "<p>Žádná data o šifrách.</p>"

            # --- Doporučení ---
            remediation = []
            if grade == "ERR":
                remediation.append("<li><b>Chyba spojení:</b> Nepodařilo se navázat zabezpečené spojení.</li>")
            else:
                if protocols.get("tls1_0") or protocols.get("tls1_1"):
                    remediation.append("<li><b>Kritické:</b> Deaktivujte podporu TLS 1.0 a TLS 1.1.</li>")
                if not protocols.get("tls1_3"):
                    remediation.append("<li><b>Doporučení:</b> Aktivujte podporu TLS 1.3.</li>")
                if not remediation:
                    remediation.append("<li>Konfigurace SSL/TLS je v souladu se standardy.</li>")

            full_html += f"""
            <div class="page">
                <div class="header">
                    <div class="grade" style="background-color: {color};">{grade}</div>
                    <div>
                        <h2 style="margin:0;">Detailní analýza: {target['name']}</h2>
                        <p style="margin:5px 0;">Doména: <strong>{t_data.get('domain', '-')}</strong></p>
                        <p style="font-size:11px; color:#7F8C8D;">Čas měření: {t_data.get('check_time', '-')}</p>
                    </div>
                </div>
                
                <h3 style="color:#2980B9; border-bottom:1px solid #eee; padding-bottom:5px;">Konfigurace protokolů</h3>
                <table class="proto-table">
                    <tr><td class="label">TLS 1.3</td><td class="{'status-yes' if protocols.get('tls1_3') else 'status-no'}">{'ANO' if protocols.get('tls1_3') else 'NE'}</td></tr>
                    <tr><td class="label">TLS 1.2</td><td class="{'status-yes' if protocols.get('tls1_2') else 'status-no'}">{'ANO' if protocols.get('tls1_2') else 'NE'}</td></tr>
                    <tr><td class="label">TLS 1.1</td><td class="{'status-weak' if protocols.get('tls1_1') else 'status-no'}">{'ANO (Zranitelné)' if protocols.get('tls1_1') else 'NE'}</td></tr>
                    <tr><td class="label">TLS 1.0</td><td class="{'status-weak' if protocols.get('tls1_0') else 'status-no'}">{'ANO (Zranitelné)' if protocols.get('tls1_0') else 'NE'}</td></tr>
                </table>

                {ciphers_html}

                <div class="recommendation-box">
                    <h3 style="margin-top:0; color:#2980B9;">🛠️ Doporučení</h3>
                    <ul style="margin-bottom:0; padding-left:20px;">
                        {''.join(remediation)}
                    </ul>
                </div>
            </div>"""

        full_html += "</body></html>"

        # 4. Renderování
        self.status_label.setText(f"Generuji PDF ({len(selected_targets) + 1} stran)...")
        self.pdf_page = QWebEnginePage()
        self.pdf_page.setHtml(full_html)
        self.pdf_page.loadFinished.connect(lambda ok: self.pdf_page.printToPdf(path) if ok else None)
            
