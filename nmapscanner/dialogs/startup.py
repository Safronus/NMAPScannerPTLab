import os



from PySide6.QtWidgets import (
    QPushButton, QVBoxLayout, QLabel, QDialog
)


class StartupDialog(QDialog):
    """Dialog zobrazený při startu aplikace pro výběr projektu."""
    def __init__(self, recent_projects=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Nmap Scanner - Start projektu")
        self.setModal(True)
        self.choice = None  # "import", "new", nebo cesta k projektu
        self.recent_projects = recent_projects or []
        
        layout = QVBoxLayout()
        label = QLabel("Vyberte možnost spuštění:")
        label.setStyleSheet("font-weight: bold; font-size: 12px;")
        layout.addWidget(label)
        
        # Sekce: Poslední projekty
        if self.recent_projects:
            recent_label = QLabel("Poslední projekty:")
            recent_label.setStyleSheet("margin-top: 10px; font-weight: bold;")
            layout.addWidget(recent_label)
            
            for project_path in self.recent_projects[:5]:  # Zobrazit max 5
                if os.path.exists(project_path):
                    # Zkrácený název projektu pro zobrazení
                    project_name = os.path.basename(project_path)
                    if len(project_name) > 50:
                        project_name = project_name[:47] + "..."
                    
                    btn = QPushButton(f"📂 {project_name}")
                    btn.setToolTip(project_path)  # Celá cesta v tooltipu
                    btn.clicked.connect(lambda checked, path=project_path: self.make_choice(path))
                    layout.addWidget(btn)
            
            # Oddělovač
            separator = QLabel("─" * 50)
            separator.setStyleSheet("color: #cccccc; margin-top: 5px; margin-bottom: 5px;")
            layout.addWidget(separator)
        
        # Standardní možnosti
        self.import_btn = QPushButton("📁 Importovat jiný projekt (.nmapproj)")
        self.import_btn.clicked.connect(lambda: self.make_choice("import"))
        layout.addWidget(self.import_btn)
        
        self.new_btn = QPushButton("✨ Vytvořit nový prázdný projekt")
        self.new_btn.clicked.connect(lambda: self.make_choice("new"))
        layout.addWidget(self.new_btn)
        
        self.setLayout(layout)
        self.resize(500, 300)
    
    def make_choice(self, choice):
        self.choice = choice
        self.accept()

