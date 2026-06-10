"""Projektové složky — centrální správa cest, kam aplikace ukládá data.

Model: jeden projekt = jedna složka. Ta obsahuje stavový soubor
``project.nmapproj`` a podsložky ``results/``, ``screenshots/`` a
``reports/``. **Veškerá data ze skenu** (výsledky, screenshoty, reporty)
patří dovnitř této složky — nic se nerozsypává do pracovního adresáře.

Tento modul je záměrně bez závislosti na Qt, aby šel samostatně testovat.
"""
from pathlib import Path

# Název stavového souboru projektu uvnitř projektové složky.
PROJECT_FILE = "project.nmapproj"

# Výchozí název základní složky pro projekty (v domovském adresáři).
DEFAULT_PROJECTS_DIRNAME = "NmapScannerProjects"


def default_projects_dir():
    """Výchozí základní složka pro projekty: ~/NmapScannerProjects."""
    return str(Path.home() / DEFAULT_PROJECTS_DIRNAME)


def safe_name(name, fallback="projekt"):
    """Očistí název projektu na bezpečný název složky."""
    cleaned = (name or "").strip().replace(" ", "_").replace("/", "_").replace("\\", "_")
    cleaned = "".join(c for c in cleaned if c not in ':*?"<>|')
    return cleaned or fallback


class ProjectPaths:
    """Překládá název projektové složky na konkrétní cesty na disku."""

    SUBDIRS = ("results", "screenshots", "reports")

    def __init__(self, root):
        self.root = Path(root)

    # ---- konstruktory ------------------------------------------------
    @classmethod
    def from_project_file(cls, project_file_path):
        """Projektová složka = nadřazená složka souboru .nmapproj."""
        return cls(Path(project_file_path).parent)

    @classmethod
    def create(cls, base_dir, name):
        """Vytvoří novou projektovou složku ``base_dir/<safe_name>`` s podsložkami."""
        return cls(Path(base_dir) / safe_name(name)).ensure()

    # ---- vytvoření struktury ----------------------------------------
    def ensure(self):
        """Zajistí existenci projektové složky i všech podsložek."""
        self.root.mkdir(parents=True, exist_ok=True)
        for d in self.SUBDIRS:
            (self.root / d).mkdir(exist_ok=True)
        return self

    # ---- cesty -------------------------------------------------------
    @property
    def project_file(self):
        return self.root / PROJECT_FILE

    def _subdir(self, name):
        d = self.root / name
        d.mkdir(parents=True, exist_ok=True)
        return d

    @property
    def results_dir(self):
        return self._subdir("results")

    @property
    def screenshots_dir(self):
        return self._subdir("screenshots")

    @property
    def reports_dir(self):
        return self._subdir("reports")

    def results_run_dir(self, timestamp):
        """Podsložka pro jeden běh skenu: results/scan_<timestamp>."""
        d = self.results_dir / f"scan_{timestamp}"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def run_dir(self, run_id):
        """Podsložka konkrétního běhu/verze: results/<run_id> (run_id už obsahuje ``scan_``)."""
        d = self.results_dir / run_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def run_snapshot(self, run_id):
        """Cesta k snapshotu výsledků daného běhu (v3): results/<run_id>/snapshot.json."""
        return self.run_dir(run_id) / "snapshot.json"

    def run_data_file(self, run_id):
        """Cesta k datovému souboru běhu (v4): results/<run_id>/data.json."""
        return self.run_dir(run_id) / "data.json"

    def __repr__(self):
        return f"ProjectPaths({self.root!r})"
