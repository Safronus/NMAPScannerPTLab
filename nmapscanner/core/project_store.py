"""Projektový formát v4 — robustní, self-describing, rozšiřitelný (bez Qt).

Cíle:

* **Atomický zápis** — vždy se píše do dočasného souboru a pak ``os.replace``
  (atomické). Crash uprostřed ukládání tedy nepoškodí existující projekt.
* **Self-describing** — soubor nese ``schema``, ``format`` a ``updated_at``.
* **Oddělení metadat a dat** — ``project.nmapproj`` drží jen metadata projektu a
  běhů (malé), těžká data každého běhu jsou v ``results/<run_id>/data.json``.
* **Rozšiřitelnost** — data běhu jsou pod klíčem ``results`` (libovolné typy:
  nmap fáze, tls_audit, certificates, security_headers, ffuf, screenshots…).
* **Migrace** — načte i schema v3 (run_history na top-level + snapshot.json) a
  úplně starý formát (scan_results inline, bez verzí) → převede na jeden běh.

Tento modul je bez Qt, aby šel samostatně testovat (``tests/test_project_store.py``).
"""
import os
import json
import tempfile

from .run_history import (
    RunHistory, ScanRun, NMAP_PHASES, run_id_from_timestamp,
    phase_status_from_snapshot, targets_from_snapshot,
)

SCHEMA = 4
FORMAT_TAG = "nmapscanner-project"


def atomic_write_json(path, obj):
    """Zapíše JSON atomicky (temp soubor + os.replace)."""
    path = str(path)
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---- ukládání -----------------------------------------------------------
def build_project_doc(meta, run_history, updated_at):
    """Sestaví dokument projektu (schema v4). ``meta`` = dict s poli projektu."""
    return {
        "schema": SCHEMA,
        "format": FORMAT_TAG,
        "updated_at": updated_at,
        "project": dict(meta or {}),
        "run_history": run_history.to_dict(),
    }


def build_run_data(run_id, results):
    """Obálka pro data jednoho běhu (schema v4)."""
    return {"schema": SCHEMA, "run_id": run_id, "results": dict(results or {})}


def save_project_file(project_file, meta, run_history, updated_at):
    atomic_write_json(project_file, build_project_doc(meta, run_history, updated_at))


def save_run_data(data_file, run_id, results):
    atomic_write_json(data_file, build_run_data(run_id, results))


# ---- načítání + migrace -------------------------------------------------
def parse_project(doc):
    """Z dokumentu vrátí ``(meta, RunHistory, pending_data)``.

    ``pending_data`` = ``{run_id: results}`` pro běhy, jejichž data jsou inline
    v dokumentu (jen starý formát) a je potřeba je při příštím uložení odložit
    do data souboru. Pro v4/v3 je prázdné (data jsou v samostatných souborech).
    """
    doc = doc or {}
    schema = doc.get("schema", 0)

    # v4
    if schema >= 4 and "project" in doc and "run_history" in doc:
        meta = dict(doc.get("project") or {})
        return meta, RunHistory.from_dict(doc.get("run_history") or {}), {}

    # v3 — run_history na top-level, pole projektu rovnou v dokumentu
    if "run_history" in doc:
        meta = {
            "name": doc.get("project_name") or doc.get("name") or "Projekt",
            "scan_profile": doc.get("scan_profile", "master"),
            "custom_command": doc.get("custom_command", ""),
            "raw_input": doc.get("raw_input_text", ""),
            "cleaned_input": doc.get("cleaned_output_text", ""),
            "screenshots": doc.get("screenshots", {}) or {},
        }
        return meta, RunHistory.from_dict(doc["run_history"]), {}

    # legacy — scan_results inline, žádné verze → jeden běh
    return _migrate_legacy(doc)


def _migrate_legacy(doc):
    scan_results = doc.get("scan_results", {}) or {}
    targets = targets_from_snapshot(scan_results)
    if not targets:
        targets = [l.strip() for l in (doc.get("cleaned_output_text") or "").splitlines()
                   if l.strip() and not l.strip().startswith("#")]
    meta = {
        "name": doc.get("project_name") or doc.get("name") or "Projekt (import)",
        "scan_profile": doc.get("scan_profile", "master"),
        "custom_command": doc.get("custom_command", ""),
        "raw_input": doc.get("raw_input_text", ""),
        "cleaned_input": doc.get("cleaned_output_text", ""),
        "screenshots": doc.get("screenshots", {}) or {},
    }
    history = RunHistory(master_targets=targets)
    pending = {}
    has_results = any(scan_results.get(ph) for ph in NMAP_PHASES) or bool(scan_results)
    if has_results or targets:
        run_id = run_id_from_timestamp("import")
        ps = doc.get("phase_settings", {}) or {}
        enabled = {p: bool(ps.get(p, {}).get("enabled", True)) for p in NMAP_PHASES}
        run = ScanRun(run_id, label="Běh 1 (import)", created_at="",
                      profile=meta["scan_profile"], custom_command=meta["custom_command"],
                      targets=targets, enabled_phases=enabled)
        run.status = "completed"
        run.phase_status = phase_status_from_snapshot(scan_results)
        history.add_run(run)
        pending[run_id] = scan_results
    return meta, history, pending


def load_project_file(project_file):
    """Načte projekt ze souboru → ``(meta, RunHistory, pending_data)``."""
    with open(project_file, encoding="utf-8") as f:
        doc = json.load(f)
    return parse_project(doc)


def load_run_data(data_file, snapshot_fallback=None):
    """Načte data běhu. Preferuje v4 ``data.json`` ({results: …}); jako fallback
    přečte v3 ``snapshot.json`` (holý scan_results)."""
    if data_file and os.path.exists(data_file):
        with open(data_file, encoding="utf-8") as f:
            doc = json.load(f)
        if isinstance(doc, dict) and "results" in doc:
            return doc.get("results") or {}
        return doc or {}   # kdyby tam náhodou byl holý dict
    if snapshot_fallback and os.path.exists(snapshot_fallback):
        with open(snapshot_fallback, encoding="utf-8") as f:
            return json.load(f) or {}
    return {}
