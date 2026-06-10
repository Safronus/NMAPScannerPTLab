"""Registr vytvořených reportů v projektu (manifest) — bez Qt.

Každý report (souhrnné PDF, ale i dílčí exporty: ffuf TXT, TLS PDF, certifikáty,
hlavičky, Word vuln report, ZAP …) se zapíše do ``reports/manifest.json`` ve
složce projektu. Manažer reportů z toho staví přehled seskupený podle zdroje
(části aplikace, která report vygenerovala).

Položka manifestu::

    {
      "id": "<unikatni>",
      "created_at": "YYYY-MM-DD HH:MM:SS",
      "source": "report_full" | "ffuf" | "tls" | "cert" | "headers" | "vuln_docx" | "zap" | ...,
      "type": "technical" | "management" | "txt" | "pdf" | "docx" | "json" | "csv",
      "language": "cs" | "en" | "",
      "title": "<lidsky citelny nazev>",
      "filename": "<jen jmeno souboru>",
      "size": <bytes>
    }
"""

import json
import os
import time

MANIFEST = "manifest.json"

# Lidské názvy zdrojů (CZ) pro seskupení v manažeru
SOURCE_LABELS = {
    "report_full": "Souhrnné reporty (PDF)",
    "ffuf": "Directory fuzzing (ffuf)",
    "tls": "TLS audit",
    "cert": "Certifikáty",
    "headers": "Bezpečnostní hlavičky",
    "vuln_docx": "Zranitelnosti (Word)",
    "zap": "OWASP ZAP",
    "ports": "Porty",
    "services": "Služby",
    "hostnames": "Hostnames",
    "other": "Ostatní",
}


def manifest_path(reports_dir):
    return os.path.join(reports_dir, MANIFEST)


def load_manifest(reports_dir):
    p = manifest_path(reports_dir)
    if not os.path.exists(p):
        return []
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_manifest(reports_dir, entries):
    os.makedirs(reports_dir, exist_ok=True)
    tmp = manifest_path(reports_dir) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)
    os.replace(tmp, manifest_path(reports_dir))


def _gen_id(source):
    return f"{source}-{time.strftime('%Y%m%d-%H%M%S')}-{os.urandom(2).hex()}"


def suggested_filename(source, type_, language="", ext="pdf", title=""):
    """Vhodný, timestampovaný název souboru reportu."""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    parts = ["PTLab", source]
    if type_ and type_ not in (ext,):
        parts.append(type_)
    if language:
        parts.append(language.upper())
    parts.append(stamp)
    base = "_".join(p for p in parts if p)
    return f"{base}.{ext.lstrip('.')}"


def register_report(reports_dir, path, source, type_, language="", title=""):
    """Zaregistruje existující soubor reportu do manifestu. Vrací položku."""
    entries = load_manifest(reports_dir)
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    entry = {
        "id": _gen_id(source),
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "source": source,
        "type": type_,
        "language": language or "",
        "title": title or os.path.basename(path),
        "filename": os.path.basename(path),
        "size": size,
    }
    # nahradit případný duplicitní záznam se stejným filename
    entries = [e for e in entries if e.get("filename") != entry["filename"]]
    entries.append(entry)
    _save_manifest(reports_dir, entries)
    return entry


def remove_report(reports_dir, report_id, delete_file=True):
    """Odebere report z manifestu (a volitelně smaže soubor)."""
    entries = load_manifest(reports_dir)
    kept, removed = [], None
    for e in entries:
        if e.get("id") == report_id:
            removed = e
        else:
            kept.append(e)
    if removed is None:
        return False
    if delete_file:
        try:
            os.remove(os.path.join(reports_dir, removed.get("filename", "")))
        except OSError:
            pass
    _save_manifest(reports_dir, kept)
    return True


def reports_grouped(reports_dir):
    """Vrátí ``{source: [entry, …]}`` seřazené (nejnovější první v každé skupině)."""
    groups = {}
    for e in load_manifest(reports_dir):
        groups.setdefault(e.get("source", "other"), []).append(e)
    for src in groups:
        groups[src].sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return groups


def prune_missing(reports_dir):
    """Odstraní z manifestu položky, jejichž soubor už neexistuje."""
    entries = load_manifest(reports_dir)
    kept = [e for e in entries
            if os.path.exists(os.path.join(reports_dir, e.get("filename", "")))]
    if len(kept) != len(entries):
        _save_manifest(reports_dir, kept)
    return kept
