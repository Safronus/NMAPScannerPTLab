"""Headless testy projektového formátu v4 (ProjectStore) — atomický zápis,
round-trip a migrace ze starších formátů (v3 i úplně starý inline)."""
import os
import sys
import json
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nmapscanner.core import project_store as ps
from nmapscanner.core.run_history import RunHistory, ScanRun


def main():
    fails = []
    with tempfile.TemporaryDirectory() as base:
        # --- atomický zápis + round-trip dat běhu ---
        data_file = os.path.join(base, "results", "scan_1", "data.json")
        results = {"online": {"1.1.1.1": {"status": {"state": "up"}}},
                   "tcp": {"1.1.1.1": {"tcp": {"22": {"state": "open"}}}},
                   "tls_audit": {"1.1.1.1:443": {"TestSSL": {"engine": "TestSSL", "history": []}}}}
        ps.save_run_data(data_file, "scan_1", results)
        if not os.path.exists(data_file):
            fails.append("save_run_data nevytvořil soubor")
        loaded = ps.load_run_data(data_file)
        if loaded != results:
            fails.append("round-trip dat běhu nesedí")
        # obálka má schema
        with open(data_file, encoding="utf-8") as f:
            raw = json.load(f)
        if raw.get("schema") != ps.SCHEMA or "results" not in raw:
            fails.append(f"data soubor nemá v4 obálku: {list(raw.keys())}")

        # --- project doc round-trip (v4) ---
        rh = RunHistory(master_targets=["1.1.1.1"])
        run = ScanRun("scan_1", label="Běh 1", targets=["1.1.1.1"],
                      enabled_phases={"online": True, "tcp": True})
        run.status = "completed"
        run.set_status("1.1.1.1", "tcp", "hotovo")
        run.add_event("2026-01-01T10:00:00", "vytvořeno", "1 cíl")
        rh.add_run(run)
        meta = {"name": "Test", "scan_profile": "master", "custom_command": "",
                "raw_input": "1.1.1.1", "cleaned_input": "1.1.1.1", "screenshots": {}}
        pf = os.path.join(base, "project.nmapproj")
        ps.save_project_file(pf, meta, rh, "2026-01-01T10:00:00")

        meta2, rh2, pending = ps.load_project_file(pf)
        if meta2.get("name") != "Test":
            fails.append("v4 meta round-trip nesedí")
        if len(rh2.runs) != 1 or rh2.runs[0].get_status("1.1.1.1", "tcp") != "hotovo":
            fails.append("v4 run_history round-trip nesedí")
        if rh2.runs[0].timeline[0].get("action") != "vytvořeno":
            fails.append("v4 timeline round-trip nesedí")
        if pending:
            fails.append("v4: pending má být prázdné")

        # --- migrace v3 (run_history na top-level) ---
        v3 = {
            "schema": 3, "project_name": "V3 projekt", "scan_profile": "light",
            "raw_input_text": "x", "cleaned_output_text": "y",
            "run_history": rh.to_dict(),
        }
        meta3, rh3, pend3 = ps.parse_project(v3)
        if meta3.get("name") != "V3 projekt" or meta3.get("scan_profile") != "light":
            fails.append(f"migrace v3 meta špatně: {meta3}")
        if len(rh3.runs) != 1 or pend3:
            fails.append("migrace v3 run_history/pending špatně")

        # --- migrace legacy (scan_results inline, bez verzí) ---
        legacy = {
            "project_name": "Starý",
            "scan_results": {"online": {"2.2.2.2": {"status": {"state": "up"}}},
                             "tcp": {"2.2.2.2": {"tcp": {"80": {"state": "open"}}}}},
        }
        metaL, rhL, pendL = ps.parse_project(legacy)
        if metaL.get("name") != "Starý":
            fails.append("migrace legacy meta špatně")
        if len(rhL.runs) != 1:
            fails.append(f"migrace legacy: čekán 1 běh, je {len(rhL.runs)}")
        rid = rhL.runs[0].id
        if rid not in pendL or "tcp" not in pendL[rid]:
            fails.append("migrace legacy: data nejsou v pending")
        if rhL.runs[0].get_status("2.2.2.2", "tcp") != "hotovo":
            fails.append("migrace legacy: phase_status neodvozen")

        # --- load_run_data fallback na v3 snapshot.json ---
        snap = os.path.join(base, "results", "scan_old", "snapshot.json")
        os.makedirs(os.path.dirname(snap), exist_ok=True)
        with open(snap, "w", encoding="utf-8") as f:
            json.dump({"tcp": {"3.3.3.3": {"tcp": {"443": {"state": "open"}}}}}, f)
        got = ps.load_run_data(os.path.join(base, "results", "scan_old", "data.json"),
                               snapshot_fallback=snap)
        if "tcp" not in got or "3.3.3.3" not in got["tcp"]:
            fails.append("load_run_data fallback na snapshot.json nefunguje")

    if fails:
        print("❌ SELHALO:")
        for f in fails:
            print("  -", f)
        return 1
    print("✅ test_project_store: VŠE OK — atomický zápis, v4 round-trip, migrace v3 i legacy, fallback.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
