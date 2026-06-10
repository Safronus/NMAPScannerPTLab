"""Headless test on-disk modelu verzování: projektová složka + snapshoty + historie.

Simuluje uložení a opětovné načtení projektu se dvěma verzemi (běhy), aniž by
bylo potřeba GUI. Ověřuje, že snapshoty jdou na disk vedle metadat a po načtení
sedí.
"""
import os
import sys
import json
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nmapscanner.core.project import ProjectPaths
from nmapscanner.core.run_history import (
    RunHistory, ScanRun, run_id_from_timestamp, phase_status_from_snapshot,
)


def main():
    fails = []
    with tempfile.TemporaryDirectory() as base:
        paths = ProjectPaths.create(base, "Test Projekt")

        # --- dvě verze (běhy) se snapshoty ---
        history = RunHistory(master_targets=["10.0.0.1"])
        snap1 = {"online": {"10.0.0.1": {"status": {"state": "up"}}},
                 "tcp": {"10.0.0.1": {"tcp": {"22": {"state": "open", "name": "ssh"}}}}}
        snap2 = {"online": {"10.0.0.1": {"status": {"state": "up"}}},
                 "tcp": {"10.0.0.1": {"tcp": {"22": {"state": "open", "name": "ssh"},
                                              "443": {"state": "open", "name": "https"}}}}}

        for i, snap in enumerate((snap1, snap2), start=1):
            run_id = run_id_from_timestamp(f"2026010{i}-120000")
            run = ScanRun(run_id, label=f"Běh {i}", created_at=f"2026-01-0{i}T12:00:00",
                          targets=["10.0.0.1"], enabled_phases={"online": True, "tcp": True})
            run.status = "completed"
            run.phase_status = phase_status_from_snapshot(snap)
            run.snapshot_path = f"results/{run_id}/snapshot.json"
            history.add_run(run)
            # snapshot na disk
            with open(paths.run_snapshot(run_id), "w", encoding="utf-8") as f:
                json.dump(snap, f)

        # cesta snapshotu sedí na očekávané místo
        rid1 = history.runs[0].id
        if paths.run_snapshot(rid1) != paths.root / "results" / rid1 / "snapshot.json":
            fails.append("run_snapshot cesta nesedí")

        # --- uložit projekt (metadata) ---
        project_data = {
            "schema": 3, "project_name": "Test Projekt",
            "run_history": history.to_dict(),
        }
        with open(paths.project_file, "w", encoding="utf-8") as f:
            json.dump(project_data, f)

        # --- načíst projekt z disku (nová instance) ---
        with open(paths.project_file, encoding="utf-8") as f:
            loaded = json.load(f)
        history2 = RunHistory.from_dict(loaded["run_history"])
        paths2 = ProjectPaths.from_project_file(paths.project_file)

        if len(history2.runs) != 2:
            fails.append(f"po načtení má být 2 běhy, je {len(history2.runs)}")
        if history2.active_run_id != history.runs[-1].id:
            fails.append("aktivní běh po načtení nesedí")

        # načíst snapshot aktivního běhu z disku a ověřit obsah
        active = history2.active()
        snap_file = paths2.root / active.snapshot_path
        if not snap_file.exists():
            fails.append("snapshot aktivního běhu na disku chybí")
        else:
            with open(snap_file, encoding="utf-8") as f:
                loaded_snap = json.load(f)
            ports = set(loaded_snap.get("tcp", {}).get("10.0.0.1", {}).get("tcp", {}).keys())
            if ports != {"22", "443"}:
                fails.append(f"snapshot aktivní verze: porty {ports}, čekáno 22+443")

        # stav fází přežil serializaci
        if active.get_status("10.0.0.1", "tcp") != "hotovo":
            fails.append("phase_status po načtení nesedí")
        if history2.master_targets != ["10.0.0.1"]:
            fails.append("master_targets po načtení nesedí")

    if fails:
        print("❌ SELHALO:")
        for f in fails:
            print("  -", f)
        return 1
    print("✅ test_project_versioning: VŠE OK (projektová složka, snapshoty verzí, round-trip).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
