"""Headless testy verzování běhů a diffu verzí (čistá logika, bez Qt)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nmapscanner.core.run_history import (
    ScanRun, RunHistory, diff_snapshots, SUCCESS_STATUSES,
    status_from_data, phase_status_from_snapshot, targets_from_snapshot,
)


def snap(online=None, tcp=None, udp=None, osscan=None):
    s = {}
    if online:
        s["online"] = online
    if tcp:
        s["tcp"] = tcp
    if udp:
        s["udp"] = udp
    if osscan:
        s["osscan"] = osscan
    return s


def port(state="open", name="", version=""):
    return {"state": state, "name": name, "version": version}


def main():
    fails = []

    # --- ScanRun: needs_run podle stavu (resume = jen úspěšné přeskočit) ---
    run = ScanRun("scan_1", targets=["1.1.1.1"], enabled_phases={p: True for p in
                  ["online", "tcp", "udp", "vuln", "osscan"]})
    run.set_status("1.1.1.1", "online", "online")
    run.set_status("1.1.1.1", "tcp", "hotovo")
    run.set_status("1.1.1.1", "udp", "chyba")        # chyba → re-run
    run.set_status("1.1.1.1", "vuln", "probíhá")     # přerušeno → re-run
    # osscan: žádný stav → re-run
    if run.needs_run("1.1.1.1", "online"):
        fails.append("online (online) by se NEměl spouštět znovu")
    if run.needs_run("1.1.1.1", "tcp"):
        fails.append("tcp (hotovo) by se NEměl spouštět znovu")
    if not run.needs_run("1.1.1.1", "udp"):
        fails.append("udp (chyba) by se MĚL spustit znovu")
    if not run.needs_run("1.1.1.1", "vuln"):
        fails.append("vuln (probíhá) by se MĚL spustit znovu")
    if not run.needs_run("1.1.1.1", "osscan"):
        fails.append("osscan (chybí) by se MĚL spustit znovu")
    if not run.is_incomplete():
        fails.append("run by měl být incomplete")
    c = run.counts()
    if c != {"done": 2, "error": 1, "pending": 2}:
        fails.append(f"counts špatně: {c}")

    # offline se počítá jako hotové (online fáze proběhla)
    run2 = ScanRun("scan_x", targets=["2.2.2.2"], enabled_phases={"online": True})
    run2.set_status("2.2.2.2", "online", "offline")
    if run2.needs_run("2.2.2.2", "online"):
        fails.append("online (offline) je dokončené, nemá se opakovat")
    if "offline" not in SUCCESS_STATUSES:
        fails.append("offline má patřit mezi SUCCESS_STATUSES")

    # --- RunHistory: serializace roundtrip + master cíle ---
    h = RunHistory(master_targets=["1.1.1.1"])
    h.add_run(run)
    h.merge_master_targets(["1.1.1.1", "3.3.3.3"])  # 1.1.1.1 už je, 3.3.3.3 nový
    if h.master_targets != ["1.1.1.1", "3.3.3.3"]:
        fails.append(f"merge_master_targets špatně: {h.master_targets}")
    if h.active_run_id != "scan_1":
        fails.append("aktivní běh má být scan_1")
    if h.next_label() != "Běh 2":
        fails.append(f"next_label špatně: {h.next_label()}")

    h2 = RunHistory.from_dict(h.to_dict())
    if h2.master_targets != h.master_targets or h2.active_run_id != h.active_run_id:
        fails.append("RunHistory roundtrip: master/active nesedí")
    if len(h2.runs) != 1 or h2.runs[0].get_status("1.1.1.1", "tcp") != "hotovo":
        fails.append("RunHistory roundtrip: stav fáze nesedí")
    if h2.remove("scan_1") is None or h2.active_run_id is not None:
        fails.append("remove běhu nefunguje (active má spadnout na None)")

    # --- diff_snapshots ---
    a = snap(
        online={"1.1.1.1": {"status": {"state": "up"}}},
        tcp={"1.1.1.1": {"tcp": {"22": port(name="ssh"), "80": port(name="http", version="1.0")}}},
        osscan={"1.1.1.1": {"osmatch": [{"name": "Linux 5.0"}]}},
    )
    b = snap(
        online={"1.1.1.1": {"status": {"state": "up"}}},
        tcp={"1.1.1.1": {"tcp": {
            "22": port(name="ssh"),
            "80": port(name="http", version="2.0"),   # změna verze
            "443": port(name="https"),                # nový port
        }}},
        osscan={"1.1.1.1": {"osmatch": [{"name": "Linux 6.0"}]}},  # změna OS
    )
    d = diff_snapshots(a, b)
    e = d.get("1.1.1.1", {})
    if e.get("added") != [("tcp", 443)]:
        fails.append(f"diff added špatně: {e.get('added')}")
    # port 80 stále open v obou, ale změnila se verze → changed; nic removed
    if e.get("removed"):
        fails.append(f"diff removed má být prázdné: {e.get('removed')}")
    changed_ports = [k for (k, _pa, _pb) in e.get("changed", [])]
    if changed_ports != [("tcp", 80)]:
        fails.append(f"diff changed špatně: {changed_ports}")
    if e.get("os_changed") != ("Linux 5.0", "Linux 6.0"):
        fails.append(f"diff os_changed špatně: {e.get('os_changed')}")

    # zavřený/zmizelý port: A má 8080 open, B ne
    a2 = snap(tcp={"9.9.9.9": {"tcp": {"8080": port()}}})
    b2 = snap(tcp={"9.9.9.9": {"tcp": {}}})
    d2 = diff_snapshots(a2, b2).get("9.9.9.9", {})
    if d2.get("removed") != [("tcp", 8080)]:
        fails.append(f"diff removed (zmizelý port) špatně: {d2.get('removed')}")

    # --- status_from_data / phase_status_from_snapshot (migrace starých projektů) ---
    if status_from_data("online", {"status": {"state": "up"}}) != "online":
        fails.append("status_from_data online up špatně")
    if status_from_data("online", {"status": {"state": "down"}}) != "offline":
        fails.append("status_from_data online down špatně")
    if status_from_data("tcp", {"error": "x"}) != "chyba":
        fails.append("status_from_data error špatně")
    if status_from_data("tcp", {"status": "skipped_by_user"}) != "zakázáno":
        fails.append("status_from_data zakázáno špatně")
    if status_from_data("tcp", {"tcp": {"22": port()}}) != "hotovo":
        fails.append("status_from_data hotovo špatně")
    snap_mig = snap(
        online={"1.1.1.1": {"status": {"state": "up"}}, "2.2.2.2": {"status": {"state": "down"}}},
        tcp={"1.1.1.1": {"tcp": {"22": port()}}, "2.2.2.2": {"error": "timeout"}},
    )
    ps = phase_status_from_snapshot(snap_mig)
    if ps.get("1.1.1.1", {}).get("online") != "online" or ps.get("1.1.1.1", {}).get("tcp") != "hotovo":
        fails.append(f"phase_status_from_snapshot .1 špatně: {ps.get('1.1.1.1')}")
    if ps.get("2.2.2.2", {}).get("tcp") != "chyba":
        fails.append(f"phase_status_from_snapshot .2 tcp špatně: {ps.get('2.2.2.2')}")
    if targets_from_snapshot(snap_mig) != ["1.1.1.1", "2.2.2.2"]:
        fails.append(f"targets_from_snapshot špatně: {targets_from_snapshot(snap_mig)}")

    if fails:
        print("❌ SELHALO:")
        for f in fails:
            print("  -", f)
        return 1
    print("✅ test_run_history: VŠE OK (needs_run/resume, counts, serializace, master cíle, diff, migrace).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
