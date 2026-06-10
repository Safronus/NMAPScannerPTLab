"""Headless testy progresivního orchestrátoru skenu (bez GUI, bez nmapu).

Ověřuje (od 4.3.0): progresivní stupně (rychlé top porty → plný sken se sloučením
výsledků), ``final`` příznak (průběžný vs finální výsledek), ``-Pn`` jako první
zmírnění při nedostupném pingu, zaměření ``vuln`` na nalezené porty a korektní
dokončení workflow.
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("QT_QPA_PLATFORM", "minimal")

from PySide6.QtCore import QCoreApplication, QTimer

import nmapscanner.workers.scan as scanmod
from nmapscanner.signals import WorkerSignals
from nmapscanner.core.scan_manager import ScanManager
from nmapscanner.core import scan_profiles as sp

TARGETS = ["10.0.0.1", "10.0.0.2"]


def xml(ip, up=True, tcp=(), udp=(), osmatch=False):
    if not up:
        return (f'<?xml version="1.0"?><nmaprun version="7.99"><host>'
                f'<status state="down" reason="no-response"/>'
                f'<address addr="{ip}" addrtype="ipv4"/></host>'
                f'<runstats><finished elapsed="1"/><hosts up="0" down="1" total="1"/></runstats></nmaprun>')
    ports = ""
    for p in tcp:
        ports += f'<port protocol="tcp" portid="{p}"><state state="open" reason="syn-ack"/><service name="s{p}"/></port>'
    for p in udp:
        ports += f'<port protocol="udp" portid="{p}"><state state="open" reason="udp"/><service name="u{p}"/></port>'
    os_xml = '<os><osmatch name="Linux 5.X" accuracy="95"/></os>' if osmatch else ''
    return (f'<?xml version="1.0"?><nmaprun version="7.99"><host><status state="up" reason="syn-ack"/>'
            f'<address addr="{ip}" addrtype="ipv4"/><ports>{ports}</ports>{os_xml}</host>'
            f'<runstats><finished elapsed="1"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>')


def run_workflow():
    seen_cmds = []

    def R(rc=0, out="", err=""):
        # Worker běží v bajtovém režimu (kvůli sudo heslu na stdin) → stdout/stderr bytes.
        return types.SimpleNamespace(
            returncode=rc,
            stdout=out.encode() if isinstance(out, str) else out,
            stderr=err.encode() if isinstance(err, str) else err)

    def fake_run(cmd, **kw):
        s = " ".join(cmd)
        seen_cmds.append(s)
        tgt = next((t for t in TARGETS if t in s), "?")
        pn = "-Pn" in cmd
        up = tgt == "10.0.0.1"   # .2 je „down" (ping selže)

        if "-sn" in cmd:                       # online
            return R(0, xml(tgt, up=up))
        # .2 down → hloubkové stupně musí běžet s -Pn
        if tgt == "10.0.0.2" and not pn:
            raise AssertionError(f"{tgt} hloubkový sken bez -Pn (ping selhal → má být -Pn)")

        if "-sU" in cmd:                       # udp (2 stupně)
            return R(0, xml(tgt, tcp=(), udp=(53,) if "--top-ports 100" in s else (53, 161)))
        if "-O" in cmd:                        # osscan
            return R(0, xml(tgt, osmatch=True))
        if "--script" in cmd:                  # vuln
            return R(0, xml(tgt, tcp=(22, 443)))
        # tcp (2 stupně): top 1000 → jen 22; -p- → 22 + 443
        if "--top-ports 1000" in s:
            return R(0, xml(tgt, tcp=(22,)))
        return R(0, xml(tgt, tcp=(22, 443)))   # -p-

    scanmod.subprocess.run = fake_run

    app = QCoreApplication.instance() or QCoreApplication(sys.argv)
    sig = WorkerSignals()
    mgr = ScanManager(sig, max_concurrent=4)

    results = []     # (phase, target, data, final)
    progress = {}
    sig.scan_result.connect(lambda ph, t, d, f: results.append((ph, t, dict(d), f)))
    sig.phase_progress.connect(lambda ph, c, tot: progress.__setitem__(ph, (c, tot)))
    done = {"v": False}
    mgr.workflow_finished.connect(lambda: done.__setitem__("v", True))

    mgr.start_workflow(TARGETS, "master", {p: True for p in sp.PHASES}, "")

    def poll(n=[0]):
        mgr.thread_pool.waitForDone(50)
        app.processEvents()
        n[0] += 1
        if done["v"] or n[0] > 400:
            app.quit()
        else:
            QTimer.singleShot(20, poll)

    QTimer.singleShot(0, poll)
    app.exec()
    return done["v"], results, progress, seen_cmds


def main():
    done, results, progress, seen_cmds = run_workflow()
    fails = []

    if not done:
        fails.append("workflow_finished se neemitoval")

    # progresivní stupně: tcp 2 stupně × 2 cíle = 4, udp 4, online 2, vuln 2, osscan 2
    exp = {"online": (2, 2), "tcp": (4, 4), "udp": (4, 4), "vuln": (2, 2), "osscan": (2, 2)}
    for ph, e in exp.items():
        if progress.get(ph) != e:
            fails.append(f"progress[{ph}] = {progress.get(ph)}, čekáno {e}")

    def finals(ph, t):
        return [d for (p, tt, d, f) in results if p == ph and tt == t and f]

    def all_events(ph, t):
        return [(d, f) for (p, tt, d, f) in results if p == ph and tt == t]

    # TCP .1: průběžný stupeň final=False, pak finální final=True; finální = sloučené porty {22,443}
    tcp_ev = all_events("tcp", "10.0.0.1")
    flags = [f for _d, f in tcp_ev]
    if flags != [False, True]:
        fails.append(f"tcp .1 final-příznaky = {flags}, čekáno [False, True] (progresivní)")
    ftcp = finals("tcp", "10.0.0.1")
    if not ftcp or set(int(x) for x in ftcp[-1].get("tcp", {})) != {22, 443}:
        fails.append(f"tcp .1 finální porty špatně (slučování stupňů): {ftcp[-1] if ftcp else None}")

    # online: .1 up, .2 down
    fon1 = finals("online", "10.0.0.1")
    fon2 = finals("online", "10.0.0.2")
    if not fon1 or fon1[-1] != {"status": {"state": "up"}}:
        fails.append("online .1 není up")
    if not fon2 or fon2[-1] != {"status": {"state": "down"}}:
        fails.append("online .2 není down")

    # vuln .1 zaměřen na sloučené otevřené porty (22,443)
    vuln_cmd = next((c for c in seen_cmds if "--script" in c and "10.0.0.1" in c), "")
    if "-p 22,443" not in vuln_cmd:
        fails.append(f"vuln .1 není zaměřen na nalezené porty: {vuln_cmd}")

    # .2 (-Pn) – žádný AssertionError = ok; finální tcp má 22+443
    ftcp2 = finals("tcp", "10.0.0.2")
    if not ftcp2 or 443 not in [int(x) for x in ftcp2[-1].get("tcp", {})]:
        fails.append(f"tcp .2 (-Pn) finální špatně: {ftcp2[-1] if ftcp2 else None}")

    # priorita: OS úloha má nejnižší prioritu
    if sp.priority("osscan", 0) >= sp.priority("vuln", 0) or sp.priority("vuln", 0) >= sp.priority("tcp", 0):
        fails.append("priorita fází není online>TCP>UDP>vuln>OS")

    if fails:
        print("❌ SELHALO:")
        for f in fails:
            print("  -", f)
        return 1
    print("✅ test_scan_orchestration: VŠE OK (progresivní stupně, slučování, final, -Pn, vuln scope, priorita).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
