"""Headless test navázání (resume) skenu — spustí jen ne-úspěšné fáze (celé,
včetně všech progresivních stupňů); úspěšné (cíl×fáze) přeskočí."""
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
from _fakeproc import make_fake_popen

T = ["10.0.0.1", "10.0.0.2"]


def xml(ip, tcp=(), udp=()):
    ports = "".join(f'<port protocol="tcp" portid="{p}"><state state="open"/><service name="s{p}"/></port>' for p in tcp)
    ports += "".join(f'<port protocol="udp" portid="{p}"><state state="open"/><service name="u{p}"/></port>' for p in udp)
    return (f'<?xml version="1.0"?><nmaprun version="7.99"><host><status state="up"/>'
            f'<address addr="{ip}" addrtype="ipv4"/><ports>{ports}</ports></host>'
            f'<runstats><finished elapsed="1"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>')


def main():
    calls = {}   # (target, phase) -> počet nmap volání

    def respond(argv, _input):
        tgt = next((t for t in T if t in " ".join(argv)), "?")
        ph = ("online" if "-sn" in argv else "udp" if "-sU" in argv else "osscan" if "-O" in argv
              else "vuln" if "--script" in argv else "tcp")
        calls[(tgt, ph)] = calls.get((tgt, ph), 0) + 1
        return (0, xml(tgt, udp=(53,)).encode(), b"")

    scanmod.subprocess.Popen = make_fake_popen(respond)

    app = QCoreApplication.instance() or QCoreApplication(sys.argv)
    sig = WorkerSignals()
    mgr = ScanManager(sig, max_concurrent=4)
    prog = {}
    sig.phase_progress.connect(lambda ph, c, t: prog.__setitem__(ph, (c, t)))
    done = {"v": False}
    mgr.workflow_finished.connect(lambda: done.__setitem__("v", True))

    enabled = {p: True for p in sp.PHASES}
    # .1: online/tcp/osscan hotové → zbývá udp + vuln; .2: online/tcp hotové → zbývá udp/vuln/osscan
    prior_status = {
        "10.0.0.1": {"online": "online", "tcp": "hotovo", "osscan": "hotovo"},
        "10.0.0.2": {"online": "online", "tcp": "hotovo"},
    }
    ctx = {"status": prior_status, "open_ports": {"10.0.0.1": [22], "10.0.0.2": [80]}, "needs_pn": {}}
    mgr.start_workflow(T, "master", enabled, "", True, ctx)

    def poll(n=[0]):
        mgr.thread_pool.waitForDone(50)
        app.processEvents()
        n[0] += 1
        if done["v"] or n[0] > 300:
            app.quit()
        else:
            QTimer.singleShot(20, poll)

    QTimer.singleShot(0, poll)
    app.exec()

    fails = []
    # .1: jen udp (2 stupně) + vuln; online/tcp/osscan NE
    for ph in ("online", "tcp", "osscan"):
        if ("10.0.0.1", ph) in calls:
            fails.append(f".1/{ph} se NEmělo spustit (hotové), spuštěno {calls[('10.0.0.1', ph)]}x")
    if calls.get(("10.0.0.1", "udp")) != 2:
        fails.append(f".1/udp = {calls.get(('10.0.0.1', 'udp'))} volání, čekáno 2 (2 stupně)")
    if ("10.0.0.1", "vuln") not in calls:
        fails.append(".1/vuln se mělo spustit")
    # .2: online/tcp NE; udp(2)/vuln/osscan ANO
    for ph in ("online", "tcp"):
        if ("10.0.0.2", ph) in calls:
            fails.append(f".2/{ph} se NEmělo spustit (hotové)")
    if calls.get(("10.0.0.2", "udp")) != 2:
        fails.append(f".2/udp = {calls.get(('10.0.0.2', 'udp'))} volání, čekáno 2")
    for ph in ("vuln", "osscan"):
        if ("10.0.0.2", ph) not in calls:
            fails.append(f".2/{ph} se mělo spustit")
    # progress: online 0/0, tcp 0/0, udp 4/4 (2 cíle × 2 stupně), vuln 2/2, osscan 1/1
    exp = {"online": (0, 0), "tcp": (0, 0), "udp": (4, 4), "vuln": (2, 2), "osscan": (1, 1)}
    for ph, e in exp.items():
        if prog.get(ph) != e:
            fails.append(f"progress[{ph}] = {prog.get(ph)}, čekáno {e}")
    if not done["v"]:
        fails.append("workflow_finished neproběhl")

    if fails:
        print("❌ SELHALO:")
        for f in fails:
            print("  -", f)
        return 1
    print("✅ test_scan_resume: VŠE OK — navázání spustí jen ne-úspěšné fáze (vč. všech stupňů), progress sedí.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
