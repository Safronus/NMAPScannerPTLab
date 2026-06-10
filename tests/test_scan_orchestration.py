"""Headless testy adaptivního orchestrátoru skenu (bez GUI, bez nmapu).

Spuštění z kořene projektu:

    .venv/bin/python tests/test_scan_orchestration.py

Test využívá ``QCoreApplication`` (nepotřebuje Qt platform plugin) a podstrkává
``ScanWorker``\\u-u falešné ``subprocess.run``, které vrací připravený nmap XML.
Ověřuje: pipeline per cíl, de-eskalaci při chybě/timeoutu, ``-Pn`` fallback,
zaměření ``vuln`` na nalezené porty a korektní dokončení workflow.
"""
import os
import sys
import types

# Kořen projektu na sys.path, ať jde test spustit odkudkoli.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("QT_QPA_PLATFORM", "minimal")

from PySide6.QtCore import QCoreApplication, QTimer

import nmapscanner.workers.scan as scanmod
from nmapscanner.signals import WorkerSignals
from nmapscanner.core.scan_manager import ScanManager
from nmapscanner.core import scan_profiles as sp

TARGETS = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def xml_up(ip, tcp=(), udp=(), osmatch=False):
    ports = ""
    for p in tcp:
        ports += (f'<port protocol="tcp" portid="{p}"><state state="open" '
                  f'reason="syn-ack"/><service name="svc{p}"/></port>')
    for p in udp:
        ports += (f'<port protocol="udp" portid="{p}"><state state="open" '
                  f'reason="udp"/><service name="usvc{p}"/></port>')
    os_xml = '<os><osmatch name="Linux 5.X" accuracy="95"/></os>' if osmatch else ''
    return (f'<?xml version="1.0"?><nmaprun scanner="nmap" args="x" start="1" version="7.99">'
            f'<host><status state="up" reason="syn-ack"/><address addr="{ip}" addrtype="ipv4"/>'
            f'<hostnames></hostnames><ports>{ports}</ports>{os_xml}</host>'
            f'<runstats><finished time="2" elapsed="1.0"/>'
            f'<hosts up="1" down="0" total="1"/></runstats></nmaprun>')


def xml_down(ip):
    return (f'<?xml version="1.0"?><nmaprun scanner="nmap" args="x" start="1" version="7.99">'
            f'<host><status state="down" reason="no-response"/>'
            f'<address addr="{ip}" addrtype="ipv4"/></host>'
            f'<runstats><finished time="2" elapsed="1.0"/>'
            f'<hosts up="0" down="1" total="1"/></runstats></nmaprun>')


def run_workflow():
    calls = {}
    seen_cmds = []

    def R(rc=0, out="", err=""):
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr=err)

    def fake_run(cmd, **kw):
        import subprocess as _sp
        s = " ".join(cmd)
        seen_cmds.append(s)
        tgt = next((t for t in TARGETS if t in s), "?")
        if "-sn" in cmd:
            phase = "online"
        elif "-sU" in cmd:
            phase = "udp"
        elif "-O" in cmd:
            phase = "osscan"
        elif "--script" in cmd:
            phase = "vuln"
        else:
            phase = "tcp"
        n = calls.get((tgt, phase), 0)
        calls[(tgt, phase)] = n + 1
        pn = "-Pn" in cmd

        if phase == "online":
            return R(0, xml_up(tgt) if tgt in ("10.0.0.1", "10.0.0.3") else xml_down(tgt))

        if tgt == "10.0.0.1":  # online host, vše projde na první příčce
            if phase == "tcp":
                return R(0, xml_up(tgt, tcp=(22, 80)))
            if phase == "udp":
                return R(0, xml_up(tgt, udp=(53,)))
            if phase == "osscan":
                return R(0, xml_up(tgt, osmatch=True))
            if phase == "vuln":
                return R(0, xml_up(tgt, tcp=(22, 80)))

        if tgt == "10.0.0.2":  # ping blokován → deep musí běžet rovnou s -Pn
            assert pn, f"{tgt}/{phase} běží bez -Pn, ač host hlášen down"
            return R(0, xml_up(tgt, tcp=(443,))) if phase == "tcp" else R(0, xml_up(tgt))

        if tgt == "10.0.0.3":  # tcp 2× fail→3.příčka; udp timeout→ok; osscan fail→ok
            if phase == "tcp":
                return R(1, "", "dummy error") if n < 2 else R(0, xml_up(tgt, tcp=(8080,)))
            if phase == "udp":
                if n < 1:
                    raise _sp.TimeoutExpired(cmd, kw.get("timeout", 1))
                return R(0, xml_up(tgt, udp=(123,)))
            if phase == "osscan":
                return R(1, "", "os fail") if n < 1 else R(0, xml_up(tgt, osmatch=True))
            if phase == "vuln":
                return R(0, xml_up(tgt, tcp=(8080,)))
        return R(0, xml_up(tgt))

    scanmod.subprocess.run = fake_run

    app = QCoreApplication.instance() or QCoreApplication(sys.argv)
    sig = WorkerSignals()
    mgr = ScanManager(sig, max_concurrent=4)

    results, progress = [], {}
    sig.result.connect(lambda ph, t, d: results.append((ph, t, dict(d))))
    sig.phase_progress.connect(lambda ph, c, tot: progress.__setitem__(ph, (c, tot)))
    done = {"v": False}
    mgr.workflow_finished.connect(lambda: done.__setitem__("v", True))

    mgr.start_workflow(TARGETS, "master", {p: True for p in sp.PHASES}, "")

    def poll(tries=[0]):
        mgr.thread_pool.waitForDone(50)
        app.processEvents()
        tries[0] += 1
        if done["v"] or tries[0] > 400:
            app.quit()
        else:
            QTimer.singleShot(25, poll)

    QTimer.singleShot(0, poll)
    app.exec()
    return done["v"], results, progress, calls, seen_cmds


def main():
    done, results, progress, calls, seen_cmds = run_workflow()
    fails = []

    if not done:
        fails.append("workflow_finished se neemitoval")
    for ph in sp.PHASES:
        c, tot = progress.get(ph, (0, 0))
        if not (tot == 3 and c == 3):
            fails.append(f"progress[{ph}] = {c}/{tot}, čekáno 3/3")

    def find(ph, t):
        return next((d for (p, tt, d) in results if p == ph and tt == t), None)

    if find("online", "10.0.0.1") != {"status": {"state": "up"}}:
        fails.append("online .1 není up")
    if find("online", "10.0.0.2") != {"status": {"state": "down"}}:
        fails.append("online .2 není down")

    d1 = find("tcp", "10.0.0.1")
    if not (d1 and set(int(x) for x in d1.get("tcp", {})) == {22, 80}):
        fails.append(f"tcp .1 porty špatně: {d1}")
    d3 = find("tcp", "10.0.0.3")
    if not (d3 and 8080 in [int(x) for x in d3.get("tcp", {})]):
        fails.append(f"tcp .3 po de-eskalaci špatně: {d3}")
    if calls.get(("10.0.0.3", "tcp")) != 3:
        fails.append(f"tcp .3 počet pokusů = {calls.get(('10.0.0.3', 'tcp'))}, čekáno 3 (de-eskalace)")
    if calls.get(("10.0.0.3", "udp")) != 2:
        fails.append(f"udp .3 počet pokusů = {calls.get(('10.0.0.3', 'udp'))}, čekáno 2 (timeout→zmírnit)")

    vuln_cmd_1 = next((c for c in seen_cmds if "--script" in c and "10.0.0.1" in c), "")
    if "-p 22,80" not in vuln_cmd_1:
        fails.append(f"vuln .1 není zaměřen na nalezené porty: {vuln_cmd_1}")

    d2 = find("tcp", "10.0.0.2")
    if not (d2 and 443 in [int(x) for x in d2.get("tcp", {})]):
        fails.append(f"tcp .2 (-Pn fallback) špatně: {d2}")
    if len(results) != 15:
        fails.append(f"terminálních výsledků {len(results)}, čekáno 15 (5 fází × 3 cíle)")

    if fails:
        print("❌ SELHALO:")
        for f in fails:
            print("  -", f)
        return 1
    print("✅ test_scan_orchestration: VŠE OK "
          "(pipeline, de-eskalace, -Pn fallback, vuln scope, dokončení).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
