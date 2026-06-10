"""Headless test bezpečného předání sudo hesla nmap workeru.

Klíčová bezpečnostní vlastnost: heslo se předává jen na **stdin** (`sudo -S`),
NIKDY ne na příkazovou řádku (nebylo by vidět v `ps`). Ověřuje i tři režimy:
root (bez sudo), sudo bez hesla (NOPASSWD/cache) a sudo s heslem.
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("QT_QPA_PLATFORM", "minimal")

from PySide6.QtCore import QCoreApplication

import nmapscanner.workers.scan as scanmod
from nmapscanner.signals import WorkerSignals

ONLINE_XML = (b'<?xml version="1.0"?><nmaprun version="7.99"><host>'
              b'<status state="up"/><address addr="1.2.3.4" addrtype="ipv4"/></host>'
              b'<runstats><finished elapsed="1"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>')


def run_worker(sudo_password=None, use_sudo=True):
    captured = {}

    def fake_run(argv, input=None, **kw):
        captured["argv"] = list(argv)
        captured["input"] = input
        return types.SimpleNamespace(returncode=0, stdout=ONLINE_XML, stderr=b"")

    scanmod.subprocess.run = fake_run
    sig = WorkerSignals()
    w = scanmod.ScanWorker("online", "1.2.3.4", 0, "nmap -sn -T4 -oX - 1.2.3.4",
                           "ONLINE", False, 120, sig,
                           sudo_password=sudo_password, use_sudo=use_sudo)
    w.run()  # synchronně
    return captured


def main():
    QCoreApplication.instance() or QCoreApplication(sys.argv)
    fails = []

    secret = bytearray(b"S3cr3t!heslo")

    # 1) sudo s heslem → 'sudo -S -p ''' + heslo na stdin, NE v argv
    c = run_worker(sudo_password=secret, use_sudo=True)
    argv, inp = c["argv"], c["input"]
    if argv[:4] != ["sudo", "-S", "-p", ""]:
        fails.append(f"sudo+heslo: argv prefix špatně: {argv[:4]}")
    if inp != bytes(secret) + b"\n":
        fails.append(f"sudo+heslo: heslo se nepředalo na stdin: {inp!r}")
    if any("S3cr3t" in str(a) for a in argv):
        fails.append("BEZPEČNOST: heslo je v argv (viditelné v ps)!")
    if "nmap" not in argv or "-sn" not in argv:
        fails.append(f"sudo+heslo: chybí nmap příkaz v argv: {argv}")

    # 2) sudo bez hesla (cache/NOPASSWD) → 'sudo -n nmap …', stdin None
    c = run_worker(sudo_password=None, use_sudo=True)
    if c["argv"][:2] != ["sudo", "-n"]:
        fails.append(f"sudo bez hesla: argv prefix špatně: {c['argv'][:2]}")
    if c["input"] is not None:
        fails.append("sudo bez hesla: na stdin nemá jít nic")

    # 3) už root → bez sudo
    c = run_worker(sudo_password=None, use_sudo=False)
    if c["argv"][0] != "nmap":
        fails.append(f"bez sudo: argv má začínat 'nmap', je: {c['argv'][:2]}")
    if "sudo" in c["argv"]:
        fails.append("bez sudo: 'sudo' nemá být v argv")

    # 4) vymazání hesla z RAM (bytearray vynulována)
    pw = bytearray(b"tajne")
    for i in range(len(pw)):
        pw[i] = 0
    if any(b != 0 for b in pw):
        fails.append("wipe: bytearray se nevynulovala")

    if fails:
        print("❌ SELHALO:")
        for f in fails:
            print("  -", f)
        return 1
    print("✅ test_sudo: VŠE OK — heslo jen na stdin (ne v ps), tři režimy sudo, wipe funguje.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
