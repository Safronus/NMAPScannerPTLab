"""Regrese: cross-thread (queued) signály s nmap daty nesmí spamovat
``_pythonToCppCopy: Cannot copy-convert (int) to C++``.

python-nmap vrací porty jako INT klíče (``{22: {...}}``). Kdyby signál nesl
``dict`` (ne ``object``), PySide by ho přes vlákna marshaloval na QVariantMap
(vyžaduje str klíče) a pro každý int port vypsal varování do terminálu. Test
přesměruje fd 2 do souboru, prožene threadovaný sken s porty a ověří, že žádné
takové varování nevzniklo a že data (int klíče) dorazila celá.
"""
import os
import sys
import types
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("QT_QPA_PLATFORM", "minimal")


def xml(ip, tcp=()):
    p = "".join(f'<port protocol="tcp" portid="{x}"><state state="open"/><service name="s{x}"/></port>' for x in tcp)
    return (f'<?xml version="1.0"?><nmaprun version="7.99"><host><status state="up"/>'
            f'<address addr="{ip}" addrtype="ipv4"/><ports>{p}</ports></host>'
            f'<runstats><finished elapsed="1"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>').encode()


def run_threaded_scan():
    from PySide6.QtCore import QCoreApplication, QObject, Signal, QThread, QTimer
    import nmapscanner.workers.scan as scanmod
    from nmapscanner.signals import WorkerSignals
    from nmapscanner.core.scan_manager import ScanManager

    def fake_run(cmd, **kw):
        return types.SimpleNamespace(returncode=0, stdout=xml("10.0.0.9", tcp=(22, 443, 8080)), stderr=b"")
    scanmod.subprocess.run = fake_run

    class Drv(QObject):
        start = Signal(list, str, dict, str, bool, dict)

    app = QCoreApplication.instance() or QCoreApplication(sys.argv)
    sig = WorkerSignals()
    mgr = ScanManager(sig, max_concurrent=4)
    th = QThread()
    mgr.moveToThread(th)
    th.start()
    drv = Drv()
    drv.start.connect(mgr.start_workflow)

    got = {"keys": None}
    sig.scan_result.connect(lambda ph, t, d, f: got.__setitem__("keys", sorted(int(k) for k in d.get("tcp", {})))
                            if ph == "tcp" and f else None)
    done = {"v": False}
    mgr.workflow_finished.connect(lambda: done.__setitem__("v", True))

    drv.start.emit(["10.0.0.9"], "master",
                   {"online": True, "tcp": True, "udp": False, "vuln": False, "osscan": False}, "", False, {})

    def poll(n=[0]):
        mgr.thread_pool.waitForDone(50)
        app.processEvents()
        n[0] += 1
        if done["v"] or n[0] > 200:
            app.quit()
        else:
            QTimer.singleShot(20, poll)

    QTimer.singleShot(0, poll)
    app.exec()
    th.quit()
    th.wait(2000)
    return got["keys"]


def main():
    # Zachytit i C++ zápisy na fd 2.
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".err")
    tmp_path = tmp.name
    tmp.close()
    saved_fd = os.dup(2)
    fd = os.open(tmp_path, os.O_WRONLY)
    os.dup2(fd, 2)
    os.close(fd)
    try:
        keys = run_threaded_scan()
    finally:
        os.dup2(saved_fd, 2)
        os.close(saved_fd)

    with open(tmp_path, encoding="utf-8", errors="replace") as f:
        err = f.read()
    os.unlink(tmp_path)

    fails = []
    if "_pythonToCppCopy" in err:
        n = err.count("_pythonToCppCopy")
        fails.append(f"{n}× _pythonToCppCopy spam ve stderr (signál nese dict s int klíči?)")
    if keys != [22, 443, 8080]:
        fails.append(f"data nedorazila celá: porty {keys}, čekáno [22,443,8080]")

    if fails:
        print("❌ SELHALO:")
        for x in fails:
            print("  -", x)
        return 1
    print("✅ test_signal_marshal: VŠE OK — žádný _pythonToCppCopy spam, int klíče portů dorazily.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
