"""Regrese pro crash při zavírání appky během běžícího skenu.

Ověřuje: (1) emise signálu přežije zničený C++ objekt (RuntimeError),
(2) worker se při ``registry.stopped`` vrátí brzo a nic nehlásí,
(3) ``terminate_all`` zabije sledované procesy a nastaví ``stopped``.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("QT_QPA_PLATFORM", "minimal")

from PySide6.QtCore import QCoreApplication

from nmapscanner.signals import WorkerSignals
from nmapscanner.workers.scan import ScanWorker, ProcessRegistry, _safe_emit


def main():
    QCoreApplication.instance() or QCoreApplication(sys.argv)
    fails = []

    # 1) _safe_emit pohltí RuntimeError "Signal source has been deleted"
    class Boom:
        def emit(self, *a):
            raise RuntimeError("Signal source has been deleted")
    try:
        _safe_emit(Boom(), "x", "y")
    except Exception as e:
        fails.append(f"_safe_emit nepohltil RuntimeError: {e!r}")

    # 2) registry.stopped → worker se vrátí hned a NIC neemituje
    reg = ProcessRegistry()
    reg.stopped = True
    sig = WorkerSignals()
    got = []
    sig.task_outcome.connect(lambda *a: got.append(a))
    sig.task_started.connect(lambda *a: got.append(("started",) + a))
    w = ScanWorker("tcp", "1.1.1.1", 0, "nmap -sS 1.1.1.1", "TCP", False, 10, sig, registry=reg)
    w.run()
    QCoreApplication.instance().processEvents()
    if got:
        fails.append(f"worker emitoval i při registry.stopped: {got}")

    # 3) terminate_all zabije sledované procesy a nastaví stopped
    class FakeProc:
        def __init__(self):
            self.killed = False

        def kill(self):
            self.killed = True

    reg2 = ProcessRegistry()
    p1, p2 = FakeProc(), FakeProc()
    reg2.add(p1)
    reg2.add(p2)
    reg2.terminate_all()
    if not (p1.killed and p2.killed):
        fails.append("terminate_all nezabil všechny procesy")
    if not reg2.stopped:
        fails.append("terminate_all nenastavil stopped=True")

    # 4) reset vyčistí a povolí další běh
    reg2.reset()
    if reg2.stopped:
        fails.append("reset nevynuloval stopped")

    if fails:
        print("❌ SELHALO:")
        for f in fails:
            print("  -", f)
        return 1
    print("✅ test_shutdown: VŠE OK — guard emisí, kill procesů, early-return při stopu.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
