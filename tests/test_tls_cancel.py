"""Headless test zrušitelnosti TLS workerů (Inspektor TLS).

Qualys SSL Labs API se polluje klidně i pár minut na cíl — během toho musí jít
běh zastavit a workery se musí ukončit bez čekání na celý poll. Test ověřuje:
  1) všechny tři workery přijmou ``cancel_event`` (kompat. signatura),
  2) Qualys s předem nastaveným zrušením skončí stavem ``Zrušeno`` a vůbec
     nesáhne na síť (kontrola je na začátku poll-smyčky),
  3) ``_wait_or_cancel`` se probudí okamžitě po zrušení (ne až po N sekundách).
"""
import os
import sys
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import shutil

from nmapscanner.workers.tls import (
    SslLabsWorker, TestSslWorker, TlsAuditWorker, SslyzeWorker, SslscanWorker
)


class _FakeSig:
    def __init__(self):
        self.calls = []

    def emit(self, *a):
        self.calls.append(a)

    def connect(self, *a):
        pass


class _FakeSignals:
    def __init__(self):
        self.result = _FakeSig()
        self.finished = _FakeSig()


def main():
    fails = []

    # 1) kompatibilní signatura — všechny workery přijmou cancel_event i bez něj
    ev = threading.Event()
    for cls in (TlsAuditWorker, SslLabsWorker, TestSslWorker, SslyzeWorker, SslscanWorker):
        try:
            cls("1.1.1.1", "443", _FakeSignals(), ev)
            cls("1.1.1.1", "443", _FakeSignals())  # bez cancel_event (default None)
        except TypeError as e:
            fails.append(f"{cls.__name__} nepřijal cancel_event: {e}")

    # 1b) chybějící nástroj → 'Chyba' s návodem na instalaci + finished
    #     (deterministické jen, když nástroj NENÍ dostupný — jinak by se spustil
    #     reálný subprocess, což v testu nechceme). sslyze bývá jen modul, proto
    #     u něj kontrolujeme dostupnost přes _sslyze_base_cmd, ne jen PATH.
    sslscan_available = shutil.which("sslscan") is not None
    sslyze_available = SslyzeWorker._sslyze_base_cmd() is not None
    checks = []
    if not sslscan_available:
        checks.append((SslscanWorker, "brew install"))
    if not sslyze_available:
        checks.append((SslyzeWorker, "pip install"))
    for cls, hint in checks:
        s = _FakeSignals()
        cls("1.2.3.4", "443", s).run()
        recs = [c[2] for c in s.result.calls if len(c) >= 3]
        if not recs or recs[-1].get("status") != "Chyba" or hint not in (recs[-1].get("error") or ""):
            fails.append(f"{cls.__name__} bez nástroje nehlásí instalaci: {recs[-1] if recs else None}")
        if not s.finished.calls:
            fails.append(f"{cls.__name__} bez nástroje neemitoval finished")

    # 2) Qualys s předem nastaveným zrušením → 'Zrušeno' bez síťového dotazu.
    #    'example.com' není IP, takže _resolve_host nesahá na DNS; kontrola
    #    zrušení je hned na začátku smyčky, tedy před prvním requests.get.
    ev2 = threading.Event()
    ev2.set()
    sig = _FakeSignals()
    SslLabsWorker("example.com", "443", sig, ev2).run()
    statuses = [c[2].get("status") for c in sig.result.calls if len(c) >= 3]
    if not statuses or statuses[-1] != "Zrušeno":
        fails.append(f"Qualys nezrušeno (stavy={statuses})")
    if not sig.finished.calls:
        fails.append("Qualys neemitoval finished po zrušení")

    # 3) _wait_or_cancel se probudí okamžitě po zrušení
    ev3 = threading.Event()
    w3 = SslLabsWorker("example.com", "443", _FakeSignals(), ev3)
    ev3.set()
    t0 = time.monotonic()
    woke = w3._wait_or_cancel(10)
    dt = time.monotonic() - t0
    if not woke or dt > 1.0:
        fails.append(f"_wait_or_cancel nereaguje na zrušení (woke={woke}, dt={dt:.2f}s)")

    # 4) _wait_or_cancel bez zrušení proběhne celou dobu (ale krátce)
    w4 = SslLabsWorker("example.com", "443", _FakeSignals(), threading.Event())
    t0 = time.monotonic()
    woke = w4._wait_or_cancel(1)
    dt = time.monotonic() - t0
    if woke or dt < 0.9:
        fails.append(f"_wait_or_cancel se ukončil předčasně (woke={woke}, dt={dt:.2f}s)")

    # 5) _run_killable vrátí výstup; TLS_PROCS.terminate_all() umí zabít proces
    #    (kvůli rychlému zavírání appky — global pool pak nečeká na timeout).
    import subprocess
    from nmapscanner.workers.tls import _run_killable, TLS_PROCS
    out, rc = _run_killable(["echo", "halo"], timeout=5)
    if "halo" not in out or rc != 0:
        fails.append(f"_run_killable echo selhal: out={out!r} rc={rc}")
    p = subprocess.Popen(["sleep", "30"])
    TLS_PROCS.add(p)
    TLS_PROCS.terminate_all()
    try:
        p.wait(timeout=3)
    except subprocess.TimeoutExpired:
        fails.append("TLS_PROCS.terminate_all nezabil proces (sleep běží dál)")
    if p.returncode is None:
        fails.append("proces po terminate_all stále běží")

    if fails:
        print("❌ SELHALO:")
        for f in fails:
            print("  -", f)
        return 1
    print("✅ test_tls_cancel: VŠE OK — workery zrušitelné, Qualys končí 'Zrušeno' bez sítě.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
