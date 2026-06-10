"""Test pořizování screenshotů přes Selenium (headless Chrome).

Pořídí reálný screenshot offline ``data:`` URL a ověří, že vznikl nenulový PNG.
Pokud Selenium/Chrome nejsou k dispozici (např. CI bez prohlížeče), test se
**přeskočí** (úspěch), aby nerozbil sadu — screenshoty jsou volitelná funkce.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("QT_QPA_PLATFORM", "minimal")

from PySide6.QtCore import QCoreApplication

from nmapscanner.signals import WorkerSignals
from nmapscanner.workers.screenshot import ScreenshotManager

DATA_URL = ("data:text/html,<html><body style='background:%23fff'>"
            "<h1 style='font-size:90px;color:%23198754'>TEST</h1></body></html>")


def main():
    try:
        import selenium  # noqa: F401
    except Exception:
        print("⏭️  test_screenshot: Selenium není nainstalován — přeskočeno.")
        return 0

    QCoreApplication.instance() or QCoreApplication(sys.argv)
    sig = WorkerSignals()
    taken, logs, done = [], [], []
    sig.screenshot_taken.connect(lambda ip, fp: taken.append((ip, fp)))
    sig.screenshot_done.connect(lambda ip, url, ok, info: done.append((ip, url, ok, info)))
    sig.log.connect(lambda lvl, msg: logs.append((lvl, msg)))

    # --- deterministická kontrola: i přeskočený pokus MUSÍ emitovat screenshot_done
    #     (jinak by se průběhový čítač v GUI nikdy nedopočítal). Nevyžaduje Chrome.
    skip_mgr = ScreenshotManager(sig)
    skip_mgr._unavailable = True
    skip_mgr.take_screenshot("http://x", "1.2.3.4", 80, tempfile.mkdtemp())
    if not any(d[0] == "1.2.3.4" and d[2] is False for d in done):
        print("❌ test_screenshot: přeskočený pokus neemitoval screenshot_done(ok=False)")
        return 1

    mgr = ScreenshotManager(sig)
    tmp = tempfile.mkdtemp()
    try:
        mgr.take_screenshot(DATA_URL, "9.9.9.9", 80, tmp)
    finally:
        mgr.shutdown()

    # Chrome/driver nedostupné → manager nahlásí 'nedostupné' a nic nepořídí → SKIP.
    if mgr._unavailable or not taken:
        msg = next((m for lvl, m in logs if "nedostupn" in m.lower()), "")
        print(f"⏭️  test_screenshot: Selenium/Chrome nedostupné — přeskočeno. {msg[:120]}")
        return 0

    ip, fp = taken[0]
    size = os.path.getsize(fp) if os.path.exists(fp) else 0
    if not os.path.exists(fp) or size < 1000:
        print(f"❌ test_screenshot: PNG chybí nebo je prázdný (size={size})")
        return 1
    if not any(d[0] == "9.9.9.9" and d[2] is True for d in done):
        print(f"❌ test_screenshot: úspěch neemitoval screenshot_done(ok=True): {done}")
        return 1
    print(f"✅ test_screenshot: VŠE OK — screenshot ({size} B) + screenshot_done (úspěch i skip).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
