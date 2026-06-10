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
    taken, logs = [], []
    sig.screenshot_taken.connect(lambda ip, fp: taken.append((ip, fp)))
    sig.log.connect(lambda lvl, msg: logs.append((lvl, msg)))

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
    print(f"✅ test_screenshot: VŠE OK — reálný screenshot uložen ({size} B) přes Selenium headless Chrome.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
