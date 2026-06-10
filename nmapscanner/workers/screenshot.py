"""Pořizování screenshotů webových služeb přes Selenium (headless Chrome).

Proč Selenium a ne QtWebEngine: ``QWebEngineView.grab()`` na nezobrazeném
off-screen view vrací prázdný/null pixmap (web obsah se renderuje v odděleném
procesu a `grab()` ho nezachytí) — proto dřív screenshoty nikdy nevznikly.
Selenium řídí Chrome mimo proces, takže smí běžet **ve vlákně** a screenshot
spolehlivě uloží.

``ScreenshotManager`` žije ve vlastním vlákně, drží **jeden** znovupoužitý
headless Chrome (rychlejší než spouštět prohlížeč pro každý cíl) a zpracovává
požadavky sériově (jeden Selenium driver = jedna session, není thread-safe).
chromedriver se neinstaluje ručně — Selenium 4.6+ ho přes Selenium Manager
vyřeší sám, stačí mít nainstalovaný Google Chrome / Chromium.
"""
import os
import time
from datetime import datetime

from PySide6.QtCore import QObject, Slot

_CHROME_ARGS = (
    "--headless=new",
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--hide-scrollbars",
    "--ignore-certificate-errors",
    "--allow-insecure-localhost",
    "--window-size=1366,768",
)


class ScreenshotManager(QObject):
    """Sériově pořizuje screenshoty přes znovupoužitý headless Chrome."""

    def __init__(self, signals):
        super().__init__()
        self.signals = signals          # WorkerSignals: screenshot_taken, log
        self._driver = None
        self._unavailable = False       # Selenium/Chrome nejde → další pokusy přeskakuj

    @Slot(str, str, int, str)
    def take_screenshot(self, url, ip, port, path):
        if self._unavailable:
            return
        driver = self._ensure_driver()
        if driver is None:
            return

        from selenium.common.exceptions import TimeoutException, WebDriverException
        try:
            driver.set_page_load_timeout(20)
            try:
                driver.get(url)
            except TimeoutException:
                self.signals.log.emit(
                    "warning", f"⏱️ {url} – timeout načítání, pořizuji screenshot i tak…")

            time.sleep(2)  # nechat doběhnout vykreslení JS

            os.makedirs(path, exist_ok=True)
            fname = f"{ip.replace('.', '_')}_{port}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            filepath = os.path.join(path, fname)

            if driver.save_screenshot(filepath) and os.path.exists(filepath):
                self.signals.log.emit("info", f"📸 Screenshot {url} → {filepath}")
                self.signals.screenshot_taken.emit(ip, filepath)
            else:
                self.signals.log.emit("error", f"❌ Screenshot {url} se nepodařilo uložit.")
        except WebDriverException as e:
            self.signals.log.emit("error", f"❌ Screenshot {url} selhal: {str(e)[:140]}")
            self._reset_driver()  # driver mohl umřít → příště se vytvoří znovu
        except Exception as e:
            self.signals.log.emit("error", f"❌ Screenshot {url}: {str(e)[:140]}")

    def _ensure_driver(self):
        if self._driver is not None:
            return self._driver
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            opts = Options()
            for arg in _CHROME_ARGS:
                opts.add_argument(arg)
            # Selenium Manager (4.6+) si chromedriver vyřeší sám podle nainstalovaného Chrome.
            self._driver = webdriver.Chrome(options=opts)
            self.signals.log.emit("info", "🌐 Selenium (headless Chrome) připraven pro screenshoty.")
            return self._driver
        except Exception as e:
            self._unavailable = True
            self.signals.log.emit(
                "error",
                f"⚠️ Screenshoty nedostupné (Selenium/Chrome): {str(e)[:160]}. "
                "Nainstaluj Google Chrome nebo Chromium; chromedriver si Selenium stáhne sám.")
            return None

    def _reset_driver(self):
        try:
            if self._driver is not None:
                self._driver.quit()
        except Exception:
            pass
        self._driver = None

    @Slot()
    def shutdown(self):
        """Zavře headless Chrome (volat při ukončení aplikace)."""
        self._reset_driver()
