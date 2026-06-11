"""Testy obohacení (čistá logika bez sítě)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nmapscanner.core import enrichment as enr
from nmapscanner.core.report_classify import build_findings


def test_cvss_to_severity():
    assert enr.cvss_to_severity(10.0) == "CRITICAL"
    assert enr.cvss_to_severity(9.0) == "CRITICAL"
    assert enr.cvss_to_severity(8.2) == "HIGH"
    assert enr.cvss_to_severity(5.0) == "MEDIUM"
    assert enr.cvss_to_severity(3.9) == "LOW"
    assert enr.cvss_to_severity(0.0) == "INFO"
    assert enr.cvss_to_severity(None) == "INFO"


def test_product_slug():
    assert enr.product_slug("nginx") == "nginx"
    assert enr.product_slug("Apache httpd 2.4.41") == "apache-http-server"
    assert enr.product_slug("Apache Tomcat 8.5") == "tomcat"
    assert enr.product_slug("MariaDB 10.3") == "mariadb"
    assert enr.product_slug("phpMyAdmin 4.9") == "phpmyadmin"  # delší klíč napřed
    assert enr.product_slug("Něco neznámého") is None


def test_match_cycle():
    cycles = [{"cycle": "1.18"}, {"cycle": "1.20"}, {"cycle": "1.1"}]
    assert enr.match_cycle(cycles, "1.18.0")["cycle"] == "1.18"
    assert enr.match_cycle(cycles, "1.20.1")["cycle"] == "1.20"
    assert enr.match_cycle(cycles, "9.9.9") is None
    # nesmí splést 1.1 s 1.18
    assert enr.match_cycle(cycles, "1.18.5")["cycle"] == "1.18"


def test_eol_status():
    assert enr.eol_status({"eol": True})[0] is True
    assert enr.eol_status({"eol": False})[0] is False
    assert enr.eol_status({"eol": "2000-01-01"}, today="2026-06-11")[0] is True
    assert enr.eol_status({"eol": "2099-01-01"}, today="2026-06-11")[0] is False


def test_build_eol_from_enrichment():
    sr = {
        "tcp": {"10.0.0.1": {"tcp": {"80": {"state": "open", "name": "http",
                                            "product": "nginx", "version": "1.14.0"}}}},
        "enrichment": {"eol": {"10.0.0.1:80": {"is_eol": True, "eol_date": "2021-04-21",
                                               "latest": "1.27.0", "product": "nginx",
                                               "version": "1.14.0"}}},
    }
    r = build_findings(sr, sections=["eol"])
    assert r["total"] == 1
    f = r["findings"][0]
    assert "nginx" in f["title"] and "1.14.0" in f["title"]
    assert f["severity"] == "HIGH" and f["owasp"] == "A03"
    assert "1.27.0" in f["recommendation"] or "1.27.0" in f["evidence"]


def test_build_eol_skips_supported():
    sr = {"enrichment": {"eol": {"10.0.0.1:80": {"is_eol": False}}}}
    assert build_findings(sr, sections=["eol"])["total"] == 0


def test_cve_severity_from_enrichment():
    sr = {
        "vuln": {"10.0.0.1": {"tcp": {"445": {"script": {
            "x": "State: VULNERABLE IDs: CVE:CVE-2099-0001 something"}}}}},
        "enrichment": {"cve": {"CVE-2099-0001": {"cvss": 5.0, "severity": "MEDIUM"}}},
    }
    r = build_findings(sr, sections=["vulns"])
    assert r["total"] == 1
    assert r["findings"][0]["severity"] == "MEDIUM"  # z NVD, ne heuristika


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    fails = []
    for t in tests:
        try:
            t()
        except AssertionError as e:
            fails.append(f"{t.__name__}: {e or 'assert selhal'}")
        except Exception as e:  # noqa: BLE001
            fails.append(f"{t.__name__}: VÝJIMKA {type(e).__name__}: {e}")
    if fails:
        print("❌ SELHALO:")
        for f in fails:
            print("  -", f)
        return 1
    print(f"✅ test_enrichment: VŠE OK — {len(tests)} testů prošlo.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
