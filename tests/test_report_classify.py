"""Testy klasifikace nálezů do závažnosti + OWASP (bez Qt).

Spouští se ``python tests/test_report_classify.py`` (konvence repa, bez pytest).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nmapscanner.core.report_classify import (
    build_findings, worst, SEVERITY_RANK, OWASP_2025,
)


def _sample():
    return {
        "tcp": {
            "10.0.0.1": {
                "tcp": {
                    "22": {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "8.9"},
                    "23": {"state": "open", "name": "telnet"},
                    "3306": {"state": "open", "name": "mysql", "product": "MySQL", "version": "5.7"},
                    "80": {"state": "open", "name": "http", "product": "nginx", "version": "1.18"},
                    "9999": {"state": "open", "name": "unknown"},
                    "21": {"state": "closed", "name": "ftp"},
                }
            }
        },
        "vuln": {
            "10.0.0.1": {
                "tcp": {
                    "445": {"script": {
                        "smb-vuln-ms17-010": "State: VULNERABLE\nIDs: CVE:CVE-2017-0143 remote code execution",
                        "smb-double-pulsar": "Couldn't find any backdoors",
                    }}
                }
            }
        },
        "tls_audit": {
            "10.0.0.1:443": {
                "Nmap": {
                    "engine": "Nmap",
                    "protocols": {"sslv3": True, "tls1_2": True},
                    "cipher_tree": {"tls1_2": [{"name": "AES128-GCM", "grade_label": "WEAK"}]},
                }
            }
        },
        "certificates": {
            "10.0.0.1:443": {"status": "Expired", "cn": "old.example", "expiry": "2020-01-01", "days": -500},
        },
        "security_headers": {
            "10.0.0.1:443": {
                "ip": "10.0.0.1", "port": "443", "status": "Slabé zabezpečení",
                "headers": {
                    "Strict-Transport-Security": "CHYBÍ",
                    "Content-Security-Policy": "CHYBÍ",
                    "X-Frame-Options": "DENY",
                    "X-Content-Type-Options": "CHYBÍ",
                    "Referrer-Policy": "CHYBÍ",
                    "Permissions-Policy": "CHYBÍ",
                },
                "missing_count": 5,
            }
        },
        "ffuf": [
            {"url": "http://10.0.0.1:80/.git/config", "status": 200, "length": 92},
            {"url": "http://10.0.0.1:80/admin", "status": 403, "length": 12},
            {"url": "http://10.0.0.1:80/index.html", "status": 200, "length": 500},
            {"url": "http://10.0.0.1:80/images/", "status": 301, "length": 0},
            {"url": "http://10.0.0.1:80/none", "status": 404, "length": 0},
            {"_meta": "empty_scan", "url": "http://10.0.0.1:80"},
        ],
        "webserver": {
            "10.0.0.1": {"family": "nginx", "detail": "nginx/1.18.0", "source": "header"},
        },
    }


def test_telnet_is_high():
    r = build_findings(_sample(), sections=["ports"])
    telnet = [f for f in r["findings"] if "23/tcp" in f["title"]]
    assert telnet and telnet[0]["severity"] == "HIGH"
    assert telnet[0]["owasp"] == "A04"


def test_mysql_port_high_a01():
    r = build_findings(_sample(), sections=["ports"])
    mysql = [f for f in r["findings"] if f["target"] == "10.0.0.1:3306"]
    assert mysql and mysql[0]["severity"] == "HIGH" and mysql[0]["owasp"] == "A01"


def test_closed_port_ignored():
    r = build_findings(_sample(), sections=["ports"])
    assert not any(":21" in f["target"] for f in r["findings"])


def test_unknown_port_info():
    r = build_findings(_sample(), sections=["ports"])
    unk = [f for f in r["findings"] if f["target"] == "10.0.0.1:9999"]
    assert unk and unk[0]["severity"] == "INFO"


def test_vuln_confirmed_critical_cve():
    r = build_findings(_sample(), sections=["vulns"])
    # ms17-010 obsahuje "remote code execution" → CRITICAL, CVE → A03
    assert len(r["findings"]) == 1
    f = r["findings"][0]
    assert f["severity"] == "CRITICAL"
    assert f["owasp"] == "A03"


def test_vuln_clean_not_reported():
    r = build_findings(_sample(), sections=["vulns"])
    assert not any("double-pulsar" in f["title"] for f in r["findings"])


def test_tls_grade_and_cert():
    r = build_findings(_sample(), sections=["tls"])
    # SSLv3 → strop C → MEDIUM; WEAK šifry; ale SSLv3 dává C
    tls = [f for f in r["findings"] if f["category"] == "TLS audit" and "hodnocení" in f["title"]]
    assert tls and tls[0]["severity"] in ("MEDIUM", "HIGH")
    assert tls[0]["owasp"] == "A04"
    cert = [f for f in r["findings"] if "certifikátu" in f["title"]]
    assert cert and cert[0]["severity"] == "MEDIUM"


def test_headers_missing():
    r = build_findings(_sample(), sections=["headers"])
    assert len(r["findings"]) == 1
    f = r["findings"][0]
    # chybí HSTS+CSP (MEDIUM) → worst MEDIUM
    assert f["severity"] == "MEDIUM"
    assert f["owasp"] == "A02"
    assert "Strict-Transport-Security" in f["evidence"]


def test_ffuf_git_critical():
    r = build_findings(_sample(), sections=["ffuf"])
    git = [f for f in r["findings"] if ".git" in f["title"]]
    assert git and git[0]["severity"] == "CRITICAL"


def test_ffuf_admin_403_downgraded():
    r = build_findings(_sample(), sections=["ffuf"])
    admin = [f for f in r["findings"] if "/admin" in f["title"]]
    # /admin MEDIUM, ale 403 → o stupeň níž = LOW
    assert admin and admin[0]["severity"] == "LOW"


def test_ffuf_generic_aggregated_info():
    r = build_findings(_sample(), sections=["ffuf"])
    generic = [f for f in r["findings"] if "přístupných cest" in f["title"]]
    assert generic and generic[0]["severity"] == "INFO"


def test_ffuf_empty_scan_ignored():
    r = build_findings(_sample(), sections=["ffuf"])
    # 404 i empty_scan se nepočítají do generic agregace (index.html+images/ = 2)
    generic = [f for f in r["findings"] if "přístupných cest" in f["title"]]
    assert "2 přístupných" in generic[0]["title"]


def test_webserver_version_low():
    r = build_findings(_sample(), sections=["webserver"])
    assert r["findings"] and r["findings"][0]["severity"] == "LOW"


def test_summary_and_owasp_aggregation():
    r = build_findings(_sample())
    assert r["total"] == sum(r["summary"].values())
    # musí existovat aspoň jedna CRITICAL (git + ms17-010)
    assert r["summary"]["CRITICAL"] >= 2
    assert "A04" in r["owasp"] and "A01" in r["owasp"]
    # owasp worst je validní severita
    for a, info in r["owasp"].items():
        assert info["worst"] in SEVERITY_RANK


def test_min_severity_filter():
    r = build_findings(_sample(), min_severity="HIGH")
    assert all(SEVERITY_RANK[f["severity"]] <= SEVERITY_RANK["HIGH"] for f in r["findings"])
    assert all(f["severity"] in ("CRITICAL", "HIGH") for f in r["findings"])


def test_worst_helper():
    assert worst(["INFO", "LOW", "HIGH", "MEDIUM"]) == "HIGH"
    assert worst([]) == "INFO"


def test_owasp_catalogue_complete():
    assert len(OWASP_2025) == 10
    assert OWASP_2025["A01"] == "Broken Access Control"


def main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
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
    print(f"✅ test_report_classify: VŠE OK — {len(tests)} testů prošlo.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
