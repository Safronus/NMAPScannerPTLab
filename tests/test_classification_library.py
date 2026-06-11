"""Testy referenční knihovny klasifikací (loader + accessory). Bez Qt."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nmapscanner.core import classification_library as lib


def test_default_library_loads():
    d = lib.default_library()
    assert "ports" in d and "headers" in d and "ffuf" in d and "tls_grade" in d


def test_port_rule_bilingual():
    cs = lib.port_rule(23, "cs")
    en = lib.port_rule(23, "en")
    assert cs["severity"] == "HIGH" and cs["owasp"] == "A04"
    assert "SSH" in cs["recommendation"] and "SSH" in en["recommendation"]
    assert cs["recommendation"] != en["recommendation"]


def test_port_default_and_unknown():
    assert lib.port_rule(99999, "cs") is None
    d = lib.port_default("cs")
    assert d["severity"] == "INFO"


def test_service_keyword_rule():
    r = lib.service_keyword_rule("ms-wbt-server", "cs")
    assert r and r["owasp"] == "A07"


def test_header_rule_recommended_value():
    h = lib.header_rule("Strict-Transport-Security", "en")
    assert h["recommended_value"].startswith("max-age=")
    assert h["severity"] == "MEDIUM"


def test_tls_grade_rule():
    assert lib.tls_grade_rule("F", "cs")["severity"] == "HIGH"
    assert lib.tls_grade_rule("A", "cs")["severity"] == "INFO"


def test_ffuf_rule_and_downgrade():
    r, kw = lib.ffuf_rule("/.git/config", "cs")
    assert r["severity"] == "CRITICAL" and kw == ".git"
    assert lib.ffuf_status_downgrade(403) == 1
    assert lib.ffuf_status_downgrade(200) == 0


def test_cve_rule_and_link():
    c = lib.cve_rule("CVE-2021-44228", "cs")
    assert c["severity"] == "CRITICAL"
    assert lib.cve_link("nvd", "CVE-2021-44228") == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"


def test_deep_merge_override():
    base = {"ports": {"23": {"severity": "HIGH"}}, "x": 1}
    over = {"ports": {"23": {"severity": "LOW"}, "24": {"severity": "INFO"}}}
    merged = lib._deep_merge(base, over)
    assert merged["ports"]["23"]["severity"] == "LOW"
    assert merged["ports"]["24"]["severity"] == "INFO"
    assert merged["x"] == 1


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
    print(f"✅ test_classification_library: VŠE OK — {len(tests)} testů prošlo.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
