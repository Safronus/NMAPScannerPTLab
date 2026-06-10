"""Headless test klasifikace výstupu nmap vuln skriptů (core.vuln_classify).

Ověřuje, že benigní hlášky a chyby skriptů (ze screenshotu uživatele) se NEberou
jako zranitelnost — jen jednoznačně potvrzené nálezy.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nmapscanner.core.vuln_classify import classify_vuln_output, is_finding

CASES = [
    # (výstup, očekávaná třída)
    ("ERROR: Script execution failed (use -d to debug)", "error"),
    ("Couldn't find any CSRF vulnerabilities.", "clean"),
    ("Couldn't find any DOM based XSS.", "clean"),
    ("Couldn't find any stored XSS vulnerabilities.", "clean"),
    ("No reply from server (TIMEOUT)", "error"),
    ("Message: unknown error: net::ERR_CONNECTION_CLOSED", "error"),
    ("", "clean"),
    ("   ", "clean"),
    ("State: NOT VULNERABLE", "clean"),
    ("This host is NOT vulnerable to CVE-2017-5638", "clean"),
    # skutečné nálezy
    ("VULNERABLE:\nSlowloris DoS attack\n  State: VULNERABLE", "finding"),
    ("State: VULNERABLE\nIDS: CVE:CVE-2014-3704", "finding"),
    ("Risk factor: High\nExploitable: true", "finding"),
]


def main():
    fails = []
    for out, expected in CASES:
        got = classify_vuln_output(out)
        if got != expected:
            fails.append(f"{out[:40]!r} → {got} (čekáno {expected})")

    # is_finding konzistentní
    if is_finding("Couldn't find any CSRF vulnerabilities."):
        fails.append("is_finding špatně označil benigní hlášku za nález")
    if not is_finding("State: VULNERABLE"):
        fails.append("is_finding nepoznal potvrzený nález")

    # konfliktní: obsahuje VULNERABLE i NOT VULNERABLE → negativní vyhrává (clean)
    if classify_vuln_output("State: NOT VULNERABLE (no VULNERABLE state)") == "finding":
        fails.append("negativní výstup s 'VULNERABLE' substringem chybně označen za nález")

    if fails:
        print("❌ SELHALO:")
        for f in fails:
            print("  -", f)
        return 1
    print(f"✅ test_vuln_classify: VŠE OK — {len(CASES)} případů, benigní/chyby ≠ nález.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
