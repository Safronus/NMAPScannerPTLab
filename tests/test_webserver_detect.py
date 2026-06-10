"""Headless test detekce webového serveru (core.webserver_detect)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nmapscanner.core.webserver_detect import detect_server

CASES = [
    # (kwargs, očekávaná family)
    (dict(server="Microsoft-IIS/10.0"), "IIS"),
    (dict(server="nginx/1.24.0"), "nginx"),
    (dict(server="Apache/2.4.57 (Unix)"), "Apache"),
    (dict(server="Apache-Coyote/1.1"), "Tomcat"),          # ne Apache!
    (dict(server="openresty/1.21.4.1"), "OpenResty"),      # ne nginx
    (dict(server="LiteSpeed"), "LiteSpeed"),
    (dict(server="cloudflare"), "Cloudflare"),
    (dict(server="Kestrel"), "Kestrel"),
    # z nmap -sV product, když není HTTP hlavička
    (dict(nmap_product="Microsoft IIS httpd", server=""), "IIS"),
    (dict(nmap_product="nginx"), "nginx"),
    (dict(nmap_product="Apache httpd 2.4.57"), "Apache"),
    # X-Powered-By jako poslední záchrana
    (dict(server="", powered_by="ASP.NET"), "neznámý"),    # ASP.NET sám rodinu serveru neurčí
    # priorita: HTTP Server přebije nmap
    (dict(server="nginx/1.25", nmap_product="Apache httpd"), "nginx"),
    # nic
    (dict(), "neznámý"),
    (dict(server="SomeRandomServer/1.0"), "neznámý"),
]


def main():
    fails = []
    for kwargs, expected in CASES:
        fam, detail, src = detect_server(**kwargs)
        if fam != expected:
            fails.append(f"{kwargs} → {fam} (čekáno {expected})")

    # detail a source se vyplní
    fam, detail, src = detect_server(server="Microsoft-IIS/10.0")
    if detail != "Microsoft-IIS/10.0" or src != "header":
        fails.append(f"detail/source špatně: {detail!r}/{src!r}")
    fam, detail, src = detect_server(nmap_product="nginx")
    if src != "nmap":
        fails.append(f"source u nmap má být 'nmap', je {src!r}")

    if fails:
        print("❌ SELHALO:")
        for f in fails:
            print("  -", f)
        return 1
    print(f"✅ test_webserver_detect: VŠE OK — {len(CASES)} případů (IIS/Apache/nginx/Tomcat/…).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
