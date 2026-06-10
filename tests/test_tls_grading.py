"""Headless test TLS hodnocení proti ground-truth z Qualys SSL Labs.

Sada 47 cipher suites (3 INSECURE, 29 WEAK, 15 SECURE) byla extrahována z reálných
výsledků Qualys SSL Labs (4 cíle). Ověřuje, že `classify_cipher` klasifikuje
přesně jako Qualys, a že `calculate_grade` dává odpovídající celkovou známku.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nmapscanner.core.tls_grading import classify_cipher, calculate_grade

# --- Ground truth z Qualys SSL Labs ---
QUALYS_INSECURE = [
    "TLS_DHE_RSA_WITH_DES_CBC_SHA",
    "TLS_RSA_WITH_RC4_128_MD5",
    "TLS_RSA_WITH_RC4_128_SHA",
]
QUALYS_WEAK = [
    "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
    "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_CCM",
    "TLS_RSA_WITH_AES_128_CCM_8",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_CCM",
    "TLS_RSA_WITH_AES_256_CCM_8",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
    "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
]
QUALYS_SECURE = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_DHE_RSA_WITH_AES_128_CCM",
    "TLS_DHE_RSA_WITH_AES_128_CCM_8",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_CCM",
    "TLS_DHE_RSA_WITH_AES_256_CCM_8",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
]


def _ciphers(*labels):
    """Postaví cipher_tree s jednou fází obsahující šifry daných labelů."""
    return {"TLSv1.2": [{"grade_label": lbl} for lbl in labels]}


def main():
    fails = []

    for name in QUALYS_INSECURE:
        lbl = classify_cipher(name)[0]
        if lbl != "INSECURE":
            fails.append(f"{name}: dostal {lbl}, Qualys = INSECURE")
    for name in QUALYS_WEAK:
        lbl = classify_cipher(name)[0]
        if lbl != "WEAK":
            fails.append(f"{name}: dostal {lbl}, Qualys = WEAK")
    for name in QUALYS_SECURE:
        lbl = classify_cipher(name)[0]
        if lbl != "SECURE":
            fails.append(f"{name}: dostal {lbl}, Qualys = SECURE")

    total = len(QUALYS_INSECURE) + len(QUALYS_WEAK) + len(QUALYS_SECURE)

    # --- celková známka (dle reálných Qualys grade) ---
    # vx.hn: TLS1.2+1.3, jen silné šifry -> A (Qualys A+ kvůli HSTS, to nehodnotíme)
    g, _ = calculate_grade({"tls1_2": True, "tls1_3": True}, _ciphers("SECURE", "SECURE"))
    if g != "A":
        fails.append(f"grade vx.hn-like = {g}, čekáno A")
    # monahan-collier: silné + WEAK (CBC) -> strop B (Qualys B)
    g, _ = calculate_grade({"tls1_2": True, "tls1_3": True}, _ciphers("SECURE", "WEAK"))
    if g != "B":
        fails.append(f"grade monahan-like = {g}, čekáno B")
    # web.bnkcapital: obsahuje INSECURE (RC4/DES) -> F
    g, _ = calculate_grade({"tls1_0": True, "tls1_2": True}, _ciphers("WEAK", "INSECURE"))
    if g != "F":
        fails.append(f"grade bnkcapital-like = {g}, čekáno F")
    # SSLv3 podporováno -> strop C
    g, _ = calculate_grade({"sslv3": True, "tls1_2": True}, _ciphers("SECURE"))
    if g != "C":
        fails.append(f"grade sslv3-like = {g}, čekáno C")
    # žádný protokol -> ERR
    g, _ = calculate_grade({}, {})
    if g != "ERR":
        fails.append(f"grade bez protokolu = {g}, čekáno ERR")
    # TLS1.0/1.1 -> strop B i bez weak šifer
    g, _ = calculate_grade({"tls1_1": True, "tls1_2": True}, _ciphers("SECURE"))
    if g != "B":
        fails.append(f"grade tls1.1-like = {g}, čekáno B")

    if fails:
        print("❌ SELHALO:")
        for f in fails:
            print("  -", f)
        return 1
    print(f"✅ test_tls_grading: VŠE OK — {total}/{total} šifer klasifikováno jako Qualys + známky sedí.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
