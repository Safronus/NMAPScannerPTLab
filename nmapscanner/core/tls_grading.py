"""Hodnocení TLS šifer a celková známka — laděno dle Qualys SSL Labs.

Čistá logika bez Qt, aby šla samostatně testovat. Klasifikace `classify_cipher`
byla vyladěna proti reálným výsledkům Qualys SSL Labs (viz
``tests/test_tls_grading.py`` s ground-truth sadou 47 šifer):

* **INSECURE** (Qualys červená): NULL, anonymní (ADH/AECDH), EXPORT, RC4,
  jednoduché DES (ne 3DES), MD5 jako MAC.
* **WEAK** (Qualys oranžová): statická RSA (bez forward secrecy — i s GCM/CCM),
  3DES (Sweet32), CBC mód (Lucky13/POODLE), IDEA/SEED.
* **SECURE** (Qualys zelená): AEAD (GCM / CHACHA20-POLY1305 / CCM) s forward
  secrecy (ECDHE/DHE/ECDSA) a TLS 1.3 sady.
"""

SECURE_COLOR = "#2ECC71"
WEAK_COLOR = "#F39C12"
INSECURE_COLOR = "#E74C3C"
GREY = "#95A5A6"

GRADE_COLORS = {
    "A": "#2ECC71",
    "B": "#27AE60",
    "C": "#F39C12",
    "F": "#E74C3C",
    "T": "#E67E22",   # cert není důvěryhodný (sem grade nedáváme — nemáme cert kontrolu)
    "ERR": GREY,
}


def classify_cipher(name):
    """Vrátí ``(label, hex_color, tag)`` pro danou cipher suite dle Qualys pravidel.

    Rozumí **oběma stylům názvů**: IANA (``TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256``,
    typicky z nmapu) i OpenSSL (``ECDHE-RSA-AES128-GCM-SHA256``, typicky z
    testssl.sh). label ∈ {"INSECURE", "WEAK", "SECURE"}.
    """
    u = (name or "").upper()

    # --- INSECURE (Qualys červená) ---
    if "NULL" in u or "ANON" in u or "ADH" in u or "AECDH" in u:
        return "INSECURE", INSECURE_COLOR, "(INSECURE)"
    if "EXPORT" in u or u.startswith("EXP-") or u.startswith("EXP1"):
        return "INSECURE", INSECURE_COLOR, "(INSECURE – export)"
    if "RC4" in u:
        return "INSECURE", INSECURE_COLOR, "(INSECURE – RC4)"
    if u.endswith("MD5"):
        return "INSECURE", INSECURE_COLOR, "(INSECURE – MD5)"
    # jednoduché DES (ne 3DES): obsahuje DES, ale ne 3DES / DES-CBC3 / EDE
    if "DES" in u and not any(x in u for x in ("3DES", "DES-CBC3", "DES_CBC3", "EDE")):
        return "INSECURE", INSECURE_COLOR, "(INSECURE – DES)"

    # --- TLS 1.3 sady (vždy bezpečné) — TLS_AES_*/TLS_CHACHA20_* bez "WITH" ---
    if u.startswith("TLS_") and "WITH" not in u and (
            "AES" in u or "CHACHA20" in u or "SM4" in u or "CCM" in u):
        return "SECURE", SECURE_COLOR, ""

    # --- WEAK (Qualys oranžová) ---
    # 3DES (Sweet32)
    if "3DES" in u or "DES-CBC3" in u or "DES_CBC3" in u or "EDE" in u:
        return "WEAK", WEAK_COLOR, "(WEAK – 3DES/Sweet32)"
    # Statická RSA (chybí forward secrecy) — i pro GCM/CCM.
    fs = ("ECDHE" in u or "DHE" in u or "EDH" in u or "EECDH" in u)
    if u.startswith("TLS_RSA_") or u.startswith("SSL_RSA_") or not fs:
        return "WEAK", WEAK_COLOR, "(WEAK – bez forward secrecy)"
    # CBC mód (Lucky13/POODLE): IANA _CBC_, nebo OpenSSL non-AEAD bloková šifra.
    aead = ("GCM" in u or "CCM" in u or "CHACHA" in u or "POLY1305" in u)
    if "_CBC_" in u or "-CBC-" in u or not aead:
        return "WEAK", WEAK_COLOR, "(WEAK – CBC)"
    # Staré algoritmy, které Qualys penalizuje
    if "IDEA" in u or "SEED" in u:
        return "WEAK", WEAK_COLOR, "(WEAK)"

    # --- SECURE (Qualys zelená) ---
    return "SECURE", SECURE_COLOR, ""


_RANK = {"A": 3, "B": 2, "C": 1}


def calculate_grade(protocols, cipher_tree=None):
    """Celková známka cíle (A/B/C/F/ERR) z podpory protokolů a klasifikace šifer.

    Vrací ``(grade, hex_color)``. Logika odpovídá Qualys stropům (bez kontroly
    certifikátu/HSTS, které nemáme — proto nejvyšší dosažitelná je „A", ne „A+",
    a „T" za nedůvěryhodný cert nehodnotíme):

    * **ERR** — nedetekován žádný protokol (chyba spojení).
    * **F**   — SSLv2, jakákoli INSECURE šifra (RC4/DES/NULL/…), nebo žádný TLS 1.2/1.3.
    * strop **C** — podporován SSLv3.
    * strop **B** — podporován TLS 1.0/1.1 **nebo** přítomny WEAK šifry (CBC/staticRSA/3DES).
    * **A**   — jen silné AEAD šifry s forward secrecy na TLS 1.2/1.3.
    """
    protocols = protocols or {}
    if not any(protocols.values()):
        return "ERR", GRADE_COLORS["ERR"]

    labels = set()
    for ciphers in (cipher_tree or {}).values():
        for c in ciphers:
            labels.add(c.get("grade_label", "SECURE"))
    has_insecure = "INSECURE" in labels
    has_weak = "WEAK" in labels
    has_modern = bool(protocols.get("tls1_2") or protocols.get("tls1_3"))

    # Okamžité F
    if protocols.get("sslv2") or has_insecure or not has_modern:
        return "F", GRADE_COLORS["F"]

    # Stropy podle protokolů
    cap = "A"
    if protocols.get("sslv3"):
        cap = "C"
    elif protocols.get("tls1_0") or protocols.get("tls1_1"):
        cap = "B"

    # WEAK šifry srážejí strop na B
    if has_weak and _RANK[cap] > _RANK["B"]:
        cap = "B"

    return cap, GRADE_COLORS[cap]
