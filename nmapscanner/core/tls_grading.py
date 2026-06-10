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

    label ∈ {"INSECURE", "WEAK", "SECURE"}.
    """
    u = (name or "").upper()

    # --- INSECURE (Qualys červená) ---
    if ("NULL" in u or "ANON" in u or "_ADH_" in u or "_AECDH_" in u
            or "EXPORT" in u or "RC4" in u
            or ("_DES_" in u and "3DES" not in u)   # jednoduché DES, ne 3DES
            or u.endswith("_MD5")):
        return "INSECURE", INSECURE_COLOR, "(INSECURE)"

    # --- WEAK (Qualys oranžová) ---
    # Statická RSA výměna klíčů → chybí forward secrecy (i pro GCM/CCM).
    if u.startswith("TLS_RSA_") or u.startswith("SSL_RSA_"):
        return "WEAK", WEAK_COLOR, "(WEAK – bez forward secrecy)"
    # 3DES (Sweet32)
    if "3DES" in u:
        return "WEAK", WEAK_COLOR, "(WEAK – 3DES/Sweet32)"
    # CBC mód (Lucky13/POODLE)
    if "_CBC_" in u:
        return "WEAK", WEAK_COLOR, "(WEAK – CBC)"
    # Staré algoritmy, které Qualys penalizuje
    if "IDEA" in u or "_SEED_" in u:
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
