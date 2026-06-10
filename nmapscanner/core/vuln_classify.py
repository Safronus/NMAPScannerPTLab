"""Klasifikace výstupu nmap ``vuln`` skriptů (bez Qt → testovatelné).

Rozliší tři stavy, aby se v záložce Vulns nezobrazovaly benigní hlášky a chyby
skriptů jako červené „nálezy":

* ``finding`` — potvrzená zranitelnost (``State: VULNERABLE``, CVE, …),
* ``error``   — skript selhal / neodpověděl (timeout, ERROR, connection closed) —
  není to nález, jen se test nepovedl,
* ``clean``   — skript proběhl a nic nenašel („Couldn't find any …", NOT vulnerable).

Konzervativně: za nález se bere jen jednoznačně potvrzená zranitelnost; cokoli
ostatního je ``clean``/``error`` (radši žádný falešný poplach).
"""

CONFIRMED = ("VULNERABLE", "EXPLOITABLE", "CONFIRMED", "STATE: VULNERABLE",
             "IDS: CVE", "RISK FACTOR:")
NEGATIVE = ("NOT VULNERABLE", "NO VULNERABILITY", "NOT AFFECTED",
            "LIKELY NOT VULNERABLE", "FALSE POSITIVE", "STATE: NOT VULNERABLE")
ERROR_MARKERS = ("error: script execution failed", "no reply from server",
                 "timeout", "couldn't connect", "could not connect",
                 "connection refused", "connection closed", "err_connection")
CLEAN_MARKERS = ("couldn't find any", "couldnt find any", "could not find any",
                 "no findings", "not detected", "nothing found")


def classify_vuln_output(output):
    """Vrátí ``'finding'`` | ``'error'`` | ``'clean'`` pro výstup jednoho skriptu."""
    s = (output or "").strip()
    if not s:
        return "clean"
    low = s.lower()
    up = s.upper()
    is_conf = any(k in up for k in CONFIRMED)
    is_neg = any(k in up for k in NEGATIVE)
    if is_conf and not is_neg:
        return "finding"
    if any(m in low for m in ERROR_MARKERS):
        return "error"
    return "clean"


def is_finding(output):
    """True, jen když výstup značí potvrzenou zranitelnost."""
    return classify_vuln_output(output) == "finding"
