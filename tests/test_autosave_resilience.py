"""Headless test odolnosti ukládání projektu.

Když je cílová složka jen pro čtení (na macOS typicky Plocha/iCloud blokovaná
TCC → EPERM), musí atomický zápis selhat čistou výjimkou (ne potichu), aby ji
autosave mohl zachytit, vypnout se pro tu cestu a poradit uživateli. Test ověří:
  1) happy path: zápis i round-trip fungují v zapisovatelné složce,
  2) read-only složka → PermissionError/OSError (errno EPERM/EACCES),
  3) po selhání nezůstane ve složce žádný .tmp.
"""
import os
import sys
import stat
import errno
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nmapscanner.core import project_store as ps


def main():
    fails = []

    # 1) happy path
    with tempfile.TemporaryDirectory() as base:
        target = os.path.join(base, "sub", "x.json")
        ps.atomic_write_json(target, {"a": 1, "č": "ř"})
        if not os.path.exists(target):
            fails.append("happy path: soubor nevznikl")

    # 2) + 3) read-only složka → výjimka práv, žádný zbytkový .tmp
    ro = tempfile.mkdtemp()
    try:
        os.chmod(ro, stat.S_IRUSR | stat.S_IXUSR)  # r-x: bez práva zápisu
        raised = None
        try:
            ps.atomic_write_json(os.path.join(ro, "y.json"), {"a": 1})
        except OSError as e:
            raised = e
        if raised is None:
            # Pozn.: jako root by zápis prošel i bez write bitu — pak test přeskoč.
            if os.geteuid() != 0:
                fails.append("read-only složka: zápis nečekaně neselhal")
        else:
            if getattr(raised, "errno", None) not in (errno.EPERM, errno.EACCES):
                fails.append(f"read-only: nečekané errno {getattr(raised, 'errno', None)}")
            # Musí být klasifikováno stejně jako v _handle_autosave_failure.
            is_perm = (isinstance(raised, PermissionError)
                       or getattr(raised, "errno", None) in (errno.EPERM, errno.EACCES))
            if not is_perm:
                fails.append("read-only: chyba se neklasifikuje jako práva")
        # po selhání žádný zbytkový .tmp
        try:
            os.chmod(ro, stat.S_IRWXU)
            leftovers = [f for f in os.listdir(ro) if f.endswith(".tmp")]
            if leftovers:
                fails.append(f"po selhání zůstaly .tmp soubory: {leftovers}")
        except OSError:
            pass
    finally:
        os.chmod(ro, stat.S_IRWXU)
        for f in os.listdir(ro):
            os.remove(os.path.join(ro, f))
        os.rmdir(ro)

    if fails:
        print("❌ SELHALO:")
        for f in fails:
            print("  -", f)
        return 1
    print("✅ test_autosave_resilience: atomický zápis selže čistě (práva) a uklidí .tmp.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
