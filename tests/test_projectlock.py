"""Testy soft-locku nad projektovou složkou (čistá logika, bez UI)."""
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nmapscanner.core import projectlock as pl


def _tmp():
    return tempfile.mkdtemp(prefix="nmaplock_")


def test_no_lock_initially():
    d = _tmp()
    assert pl.read_lock(d) is None
    assert pl.held_by_other(d) is None


def test_acquire_is_ours():
    d = _tmp()
    assert pl.acquire(d, "1.0") is True
    lk = pl.read_lock(d)
    assert pl.is_ours(lk) is True
    assert pl.is_active(lk) is True
    # vlastní zámek nevaruje
    assert pl.held_by_other(d) is None


def test_foreign_fresh_warns():
    d = _tmp()
    foreign = {"user": "alice", "host": "OTHER-PC", "pid": 999, "ts": time.time()}
    json.dump(foreign, open(pl.lock_path(d), "w"))
    o = pl.held_by_other(d)
    assert o is not None
    assert "alice@OTHER-PC" in pl.describe(o)


def test_foreign_stale_ignored():
    d = _tmp()
    foreign = {"user": "alice", "host": "OTHER-PC", "pid": 999,
               "ts": time.time() - (pl.STALE_AFTER + 60)}
    json.dump(foreign, open(pl.lock_path(d), "w"))
    assert pl.held_by_other(d) is None  # opuštěný zámek nevaruje


def test_release_only_own():
    d = _tmp()
    foreign = {"user": "bob", "host": "OTHER-PC", "pid": 1, "ts": time.time()}
    json.dump(foreign, open(pl.lock_path(d), "w"))
    pl.release(d)  # nesmí smazat cizí zámek
    assert pl.read_lock(d) is not None
    # vlastní zámek smazat lze
    pl.acquire(d)
    pl.release(d)
    assert pl.read_lock(d) is None


def test_refresh_does_not_steal_fresh_foreign():
    d = _tmp()
    foreign = {"user": "bob", "host": "OTHER-PC", "pid": 1, "ts": time.time()}
    json.dump(foreign, open(pl.lock_path(d), "w"))
    assert pl.refresh(d) is False  # čerstvý cizí → nepřebírat
    # ale opuštěný cizí přebrat lze
    foreign["ts"] = time.time() - (pl.STALE_AFTER + 60)
    json.dump(foreign, open(pl.lock_path(d), "w"))
    assert pl.refresh(d) is True
    assert pl.is_ours(pl.read_lock(d)) is True


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
    print(f"✅ test_projectlock: VŠE OK — {len(tests)} testů prošlo.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
