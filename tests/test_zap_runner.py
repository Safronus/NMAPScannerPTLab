"""Testy pomocných funkcí ZAP runneru (bez Qt, bez běžícího ZAP).

Spouští se ``python tests/test_zap_runner.py``.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nmapscanner.core.zap_runner import daemon_command, find_zap, install_hint


def test_daemon_command_basic():
    cmd = daemon_command("/x/zap.sh", host="127.0.0.1", port=8090, api_key="secret")
    assert cmd[0] == "/x/zap.sh"
    assert "-daemon" in cmd
    assert "8090" in cmd
    assert "api.key=secret" in cmd
    assert "api.disablekey=false" in cmd


def test_daemon_command_no_key_disables():
    cmd = daemon_command("/x/zap.sh", api_key="")
    assert "api.disablekey=true" in cmd
    assert not any("api.key=" in c for c in cmd)


def test_daemon_command_local_only():
    cmd = daemon_command("/x/zap.sh", port=9000)
    assert "start.checkForUpdates=false" in cmd
    # zapv2 chodí přes proxy s hostem „zap" → addr regex musí povolit i ten
    assert "api.addrs.addr.name=.*" in cmd
    assert "api.addrs.addr.regex=true" in cmd


def test_daemon_command_home_dir():
    cmd = daemon_command("/x/zap.sh", home_dir="/tmp/zh")
    assert "-dir" in cmd
    assert "/tmp/zh" in cmd


def test_find_zap_env_override(tmp_path_factory=None):
    # ZAP_PATH ukazující na existující soubor má přednost
    here = os.path.abspath(__file__)
    old = os.environ.get("ZAP_PATH")
    try:
        os.environ["ZAP_PATH"] = here
        assert find_zap() == here
    finally:
        if old is None:
            os.environ.pop("ZAP_PATH", None)
        else:
            os.environ["ZAP_PATH"] = old


def test_install_hint_nonempty():
    assert "zaproxy.org" in install_hint()


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
    print(f"✅ test_zap_runner: VŠE OK — {len(tests)} testů prošlo.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
