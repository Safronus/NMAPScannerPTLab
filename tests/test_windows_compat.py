"""Testy Windows kompatibility — převod nmap příkazu bez práv správce."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nmapscanner.utils import unprivileged_nmap_command, is_windows, is_windows_admin


def test_syn_to_connect():
    # -sS (SYN, raw sockety, vyžaduje admin) → -sT (TCP connect, bez admina)
    out = unprivileged_nmap_command("nmap -sS -sV --top-ports 1000 -T4 -oX - 10.0.0.1")
    assert "-sT" in out and "-sS" not in out
    assert "-sV" in out and "--top-ports" in out  # zbytek beze změny


def test_no_syn_unchanged():
    cmd = "nmap -sn -T4 -oX - 10.0.0.1"
    assert unprivileged_nmap_command(cmd) == cmd


def test_does_not_touch_substrings():
    # nesmí sáhnout na -sU/-sV, jen přesnou shodu -sS
    out = unprivileged_nmap_command("nmap -sU -sV -T4 10.0.0.1")
    assert out == "nmap -sU -sV -T4 10.0.0.1"


def test_empty():
    assert unprivileged_nmap_command("") == ""
    assert unprivileged_nmap_command(None) == ""


def test_platform_helpers_safe_off_windows():
    # na ne-Windows nesmí vyhazovat a admin je False
    if not sys.platform.startswith("win"):
        assert is_windows() is False
        assert is_windows_admin() is False


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
    print(f"✅ test_windows_compat: VŠE OK — {len(tests)} testů prošlo.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
