"""Testy Windows kompatibility — převod nmap příkazu bez práv správce."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nmapscanner.utils import unprivileged_nmap_command, is_windows, is_windows_admin
from nmapscanner.core import toolcheck as tc


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


def test_update_command_windows_uses_winget_not_brew():
    specs = {s["key"]: s for s in tc.TOOLS}
    # nastroje s winget -> winget, nikdy brew
    for key in ("nmap", "ffuf", "zap"):
        cmd = tc.update_command(specs[key], "windows")
        assert cmd.startswith("winget "), f"{key}: ocekavan winget, dostal '{cmd}'"
        assert "brew" not in cmd
    # SSLyze -> pip (ne brew)
    assert "pip" in tc.update_command(specs["sslyze"], "windows")
    # bez winget/pip (testssl) -> prazdne (UI ukaze homepage), nikdy brew na Win
    assert tc.update_command(specs["testssl"], "windows") == ""


def test_update_command_macos_still_brew():
    specs = {s["key"]: s for s in tc.TOOLS}
    assert tc.update_command(specs["nmap"], "darwin") == "brew install nmap"


def test_installable_here_windows():
    specs = {s["key"]: s for s in tc.TOOLS}
    # winget nástroje instalovatelné na Windows
    for key in ("nmap", "ffuf", "zap"):
        assert tc.installable_here(specs[key], "windows") is True
    # bez winget/pip → na Windows neinstalovatelné (info, ne instalace naslepo)
    for key in ("testssl", "sslscan", "searchsploit"):
        assert tc.installable_here(specs[key], "windows") is False
    # SSLyze má pip → instalovatelné i na Windows
    assert tc.installable_here(specs["sslyze"], "windows") is True
    # na macOS jsou přes brew instalovatelné (i testssl)
    assert tc.installable_here(specs["testssl"], "darwin") is True


def test_tools_have_winget_id():
    specs = {s["key"]: s for s in tc.TOOLS}
    for key in ("nmap", "ffuf", "zap"):
        assert specs[key].get("winget_id"), f"{key} nemá winget_id"


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
