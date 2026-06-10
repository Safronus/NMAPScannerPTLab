"""Sdílený fake ``subprocess.Popen`` pro headless testy ScanWorkeru.

Worker spouští nmap přes ``Popen(...).communicate(input=, timeout=)`` (aby šel
proces zabít). Testy podstrkávají ``scanmod.subprocess.Popen`` tímto fake.
``responder(argv, input)`` vrací ``(returncode, stdout_bytes, stderr_bytes)``;
pro simulaci timeoutu může vyhodit ``subprocess.TimeoutExpired``.
"""


# python-nmap (nmap.PortScanner) si při inicializaci ověřuje nmap přes `nmap -V`.
# Protože patchujeme subprocess.Popen globálně, musí fake na `-V`/`--version`
# vrátit platný verzní výstup, jinak python-nmap hlásí "nmap not found".
_NMAP_VERSION = (b"Nmap version 7.99 ( https://nmap.org )\n"
                 b"Platform: arm-apple-darwin\n"
                 b"Compiled with: liblua\n")


def make_fake_popen(responder):
    class FakePopen:
        def __init__(self, argv, **kw):
            self.argv = list(argv)
            self.returncode = None

        def communicate(self, input=None, timeout=None):
            if "-V" in self.argv or "--version" in self.argv:
                self.returncode = 0
                return _NMAP_VERSION, b""
            rc, out, err = responder(self.argv, input)
            self.returncode = rc
            return out, err

        def kill(self):
            self.returncode = -9

        def poll(self):
            return self.returncode

    return FakePopen
