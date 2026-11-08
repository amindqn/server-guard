import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from server_guard.core import Files, GuardError, sha256
from server_guard.host import Host
from server_guard.services import PanelManager, PublishedChecksum


class PanelChecksumTests(unittest.TestCase):
    def test_syntax_highlighting_and_repeated_publisher_checksum(self):
        digest = "ab" * 32
        code = f'<code><span>echo</span> <span>&quot;{digest} install.sh&quot;</span></code>'
        self.assertEqual(PublishedChecksum.parse(code + code), digest)

    def test_missing_or_ambiguous_publisher_checksum_is_rejected(self):
        for html in ["unavailable", f'echo "{"a" * 64} install.sh" echo "{"b" * 64} install.sh"']:
            with self.subTest(html=html), self.assertRaises(GuardError):
                PublishedChecksum.parse(html)

    def test_official_checksum_mismatch_never_executes_vendor(self):
        with tempfile.TemporaryDirectory() as root:
            class Runner:
                def __init__(self):
                    self.calls = []
                def run(self, *args, **kwargs):
                    self.calls.append(args)
                    if args[0] == "curl":
                        target = Path(args[args.index("--output") + 1])
                        target.write_text(f'<code>echo "{"a" * 64} install.sh"</code>')
                    return subprocess.CompletedProcess(args, 0, "", "")
            host = Host(Files(root), Runner())
            host.f.write("/var/lib/server-guard/downloads/cloudpanel.sh", "# different installer\n")
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(GuardError, "checksum mismatch"):
                PanelManager(host).install("cloudpanel", None, "MYSQL_8.4", official=True)
            self.assertTrue(all(call[0] == "curl" for call in host.r.calls))

    def test_manual_approval_is_still_supported_without_network(self):
        with tempfile.TemporaryDirectory() as root:
            class Runner:
                def __init__(self):
                    self.calls = []
                def run(self, *args, **kwargs):
                    self.calls.append(args)
                    return subprocess.CompletedProcess(args, 3 if args[0] == "systemctl" else 0, "", "")
            host = Host(Files(root), Runner())
            host.f.write("/var/lib/server-guard/downloads/cloudpanel.sh", "# reviewed installer\n")
            host.f.write("/etc/server-guard/firewall.nft", "# baseline\n")
            digest = sha256(host.f.path("/var/lib/server-guard/downloads/cloudpanel.sh"))
            with patch.object(host, "firewall_load") as restore, contextlib.redirect_stdout(io.StringIO()):
                PanelManager(host).install("cloudpanel", digest, "MYSQL_8.4")
            restore.assert_called_once_with()
            self.assertTrue(any(call[:3] == ("env", "DB_ENGINE=MYSQL_8.4", "bash") for call in host.r.calls))
            self.assertFalse(any(call[0] == "curl" for call in host.r.calls))


if __name__ == "__main__":
    unittest.main()
