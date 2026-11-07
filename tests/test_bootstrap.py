import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bootstrap.sh"
EXTRACT_CODE = SCRIPT.read_text().split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]


class GitHubBootstrapTests(unittest.TestCase):
    def test_help_is_non_mutating_and_describes_pinning(self):
        result = subprocess.run(["bash", str(SCRIPT), "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("--repo OWNER/REPO", result.stdout)
        self.assertIn("--sha256", result.stdout)

    def test_repo_ref_checksum_injection_rejected_before_host_operations(self):
        cases = [["--repo", "owner/repo;id"], ["--repo", "owner/repo", "--ref", "../main"],
                 ["--repo", "owner/repo", "--sha256", "abcd"], ["--repo"]]
        for args in cases:
            with self.subTest(args=args):
                result = subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)

    def extract(self, entries):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            archive = root / "source.tgz"
            with tarfile.open(archive, "w:gz") as tar:
                for name, kind in entries:
                    info = tarfile.TarInfo(name)
                    if kind == "file":
                        data = b"# test file\n"
                        info.size = len(data)
                        tar.addfile(info, io.BytesIO(data))
                    elif kind == "symlink":
                        info.type, info.linkname = tarfile.SYMTYPE, "/tmp/outside"
                        tar.addfile(info)
                    elif kind == "hardlink":
                        info.type, info.linkname = tarfile.LNKTYPE, "/tmp/outside"
                        tar.addfile(info)
            return subprocess.run([sys.executable, "-I", "-", str(archive), str(root / "source")],
                                   input=EXTRACT_CODE, capture_output=True, text=True)

    def test_real_extractor_accepts_project_source(self):
        result = self.extract([("repo-main/install.sh", "file"), ("repo-main/server_guard/cli.py", "file")])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.strip().endswith("source/repo-main"))

    def test_real_extractor_rejects_traversal_links_duplicates_and_wrong_source(self):
        valid = [("repo-main/install.sh", "file"), ("repo-main/server_guard/cli.py", "file")]
        for extra in [[("../escape", "file")], [("/tmp/escape", "file")],
                      [("repo-main/link", "symlink")], [("repo-main/link", "hardlink")],
                      [("repo-main/install.sh", "file")], [("second/file", "file")]]:
            with self.subTest(extra=extra):
                self.assertNotEqual(self.extract(valid + extra).returncode, 0)
        self.assertNotEqual(self.extract([("repo-main/README.md", "file")]).returncode, 0)


if __name__ == "__main__":
    unittest.main()
