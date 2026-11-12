import io
import hashlib
import os
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
        self.assertIn("--upgrade-only", result.stdout)

    def test_uninstall_cannot_be_combined_with_upgrade_flags(self):
        for flag in ["--upgrade-only", "--allow-downgrade"]:
            result = subprocess.run(["bash", str(SCRIPT), "--uninstall", flag], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Do not combine", result.stderr)

    def test_legacy_upgrade_bootstrap_routes_to_new_installer_without_old_cli(self):
        # Adapt only host preflight/absolute paths in a private harness. The real
        # Bash argument parser, archive inspector and orchestration still run.
        # Download and install are stubs; no root commands/network are permitted.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            host = root / "host"
            for name in ["opt/server-guard", "usr/local/sbin", "var/lib/server-guard", "etc"]:
                (host / name).mkdir(parents=True, exist_ok=True)
            (host / "etc/os-release").write_text("ID=ubuntu\nVERSION_ID=24.04\n")
            old_cli = host / "usr/local/sbin/server-guard"
            old_cli.write_text("#!/bin/sh\necho 'Old CLI must not be called' >&2\nexit 91\n")
            old_cli.chmod(0o755)
            sentinel = host / "var/lib/server-guard/user-data.json"
            sentinel.write_text("Existing policy/history stays here")
            archive = root / "source.tgz"
            with tarfile.open(archive, "w:gz") as tar:
                for name, payload in {
                    "repo-master/install.sh": b'printf "%s\\n" "$@" > "$SG_TEST_INSTALL_ARGS"\n',
                    "repo-master/server_guard/cli.py": b"# candidate CLI marker\n",
                    "repo-master/scripts/install_tool.py": b"# safe driver marker\n",
                }.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(payload)
                    tar.addfile(info, io.BytesIO(payload))
            fakebin = root / "bin"
            fakebin.mkdir()
            commands = {
                "uname": "#!/bin/sh\necho Linux\n",
                "curl": f"#!{sys.executable}\nimport os,shutil,sys\n"
                    "shutil.copyfile(os.environ['SG_TEST_ARCHIVE'],sys.argv[sys.argv.index('--output')+1])\n",
                "sha256sum": f"#!{sys.executable}\nimport hashlib,sys\n"
                    "print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest()+'  '+sys.argv[1])\n",
                "apt-get": "#!/bin/sh\necho 'Unexpected package mutation' >&2\nexit 92\n",
            }
            for name, content in commands.items():
                file = fakebin / name
                file.write_text(content)
                file.chmod(0o755)
            script = SCRIPT.read_text().replace("$EUID -ne 0", "0 -ne 0")
            for name in ["/etc/os-release", "/opt/server-guard", "/usr/local/sbin/server-guard",
                         "/var/lib/server-guard/pending.json"]:
                script = script.replace(name, str(host / name.lstrip("/")))
            harness = root / "bootstrap.sh"
            harness.write_text(script)
            captured = root / "arguments"
            env = dict(os.environ, PATH=str(fakebin) + os.pathsep + os.environ["PATH"],
                       SG_TEST_ARCHIVE=str(archive), SG_TEST_INSTALL_ARGS=str(captured))
            result = subprocess.run(["bash", str(harness), "--ref", "master", "--upgrade-only", "--no-ui"],
                                    env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            arguments = captured.read_text().splitlines()
            self.assertIn("--upgrade-only", arguments)
            self.assertEqual(arguments[arguments.index("--repo") + 1], "amindqn/server-guard")
            self.assertEqual(arguments[arguments.index("--archive-sha256") + 1], hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertEqual(sentinel.read_text(), "Existing policy/history stays here")
            self.assertIn("Open management:", result.stdout)

    def test_standalone_removal_entrypoints_show_help_without_installing(self):
        commands = [["bash", str(ROOT / "uninstall.sh"), "--help"],
                    [sys.executable, "-I", str(ROOT / "scripts/uninstall_entry.py"), "--help"]]
        for command in commands:
            with self.subTest(command=command):
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("--dry-run", result.stdout)
                self.assertIn("--purge", result.stdout)

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
