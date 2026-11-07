#!/usr/bin/env python3
"""Build a deterministic release without .git, caches or local configuration."""
import gzip
import hashlib
import io
from pathlib import Path
import tarfile
import sys


root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from server_guard import __version__
version = __version__
prefix = "server-guard-" + version
output = root / "dist"
output.mkdir(exist_ok=True)
members = [root / "install.sh", root / "bootstrap.sh", root / "README.md"]
for directory, suffix in [("server_guard", ".py"), ("tests", ".py"), ("docs", ".md"), ("scripts", ".py")]:
    members.extend(sorted((root / directory).glob("*" + suffix)))
buffer = io.BytesIO()
with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
    for path in sorted(members):
        if path.is_symlink():
            raise RuntimeError(f"Refusing release symlink: {path}")
        payload = path.read_bytes()
        entry = tarfile.TarInfo(prefix + "/" + str(path.relative_to(root)))
        entry.size = len(payload)
        entry.mode = 0o755 if path.name in {"install.sh", "bootstrap.sh", "pam_sessions.py", "build_release.py"} else 0o644
        entry.mtime = 0
        entry.uid = entry.gid = 0
        entry.uname = entry.gname = "root"
        archive.addfile(entry, io.BytesIO(payload))
target = output / (prefix + ".tar.gz")
target.write_bytes(gzip.compress(buffer.getvalue(), mtime=0))
digest = hashlib.sha256(target.read_bytes()).hexdigest()
(output / (target.name + ".sha256")).write_text(digest + "  " + target.name + "\n")
print(target)
print("SHA256: " + digest)
