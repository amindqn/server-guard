"""GitHub source identity and bounded, non-executable release inspection."""
from __future__ import annotations

import ast
from dataclasses import dataclass
import re
from pathlib import Path, PurePosixPath
import tarfile

from .core import GuardError


SOURCE_INFO = "/opt/server-guard/source.json"
DEFAULT_REPOSITORY = "amindqn/server-guard"
DEFAULT_REF = "master"


def version_tuple(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d+\.\d+\.\d+", value):
        raise GuardError("Expected a release version such as 1.5.0.")
    return tuple(int(part) for part in value.split("."))


def source_version(project):
    try:
        tree = ast.parse((Path(project) / "server_guard/__init__.py").read_text())
        versions = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)]
        if len(versions) != 1:
            raise ValueError()
        version_tuple(versions[0])
        return versions[0]
    except (OSError, ValueError, SyntaxError, TypeError):
        raise GuardError("Release has no valid, literal Server Guard version.") from None


@dataclass(frozen=True)
class GitHubSource:
    repository: str = DEFAULT_REPOSITORY
    ref: str = DEFAULT_REF

    def __post_init__(self):
        if not isinstance(self.repository, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9._-]*", self.repository):
            raise GuardError("Specify the GitHub source as OWNER/REPOSITORY.")
        if not isinstance(self.ref, str) or len(self.ref) > 200 or ".." in self.ref or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", self.ref):
            raise GuardError("Invalid GitHub branch, tag or commit.")

    @property
    def archive_url(self):
        return f"https://codeload.github.com/{self.repository}/tar.gz/{self.ref}"

    def metadata(self, digest):
        if not isinstance(digest, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
            raise GuardError("Source archive SHA-256 must contain 64 hexadecimal characters.")
        return {"repository": self.repository, "ref": self.ref, "archive_sha256": digest.lower()}


def extract_source(archive, destination):
    try:
        return _extract_source(archive, destination)
    except (tarfile.TarError, EOFError) as exc:
        raise GuardError("The downloaded source is not a valid complete archive.") from exc


def _extract_source(archive, destination):
    """No links/traversal/duplicates; validate sizes before skipping member data."""
    with tarfile.open(archive, "r:gz") as source:
        members, roots, seen, size = [], set(), set(), 0
        for item in source:
            name = PurePosixPath(item.name)
            if (name.is_absolute() or ".." in name.parts or not name.parts or "\\" in item.name
                    or not (item.isfile() or item.isdir()) or name in seen):
                raise GuardError("Unsafe or duplicate source archive entry.")
            seen.add(name)
            roots.add(name.parts[0])
            size += item.size
            members.append(item)
            if len(members) > 4000 or size > 64 * 1024 ** 2:
                raise GuardError("Source archive exceeds the entry/size limit.")
        if not members or len(roots) != 1:
            raise GuardError("Expected one GitHub source directory.")
        source.extractall(destination, members=members, filter="data")
    project = Path(destination) / next(iter(roots))
    if not (project / "server_guard/cli.py").is_file() or not (project / "README.md").is_file():
        raise GuardError("Source does not contain the complete Server Guard program and guide.")
    source_version(project)
    return project
