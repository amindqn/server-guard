#!/usr/bin/env bash
# Standalone GitHub downloader. All work is inside main so a truncated piped
# download cannot execute an incomplete body before the final main invocation.
server_guard_bootstrap_main() {
  set -Eeuo pipefail
  umask 077
  task_repo='amindqn/server-guard'
  task_ref='main'
  task_sha256=''
  task_ui=1
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --repo|--ref|--sha256)
        if [[ $# -lt 2 ]]; then echo "Missing value for $1" >&2; return 1; fi
        case "$1" in
          --repo) task_repo=$2 ;;
          --ref) task_ref=$2 ;;
          --sha256) task_sha256=$2 ;;
        esac
        shift 2 ;;
      --no-ui) task_ui=0; shift ;;
      -h|--help)
        echo 'Usage: sudo bash bootstrap.sh [--repo OWNER/REPO] [--ref main|TAG|COMMIT] [--sha256 SOURCE_ARCHIVE_SHA256] [--no-ui]'
        echo 'Default repository: amindqn/server-guard (main branch).'
        echo 'Installs the tool and opens guided setup in a terminal. --no-ui skips interactive setup.'
        return 0 ;;
      *) echo "Unknown option: $1" >&2; return 1 ;;
    esac
  done
  if [[ ! $task_repo =~ ^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    echo 'Specify the public GitHub repository as --repo OWNER/REPO.' >&2; return 1
  fi
  if [[ ! $task_ref =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ || $task_ref == *'..'* || ${#task_ref} -gt 200 ]]; then
    echo 'Invalid GitHub branch, tag or commit.' >&2; return 1
  fi
  if [[ -n $task_sha256 && ! $task_sha256 =~ ^[a-fA-F0-9]{64}$ ]]; then
    echo 'Expected a full SHA-256 checksum of the GitHub source archive.' >&2; return 1
  fi
  if [[ $(uname -s) != Linux || $EUID -ne 0 ]]; then
    echo 'Run with sudo/root on the Ubuntu 24.04 server.' >&2; return 1
  fi
  source /etc/os-release
  if [[ ${ID:-} != ubuntu || ${VERSION_ID:-} != 24.04 ]]; then
    echo 'This tool supports Ubuntu 24.04 LTS only.' >&2; return 1
  fi
  if [[ -f /var/lib/server-guard/pending.json ]]; then
    echo 'Confirm or roll back the pending access change before updating the tool.' >&2; return 1
  fi
  if ! command -v curl >/dev/null || ! command -v python3 >/dev/null; then
    apt-get update
    apt-get install -y ca-certificates curl python3
  fi
  task_checkout_dir=$(mktemp -d -t server-guard-download.XXXXXXXX)
  trap 'rm -rf -- "$task_checkout_dir"' EXIT
  task_archive="$task_checkout_dir/source.tar.gz"
  echo "Downloading https://github.com/$task_repo at $task_ref"
  curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
    --tlsv1.2 --connect-timeout 20 --max-time 300 --max-filesize 33554432 \
    "https://codeload.github.com/$task_repo/tar.gz/$task_ref" --output "$task_archive"
  task_actual_sha256=$(sha256sum "$task_archive")
  task_actual_sha256=${task_actual_sha256%% *}
  if [[ -n $task_sha256 && ${task_sha256,,} != "$task_actual_sha256" ]]; then
    echo 'GitHub source archive checksum mismatch. Installation cancelled.' >&2; return 1
  fi
  task_install_dir=$(python3 -I - "$task_archive" "$task_checkout_dir/source" <<'PY'
from pathlib import Path, PurePosixPath
import sys
import tarfile

archive, destination = sys.argv[1], Path(sys.argv[2])
with tarfile.open(archive, 'r:gz') as source:
    members = source.getmembers()
    if not members or len(members) > 4000:
        raise SystemExit('Unexpected GitHub archive member count.')
    top = set()
    size = 0
    seen = set()
    for item in members:
        name = PurePosixPath(item.name)
        if (name.is_absolute() or '..' in name.parts or not name.parts
                or '\\' in item.name or not (item.isfile() or item.isdir())):
            raise SystemExit('Unsafe GitHub archive path/type.')
        if name in seen:
            raise SystemExit('Duplicate GitHub archive entry.')
        seen.add(name)
        top.add(name.parts[0])
        size += item.size
        if size > 67108864:
            raise SystemExit('GitHub source archive is unexpectedly large.')
    if len(top) != 1:
        raise SystemExit('Expected a single GitHub source directory.')
    source.extractall(destination, members=members, filter='data')
    project = destination / next(iter(top))
    if not (project / 'install.sh').is_file() or not (project / 'server_guard/cli.py').is_file():
        raise SystemExit('This repository/ref does not contain the Server Guard source.')
    print(project)
PY
  )
  bash "$task_install_dir/install.sh"
  python3 -I - "$task_repo" "$task_ref" "$task_actual_sha256" <<'PY'
import json
from pathlib import Path
import sys
Path('/opt/server-guard/source.json').write_text(json.dumps({
    'repository': sys.argv[1], 'ref': sys.argv[2], 'archive_sha256': sys.argv[3]
}, indent=2) + '\n')
PY
  echo "GitHub source archive SHA256: $task_actual_sha256"
  echo 'Installation complete. Guide: /usr/local/share/doc/server-guard/README.md'
  if [[ $task_ui == 1 && -t 1 ]] && ( : </dev/tty ) 2>/dev/null; then
    # Reconnect stdin to the terminal for pipe/process-substitution installs.
    # The local install.sh process has exited and released its management lock.
    /usr/local/sbin/server-guard setup </dev/tty
  else
    echo 'Open guided setup: sudo --preserve-env=SSH_CONNECTION server-guard setup'
  fi
}

server_guard_bootstrap_main "$@"
