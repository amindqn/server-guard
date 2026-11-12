#!/usr/bin/env bash
# Standalone GitHub downloader. All work is inside main so a truncated piped
# download cannot execute an incomplete body before the final main invocation.
server_guard_bootstrap_main() {
  set -Eeuo pipefail
  umask 077
  task_repo='amindqn/server-guard'
  task_ref='master'
  task_sha256=''
  task_ui=1
  task_uninstall=0
  task_upgrade=0
  task_downgrade=0
  task_uninstall_args=()
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
      --uninstall) task_uninstall=1; shift ;;
      --upgrade-only) task_upgrade=1; task_ui=0; shift ;;
      --allow-downgrade) task_downgrade=1; shift ;;
      --yes|--dry-run|--purge) task_uninstall_args+=("$1"); shift ;;
      -h|--help)
        echo 'Usage: sudo bash bootstrap.sh [--repo OWNER/REPO] [--ref BRANCH|TAG|COMMIT] [--sha256 SOURCE_ARCHIVE_SHA256] [--no-ui] [--upgrade-only] [--allow-downgrade] [--uninstall [--dry-run|--yes] [--purge]]'
        echo 'Default repository: amindqn/server-guard (master branch).'
        echo 'Installs the tool and opens guided setup in a terminal. --no-ui skips interactive setup.'
        echo '--upgrade-only updates an existing manager without setup, including versions without self-update.'
        return 0 ;;
      *) echo "Unknown option: $1" >&2; return 1 ;;
    esac
  done
  if [[ $task_uninstall == 1 && ( $task_upgrade == 1 || $task_downgrade == 1 ) ]]; then
    echo 'Do not combine uninstall and upgrade options.' >&2; return 1
  fi
  if [[ $task_uninstall == 0 && ${#task_uninstall_args[@]} -gt 0 ]]; then
    echo '--yes, --dry-run and --purge require --uninstall.' >&2; return 1
  fi
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
    echo 'Confirm or roll back the pending access change before updating or uninstalling the tool.' >&2; return 1
  fi
  if [[ $task_upgrade == 1 && ( ! -f /usr/local/sbin/server-guard || ! -d /opt/server-guard ) ]]; then
    echo 'No installed manager found. Use the normal installer for a first installation.' >&2; return 1
  fi
  if ! command -v curl >/dev/null || ! command -v python3 >/dev/null; then
    if [[ $task_uninstall == 1 || $task_upgrade == 1 ]]; then
      echo 'This operation requires curl and python3; no packages were installed.' >&2; return 1
    fi
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
    members = []
    top = set()
    size = 0
    seen = set()
    for item in source:
        name = PurePosixPath(item.name)
        if (name.is_absolute() or '..' in name.parts or not name.parts
                or '\\' in item.name or not (item.isfile() or item.isdir())):
            raise SystemExit('Unsafe GitHub archive path/type.')
        if name in seen:
            raise SystemExit('Duplicate GitHub archive entry.')
        seen.add(name)
        members.append(item)
        top.add(name.parts[0])
        size += item.size
        if len(members) > 4000 or size > 67108864:
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
  if [[ $task_uninstall == 1 ]]; then
    if [[ ! -f "$task_install_dir/scripts/uninstall_entry.py" ]]; then
      echo 'This repository/ref does not contain the standalone uninstaller.' >&2; return 1
    fi
    if [[ " ${task_uninstall_args[*]} " != *' --yes '* && " ${task_uninstall_args[*]} " != *' --dry-run '* && -t 1 ]] && ( : </dev/tty ) 2>/dev/null; then
      python3 -I "$task_install_dir/scripts/uninstall_entry.py" "${task_uninstall_args[@]}" </dev/tty
    else
      python3 -I "$task_install_dir/scripts/uninstall_entry.py" "${task_uninstall_args[@]}"
    fi
    return
  fi
  if [[ ! -f "$task_install_dir/scripts/install_tool.py" ]]; then
    echo 'Selected source predates the safe installer. Choose a release with scripts/install_tool.py.' >&2; return 1
  fi
  task_install_args=(--repo "$task_repo" --ref "$task_ref" --archive-sha256 "$task_actual_sha256")
  if [[ $task_upgrade == 1 ]]; then task_install_args+=(--upgrade-only); fi
  if [[ $task_downgrade == 1 ]]; then task_install_args+=(--allow-downgrade); fi
  bash "$task_install_dir/install.sh" "${task_install_args[@]}"
  echo "GitHub source archive SHA256: $task_actual_sha256"
  echo 'Management files ready. Guide: /usr/local/share/doc/server-guard/README.md'
  if [[ $task_ui == 1 && -t 1 ]] && ( : </dev/tty ) 2>/dev/null; then
    # Reconnect stdin to the terminal for pipe/process-substitution installs.
    # The local install.sh process has exited and released its management lock.
    /usr/local/sbin/server-guard setup </dev/tty
  else
    if [[ $task_upgrade == 1 ]]; then
      echo 'Open management: sudo --preserve-env=SSH_CONNECTION server-guard'
    else
      echo 'Open guided setup: sudo --preserve-env=SSH_CONNECTION server-guard setup'
    fi
  fi
}

server_guard_bootstrap_main "$@"
