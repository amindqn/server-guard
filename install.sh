#!/usr/bin/env bash
# Installs only the management tool. It does not alter SSH/firewall or install a panel.
set -Eeuo pipefail
umask 077
if [[ $(uname -s) != Linux || $EUID -ne 0 ]]; then
  echo 'Run with sudo/root ON your Ubuntu 24.04 server, not on your computer.' >&2
  exit 1
fi
source /etc/os-release
if [[ ${ID:-} != ubuntu || ${VERSION_ID:-} != 24.04 ]]; then
  echo 'Only Ubuntu 24.04 LTS is supported by this release.' >&2
  exit 1
fi
task_source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ ! -f "$task_source_dir/scripts/install_tool.py" ]]; then
  echo 'Copy/extract the entire release directory before running install.sh.' >&2
  exit 1
fi
if ! command -v python3 >/dev/null; then
  echo 'Install python3 before installing the manager. No configuration was changed.' >&2
  exit 1
fi
# The Python driver owns the management lock, snapshot and atomic publication.
python3 -I "$task_source_dir/scripts/install_tool.py" --source-root "$task_source_dir" "$@"
echo 'Open management: sudo --preserve-env=SSH_CONNECTION server-guard'
if [[ " $* " != *' --upgrade-only '* ]]; then
  echo 'First-time setup: sudo --preserve-env=SSH_CONNECTION server-guard setup'
fi
