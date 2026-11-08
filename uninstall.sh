#!/usr/bin/env bash
# Standalone removal entry point, including for older manager installations.
server_guard_uninstall_main() {
  set -Eeuo pipefail
  umask 077
  if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    echo 'Usage: sudo bash uninstall.sh [--dry-run|--yes] [--purge] [--repo OWNER/REPO] [--ref TAG|COMMIT]'
    echo 'Removes the manager; preserves working protection, users, applications and database data.'
    echo '--purge removes unused configuration only before hardening or optional-service setup.'
    return 0
  fi
  if [[ $(uname -s) != Linux || $EUID -ne 0 ]]; then
    echo 'Run this command as root on your Ubuntu server.' >&2
    return 1
  fi
  task_uninstall_dir=$(mktemp -d -t server-guard-uninstall.XXXXXXXX)
  trap 'rm -rf -- "$task_uninstall_dir"' EXIT
  curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 20 --max-time 120 \
    https://raw.githubusercontent.com/amindqn/server-guard/master/bootstrap.sh \
    --output "$task_uninstall_dir/bootstrap.sh"
  bash "$task_uninstall_dir/bootstrap.sh" --uninstall "$@"
}

server_guard_uninstall_main "$@"
