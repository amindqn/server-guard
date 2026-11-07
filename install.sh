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
if [[ ! -f "$task_source_dir/server_guard/cli.py" ]]; then
  echo 'Copy/extract the entire release directory before running install.sh.' >&2
  exit 1
fi
# Serialize tool updates with management commands, then recheck pending state.
install -d -m 0700 /run/server-guard
exec 9>/run/server-guard/management.lock
flock -x 9
if [[ -f /var/lib/server-guard/pending.json ]]; then
  echo 'Confirm or roll back the pending change before updating the tool.' >&2
  exit 1
fi
if ! command -v python3 >/dev/null; then
  apt-get update
  apt-get install -y python3
fi
install -d -m 0755 /opt/server-guard /opt/server-guard/server_guard
task_install_python() {
  task_file=$1
  task_stage=$(mktemp /opt/server-guard/server_guard/.install.XXXXXXXX)
  install -o root -g root -m 0644 "$task_file" "$task_stage"
  if [[ ${task_file##*/} == pam_sessions.py ]]; then chmod 0755 "$task_stage"; fi
  mv -f -- "$task_stage" "/opt/server-guard/server_guard/${task_file##*/}"
}
for task_file in "$task_source_dir"/server_guard/*.py; do
  if [[ ${task_file##*/} != cli.py ]]; then task_install_python "$task_file"; fi
done
# Publish the entry module after new dependency modules are present.
task_install_python "$task_source_dir/server_guard/cli.py"
install -d -m 0700 /etc/server-guard /var/lib/server-guard
install -d -m 0755 /usr/local/share/doc/server-guard /usr/local/share/doc/server-guard/docs
install -o root -g root -m 0644 "$task_source_dir/README.md" /usr/local/share/doc/server-guard/README.md
for task_doc in "$task_source_dir"/docs/*.md; do
  install -o root -g root -m 0644 "$task_doc" /usr/local/share/doc/server-guard/docs/
done
task_launcher=$(mktemp /usr/local/sbin/.server-guard.XXXXXXXX)
cat > "$task_launcher" <<'LAUNCHER'
#!/usr/bin/python3 -I
import sys
sys.path.insert(0, '/opt/server-guard')
from server_guard.cli import main
sys.exit(main())
LAUNCHER
chown root:root "$task_launcher"
chmod 0755 "$task_launcher"
mv -f -- "$task_launcher" /usr/local/sbin/server-guard
echo 'Installed server-guard. Next: sudo server-guard prepare'
echo 'Guided terminal setup: sudo --preserve-env=SSH_CONNECTION server-guard setup'
echo 'Guide: /usr/local/share/doc/server-guard/README.md. Keep provider console access available.'
