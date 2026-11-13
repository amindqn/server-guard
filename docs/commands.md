# Server Guard command reference

Complete public CLI reference for **Server Guard 1.6.1**, with SSH/key setup and common Ubuntu diagnostics. Examples are alternatives and individual procedures: **do not run this whole document as a script**.

**Your computer** means the local Mac/Linux terminal. **Server** means an SSH session on your Ubuntu 24.04 VPS, or its provider console. Run `server-guard` commands on the server. Replace uppercase placeholders before running commands; do not add angle brackets around them.

| Placeholder | Meaning |
| --- | --- |
| `SERVER_IP` | Your server's address or hostname |
| `SSH_PORT` | Its currently working SSH port, usually `22` |
| `ADMIN_USER` | Your actual administrator username; creating an example `admin` below does not rename an existing account |
| `INITIAL_USER` | The root/password/sudo account you currently use for initial setup |
| `USER_NAME`, `SITE_USER` | A real managed/new user, or an existing panel account to adopt |
| `ADMIN_IP`, `CLIENT_IP` | An actual client/administration IP; documentation addresses are not your real address |
| `CHANGE_ID` | The transaction ID printed by `apply` or defense enable/disable |
| `SCAN_ID`, `ITEM` | The inventory ID and item number printed by `health files` |
| `TRUSTED_COMMIT_SHA` | A reviewed full Git commit SHA |
| `TRUSTED_SHA256` | A full trusted publisher/reviewed installer digest, not an invented value |
| `SOURCE_ARCHIVE_SHA256` | SHA-256 of the selected GitHub codeload source archive |
| `V2RAY_VERSION`, `OFFICIAL_ARCHIVE_SHA256` | A reviewed stable `v5.X.Y` release and its Linux x86_64 ZIP digest |

Never paste private keys, passwords or VMess links into GitHub. A **key passphrase** unlocks your private key locally; the **server account password** is used for password-enabled login and usually sudo. Password input normally displays no characters.

## Contents

1. [Create an SSH key and connect](#1-create-an-ssh-key-and-connect-your-computer)
2. [Install, upgrade and open the menu](#2-install-upgrade-and-open-the-menu-server)
3. [First setup, apply, confirm and rollback](#3-first-setup-apply-confirm-and-rollback-server)
4. [Users, permissions and SSH session limits](#4-users-permissions-and-ssh-session-limits-server)
5. [SSH settings and key recovery](#5-ssh-settings-and-key-recovery)
6. [Firewall and public websites](#6-firewall-and-public-websites-server)
7. [CloudPanel or aaPanel](#7-cloudpanel-or-aapanel)
8. [MongoDB](#8-mongodb-server)
9. [V2Ray and client configurations](#9-v2ray-and-client-configurations-server)
10. [Service controls](#10-service-controls-server)
11. [Automatic attack protection](#11-automatic-attack-protection-server)
12. [Health, monitoring, storage and cleanup](#12-health-monitoring-storage-and-cleanup-server)
13. [Ordinary Ubuntu diagnostics](#13-ordinary-ubuntu-diagnostics-server)
14. [Recovery and troubleshooting](#14-recovery-and-troubleshooting)
15. [Uninstall](#15-uninstall-server)
16. [Help, internal commands and development](#16-help-internal-commands-and-development)

## 1. Create an SSH key and connect (your computer)

Create a dedicated key. If this filename already exists, choose a new filename rather than overwriting it:

```bash
ssh-keygen -t ed25519 -a 100 -f ~/.ssh/server_guard_admin
cat ~/.ssh/server_guard_admin.pub
ssh-keygen -lf ~/.ssh/server_guard_admin.pub
```

Keep `~/.ssh/server_guard_admin` private and on your computer. Only the `.pub` file is uploaded/pasted into Server Guard.

While the initial password/root account still works, copy the public key:

```bash
scp -P SSH_PORT ~/.ssh/server_guard_admin.pub INITIAL_USER@SERVER_IP:~/server_guard_admin.pub
```

Optional initial password login, before hardening:

```bash
ssh -p SSH_PORT INITIAL_USER@SERVER_IP
```

After adding your public key to the administrator on the server, open a **new terminal** and test a new key-only connection:

```bash
ssh -o IdentitiesOnly=yes -o ControlMaster=no -o ControlPath=none \
  -o PreferredAuthentications=publickey -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -i ~/.ssh/server_guard_admin -p SSH_PORT ADMIN_USER@SERVER_IP
```

Enter the passphrase chosen in `ssh-keygen`, not the server password. This command disables password fallback and connection reuse. Keep the original working server session open.

For subsequent ordinary key connections:

```bash
ssh -o IdentitiesOnly=yes -i ~/.ssh/server_guard_admin -p SSH_PORT ADMIN_USER@SERVER_IP
```

Optional local SSH-agent commands, if an agent is available:

```bash
ssh-add ~/.ssh/server_guard_admin
ssh-add -l
```

Copy files using your working administrator key:

```bash
scp -o IdentitiesOnly=yes -i ~/.ssh/server_guard_admin -P SSH_PORT ./local-file.txt ADMIN_USER@SERVER_IP:~/
scp -o IdentitiesOnly=yes -i ~/.ssh/server_guard_admin -P SSH_PORT ADMIN_USER@SERVER_IP:~/remote-file.txt ./
```

Use the matching SFTP user's key for an SFTP-only account after its role/session policy has been applied and confirmed:

```bash
sftp -i ~/.ssh/upload_key -P SSH_PORT uploads@SERVER_IP
```

## 2. Install, upgrade and open the menu (server)

Run download/install commands **on the Ubuntu server**. The selected GitHub ref must already contain all new project files. The example repository is `amindqn/server-guard`, branch `master`.

### First installation from GitHub

This downloads the complete bootstrap into a private temporary file before execution, then opens guided setup when a terminal is available:

```bash
sudo --preserve-env=SSH_CONNECTION bash <<'BASH'
set -euo pipefail
umask 077
task_bootstrap=$(mktemp -t server-guard-bootstrap.XXXXXXXX)
trap 'rm -f -- "$task_bootstrap"' EXIT
curl -fsSL --proto '=https' --proto-redir '=https' \
  https://raw.githubusercontent.com/amindqn/server-guard/master/bootstrap.sh \
  --output "$task_bootstrap"
bash "$task_bootstrap" --repo amindqn/server-guard --ref master
BASH
```

Add `--no-ui` to the final `bash` command for installation without setup. If `curl` is missing, install the download prerequisites first:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl
```

Do not use `sudo bash <(curl ...)`: sudo can close the process-substitution descriptor and produce `/dev/fd/63: No such file or directory`.

### Upgrade an old installation without `self-update`

This preserves existing configuration/data and skips guided setup. It refuses a host without an existing manager:

```bash
sudo --preserve-env=SSH_CONNECTION bash <<'BASH'
set -euo pipefail
umask 077
task_bootstrap=$(mktemp -t server-guard-bootstrap.XXXXXXXX)
trap 'rm -f -- "$task_bootstrap"' EXIT
curl -fsSL --proto '=https' --proto-redir '=https' \
  https://raw.githubusercontent.com/amindqn/server-guard/master/bootstrap.sh \
  --output "$task_bootstrap"
bash "$task_bootstrap" --repo amindqn/server-guard --ref master --upgrade-only --no-ui
BASH
```

### Future manager updates

```bash
sudo server-guard self-update --check
sudo server-guard self-update
sudo server-guard --version
```

Select a repository/ref explicitly, optionally pinning its source archive:

```bash
sudo server-guard self-update --repo amindqn/server-guard --ref master --check
sudo server-guard self-update --repo amindqn/server-guard --ref TRUSTED_COMMIT_SHA --sha256 SOURCE_ARCHIVE_SHA256
```

Downgrades require the explicit flag below and a format-compatibility review:

```bash
sudo server-guard self-update --ref REVIEWED_OLDER_REF --allow-downgrade
```

`self-update` updates **Server Guard**. `update` upgrades **Ubuntu packages**. Confirm or roll back pending access changes before installation/updating; `self-update --check` can inspect without publishing changes.

### Install from a complete local checkout or release

From the extracted project directory:

```bash
sudo bash install.sh
sudo bash install.sh --upgrade-only
```

The first command installs/updates manager files; the second requires an existing installation. These are alternatives, not two required steps. Local installation does not open setup automatically. `scripts/install_tool.py`, the Python package and documentation must be present.

Bootstrap flags when running a downloaded `bootstrap.sh`:

| Flag | Use |
| --- | --- |
| `--repo OWNER/REPO` | Select a trusted public GitHub source |
| `--ref BRANCH_OR_TAG_OR_COMMIT` | Select its code revision; default `master` |
| `--sha256 SOURCE_ARCHIVE_SHA256` | Check the GitHub source archive digest |
| `--no-ui` | Skip interactive setup |
| `--upgrade-only` | Update an installed manager without setup |
| `--allow-downgrade` | Explicitly permit an older manager version |
| `--uninstall` | Run the downloaded remover instead of installing |
| `--dry-run`, `--yes`, `--purge` | Removal options; require `--uninstall` |
| `--help` | Show bootstrap usage |

For a reproducible bootstrap, use the same reviewed commit in both the raw download URL and `--ref`. The separately built release archive has a different digest from GitHub's codeload archive.

### Open management and help

```bash
sudo --preserve-env=SSH_CONNECTION server-guard
sudo --preserve-env=SSH_CONNECTION server-guard menu
sudo --preserve-env=SSH_CONNECTION server-guard setup
server-guard --help
server-guard --version
```

The menu has setup, accounts/SSH, firewall/web, applications, V2Ray, health, recovery, uninstall, manager updates and automatic defenses. `0` goes back; `:back` cancels a form. Preserve `SSH_CONNECTION` for menu actions that verify/confirm the current transport.

Read the installed command reference after upgrading:

```bash
less /usr/local/share/doc/server-guard/docs/commands.md
```

## 3. First setup, apply, confirm and rollback (server)

Use guided setup above, or these manual steps **only on a first installation**. Replace `22` with the working SSH port. `init` refuses an existing policy rather than resetting it:

```bash
sudo server-guard prepare
sudo server-guard init --ssh-port 22
sudo server-guard user add admin --role admin --sessions 3 --key-file /home/INITIAL_USER/server_guard_admin.pub
```

If `INITIAL_USER` is root, the copied public key is normally `/root/server_guard_admin.pub`. Creating `admin` prompts for a local password for sudo. `prepare` installs dependencies; it does not upgrade existing packages. Review an Ubuntu package upgrade separately:

```bash
sudo server-guard update
```

Open a new key-only connection to the new/existing managed administrator as shown in section 1. **Inside that new server session**:

```bash
sudo -v
sudo --preserve-env=SSH_CONNECTION server-guard ssh diagnose
sudo --preserve-env=SSH_CONNECTION server-guard verify-login
sudo server-guard plan
sudo --preserve-env=SSH_CONNECTION server-guard apply
```

Login proof lasts one hour. If it is stale, open a fresh key connection and rerun `verify-login` immediately before `apply`.

If UFW is active and you have reviewed its replacement, use this **instead of** the normal apply command:

```bash
sudo --preserve-env=SSH_CONNECTION server-guard apply --replace-ufw
```

`apply` arms a 10-minute rollback. Keep the current session open, establish another new administrator key connection after apply, and confirm from it:

```bash
sudo --preserve-env=SSH_CONNECTION server-guard confirm CHANGE_ID
```

To undo an unconfirmed change from a still-working session/provider console:

```bash
sudo server-guard rollback
```

Rollback restores managed access settings and selected service state, not newly created users, keys, packages, panel/database installations or application data. Provider firewall rules are configured separately.

| Operation | When it takes effect |
| --- | --- |
| SSH port/source/root policy, extra ports, web ports, SSH session limits and adopted role rules | Staged; review `plan`, then `apply`, reconnect and confirm |
| User creation, key addition/replacement, account disabling, package/app/database/client/service operations | Immediate; not undone by access rollback |
| `defense enable --yes` / `defense disable --yes` | Changes its profile and starts its own confirmation timer; do not add another `apply` while pending |
| Health checks, inventories and preview-only maintenance forms | Inspection; no deletion/tuning until its execution option is selected |

## 4. Users, permissions and SSH session limits (server)

Copy each user's public key to the server first. Choose the appropriate role:

```bash
sudo server-guard user list
sudo server-guard user add USER_NAME --role admin --sessions 3 --key-file /ABSOLUTE/PATH/admin.pub
sudo server-guard user add USER_NAME --role developer --sessions 2 --key-file /ABSOLUTE/PATH/developer.pub
sudo server-guard user add uploads --role sftp --sessions 1 --key-file /ABSOLUTE/PATH/upload.pub
```

`admin` gets sudo; `developer` does not; `sftp` is an upload-only chroot account. Choose one creation example per new username. New SFTP restrictions become complete at apply; do not distribute access before confirmation. Administrators need at least two allowed connections for confirmation.

Adopt an **existing** ordinary panel/Linux shell account without recreating its home or keys:

```bash
sudo server-guard user adopt SITE_USER --role developer --sessions 2
sudo server-guard user adopt EXISTING_ADMIN --role admin --sessions 3
```

An adopted administrator must already have sudo. A developer must not retain privileged groups such as sudo/docker/lxd/disk. Panel UI permissions are separate from these Linux/SSH roles.

Change the concurrent SSH transport allowance (1–100; administrators at least 2):

```bash
sudo server-guard user limit USER_NAME 4
sudo server-guard plan
sudo --preserve-env=SSH_CONNECTION server-guard apply
```

Reconnect and confirm. Limits are per managed user's PAM-opened SSH transports; they are not a count of browser tabs or unauthenticated sockets. Existing connections are not terminated by changing a limit.

Append a key while retaining ordinary existing public keys:

```bash
sudo server-guard user key ADMIN_USER --key-file /ABSOLUTE/PATH/new-key.pub --append
```

Replace the key file instead, only when deliberate recovery access exists:

```bash
sudo server-guard user key USER_NAME --key-file /ABSOLUTE/PATH/replacement.pub
```

Keys change immediately and invalidate recorded login proof. Test a fresh key login before applying access changes.

Disable an account immediately:

```bash
sudo server-guard user disable USER_NAME
```

The last managed administrator and current sudo identity cannot be disabled by this command. Existing processes/sessions remain. If you deliberately need to terminate all that account's sessions/processes, assess workload impact first:

```bash
sudo loginctl terminate-user USER_NAME
```

There is no `user delete`, role-change or re-enable subcommand. Do not invent one or blindly edit the policy; use a reviewed administrative procedure for those operations.

## 5. SSH settings and key recovery

### Stage SSH changes — server

```bash
sudo server-guard ssh root disable
sudo server-guard ssh root key-only
sudo server-guard ssh sources ADMIN_IP/32
sudo server-guard ssh sources 203.0.113.7/32 2001:db8::7/128
sudo server-guard ssh sources any
sudo server-guard ssh port 2222
```

These are alternatives/examples. `root disable` blocks root SSH, not local root/sudo; `root key-only` permits root public keys, never root SSH passwords. `sources` replaces the complete SSH source list. Use `/32` for a single IPv4 address, `/128` for a single IPv6 address. `any` removes only the source restriction; key authentication remains required. Replace the documentation addresses with your own.

Review, verify a fresh key login, apply, reconnect and confirm. Before a port change, allow the **new port in the provider firewall**. Ubuntu socket activation can prevent changing ports through this workflow; see [OPERATIONS.md](OPERATIONS.md#ssh-ports-and-ubuntu-socket-activation) and use provider-console recovery for the documented migration. Do not disable the only working listener remotely.

### Forgotten private-key passphrase — your computer, then server

The old passphrase cannot be recovered by Server Guard. Keep your working server session open and create a new key under a **new filename on your computer**:

```bash
ssh-keygen -t ed25519 -a 100 -f ~/.ssh/server_guard_admin_new
cat ~/.ssh/server_guard_admin_new.pub
```

Upload its public half using your still-working old key if that key can be unlocked:

```bash
scp -o IdentitiesOnly=yes -i ~/.ssh/server_guard_admin -P SSH_PORT \
  ~/.ssh/server_guard_admin_new.pub ADMIN_USER@SERVER_IP:~/server_guard_admin_new.pub
```

If the old private key cannot be unlocked, use the existing server session's **Add SSH key** form to paste the new `.pub` text, or upload with another authorized connection. Do not close your remaining working session while attempting the unusable old key.

On the **server**, if the public file was uploaded:

```bash
sudo server-guard user key ADMIN_USER --key-file /home/ADMIN_USER/server_guard_admin_new.pub --append
```

On **your computer**, test the new key only:

```bash
ssh -o IdentitiesOnly=yes -o ControlMaster=no -o ControlPath=none \
  -o PreferredAuthentications=publickey -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -i ~/.ssh/server_guard_admin_new -p SSH_PORT ADMIN_USER@SERVER_IP
```

In that **new server session**:

```bash
sudo -v
sudo --preserve-env=SSH_CONNECTION server-guard verify-login
```

If every connection is lost, use the hosting provider's console to restore authorized access. Adding a key retains the previous one; removing a compromised old key needs an explicit reviewed key replacement.

## 6. Firewall and public websites (server)

```bash
sudo server-guard firewall list
sudo server-guard web enable
sudo server-guard web disable
```

`web enable` stages public TCP 80/443. `web disable` removes those standard public allow entries. These are alternatives. Also configure the provider firewall intentionally; no panel/database/backend port is opened automatically.

Allow an additional port from a particular source, or remove that exact allow rule:

```bash
sudo server-guard firewall allow 9443 --protocol tcp --source ADMIN_IP/32
sudo server-guard firewall deny 9443 --protocol tcp --source ADMIN_IP/32
```

For an intentionally public extra service:

```bash
sudo server-guard firewall allow 9443 --protocol tcp --source any
sudo server-guard firewall deny 9443 --protocol tcp --source any
```

Optional UDP 443, **only if your web stack intentionally supports HTTP/3**:

```bash
sudo server-guard firewall allow 443 --protocol udp --source any
sudo server-guard firewall deny 443 --protocol udp --source any
```

`deny` removes a matching allow entry; port, protocol **and source** must match. It is not a new explicit drop rule. TCP is the default protocol and `any` the default source. Manage SSH with `ssh port/sources`, not extra port rules. For each chosen staged change:

```bash
sudo server-guard plan
sudo --preserve-env=SSH_CONNECTION server-guard verify-login
sudo --preserve-env=SSH_CONNECTION server-guard apply
```

Reconnect and confirm. Existing established connections may continue after an allow rule is removed; test with a new connection. Bind app backends/databases to loopback and publish them through your intentional HTTPS reverse proxy rather than exposing every application port.

## 7. CloudPanel or aaPanel

### Install one panel — server

Complete and confirm the baseline first. Choose **one** panel; installing both over the same stack is unsupported. Downloads are not execution:

```bash
sudo server-guard panel info
sudo server-guard panel download cloudpanel
sudo less /var/lib/server-guard/downloads/cloudpanel.sh
sudo server-guard panel install cloudpanel --official-checksum --db-engine MYSQL_8.4
```

Or verify against a trusted full digest yourself:

```bash
sudo server-guard panel install cloudpanel --sha256 TRUSTED_SHA256 --db-engine MYSQL_8.4
```

CloudPanel engine choices accepted by this release: `MYSQL_8.4`, `MYSQL_8.0`, `MARIADB_12.3`, `MARIADB_11.4`, `MARIADB_10.11`. The publisher must also support the selected engine for the downloaded installer; review its current guide.

aaPanel alternative:

```bash
sudo server-guard panel download aapanel
sudo less /var/lib/server-guard/downloads/aapanel.sh
sudo server-guard panel install aapanel --sha256 TRUSTED_SHA256
```

`--official-checksum` is only implemented for CloudPanel. The aaPanel engine/plugins are managed by its own installer/panel; the CloudPanel `--db-engine` choice does not configure aaPanel. A hash printed by the download command alone is not independent publisher verification. Review the exact root installer and obtain/approve its digest before executing it.

There is no `panel uninstall` command in this release. Removing/replacing a panel or its databases requires a reviewed procedure for that actual installation.

### Private panel access — your computer

For CloudPanel, start this new administrator key connection and leave it open:

```bash
ssh -o IdentitiesOnly=yes -o ControlMaster=no -o ControlPath=none \
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
  -o ExitOnForwardFailure=yes -i ~/.ssh/server_guard_admin -p SSH_PORT \
  -L 127.0.0.1:8443:127.0.0.1:8443 ADMIN_USER@SERVER_IP sleep 3600
```

Visit `https://127.0.0.1:8443` on your computer; verify the initial certificate through a trusted channel. For aaPanel, replace `PANEL_PORT` with its actual assigned management port, use local port 8888, and retain the panel's actual HTTPS/access path:

```bash
ssh -o IdentitiesOnly=yes -o ControlPath=none -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no -o ExitOnForwardFailure=yes \
  -i ~/.ssh/server_guard_admin -p SSH_PORT \
  -L 127.0.0.1:8888:127.0.0.1:PANEL_PORT ADMIN_USER@SERVER_IP sleep 3600
```

Keep panel management ports closed publicly. These tunnels consume an administrator SSH transport allowance. A tunnel started with the wrong username or without the correct `-i` key can fail with `Permission denied (publickey)`.

## 8. MongoDB (server)

Install the panel first, then the optional separately managed MongoDB. Do not install an aaPanel MongoDB plugin over it. Choose one port; default 27017, alternative 27018:

```bash
sudo server-guard mongodb install
sudo server-guard mongodb install --port 27018
```

Those are alternatives for the first installation. Installation leaves MongoDB stopped/disabled until bootstrap; it refuses existing installations/data. Bootstrap its first administrator at hidden password prompts:

```bash
sudo server-guard mongodb bootstrap --admin mongoAdmin
sudo server-guard mongodb status
```

If initialization was interrupted **after** the administrator was created, authenticate with that existing administrator instead:

```bash
sudo server-guard mongodb bootstrap --admin mongoAdmin --authenticate
```

Create scoped application users, rotate a password, revoke access or open the authenticated administrator shell:

```bash
sudo server-guard mongodb user-add appuser --database myapp --role readWrite --admin mongoAdmin
sudo server-guard mongodb user-add reports --database myapp --role read --admin mongoAdmin
sudo server-guard mongodb password appuser --database myapp --admin mongoAdmin
sudo server-guard mongodb user-revoke reports --database myapp --admin mongoAdmin
sudo server-guard mongodb shell --admin mongoAdmin
```

Enter passwords at prompts; do not put them in command arguments. `readWrite` is the default application role. The `--admin` default is `mongoAdmin`; use the administrator's actual name. Bootstrap is required before starting/restarting through the service controls below.

For a GUI on **your computer**, forward local 27018 to the server's MongoDB port (shown here as 27017):

```bash
ssh -o IdentitiesOnly=yes -o ControlPath=none -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no -o ExitOnForwardFailure=yes \
  -i ~/.ssh/server_guard_admin -p SSH_PORT \
  -L 127.0.0.1:27018:127.0.0.1:27017 ADMIN_USER@SERVER_IP sleep 3600
```

Connect the GUI to `127.0.0.1:27018`, using the relevant MongoDB identity/authentication database. Do not publicly allow 27017. The deployment is standalone; replica-set features and consistent data backups need separate administration. There is no MongoDB removal or database-drop command in Server Guard.

## 9. V2Ray and client configurations (server)

Create DNS and a valid HTTPS site for `vpn.example.com` in the panel first. Replace that example domain and use a reviewed v5 release/digest for **`v2ray-linux-64.zip`**:

```bash
sudo server-guard v2ray install --version V2RAY_VERSION --sha256 OFFICIAL_ARCHIVE_SHA256
sudo server-guard v2ray configure --domain vpn.example.com --local-port 10000
sudo server-guard v2ray add phone
sudo server-guard v2ray nginx
```

Insert the printed WebSocket `location` block inside that site's HTTPS Nginx server block. Validate/reload through the panel, preserving TLS certificates and renewal. The backend stays on localhost; public clients use HTTPS 443. Public web access also needs `web enable`, apply/confirmation and matching provider rules.

```bash
sudo server-guard v2ray list
sudo server-guard v2ray export phone
sudo server-guard v2ray revoke phone
```

Export prints a **secret** VMess connection link. Use separate names per intended user/device. Configure/add/revoke restarts V2Ray and interrupts its sessions. This does not implement quotas, per-client device limits or an IP-forwarding VPN.

For a reviewed binary update, stop the service before the pinned replacement, then configure with your existing domain/backend port again:

```bash
sudo server-guard service v2ray stop
sudo server-guard v2ray install --version V2RAY_VERSION --sha256 OFFICIAL_ARCHIVE_SHA256
sudo server-guard v2ray configure --domain vpn.example.com --local-port 10000
```

This is separate from `self-update`. Keep a verified binary/config backup for recovery.

## 10. Service controls (server)

These commands act immediately on already installed services:

```bash
sudo server-guard service mongodb status
sudo server-guard service mongodb start
sudo server-guard service mongodb restart
sudo server-guard service mongodb stop
sudo server-guard service v2ray status
sudo server-guard service v2ray start
sudo server-guard service v2ray restart
sudo server-guard service v2ray stop
```

Choose the needed action; do not paste the whole block to cycle services. Stop/restart interrupts applications/connections. Managed start/restart requires service readiness; MongoDB must be bootstrapped first. Pending access changes block service mutations. There is no generic `service NAME` control for SSH/firewall through Server Guard.

## 11. Automatic attack protection (server)

Menu **10**, or preview and activate the optional profile after confirmed baseline setup:

```bash
sudo --preserve-env=SSH_CONNECTION server-guard defense enable
sudo --preserve-env=SSH_CONNECTION server-guard defense enable --yes
```

The second command changes ban policy and starts its **own** 10-minute confirmation timer. Open a fresh administrator key connection and use the printed `confirm CHANGE_ID` command. The current client is exempted from managed bans when the real `SSH_CONNECTION` is preserved; exemptions do not open ports.

Additional trusted administration networks and check interval (5–1440 minutes, default 15):

```bash
sudo --preserve-env=SSH_CONNECTION server-guard defense enable --trusted ADMIN_IP/32 --minutes 30 --yes
```

Optional root-owned Nginx **error log**, only when clients connect directly without a CDN/upstream proxy:

```bash
sudo --preserve-env=SSH_CONNECTION server-guard defense enable \
  --nginx-log /var/log/nginx/error.log --direct-web-clients --yes
```

Repeat `--nginx-log` for multiple exact trusted logs. Inspect the actual panel log path and rotation ownership; do not enable origin firewall bans for client addresses carried only in proxy headers. This is limited auth/bot-search detection, not a general WAF or protection from every attack.

```bash
sudo server-guard defense status
sudo server-guard defense scan
sudo server-guard defense history
sudo journalctl -u server-guard-defense.service --since today --no-pager
```

After explaining all legitimate reported changes, explicitly replace the trusted file/firewall baseline:

```bash
sudo server-guard defense baseline
sudo server-guard defense baseline --yes
```

The first command previews; the second accepts the reviewed **current** state. Do not accept unexplained drift or run it while access confirmation is pending. Scanning never deletes/restores files or silently accepts a changed baseline. Alerts/history are local; external notification delivery needs separate setup.

Preview or execute a false-ban recovery, including during a pending access change:

```bash
sudo server-guard defense unban sshd CLIENT_IP
sudo server-guard defense unban sshd CLIENT_IP --yes
sudo server-guard defense unban server-guard-nginx-auth CLIENT_IP --yes
sudo server-guard defense unban server-guard-nginx-bots CLIENT_IP --yes
```

Choose the actual jail. Unbanning does not permanently trust the client or erase all history; new failures can cause a new ban.

Disable the extra profile, keeping basic SSH bans, SSH/firewall policy and security updates:

```bash
sudo server-guard defense disable
sudo server-guard defense disable --yes
```

Confirm the executed disable operation from a fresh administrator key connection. Review [DEFENSE.md](DEFENSE.md) for coverage, limits and restore behavior.

## 12. Health, monitoring, storage and cleanup (server)

### Checks and saved results

```bash
sudo server-guard health check
sudo server-guard health check --json
sudo server-guard health check --record
sudo server-guard health check --no-record
sudo server-guard health show
sudo server-guard health show --json
sudo server-guard health history --limit 20
```

Checks save reports by default; `--record` makes that default explicit and `--no-record` skips saving this check. JSON progress goes to stderr. `show/history` read saved evidence, not a fresh probe. History accepts limits 1–200; up to 200 health reports are retained separately from defense reports.

### Live view

```bash
sudo server-guard health watch --interval 5
sudo server-guard health watch --interval 5 --count 12
```

Ctrl+C stops the live view. Intervals are 2–3600 seconds; count 0 (default) runs until interrupted, otherwise 1–10000 frames. The first frame includes security; later frames sample resources.

### Scheduled local health checks

```bash
sudo server-guard health monitor status
sudo server-guard health monitor enable --minutes 5 --cpu 90 --memory 90 --disk 85 --inodes 85
sudo server-guard health monitor enable --minutes 5 --cpu 90 --memory 90 --disk 85 --inodes 85 --yes
sudo server-guard health monitor disable
sudo server-guard health monitor disable --yes
```

Mutation commands preview unless `--yes` is present. Intervals are 1–1440 minutes; warning thresholds 50–99 percent. Defaults: CPU/RAM 90, disk/inodes 85. Health scheduling reports findings; it does not delete files, restart applications or enable attack protection automatically.

### Find large files without deleting them

```bash
sudo server-guard health files
sudo server-guard health files /root --min-mib 500 --limit 50
sudo server-guard health files /var/backups --min-mib 100 --limit 50
sudo server-guard health files / --min-mib 500 --limit 50 --max-entries 1000000 --max-seconds 120
```

The default path is `/var`, minimum 100 MiB, displayed limit 20, scan budget 100000 entries/30 seconds. Minimum size accepts 1–1048576 MiB, display limit 1–100, scan budget up to 10000000 entries/3600 seconds. Budgets are cooperative; scans stay on one filesystem and report partial/skipped coverage. A directory can hold many small files even when no individual file exceeds the filter.

### Review and remove one inventoried file

```bash
sudo server-guard health delete SCAN_ID ITEM
sudo server-guard health delete SCAN_ID ITEM --yes
```

First inspect the exact item printed by an inventory, then execute only if wanted. Deletion is permanent and refuses changed, open, hard-linked, stale or protected entries. It operates on one eligible regular file, not a backup directory tree; database/SSH/system/recovery files have extra restrictions. Inventories expire for deletion after one hour. See [HEALTH.md](HEALTH.md#find-and-remove-a-large-file).

### Reviewed cache/journal cleanup

```bash
sudo server-guard health cleanup apt-cache
sudo server-guard health cleanup apt-cache --yes
sudo server-guard health cleanup journal --days 14
sudo server-guard health cleanup journal --days 14 --yes
```

APT-cache cleanup removes downloaded package archives, not installed packages. Journal cleanup permanently removes eligible archived logs and can remove investigation evidence; active logs may remain. Journal retention accepts 7–3650 days. No arbitrary app/database cleanup is performed.

### Reversible application CPU scheduling

```bash
sudo server-guard health cpu-weight mongodb --weight 200
sudo server-guard health cpu-weight mongodb --weight 200 --yes
sudo server-guard health cpu-weight mongodb --reset
sudo server-guard health cpu-weight mongodb --reset --yes
```

Service choices: `mongodb`, `v2ray`, `nginx`, `mysql`, `mariadb`. Weight is 1–10000; select **either** `--weight` or `--reset`. This adjusts runtime sharing under contention without restarting; it does not create CPU capacity or set a hard limit. Changes expire at reboot; reset restores the saved prior value.

## 13. Ordinary Ubuntu diagnostics (server)

These utilities work independently of Server Guard. They are inspection commands unless explicitly marked otherwise.

### Disk usage and free space

```bash
df -hT
df -h /
df -ih
sudo du -xhd1 / | sort -hr
sudo du -xhd1 /root | sort -hr
sudo du -xah --max-depth=1 /var/backups | sort -hr | head -30
sudo journalctl --disk-usage
findmnt -rn -o TARGET,SOURCE
```

`df` shows filesystem capacity/used/available space; `du` attributes usage to files/directories. `-x` stays on one filesystem. A large directory can be a copied filesystem/backup tree rather than one large archive.

Find individual regular files larger than 10 GiB on the root filesystem; no deletion:

```bash
sudo find / -xdev -type f -size +10G -printf '%s\t%p\n' | sort -nr | head -50
```

For one candidate, use its exact absolute path:

```bash
sudo ls -ldh -- /ABSOLUTE/PATH/backup.tar.gz
sudo file -- /ABSOLUTE/PATH/backup.tar.gz
```

Only after verifying that the candidate is an unwanted ordinary file and not live data, this **permanently deletes that one file after a prompt**:

```bash
sudo rm -i -- /ABSOLUTE/PATH/backup.tar.gz
```

This is an ordinary utility and has none of Server Guard's inventory/open-file/protected-path checks. Do not turn a search into an automatic `find ... -delete` command or use a guessed recursive path.

### CPU, RAM, uptime and processes

```bash
uptime
free -h
top
ps -eo pid,user,comm,%cpu,%mem --sort=-%cpu | head -20
ps -eo pid,user,comm,%cpu,%mem --sort=-%mem | head -20
```

### Listening ports, services and logs

```bash
sudo ss -lntup
sudo nft list table inet server_guard
sudo nft list table inet server_guard_v2ray
sudo systemctl --failed --no-pager
sudo systemctl status ssh ssh.socket --no-pager
sudo journalctl -u ssh --since today --no-pager
sudo journalctl -u fail2ban --since today --no-pager
sudo journalctl -u mongod --since today --no-pager
sudo journalctl -u server-guard-v2ray --since today --no-pager
sudo systemctl list-timers --all --no-pager
```

An absent optional unit/table is expected before installing its feature. `ss`/local rules do not establish reachability through the provider firewall or external IPv4/IPv6 networks.

### Security inspection and package maintenance

```bash
sudo server-guard status
sudo server-guard audit
sudo fail2ban-client status
sudo fail2ban-client status sshd
sudo aa-status
timedatectl status
sudo /usr/sbin/sshd -t
sudo /usr/sbin/sshd -T
test -f /var/run/reboot-required && cat /var/run/reboot-required
```

`audit` runs Lynis and reports recommendations. `sshd -t/-T` validate/read configuration; they do not themselves reload the daemon. Schedule a reboot deliberately after confirming access and application impact; the manager does not automatically reboot.

On a standard Ubuntu Nginx installation, validate before reload; a panel's custom binary/config may instead require its own controls:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

## 14. Recovery and troubleshooting

### Inspect pending rollback — server/provider console

```bash
sudo systemctl status server-guard-rollback.timer --no-pager
sudo journalctl -u server-guard-rollback.service --no-pager
sudo server-guard rollback
```

Use `rollback` only when you intend to restore the pending snapshot; it is not a status command. The durable record is `/var/lib/server-guard/pending.json`, with archived transactions under `/var/lib/server-guard/history/`. Do not delete that record or all nftables rules as a shortcut. Provider console access is the recovery route when SSH is unavailable.

### Diagnose connection errors — your computer

```bash
ssh -vv -o IdentitiesOnly=yes -o ControlMaster=no -o ControlPath=none \
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
  -i ~/.ssh/server_guard_admin -p SSH_PORT ADMIN_USER@SERVER_IP
```

Verbose output can reveal addresses, usernames and local paths; redact before sharing. Repeated **key passphrase** prompts mean local key unlocking needs attention; `Permission denied (publickey)` needs the actual username/key/port/public-key registration checked. A server-password login does not satisfy `verify-login`. Do not solve these errors by turning password/root SSH back on blindly.

For stale login proof, establish a fresh key-only transport, run `sudo --preserve-env=SSH_CONNECTION server-guard verify-login` there, then review/apply promptly. For a pending transaction, confirm it from a post-change key connection or roll it back before attempting another mutation/update/uninstall.

### Fail2Ban socket not ready after restart — server

Version **1.6.0** could check Fail2Ban before its control socket/jails were ready, then roll back a valid profile. **1.6.1** waits up to 30 seconds for readiness and preserves recovery on genuine failure. Publish/install the fixed release before retrying profile activation. A configuration test alone does not establish that the live daemon/jail is ready:

```bash
sudo systemctl status fail2ban --no-pager -l
sudo journalctl -u fail2ban -n 80 --no-pager
sudo fail2ban-client -t
sudo fail2ban-client ping
sudo fail2ban-client status sshd
```

After upgrading, verify the installed version and retry:

```bash
sudo server-guard --version
sudo --preserve-env=SSH_CONNECTION server-guard defense enable --yes
```

Expect 1.6.1 or newer. Keep the old SSH connection open and confirm the printed ID from a fresh administrator key connection. The `allowipv6 ... Using default one: auto` warning can accompany a successful configuration test; it does not explain this timing failure.

## 15. Uninstall (server)

### Installed manager

```bash
sudo server-guard uninstall --dry-run
sudo server-guard uninstall
```

The interactive command shows a plan and requires typing `UNINSTALL`. After reviewing, automation can use:

```bash
sudo server-guard uninstall --yes
```

To additionally remove unused configuration **only before hardening/optional-service setup**:

```bash
sudo server-guard uninstall --dry-run --purge
sudo server-guard uninstall --purge
```

`--purge` is refused when configuration is needed for working protection/services. Uninstall removes manager code/docs/history and its scheduled checks, retaining Linux users, SSH keys/settings, native protection, installed packages, panels, MongoDB/V2Ray and application/database data. It creates a private recovery backup under `/var/backups/server-guard/`. Pending access changes block removal. It does not reset Ubuntu or remove a panel/database stack.

### Older version or missing uninstall command

Download the standalone remover completely before executing. The example executes an **interactive removal plan**, not a preview:

```bash
sudo bash <<'BASH'
set -euo pipefail
umask 077
task_uninstaller=$(mktemp -t server-guard-uninstall.XXXXXXXX)
trap 'rm -f -- "$task_uninstaller"' EXIT
curl -fsSL --proto '=https' --proto-redir '=https' \
  https://raw.githubusercontent.com/amindqn/server-guard/master/uninstall.sh \
  --output "$task_uninstaller"
bash "$task_uninstaller" --repo amindqn/server-guard --ref master
BASH
```

Append `--dry-run` to the final `bash` command for preview only, `--yes` for reviewed noninteractive removal, or `--purge` under its documented restriction. This fetches the remover without installing/upgrading the manager. A downloaded bootstrap can also run `sudo bash bootstrap.sh --uninstall --dry-run`; never combine uninstall with upgrade-only flags.

## 16. Help, internal commands and development

### Help for every command group — server

```bash
server-guard --help
server-guard self-update --help
server-guard user --help
server-guard ssh --help
server-guard firewall --help
server-guard panel --help
server-guard mongodb --help
server-guard v2ray --help
server-guard service --help
server-guard defense --help
server-guard health --help
server-guard uninstall --help
server-guard defense enable --help
server-guard health files --help
```

Append `--help` to any command/subcommand to see that parser's options without executing its operation. `web` accepts `enable` or `disable`; service actions are `start`, `stop`, `restart`, `status`.

### Internal entry points — reference only

These are included for completeness, not the normal way to apply changes:

| Entry point/flag | Purpose |
| --- | --- |
| `server-guard firewall-load` | systemd loads the **already applied** firewall; bypasses normal plan/apply confirmation flow |
| `server-guard v2ray-egress-load` | systemd restores the proxy's owned egress-isolation table |
| `server-guard defense scan --scheduled` | Security timer tags a read-only scan as scheduled |
| `server-guard uninstall --expected FINGERPRINT` | Interactive adapter detects configuration changes between plan review and execution |
| `python3 -I scripts/install_tool.py --source-root /ABSOLUTE/RELEASE` | Installer driver used by `install.sh`; also accepts `--upgrade-only`, `--allow-downgrade`, and source metadata options `--repo`, `--ref`, `--archive-sha256` (provide the metadata trio together) |
| `python3 -I scripts/uninstall_entry.py` | Downloaded removal adapter; accepts normal uninstall options without installing the manager |

### Source development — your computer/checkout

These do not configure the Ubuntu host when run as documented in a local checkout. The preview disables submitted host commands:

```bash
python3 scripts/preview_terminal.py
python3 -m unittest discover -s tests -q
python3 -m compileall -q server_guard tests scripts
bash -n install.sh
bash -n bootstrap.sh
bash -n uninstall.sh
python3 scripts/build_release.py
```

Release archives/checksums appear in `dist/`. Local tests/previews are not proof of live Ubuntu firewall/PAM/SSH behavior; see [VALIDATION.md](VALIDATION.md). Related guides: [README](../README.md), [operations/recovery](OPERATIONS.md), [health/cleanup](HEALTH.md), [automatic defenses](DEFENSE.md) and [terminal menus](TERMINAL_UI.md).
