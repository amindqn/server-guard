# Server Guard

A repeatable administration tool for **Ubuntu 24.04 LTS**, targeting your **x86_64** server. Install it once, follow the terminal setup wizard, then run `server-guard` whenever you need to manage the server. Python's standard library handles orchestration; Ubuntu packages provide the actual security services.

See the [complete command reference](docs/commands.md) for SSH key setup/login, installation and upgrades, users, firewall, panels, MongoDB/V2Ray, automatic defenses, monitoring, storage cleanup, recovery and uninstall. It separates commands for your computer from commands for the server and is installed with the other guides.

## Quick start

From your normal SSH account with sudo access, run this command on the server. It downloads the `master` branch of [amindqn/server-guard](https://github.com/amindqn/server-guard):

```bash
sudo --preserve-env=SSH_CONNECTION bash -c 'bash <(curl -fsSL --proto "=https" --proto-redir "=https" https://raw.githubusercontent.com/amindqn/server-guard/master/bootstrap.sh) --ref master'
```

The outer privileged Bash creates the `<(...)` descriptor after sudo has started. Do not use `sudo bash <(curl ...)`: sudo normally closes that descriptor, causing `/dev/fd/63: No such file or directory`. If already in a root Bash shell, use `bash <(curl ...)` directly without sudo. A complete-download temporary-file method is also provided below.

The installer downloads the project and **opens the terminal setup UI automatically**. It guides you through dependency installation, the current SSH port, an administrator username/public key and a tested key login. It pauses for the new SSH login before applying access restrictions, then requires another new login to confirm the rollback-protected change. Your existing root/password connection stays available during the initial account setup.

Reopen the management UI anytime:

```bash
sudo server-guard
```

Resume the first-time wizard from the new administrator SSH connection:

```bash
sudo --preserve-env=SSH_CONNECTION server-guard setup
```

The home menu has ten groups: **setup, accounts/SSH, firewall/web, applications/databases, V2Ray, health/maintenance, changes/recovery, uninstall, update Server Guard, and automatic attack protection**. Existing features remain available inside those groups. Setup shows completed steps and the next action; roles, database engines and key actions use numbered choices. Enter a number, press Enter to accept a default, use `0` to go back, or enter `:back` to cancel a form. Colors are optional (`NO_COLOR=1`), and all choices/errors are written as text. No additional terminal UI packages are needed.

For an install without opening the UI, append `--no-ui`. With no interactive terminal, the installer prints the command to open setup later. Have provider console access and a snapshot ready before applying security changes. Keep the panel/database ports closed in your provider firewall. [Detailed terminal walkthrough](docs/TERMINAL_UI.md).

## Update Server Guard without resetting your server

**Already installed an older version without an update option?** Run this entire block on the server from your normal sudo account. It downloads the new bootstrap completely before execution and updates the existing manager without opening setup:

```bash
sudo bash <<'BASH'
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

This works with the previous 1.4.x layout and does not call any command from the old manager. `--upgrade-only` refuses a server without an existing installation. The repository's selected ref must contain the new bootstrap and installer (1.5.0 or later); publish those files before using this command. If using a fork, replace the owner/repository in both places.

**After this first upgrade**, use these commands or open `sudo server-guard` → **9 Update Server Guard**:

```bash
sudo server-guard self-update --check   # download/inspect; no installed files changed
sudo server-guard self-update           # install the available manager update
sudo server-guard --version
```

The update submenu offers **Check** and **Install**, then reopens the menu using the updated code after success. The CLI update runs without interactive setup. The existing `sudo server-guard update` still upgrades **Ubuntu packages**; it is separate from `self-update`.

Updates replace management code and documentation. They preserve existing policy, SSH settings and authorized keys, Linux users/roles, session limits/ledger, firewall rules and open ports, panel installations, MongoDB and V2Ray configuration/data/clients, scheduled monitoring and saved history. They do not run `prepare`, `init` or `apply`, install/upgrade Ubuntu packages, restart services or reboot the server. Confirm or roll back any pending access change first; a pending rollback blocks installation, while `--check` remains available.

The installer validates a complete staged version before activation and creates a private recovery backup at `/var/backups/server-guard/updates/`. A detected publication/validation failure or caught interruption restores the previous manager files. Complete releases remain under `/opt/server-guard/releases/`; the launcher resolves `/opt/server-guard/current` once per process. The stable standalone PAM helper path remains available to older SSH configurations. Existing settings are not reinitialized, and this release requires no policy-format migration. See [update and recovery details](docs/OPERATIONS.md#updating-the-manager).

The default source is the recorded GitHub repository/ref, or `amindqn/server-guard` at `master` for a local installation. To select reviewed code explicitly:

```bash
sudo server-guard self-update --ref TRUSTED_COMMIT_SHA --sha256 SOURCE_ARCHIVE_SHA256
```

Use a repository/ref you trust: installing an update executes its code as root. `--sha256` checks the GitHub source archive, not the separately built release archive. Downgrades require `--allow-downgrade`; source/ref/digest are recorded only after successful installation. The recovery backup contains manager code and configuration, including sensitive SSH/V2Ray files. It is **not** a full website/database backup; continue your regular off-server backups.

## Quick uninstall

From your normal SSH account with sudo access, including when your installed version has no uninstall command:

```bash
sudo bash -c 'bash <(curl -fsSL --proto "=https" --proto-redir "=https" https://raw.githubusercontent.com/amindqn/server-guard/master/uninstall.sh)'
```

It downloads the standalone uninstaller without installing/updating the manager, shows a removal plan and requests confirmation. To preview only, append `--dry-run`. The bootstrap also accepts `--uninstall` with the same options.

With the updated manager already installed:

```bash
sudo server-guard uninstall --dry-run  # review only
sudo server-guard uninstall            # review and type UNINSTALL
```

For automation, `sudo server-guard uninstall --yes` executes the same plan without a prompt. Menu **8** also removes the manager.

**Removal preserves protection and applications.** It removes the management command/package/docs/history; it keeps Linux users, SSH keys, packages, panels, MongoDB, V2Ray and all application/database data. It also keeps current SSH settings, Fail2Ban, automatic updates and firewall/session limits. Necessary standalone helpers are retained under `/usr/local/lib/server-guard-retained`; `/etc/server-guard` remains for recovery or reinstall. SSH and applications are not restarted. This is manager removal, not a reset of Ubuntu or a re-enable of root/password login.

A private recovery copy is created under `/var/backups/server-guard/`; its location is printed and recorded in `last-uninstall.json` there. Pending access changes block removal. If validation fails, the manager is kept and runtime edits are restored. `--purge` additionally removes unused `/etc/server-guard` configuration **only before hardening or optional-service setup**. It never deletes application data or users. [Removal details](docs/OPERATIONS.md#uninstall-and-reinstall).

The default panel recommendation is **CloudPanel**, because it supports static/front-end sites, Node.js, Python, PHP, reverse proxies, and separate Admin / Site Manager / site-specific User permissions. Its panel-managed databases are MySQL/MariaDB. **MongoDB is an optional service managed by this tool**, alongside either panel. **aaPanel is also supported** if you prefer its broader plugin and database ecosystem. Install exactly one panel first, on an otherwise empty server; then add MongoDB. PostgreSQL/Redis need separate installation with CloudPanel. MongoDB supplements the panel's database engine; it does not replace CloudPanel's required MySQL/MariaDB installation.

Read [the research and tradeoffs](docs/RESEARCH.md), [ongoing operations](docs/OPERATIONS.md), and [the Ubuntu validation checklist](docs/VALIDATION.md).

## Automatic attack protection

Version **1.6.0** adds menu **10 Automatic attack protection and security alerts**. After updating the manager and confirming Guided setup, review and enable the profile:

```bash
sudo --preserve-env=SSH_CONNECTION server-guard defense enable        # preview
sudo --preserve-env=SSH_CONNECTION server-guard defense enable --yes  # activate
```

Use **1.6.1 or later** for activation. This patch waits for Fail2Ban's control socket and required jails after restart; version 1.6.0 could check too early and roll back a valid setup. If your installed copy shows 1.6.0, publish/install the fixed release using the upgrade instructions above first.

Keep the existing SSH connection open. Activation arms a **10-minute rollback**. Reconnect with a new administrator **key** login and run the printed `server-guard confirm CHANGE_ID` command. Subsequent checks/blocking run automatically, including after boot.

The profile adds **increasing bans for repeated SSH attacks**, trusted root-origin SSH journal matching, optional direct-client **Nginx authentication/bot-search bans**, scheduled **critical-file and running-firewall drift detection**, stopped-defense/AppArmor checks, and private alert history. Ubuntu security-update timers are enabled without automatic reboot. The current SSH client's address is exempted from managed bans when its environment is preserved; this does not open firewall ports. Enable/disable is rollback protected, and existing settings/users/application/database data are retained.

```bash
sudo server-guard defense scan
sudo server-guard defense status
sudo server-guard defense history
sudo server-guard defense unban sshd CLIENT_IP --yes
```

Alerts remain local, and changed files are never automatically deleted, restored or accepted as trusted. A legitimate reviewed change can be accepted with `defense baseline --yes` after confirming pending access changes. Optional web bans require reviewed root-owned logs and `--direct-web-clients`; they are unsuitable for an origin behind a CDN/upstream proxy. Application WAF/authentication controls, external alerts, restore-tested off-server backups and provider DDoS protection still need deployment-specific setup. Installing/updating the manager does not silently enable this profile. [Setup, limits, commands and primary sources](docs/DEFENSE.md).

## Server checks, monitoring and cleanup

Open menu **6 Server health, monitoring and maintenance** for a progress check, live CPU/RAM/storage/network view, saved results, storage explorer, reviewed cleanup and application CPU scheduling. Existing audits, updates and security-service status are inside that menu.

```bash
sudo server-guard health check
sudo server-guard health watch --interval 5
sudo server-guard health history
sudo server-guard health files /var --min-mib 100
```

Findings include security controls, CPU/load/steal/I/O pressure, available RAM/swap, disks/inodes, busy processes, listeners, failed services, package-upgrade and reboot state. Reports distinguish warnings from unknown evidence and suggest a next step. Optional scheduled checks keep up to 200 private local reports; no public port or external account is required. Large-file deletion, APT-cache/journal cleanup and reversible runtime CPU scheduling require explicit review/confirmation. CPU priority shares existing capacity; it is not a universal speedup. [Commands, thresholds and maintenance details](docs/HEALTH.md).

## What it does

- Creates administrators with password-protected sudo, ordinary developers without sudo, and chrooted SFTP-only accounts.
- Requires a successful administrator SSH **public-key** login and sudo test before hardening access. Disables password SSH and root SSH by default, preserving the local root account for console recovery.
- Enforces configurable concurrent **PAM-opened SSH transport** allowances per managed user with a locked ledger; limits multiplexed channels to one per connection. OpenSSH 9.6 opens PAM for authenticated transports, including `ssh -N`; validate this against the server's actual package. This is not a cap on unauthenticated network sockets. Administrators can bypass controls using sudo; they are fully trusted.
- Applies a default-deny IPv4/IPv6 nftables firewall. Initially only the configured SSH port is allowed. Loopback, established traffic, ICMP/IPv6 neighbor discovery and DHCP replies remain available. Egress is allowed.
- Keeps the panel, database and app backend ports private. `web enable` opens TCP 80/443 for the panel-managed Nginx front end. New panel apps do **not** automatically open arbitrary ports.
- Arms a persistent **10-minute rollback timer** before SSH/firewall changes. A new administrator key login must confirm the change. Snapshots restore managed config, the tool's firewall table and selected service/sysctl state; package installs, accounts, passwords, keys and panel installation are retained.
- Configures SSH Fail2Ban, Ubuntu automatic security updates without automatic reboot, persistent bounded journals, and conservative network/kernel settings. Installs AppArmor utilities, auditd and Lynis; it does not automatically enforce new AppArmor profiles or claim a CIS certification.
- Installs a checksum-pinned V2Ray v5 binary, runs it as a restricted service user, generates/revokes VMess clients, and exports `vmess://` links. Uses a private WebSocket backend behind your panel's HTTPS site. Its egress firewall blocks new connections to private networks, loopback services, link-local metadata and SMTP submission ports, with an exception for Ubuntu's local DNS stub.
- Optionally installs MongoDB Community 8.0 from its signed official repository, enables authentication, binds it to localhost, and creates/revokes database-scoped read/read-write users. Passwords are entered at hidden prompts, never command arguments or saved credential files.

**Limits:** no script protects against every attack. Application vulnerabilities, leaked credentials, malicious root administrators, compromised package/installer publishers and bandwidth-exhausting DDoS attacks require additional controls. Use provider filtering/DDoS protection, application patching, HTTPS, MFA, separate site/database users, monitoring and off-server backups with restore tests. Hosting a proxy on the same server increases its attack and abuse exposure; a separate VPS is preferable when practical.

This release is for a normal systemd VM or bare-metal server, **not a router, Docker bridge host, Kubernetes node, VPN gateway, or shared tenant sandbox**. Forwarded traffic is dropped. Native panel apps and application proxies work without IP forwarding. Do not install a panel over an existing production stack.

## GitHub installation with a pinned ref or downloaded script

After pushing **all project files**, including `bootstrap.sh`, `install.sh`, `server_guard/` and `docs/`, to [amindqn/server-guard](https://github.com/amindqn/server-guard), copy this **single compound command** into the Ubuntu server terminal. Change `task_ref` to install a specific tag or commit. Forks can change `task_repo_url` to their own public GitHub repository:

```bash
(
  set -eu
  task_repo_url='https://github.com/amindqn/server-guard'
  task_repo=${task_repo_url#https://github.com/}
  task_repo=${task_repo%/}
  task_repo=${task_repo%.git}
  task_ref='master'
  task_bootstrap=$(mktemp)
  trap 'rm -f -- "$task_bootstrap"' EXIT
  curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
    "https://raw.githubusercontent.com/$task_repo/$task_ref/bootstrap.sh" --output "$task_bootstrap"
  sudo bash "$task_bootstrap" --repo "$task_repo" --ref "$task_ref"
)
```

This downloads the complete source archive from GitHub, checks its paths/file types, installs the management tool and saves its source repository/ref/archive digest in `/opt/server-guard/source.json`. It needs `curl` for the initial download; if missing, first run `sudo apt-get update && sudo apt-get install -y ca-certificates curl`.

The command installs/updates the tool and opens guided setup when a terminal is available. It preserves an existing policy and refuses an update during an unconfirmed access change. Setup prompts you before submitting changes and retains SSH login verification and rollback confirmation. Add `--no-ui` to the `sudo bash` line for installation only. The guide is also installed at `/usr/local/share/doc/server-guard/README.md`. The manual CLI steps below remain available; skip the source-copy and `bash install.sh` steps when using the GitHub installer.

For a reproducible install, set `task_ref` to a full trusted commit SHA; it is used for both the bootstrap download and source archive. Optionally add `--sha256 SOURCE_ARCHIVE_SHA256` to the `sudo bash` line to verify the **GitHub codeload source archive**, whose hash differs from the separately built release archive. A moving branch installs whatever code the repository currently publishes; use a repository/ref you trust. The same command can update the tool later; review changes and retain recovery access first.

## 1. Prepare access and copy the tool

Have the hosting provider's console/rescue interface available and take a server snapshot. Keep the current root/password SSH connection open until a new administrator login works.

In your **provider firewall/security group**, allow the current SSH port. Keep panel ports (CloudPanel 8443 and aaPanel's assigned port) and database ports closed, for both IPv4 and IPv6. Later allow TCP 80/443 for public websites. Provider filtering protects the panel even while its root installer runs.

On **your computer**, create a dedicated key with a passphrase. Keep the private file on your computer; only copy the `.pub` file:

```bash
ssh-keygen -t ed25519 -a 100 -f ~/.ssh/server_guard_admin
scp ~/.ssh/server_guard_admin.pub root@SERVER_IP:/root/server_guard_admin.pub
scp -r /PATH/TO/server-config root@SERVER_IP:/root/server-config
```

Use `scp -P CURRENT_SSH_PORT` if the current port is not 22. Replace placeholders and paths with real values. Alternatively, copy and extract the supplied release archive on the server.

For the archive, copy `server-guard-1.6.1.tar.gz` and its `.sha256` file to `/root`, then on the server run:

```bash
cd /root
sha256sum -c server-guard-1.6.1.tar.gz.sha256
tar -xzf server-guard-1.6.1.tar.gz
cd /root/server-guard-1.6.1
```

Use this extracted directory in place of `/root/server-config` below. The adjacent checksum detects transfer damage; obtain the archive/checksum through a trusted channel.

On **the server**, in your existing root connection:

```bash
cd /root/server-config
bash install.sh
server-guard prepare
server-guard update
server-guard init --ssh-port 22
server-guard user add admin --role admin --sessions 3 --key-file /root/server_guard_admin.pub
```

Use your **actual current SSH port** in `init`. `update` asks before installing updates. `user add` prompts for the new administrator's local sudo password. The key is used for SSH; the password is used for sudo. No panel or application has been installed yet.

## 2. Verify the new administrator

Open a **second terminal on your computer**:

```bash
ssh -o IdentitiesOnly=yes -o ControlPath=none -o PreferredAuthentications=publickey \
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -i ~/.ssh/server_guard_admin admin@SERVER_IP
sudo --preserve-env=SSH_CONNECTION server-guard verify-login
```

Add `-p CURRENT_SSH_PORT` to SSH when appropriate. Enter the administrator's local password for sudo. Verification matches this transport to an `Accepted publickey` SSH journal entry. If it fails, fix the new login before continuing. Proof is valid for one hour.

`Enter passphrase for key ...` asks for the passphrase you chose when creating the key **on your computer**. It is separate from the server account password and the sudo password. Repeated prompts usually mean the key passphrase was not accepted. If you forgot it, create a new key under a **new filename**, keep your working server session open and use Accounts → Users → Add or replace a public SSH key → **Add**. Test the new connection before removing old keys. The CLI equivalent is `sudo server-guard user key admin --key-file /path/to/new.pub --append`. Append supports ordinary public-key lines; custom authorized-key options require manual review and are left untouched on refusal.

Use `sudo --preserve-env=SSH_CONNECTION server-guard ssh diagnose` to see whether the current transport authenticated with a public key or a password. A password login cannot satisfy `verify-login`; switching users with `su` or `sudo` does not change the transport's authentication method.

From an open administrator or root SSH session:

```bash
sudo server-guard plan
sudo server-guard apply
```

If the tool reports active UFW, inspect the plan and use `sudo server-guard apply --replace-ufw`. This intentionally replaces UFW's inbound policy with the tool's policy; it does not import existing allow rules. Other firewall managers or container/routing services may require migration first.

`apply` prints a change ID. Open a **new administrator SSH connection after apply**, then run the printed command, replacing the example ID:

```bash
sudo --preserve-env=SSH_CONNECTION server-guard confirm CHANGE_ID
```

If you cannot reconnect, keep the old session and run `sudo server-guard rollback`, or wait ten minutes. The timer is enabled across reboots; rebooting restarts its ten-minute countdown. It cannot recover a broken OS, missing tool, stopped systemd or a provider firewall lockout.

After confirmation, password SSH and root SSH are disabled. The tool does not erase the root password or disable your provider console.

## 3. Install CloudPanel, or choose aaPanel

The vendor installer runs as root and makes broad system changes. Downloading and executing are separate commands; TLS verification is required. A checksum verifies the downloaded top-level script, not all scripts/packages it fetches afterward.

For **CloudPanel**:

```bash
sudo server-guard panel download cloudpanel
sudo less /var/lib/server-guard/downloads/cloudpanel.sh
```

The recommended option checks the downloaded installer against the checksum in [CloudPanel's official Ubuntu installation instructions](https://www.cloudpanel.io/docs/v2/getting-started/other/), without copying a long hash manually:

```bash
sudo server-guard panel install cloudpanel --official-checksum --db-engine MYSQL_8.4
sudo server-guard panel info
```

If the guide cannot be read, has ambiguous checksums or disagrees with the downloaded file, installation stops. A reviewed `--sha256 TRUSTED_SHA256` remains available instead of `--official-checksum`.

For **aaPanel instead**, use `panel download aapanel`, review `/var/lib/server-guard/downloads/aapanel.sh`, and use `panel install aapanel --sha256 REVIEWED_SHA256`. aaPanel may not publish an independently verifiable checksum for that moving script: inspect and approve the exact downloaded file and its dependencies, or do not execute it. Automatic publisher-checksum lookup is available only for CloudPanel. There is no forced bypass for a checksum mismatch.

`panel info` prints an SSH tunnel command. It deliberately requests a login session using `sleep 3600`, so the connection is counted. For CloudPanel, on **your computer**:

```bash
ssh -i ~/.ssh/server_guard_admin -L 8443:127.0.0.1:8443 admin@SERVER_IP sleep 3600
```

Visit `https://127.0.0.1:8443`, verify the initial certificate through a trusted channel and create the panel administrator immediately. Enable panel two-factor authentication. Add web users and assign their roles **inside the panel**; these are separate from Linux/SSH accounts.

If the installer enabled UFW or changed SSH settings, rerun `verify-login`, review `plan`, run `apply --replace-ufw` when needed, and confirm from a new key login. Use Server Guard for firewall/SSH changes going forward; the panel's firewall interface does not control this tool's deny policy.

To serve public websites:

```bash
sudo server-guard web enable
sudo server-guard plan
sudo server-guard apply
# Reconnect, then confirm the printed change ID.
```

Also allow TCP 80/443 in the provider firewall. In the panel, create separate sites/users, enable valid automatically renewed TLS certificates, and run front/back services as ordinary site users. Bind backend apps to `127.0.0.1`, and use Nginx reverse proxies. Keep databases on Unix sockets or loopback. Public database access is normally unnecessary; use an SSH tunnel for administration.

## 4. Install V2Ray and create client configurations

Use a hostname such as `vpn.example.com` pointing to the server. Create its HTTPS site and a valid certificate in the panel first. V2Ray uses port 443 through Nginx, so it shares the public web entry point with your sites.

Choose a stable **V2Ray v5** release from [the official release page](https://github.com/v2fly/v2ray-core/releases). For your server use the checksum of **`v2ray-linux-64.zip`**, not its `.dgst` file or the ARM archive. Pin both the version and the published archive SHA-256:

```bash
sudo server-guard v2ray install --version v5.X.Y --sha256 OFFICIAL_ARCHIVE_SHA256
sudo server-guard v2ray configure --domain vpn.example.com --local-port 10000
sudo server-guard v2ray add phone
sudo server-guard v2ray nginx
```

The placeholder version/checksum must be replaced. Copy the generated `location` block **inside that site's HTTPS Nginx server block**, using CloudPanel's Vhost editor or aaPanel's site configuration editor. Preserve TLS 1.2/1.3, certificates and renewal settings. Validate and reload Nginx through the panel. The tool does not rewrite the panel's generated vhosts.

```bash
sudo server-guard v2ray export phone
sudo server-guard v2ray list
sudo server-guard v2ray revoke phone
```

The export prints a **secret** `vmess://` link for a compatible client. It specifies WebSocket + TLS, port 443, matching SNI/Host/path and `alterId=0`. Keep certificate verification enabled in clients. Share each link only with its intended user; make separate clients for separate people/devices. Revocation restarts V2Ray and disconnects its sessions. It does not add bandwidth quotas or per-client device limits.

The backend is never opened publicly. Links work only after DNS, public 443, the HTTPS certificate and Nginx WebSocket forwarding all work. The tool does not claim ISP reachability, censorship resistance or a full-device VPN setup. V2Ray updates are explicit pinned installs; stop its service before replacing its binary.

## 5. Optional MongoDB

Install the panel first. Then, after your SSH/firewall baseline is confirmed:

```bash
sudo server-guard mongodb install
sudo server-guard mongodb bootstrap --admin mongoAdmin
sudo server-guard mongodb user-add appuser --database myapp --role readWrite --admin mongoAdmin
sudo server-guard mongodb user-add reports --database myapp --role read --admin mongoAdmin
sudo server-guard mongodb status
```

The option installs **MongoDB Community 8.0** from MongoDB's official signed Ubuntu 24.04 repository. It checks the publisher key's full fingerprint and requires an x86_64 CPU with AVX. It refuses to overwrite existing MongoDB packages/config/data or an aaPanel MongoDB plugin installation. Choose one manager for MongoDB; do not install aaPanel's MongoDB plugin on top of this option. CloudPanel will continue to manage its own MySQL/MariaDB, while your apps can use MongoDB separately.

`install` keeps the service masked during package installation, writes an authenticated localhost-only config, and leaves the installed service **stopped and disabled** until bootstrap. The default port is **27017**; optionally choose `mongodb install --port 27018`. No public firewall rule is added, and the Unix socket is disabled so the temporary bootstrap connection restriction cannot be bypassed through it.

`bootstrap` starts MongoDB with a temporary root-only loopback connection rule while it creates the first administrator using the MongoDB localhost exception. Enter a new password twice at the hidden prompts (at least 16 characters), and save it in your password manager. The script verifies administrator authentication before enabling the service at boot. This administrator has `userAdminAnyDatabase`, a trusted account-management role able to grant extensive privileges; do not use it in your application.

`user-add` first prompts for the MongoDB administrator password, then for the new application user's password twice. `readWrite` is restricted to the named application database; `read` is suitable for reporting. Password values are not saved by Server Guard or included in shell command arguments/history. Keep application credentials in your application's protected secret configuration.

An application on this host can connect using its own database/authentication database:

```text
mongodb://appuser:URL_ENCODED_PASSWORD@127.0.0.1:27017/myapp?authSource=myapp
```

This is a **connection-string template**, not a shell command. URL-encode special characters in the real password and keep the resulting URI secret. The deployment is a standalone MongoDB, not a replica set; apps needing transactions, change streams or replica-set availability need an explicitly designed replica set. Connections are local; use an SSH tunnel for remote GUI/Compass access rather than exposing 27017.

Additional commands:

```bash
sudo server-guard mongodb password appuser --database myapp --admin mongoAdmin
sudo server-guard mongodb user-revoke reports --database myapp --admin mongoAdmin
sudo server-guard mongodb shell --admin mongoAdmin
```

If bootstrap is interrupted **after** creating the administrator but before recording completion, recover by authenticating with the already-created account:

```bash
sudo server-guard mongodb bootstrap --admin mongoAdmin --authenticate
```

If package installation fails, the service remains masked; inspect the failure and review `/etc/mongod.conf` before manually recovering. The tool does not delete databases or remove an existing installation. MongoDB installation/user changes are immediate and are outside SSH/firewall rollback. Back up MongoDB independently with consistent dumps/snapshots and test a restore. Use `server-guard update` for reviewed 8.0-series package updates; major-version upgrades and production tuning require a separate migration plan.

## Everyday use

```bash
sudo server-guard                    # interactive menu
sudo server-guard status
sudo server-guard user add deploy --role developer --sessions 2 --key-file /root/deploy.pub
sudo server-guard user add upload --role sftp --sessions 1 --key-file /root/upload.pub
sudo server-guard user limit deploy 4
sudo server-guard ssh root disable
sudo server-guard firewall allow 9443 --source 203.0.113.10/32
sudo server-guard firewall deny 9443 --source 203.0.113.10/32
sudo server-guard plan
sudo server-guard apply
# Reconnect and confirm after each apply.
sudo server-guard audit
```

Replace documentation IPs with your real IPs. A rule is identified by port, protocol and source; `deny` removes that exact allow entry. Configuration changes are staged until `apply`, except account creation, disabling accounts, key replacement, package operations, MongoDB and V2Ray commands, which act immediately and are explicitly documented. Role/session restrictions for newly created SFTP users activate at apply; their initial `nologin` shell prevents ordinary shell login before then. Do not hand out their keys until apply is confirmed.

See [OPERATIONS.md](docs/OPERATIONS.md) for root access, source allowlists, SSH ports, existing panel accounts, recovery, backups and security maintenance.
