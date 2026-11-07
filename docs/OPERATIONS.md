# Operations and recovery

## Changing access

`server-guard` with no arguments opens the grouped terminal management UI. `server-guard setup` starts/resumes its guided first-time workflow. See [the terminal walkthrough](TERMINAL_UI.md) for menus and key handling. `--help` and subcommand `--help` show all command options. Run it through sudo as a managed administrator. Preserve `SSH_CONNECTION` when verifying a login or resuming setup from that login. Policy is stored root-only in `/etc/server-guard/policy.json`; generated runtime files are separate. Staging policy does not reload SSH or the firewall.

For every access-policy change:

1. Keep an existing SSH connection and provider console available.
2. Open a fresh key-authenticated administrator connection and run `sudo --preserve-env=SSH_CONNECTION server-guard verify-login` if the earlier proof is older than one hour or its key changed.
3. Stage changes, run `sudo server-guard plan`, then `sudo server-guard apply`.
4. Reconnect after apply and run `sudo --preserve-env=SSH_CONNECTION server-guard confirm CHANGE_ID`.

The first obtained OpenSSH setting often wins, so the tool places a global include first and user Match blocks last, removes active `Port` lines from the main config, then checks `sshd -t` and effective settings with `sshd -T -C`. Conflicting included settings or Match blocks cause an abort/rollback instead of a claim that a setting was applied. Existing `AllowUsers`, `AllowGroups`, `DenyUsers`, `ListenAddress`, `AuthorizedKeysCommand` and other custom policies remain your responsibility. The fresh-login confirmation tests actual access.

Root SSH is disabled by default:

```bash
sudo server-guard ssh root disable
sudo server-guard plan
sudo server-guard apply
```

If deliberately required for recovery automation, `ssh root key-only` stages `PermitRootLogin prohibit-password`. It does not create a root key. Root passwords over SSH remain disabled. Neither mode locks the local root account.

For fixed administrator source networks:

```bash
sudo server-guard ssh sources 203.0.113.10/32 2001:db8:1234::/64
# Review, apply, reconnect from an allowed source, confirm.
```

Use your real addresses. To return to SSH from changing addresses: `sudo server-guard ssh sources any`. Public-key authentication and Fail2Ban still apply. Do not use a changing home IP allowlist unless you have another recovery path. Established SSH connections survive firewall rule removal; test from a new connection.

## SSH ports and Ubuntu socket activation

Changing the SSH port reduces scanning noise; it is not an authentication control. Keeping port 22 with keys and restricted exposure is a valid choice.

Ubuntu 24.04 commonly uses `ssh.socket`. The tool refuses to change its port through an ordinary SSH reload, because the socket may keep the old listener. To use a different port, first allow the new port in the provider firewall, then switch to service activation **from the provider console** while retaining the existing configuration:

```bash
sudo systemctl disable --now ssh.socket
sudo systemctl enable ssh.service
sudo systemctl start ssh.service
sudo systemctl status ssh.service
```

Confirm that the old port still works before proceeding. Custom `ssh.socket` or service overrides must be reviewed separately. Then stage `sudo server-guard ssh port 2222`, apply, reconnect with `ssh -p 2222 ...`, and confirm. Remove the old provider allow rule only after successful confirmation. If included `Port` directives still conflict, the tool aborts; inspect `/etc/ssh/sshd_config.d/`.

## Users, site ownership and session counts

| Linux role | Access |
| --- | --- |
| admin | Full sudo/root administration; local SSH forwarding for private panel/DB access |
| developer | Ordinary shell, no sudo added, no SSH forwarding; access follows filesystem permissions |
| sftp | Internal SFTP only, root-owned chroot at `/srv/sftp/NAME`, writable `/upload`, no terminal/forwarding |

These roles are **not** a complete tenant-isolation system. A developer with a shell can execute programs and reach services allowed to local users; disabling OpenSSH forwarding cannot prevent a shell user from writing another proxy. Do not grant untrusted tenants shell access. Use separate VMs for strong isolation. Each app needs a distinct unprivileged service account, correctly scoped filesystem permissions and a distinct database user.

Linux users, panel login users and V2Ray clients are three separate identity systems. Use CloudPanel's Users screen for its web roles. Use the panel's site settings for primary site users and SSH keys. A panel-created ordinary shell account can be included in Server Guard's SSH policy without overwriting its home, password or keys:

```bash
sudo server-guard user adopt siteuser --role developer --sessions 2
sudo server-guard user limit siteuser 3
# Review/apply/confirm.
```

The tool refuses to silently take ownership of an existing account with `user add`. `adopt` rejects system UIDs and known privileged groups for a developer role; it does not audit every possible sudoers entry, ACL or privilege path.

The PAM helper uses `flock` to serialize admission and `/proc/PID/stat` start tokens to remove dead/reused process entries. It counts managed users only. OpenSSH 9.6 calls PAM open-session once after authentication, before servicing the transport; source inspection indicates that includes tunnel-only transports. `MaxSessions 1` prevents multiple simultaneous shell/SFTP channels on a transport. The actual Ubuntu PAM/OpenSSH package still needs the validation described in VALIDATION.md. Root and unknown/unmanaged accounts are not capped by this custom ledger. Global `MaxStartups` limits unauthenticated connections separately.

Sessions already open when the hook is first installed are not retroactively counted. Lowering a limit does not kill existing connections. A cap of one prevents the second connection needed for confirmation, so the tool requires **at least two, preferably three, admin transports**. The panel tunnel also consumes allowance on the targeted OpenSSH version.

Key replacement is immediate and replaces the single managed `authorized_keys` file:

```bash
sudo server-guard user key deploy --key-file /root/new-deploy.pub
```

Keep another admin/recovery path while rotating keys. The write uses directory descriptors and no-follow opens to prevent a user-controlled `.ssh` symlink from redirecting a root write. A new key requires a fresh login test. No private keys are generated or copied onto the server.

`user disable NAME` expires the account and locks its password. Password locking alone would not revoke public-key SSH. The tool refuses to disable the last managed admin or your current sudo identity. Existing processes/sessions are retained; after assessing impact, use `sudo loginctl terminate-user NAME` if immediate termination is required. To reenable deliberately, use root `usermod --expiredate '' NAME`, restore the password/key as appropriate, and review the policy's disabled flag; this version does not automate reenable.

## Firewall ownership and panel behavior

Server Guard owns `table inet server_guard`. It atomically replaces only that table, with input and forward hooks at priority -10. It never calls `flush ruleset`. Fail2Ban owns its own table. Other filter chains may still deny a packet accepted by Server Guard. A drop in Server Guard cannot be overridden by an ordinary later allow from UFW or a panel.

On the first `apply --replace-ufw`, the new policy loads before UFW is disabled. Its earlier enable/rule state is recorded for automatic rollback. Active or enabled firewalld and an independently active/enabled `nftables.service` require deliberate migration; distribution nftables configs often flush the entire ruleset. Keep them from managing this host after migration. Panel firewall/SSH buttons can cause drift; change those settings through Server Guard and recheck after panel upgrades.

The forward chain drops all traffic, including DNAT-published Docker ports. This prevents the UFW/Docker exposure problem but also means container bridges/routing do not work. Do not start Docker/Kubernetes afterward and assume the applications are supported. Macvlan/ipvlan devices, network namespaces, hardware/offloaded paths or a root administrator changing the rules require a separate network design and are outside this tool's guarantee.

New public sites normally need only TCP 80/443. A new Nginx virtual host does not require opening the app's own 3000/8000/etc. port. Additional inbound rules require an explicit CLI command plus apply/confirmation and the corresponding provider rule. Examples:

```bash
sudo server-guard firewall allow 443 --protocol udp   # only if you deliberately enable HTTP/3
sudo server-guard firewall allow 9443 --source 203.0.113.10/32
sudo server-guard firewall deny 9443 --source 203.0.113.10/32
```

Closing a rule does not kill existing conntracked flows; verify using a new connection. ICMP, DHCP and established replies are deliberate protocol exceptions, not public application listeners. Outbound traffic remains open for package updates, TLS issuance, DNS, application APIs and the proxy. This is not full egress containment for an already compromised app.

## V2Ray safety and maintenance

V2Ray listens only on `127.0.0.1:10000` (or the chosen local port). The client uses HTTPS 443, SNI/Host and a per-server WebSocket path. Nginx terminates TLS; do not expose plain WebSocket directly. Validate the Nginx config and certificate before distributing links. V2Ray is an application proxy, not WireGuard or an IP-forwarding VPN.

The `server-guard-v2ray-egress` service installs a second owned nftables output table restricted by the proxy's UID. New connections to private/link-local/loopback destinations are dropped even when a hostname resolves there; established return traffic for the local Nginx WebSocket connection is permitted. DNS queries to Ubuntu's `127.0.0.53/.54` stub are allowed. If your server uses a private resolver without a local stub, intentionally provide a working public/stub resolver instead of removing private-destination protection. Custom NAT64 or provider-specific public metadata/control endpoints need additional review. V2Ray routing also denies `geoip:private` and SMTP; this is defense in depth, not an abuse-prevention service.

Updates are explicit:

```bash
sudo systemctl stop server-guard-v2ray
sudo server-guard v2ray install --version v5.X.Y --sha256 NEW_OFFICIAL_ARCHIVE_SHA256
sudo server-guard v2ray configure --domain vpn.example.com
```

The domain/path/client IDs survive configure; pass `--local-port` again if using a non-default backend. Keep a backup of the previous verified binary and its assets for manual downgrade. Reconfiguring or adding/revoking a client restarts V2Ray and disconnects existing proxy sessions. Config validation failure restores the prior config; binary installation has no automatic downgrade. Exported links and the root-only policy/history files contain credentials; never commit or publish them.

## Maintenance, backups and monitoring

For the optional MongoDB service, use the README's `mongodb install` and `mongodb bootstrap` sequence **after** panel installation. It is managed independently of the panel. `mongodb status` shows initialization state and systemd status; `mongodb shell --admin NAME` prompts for administrator authentication. App identities live in their named database, so their URI uses that database as `authSource`.

The terminal UI also controls optional service lifecycle through `server-guard service mongodb start|stop|restart|status` and `server-guard service v2ray start|stop|restart|status`. Choose one action rather than typing the `|` notation. Start/restart checks service readiness; MongoDB must be bootstrapped first. Service mutations refuse a pending SSH/firewall change. Stopping a service interrupts its applications/proxy connections; it does not uninstall its data, configuration or enabled-at-boot setting.

MongoDB's generated `/etc/mongod.conf` is JSON (valid YAML) with authentication enabled and a loopback listener. `/etc/server-guard/mongodb.json` records series/port/bootstrap state and the administrator's name, without a password. If you intentionally customize TLS, ports, memory or replica-set settings, review the config and matching metadata together and restart the service through systemd; do not point this initial installer at another installation/data directory. Bootstrap deliberately refuses a modified pre-initialization config.

If first-user creation is interrupted, `mongodb bootstrap --admin NAME --authenticate` recovers by authenticating the existing account. When a failed bootstrap cannot stop MongoDB, its temporary root-only loopback firewall guard remains: inspect `nft list table inet server_guard_mongodb_bootstrap` and `journalctl -u mongod`, then stop/fix/retry initialization before removing that protection. The service is not enabled for boot before successful bootstrap. A package-install failure leaves the service masked for deliberate recovery; use a snapshot/package repair and verify the configuration before unmasking. No database files are automatically deleted.

MongoDB operations and package upgrades are immediate, outside SSH rollback. Store passwords in a password manager and protected application secrets; rotate/revoke app users using the dedicated commands. Include MongoDB in separate, consistent off-server backups and restore tests. A standalone server is not a replica set and does not provide replica-set transactions/change streams or failover. Native database TLS is not configured for this loopback deployment; use an SSH tunnel for remote administration, and plan TLS/replica-set authentication separately if adding other nodes.

- Run `server-guard status` and inspect actual listening addresses, firewall state, Fail2Ban, time synchronization and `/var/run/reboot-required`. VMess needs accurate time; ensure your provider NTP/systemd-timesyncd/chrony works.
- Use `server-guard update` for a reviewed normal APT upgrade. Automatic security updates use Ubuntu's packaged origin rules; third-party panel/runtime repositories and V2Ray need their own update process. No automatic reboot is configured.
- Run `server-guard audit` for Lynis recommendations. Review findings for your workload before changing them. This is not a CIS Level 1/2 certification. AppArmor's existing Ubuntu profiles are retained; develop and test application profiles rather than forcing unknown ones to enforce mode.
- Monitor CPU/RAM/disk, application health, TLS expiry, unusual logins and update failures through an external service. Configure destinations/notification credentials yourself; the script has none and does not send alerts. Forward security/audit logs off the host where practical.
- Use panel remote backups or your backup system for website files and **consistent database dumps/snapshots**, encrypted and stored off-server. Include `/etc/server-guard`, `/var/lib/server-guard`, `/etc/server-guard-v2ray`, selected system/service configs, DNS/TLS recovery information and the tool source. Keep backup keys elsewhere. A config rollback snapshot is not an application/data backup.
- Set an acceptable recovery point/recovery time and regularly restore a backup into an isolated VM. Keep provider snapshots before major updates; never rely only on a snapshot on the same disk/account.
- Put public HTTP apps behind a suitable provider/CDN WAF and request limits where appropriate. Scope trust of forwarded-IP headers correctly. A host firewall/Fail2Ban cannot stop a saturated network uplink or fix SQL injection, broken authorization or vulnerable npm/Python dependencies.

## Recovery

If the old SSH session works, run `sudo server-guard rollback`. Otherwise wait for the rollback timer, or use the provider console:

```bash
sudo server-guard rollback
sudo journalctl -u server-guard-rollback --no-pager
sudo systemctl status ssh ssh.socket server-guard-firewall
sudo /usr/sbin/sshd -t
```

The durable snapshot is `/var/lib/server-guard/pending.json`; confirmed/rolled-back copies are retained in `/var/lib/server-guard/history/` with original bytes, modes and ownership. Pending state blocks other management mutations. Timer countdown starts again after reboot. If restore fails, the pending record remains for investigation and manual retry. Provider firewall rules are never modified by the tool, so use its console to correct those.

Do not remove `/opt/server-guard`, Python or the launcher while its PAM hook or rollback service is installed. A broken required PAM helper fails managed logins closed. For emergency manual repair use the provider console, save a copy of `/etc/pam.d/sshd`, remove only the `server-guard/.../pam_sessions.py` hook line, validate SSH, restore a known working firewall and reconnect. Removing only the PAM line does not undo other hardening. Do not delete all firewall rules as a routine recovery step.

Panel installation and installed packages/users have no automatic uninstall. Do not install the second panel over the first. Rebuild a clean server and restore application backups to change panels safely.
