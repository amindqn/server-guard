# Research and design decisions

Reviewed 7 November 2026 for Ubuntu 24.04 LTS / x86_64. The links below are primary documentation/source repositories. Software support, installation checksums and release versions can change; consult the publisher again at installation/update time. The supplied code pins user-selected installer/archive hashes instead of silently executing a moving `latest` URL.

## Panel choice

**Recommendation: CloudPanel for the described web-app server**, provided its MySQL/MariaDB focus fits your database needs. It supports PHP, Node.js, Python, static sites and reverse proxies. Its documented Admin, Site Manager and per-site User roles directly fit separate access levels. This is a workload/permission fit assessment, not evidence that it is universally more secure than aaPanel. [CloudPanel introduction](https://www.cloudpanel.io/docs/v2/introduction/), [roles](https://www.cloudpanel.io/docs/v2/admin-area/users/), [database support](https://www.cloudpanel.io/docs/v2/admin-area/settings/).

CloudPanel requires an empty supported server, publishes a checksum for its installer and documents multiple database engine choices. The tool downloads the script over verified HTTPS, makes review possible, and refuses execution without the matching full SHA-256. Third-party root installers still have extensive authority, including code they subsequently fetch. [Official installation](https://www.cloudpanel.io/docs/v2/getting-started/other/).

CloudPanel recommends restricting its port and SSH by source IP/provider firewall, supports two-factor authentication, and recommends remote backups and restore testing. We keep the panel private behind an SSH tunnel by default. [CloudPanel security practices](https://www.cloudpanel.io/docs/v2/guides/best-practices/security/), [account MFA](https://www.cloudpanel.io/docs/v2/frontend-area/account/).

aaPanel remains an option for its broader service/plugin ecosystem. Its docs describe firewall and root/SSH controls plus panel SSL, authorized IPs, security entrance and Google Authenticator. Avoid having both its security buttons and this tool independently change SSH/firewall policy. The tool does not assume a fixed panel port or an unverified/purchased multi-user entitlement. [aaPanel quick start](https://www.aapanel.com/docs/guide/quickstart.html), [security](https://www.aapanel.com/docs/Function/Security.html), [settings](https://www.aapanel.com/docs/Function/Settings.html).

Some upstream install examples bypass TLS checks. This project does not adopt those flags. Downloading with valid HTTPS and checking an approved hash is a deliberate supply-chain improvement; it is not a guarantee against a compromised publisher.

## SSH access and concurrent sessions

Ubuntu recommends testing SSH changes and retaining a working connection. Key authentication and a non-root sudo account reduce password attack exposure. We require journal evidence of a new key-authenticated transport plus successful sudo before applying password/root restrictions. [Ubuntu OpenSSH server guide](https://ubuntu.com/server/docs/how-to/security/openssh-server/).

OpenSSH distinguishes `MaxSessions` (channels on one connection) and `MaxStartups` (unauthenticated connections). Neither alone is a per-user total. `PermitRootLogin no` blocks remote root while preserving local console identity. First-value and Match semantics also mean merely writing a late drop-in is not enough; we validate effective policy. [OpenSSH sshd_config reference](https://man.openbsd.org/sshd_config).

Linux-PAM provides `maxlogins`, but it has counting/backend constraints; it is not used here as a claim of a universal hard connection cap. The implementation uses a required `pam_exec` hook with a serialized live-process ledger, and caps multiplexing separately. PAM session environment data is treated as untrusted; the helper is root-owned and Python runs isolated. [Linux-PAM pam_limits](https://github.com/linux-pam/linux-pam/blob/master/modules/pam_limits/pam_limits.c), [pam_exec reference](https://github.com/linux-pam/linux-pam/blob/master/modules/pam_exec/pam_exec.8.xml).

**Inference from OpenSSH 9.6 source:** `sshd` opens PAM after authentication before entering transport handling. Session-open failure restricts forwarding and prevents command/SFTP execution. Thus the hook should cover authenticated transports, including tunnel-only connections, rather than relying on PTY/utmp entries. Target-server tests remain necessary because package patches, PAM-stack control flow and later versions can affect behavior. [sshd.c](https://github.com/openssh/openssh-portable/blob/V_9_6_P1/sshd.c#L2169), [auth-pam.c](https://github.com/openssh/openssh-portable/blob/V_9_6_P1/auth-pam.c#L1139), [session.c](https://github.com/openssh/openssh-portable/blob/V_9_6_P1/session.c#L1462).

## Firewall and application exposure

Docker's documentation explicitly warns that published container traffic can be diverted before UFW's normal input filtering. A host-only UFW allowlist therefore cannot justify a claim that all container ports are closed. This release uses a separate default-deny inet input table and drops forwarding; Docker bridges/Kubernetes/routing are outside its supported workload. [Docker packet filtering](https://docs.docker.com/engine/network/packet-filtering-firewalls/).

nftables supports multiple base chains. An accept in one chain does not prevent another chain from dropping a packet, whereas a drop cannot be undone by a later accept. Owning only our table avoids wiping Fail2Ban or unrelated rules, but another manager can still deny wanted traffic or flush our table as root. The script therefore rejects active competing managers where appropriate and explicitly migrates UFW only when requested. [Netfilter nftables manual](https://netfilter.org/projects/nftables/manpage.html), [chain priorities](https://wiki.iptables.org/wiki-nftables/index.php/Configuring_chains).

The panel can create sites behind already-open 80/443; databases and backend application ports should stay local. TCP 80 is commonly needed for HTTP-01 certificate issuance, so `web enable` opens both HTTP and HTTPS. HTTP/3 UDP 443 is an explicit optional rule. IPv6 is filtered instead of disabled; ICMPv6 is needed for normal network operation.

## Patching, ban rules and persistent recovery

Ubuntu provides `unattended-upgrades` and recommends a later configuration drop-in for customization. We enable the daily tasks and disable automatic reboots, retaining packaged security-origin rules. Simply adding a third-party repository does not cause automatic coverage. Panel repositories and standalone V2Ray need separate maintenance. [Ubuntu automatic updates](https://ubuntu.com/server/docs/how-to/software/automatic-updates/), [Ubuntu security updates](https://documentation.ubuntu.com/security/security-updates/).

Fail2Ban has nftables actions and can use the systemd journal backend. We enable only the SSH jail with a five-failure window and timed bans; a generic HTTP ban policy without trustworthy application logs could cause false positives. [Upstream nftables action](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/nftables.conf), [SSH filter](https://github.com/fail2ban/fail2ban/blob/master/config/filter.d/sshd.conf).

Rollback uses on-disk systemd service/timer files and a root-only snapshot, not a shell job that disappears when SSH disconnects. A monotonic `OnActiveSec` timer restarts its countdown after reboot; it is not a promise to fire at the original wall-clock deadline across outages. [systemd timer manual](https://www.freedesktop.org/software/systemd/man/systemd.timer.html).

## V2Ray protocol and isolation

V2Fly documents a loopback WebSocket backend with Nginx terminating TLS. We use the same architecture while replacing legacy example values with VMess AEAD (`alterId=0`) and client-side TLS verification. We do not copy old example TLSv1/1.1 settings or use insecure certificate bypasses. This is actual V2Ray/V2Fly, not an assumption that Xray-only REALITY settings work on V2Ray. [WebSocket/TLS deployment](https://guide.v2fly.org/en_US/advanced/wss_and_web.html), [VMess v5](https://www.v2fly.org/v5/config/proxy/vmess.html), [transport settings](https://www.v2fly.org/en_US/config/transport.html).

The installer pins official V2Fly release archives by version and full digest; the generated config is passed through V2Ray's own `test` command before restart. Its non-root unit has no Linux capabilities, a read-only filesystem view and resource limits. A UID-scoped egress firewall provides extra protection against proxy requests to local databases, cloud metadata and other private addresses, including hostname resolution to those addresses. This does not prevent all abuse or isolate a compromised root host. [Official releases](https://github.com/v2fly/v2ray-core/releases), [V2Ray test command source](https://github.com/v2fly/v2ray-core/blob/master/main/commands/test.go).

## Additional controls that need your environment

The script cannot invent your domains, SMTP/alert recipients, application authorization rules, backup repository, external WAF subscription, provider firewall API credentials or incident response contacts. The operations guide covers how these fit together: per-site/database users, minimum filesystem access, dependency updates, valid TLS and renewals, off-server encrypted backups, restore tests, time synchronization, external availability/resource monitoring and provider DDoS filtering. These remain operator tasks rather than silently configured placeholders. [Ubuntu layered security suggestions](https://ubuntu.com/server/docs/explanation/security/security_suggestions/), [CloudPanel security/backup practices](https://www.cloudpanel.io/docs/v2/guides/best-practices/security/).

## Optional MongoDB (1.1.0)

MongoDB's official 8.0 instructions provide a signed APT repository for Ubuntu 24.04 Noble on x86_64. The optional manager uses this repository with a dedicated `signed-by` keyring, pins the observed primary signing-key fingerprint, and declines takeover of existing data/configuration. It is separate from CloudPanel's MySQL/MariaDB management. Patch releases stay within the chosen 8.0 repository; major upgrades are separate work. [Official installation](https://www.mongodb.com/docs/v8.0/tutorial/install-mongodb-on-ubuntu/).

MongoDB supports enabling authorization before creating the first user through its localhost exception. Because a local application user should not claim this first-user privilege, the tool masks the service while installing, writes a loopback-only authenticated config, then temporarily allows only root-owned client connections to its TCP port during bootstrap. The Unix socket is disabled. Failure stops the daemon before removing this guard; the service is enabled at boot only after the administrator is authenticated. The first administrator has `userAdminAnyDatabase`; application users receive only `read` or `readWrite` on one named database. [Localhost exception](https://www.mongodb.com/docs/v8.0/core/localhost-exception/), [MongoDB user creation](https://www.mongodb.com/docs/manual/tutorial/create-users/).

Passwords are requested using `passwordPrompt()` and the final, valueless `--password` option for administrator authentication, keeping actual secret values out of shell command arguments and generated script files. Connections are restricted to loopback; remote access should use SSH or a separately designed TLS deployment. [mongosh options](https://www.mongodb.com/docs/mongodb-shell/reference/options/), [createUser command](https://www.mongodb.com/docs/manual/reference/command/createuser/).

The current production notes require AVX for x86_64 and document an incompatible kernel range 6.19 through 7.0.13. The installer rejects these known incompatibilities. It does not silently tune shared-host memory, filesystem or transparent huge-page settings for a particular database load. Standalone installation does not configure replica-set features or high availability. [MongoDB production notes](https://www.mongodb.com/docs/v8.0/administration/production-notes/).

## GitHub installation (1.1.0)

The standalone `bootstrap.sh` accepts an explicit public repository and branch/tag/commit. The published repository uses `master`; the quick command selects `master` in both the raw-script URL and `--ref` so it also works with older copies whose default was `main`. The downloaded-script README command fetches the bootstrap file completely into a private temporary file before executing it. The bootstrap then downloads the full source tree over verified HTTPS, optionally checks an expected archive hash, validates archive paths/types/size and invokes the normal local installer. A full commit may be selected for reproducibility; a moving branch is intentionally treated as code published by the trusted repository, not a cryptographically immutable release. This installation changes the tool files and installs documentation; access-hardening remains a separate guarded action.

## Code structure

The design follows single responsibilities and avoids shell interpolation: `Runner` and `Files` adapt operating-system operations; builders generate validated configs; `PolicyStore` centralizes persistent state; `Transactions` implements a memento-style recovery boundary; panel installer strategies share a common verification workflow; `Host` coordinates them as a facade. Patterns are used where they clarify responsibility, without adding unnecessary singleton/global-service machinery.

## Quick start and terminal setup (1.2.0)

The requested [3x-ui quick-start reference](https://github.com/MHSanaei/3x-ui#quick-start) documents a short remote installer followed by a reusable terminal management command. Server Guard now follows that interaction pattern: a root-shell one-liner invokes the GitHub bootstrap, which opens a resumable setup wizard; `server-guard` opens grouped management menus afterward. `--no-ui` and absent terminals retain headless installation behavior.

`TerminalConsole` handles rendering/input; `TerminalApp` collects validated forms; `SetupWizard` resumes from saved state. All submitted work reuses the CLI parser/dispatcher through one lock-owning Command adapter. No management lock is held during form input. The wizard pauses for a proven non-root key login before hardening, keeps plan review and timer-protected apply, and requires a later SSH transport for confirmation. These safeguards remain backend responsibilities as well as UI affordances. Optional service lifecycle commands are allowlisted to MongoDB/V2Ray; they cannot stop SSH or firewall protection through the menu.

## Usability and removal (1.3.0)

Accounts/SSH, applications/databases and review/recovery now have dedicated menu groups. The setup checklist, numbered role/engine/key choices, existing-admin adoption and key-passphrase explanation reduce command memorization while keeping backend checks. SSH evidence uses trusted root daemon journal fields, matches the actual peer/client port and chooses the latest matching authentication event; password/interactive records explain why key proof failed. Adding a replacement public key defaults to retaining existing keys and rejects unsafe file types/symlinks.

The [official CloudPanel guide](https://www.cloudpanel.io/docs/v2/getting-started/other/) was checked on 8 November 2026. It publishes the installer SHA-256 and Ubuntu 24.04 database-engine choices. Automatic lookup reads that independent guide over verified HTTPS, requires one unique checksum and compares the downloaded script before execution. A changed/ambiguous guide or mismatch stops installation; manual trusted checksum approval remains available. This verifies the top-level installer, not every dependency fetched by it.

`UninstallManager` is a removal facade with inspect/backup/detach/validate/remove phases. It preserves working policy and applications instead of guessing original SSH defaults or deleting live firewall rules. Standalone retained PAM/firewall helpers have no import dependency on the removed Python manager. Reinstallation normalizes the PAM hook rather than stacking it. `uninstall.sh` and `bootstrap.sh --uninstall` run the downloaded remover directly, including for older installed versions; no manager upgrade is needed first. Linux boot/login/runtime behavior still requires the disposable-VM checks.
