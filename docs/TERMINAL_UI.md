# Terminal setup and management

## Quick install

Run in a root Bash shell on Ubuntu 24.04, using the repository's `master` branch:

```bash
bash <(curl -fsSL --proto '=https' --proto-redir '=https' https://raw.githubusercontent.com/amindqn/server-guard/master/bootstrap.sh) --ref master
```

The command uses the same short-installer and persistent management-menu workflow that motivated the [3x-ui reference](https://github.com/MHSanaei/3x-ui#quick-start). Server Guard's menus configure the services described in this repository; no 3x-ui code or panel is installed by this command.

`bootstrap.sh` opens `server-guard setup` after its local installer exits and releases the management lock. It reconnects input to `/dev/tty`, so prompts can work even when the downloaded script was supplied through a pipe or process substitution. With `--no-ui`, or without a usable terminal, installation finishes and prints the setup command instead. The command requires curl; install `ca-certificates curl` through APT first if absent.

## The four setup steps

1. **Dependencies.** Review and install Ubuntu security/management packages. Successful preparation is recorded, so resuming the wizard skips that completed step. Use Status/maintenance to explicitly rerun preparation if repairing packages.
2. **Initial policy.** Confirm the server's current SSH port. The wizard uses `SSH_CONNECTION` as a suggested value when available. It initializes policy only if no policy exists.
3. **Administrator.** Choose a new account or adopt an existing sudo administrator. Supply an SSH public key, either pasted as one line or read from an existing `.pub` file on the server. Private keys stay on your computer. Choose the concurrency limit (administrators need at least two), review the account, then set a new administrator's local sudo password through the native hidden passwd prompt. Existing accounts keep their passwords; key addition preserves their existing ordinary keys by default.
4. **Verify, apply and confirm.** The wizard prints a second-terminal SSH command. Reconnect as the new administrator and run `sudo --preserve-env=SSH_CONNECTION server-guard setup`. It verifies the actual key login/sudo identity, displays the plan and asks before applying it. Reconnect once more to confirm the new access policy within ten minutes. The wizard never confirms its own change from the original connection.

You can leave between steps and resume with the same setup command. Existing policy/accounts remain. A pending access change routes setup to the confirmation/recovery menu. If you cancel while a backend command is already running, completed effects may remain; the UI reports that rather than claiming to undo them. Existing access rollback semantics still apply.

## Management menu

Run `sudo server-guard` or `sudo server-guard menu`:

```text
==============================================================================
SERVER GUARD 1.3.0  /  Management
==============================================================================
Policy: SSH 22 | root SSH disabled | 1 users | firewall config saved.
   1  Setup assistant / next step
   2  Accounts, SSH keys and login access
   3  Firewall and website access
   4  Applications: web panel and MongoDB
   5  V2Ray and client connections
   6  System health, updates and audit
   7  Review changes, confirm or recover
   8  Uninstall Server Guard
   0  Exit
Select:
```

The summary describes the saved policy/files, not proof that every running service matches that policy. Use Status to inspect actual listening ports and service state.

| Menu | Actions |
| --- | --- |
| Accounts / SSH | Users/roles/session caps; create or adopt admin/developer/SFTP accounts; add/replace keys; disable accounts; stage SSH port/source/root settings; diagnose/verify key login; passphrase help |
| Firewall | Stage HTTP/HTTPS, add/remove a port/protocol/source rule, review/apply |
| Applications → Panel | Download/review; verify CloudPanel against its official guide or manually approve a SHA-256; choose a numbered DB engine; install; show private tunnel access |
| Applications → MongoDB | Install locally, bootstrap/recover the admin, create/rotate/revoke scoped app users, inspect/start/restart/stop |
| V2Ray | Install a pinned binary, configure domain/local WS port, add/export/revoke clients, show Nginx block, inspect/start/restart/stop |
| Maintenance | Status, Lynis audit, repair dependencies, review package upgrades |
| Access changes | Plan, apply, confirm pending ID from a new login, roll back |
| Uninstall | Review removal scope, create a private backup and remove the manager while preserving working protection/apps/data |

Optional service controls operate only on MongoDB and V2Ray. They cannot stop SSH or the firewall through this interface. Starting MongoDB requires successful first-user bootstrap. New port/session/SSH policies remain staged until apply; database/client/account/key/package operations retain their documented immediate behavior.

Selecting a panel before applying/confirming the SSH/firewall baseline opens Guided setup immediately, before a vendor download or checksum prompt. Finish the administrator key-login test, apply the reviewed plan, reconnect and confirm its printed change ID; then return to the panel menu. The CLI installer also enforces this prerequisite. A previously downloaded installer can be reused after confirmation.

The setup checklist marks completed steps, the next incomplete step and remaining work. The key-help page explains the local private-key passphrase, server password and sudo password separately. Diagnose reports the current transport's actual authentication method from trusted SSH journal fields, including password and keyboard-interactive logins. Generated test commands disable connection sharing and password fallback, so a successful test really uses the selected key.

Removal is also available with `sudo server-guard uninstall` and the [GitHub one-line uninstaller](../README.md#quick-uninstall). A pending access change blocks removal; confirm or roll it back first. Removing the manager does not re-enable root/password access or uninstall panels/databases. The menu exits after successful removal.

## Input and secrets

- Enter a numbered choice; `0` returns to the parent menu or exits the top-level menu. `q` also leaves a menu.
- Press Enter to use the displayed default. Invalid values show a text error and request the same field again.
- Enter `:back` to cancel a form. Ctrl+C cancels the current operation/menu action where practical; Ctrl+D exits when input closes.
- Action summaries appear before submitting mutations. The final confirmation defaults to No.
- SSH public keys may be pasted; private keys are rejected. Passwords are collected by passwd/mongosh hidden prompts, not logged UI fields. V2Ray export requests explicit permission before displaying a secret link.
- All prompts occur outside the management lock. Only submitted commands acquire it; a user sitting at a menu/form cannot stall a pending rollback timer.
- Color is used only on capable interactive output and respects `NO_COLOR`/`TERM=dumb`. Text labels carry status/error meaning. The UI uses line input and ASCII separators for ordinary SSH terminals, rather than cursor-dependent full-screen rendering.

## Preview without root or server changes

From a local source checkout:

```bash
python3 scripts/preview_terminal.py
```

The preview renders the real menus and forms using temporary synthetic policy files. All submitted host commands are disabled. It does not install packages, create system users, bind ports or change the host's SSH/firewall. Actual Ubuntu service installation still requires the validation checklist.
