# pam-webhook

Rust PAM service module scaffold for `sshd`.

## What this module exports

This module exports the standard Linux-PAM service hooks:

- `pam_sm_authenticate`
- `pam_sm_setcred`
- `pam_sm_acct_mgmt`
- `pam_sm_open_session`
- `pam_sm_close_session`
- `pam_sm_chauthtok`

Current behavior is placeholder (`PAM_SUCCESS`) with diagnostic logging, intended to be extended with real policy/webhook logic.

## Build for a real PAM environment (Linux)

Build on Linux (or cross-compile to your Linux target ABI).

Install Linux PAM development headers first (Debian/Ubuntu):

```bash
sudo apt-get update
sudo apt-get install -y libpam0g-dev
```

Then build:

```bash
cargo build --release
```

Expected artifact:

- `target/release/libpam_webhook.so`

If cross-compiling, ensure:

- target architecture matches the host (for example, `x86_64`)
- glibc/musl expectations match your destination system
- Linux PAM development/runtime packages are available on the destination host

## Install module on Linux

Choose the module directory used by your distro (commonly one of these):

- `/lib/security/`
- `/lib64/security/`
- `/usr/lib/security/`
- `/usr/lib64/security/`

Copy and secure:

```bash
sudo install -o root -g root -m 0644 ~/.cargo/target/release/libpam_webhook.so /lib/x86_64-linux-gnu/security/pam_webhook.so
```

Adjust source and destination paths as needed for your distro.

## Configure `sshd` PAM stack

Before editing PAM config, keep a root session open to avoid lockout.

Edit `/etc/pam.d/sshd` and add module lines where appropriate. Example:

```pam
auth    optional    pam_webhook.so
account optional    pam_webhook.so
session optional    pam_webhook.so config=/etc/pam-webhook.toml
password optional   pam_webhook.so
```

Notes:

- PAM module names in config are typically written without the `lib` prefix and `.so` suffix (`pam_webhook.so`).
- Control flags (`required`, `requisite`, `sufficient`, `optional`) change behavior significantly. Start with `optional` while validating.

## Module configuration argument

The module accepts one actionable argument: `config=/path/to/file.toml`.

- If no `config=` argument is present, defaults are used.
- Unknown module arguments are ignored.
- If `config=` is present but the file cannot be read or parsed, the PAM hook returns an error.

Current TOML fields:

```toml
log_path = "/var/log/pam-webhook.log"
```

`log_path` controls where `log_hook_call` appends diagnostic entries.

## Ensure SSH uses PAM

In `/etc/ssh/sshd_config`:

```text
UsePAM yes
```

Then reload SSH:

```bash
sudo systemctl reload sshd
```

## Verify and troubleshoot

- Watch auth logs while testing login:
  - Debian/Ubuntu: `/var/log/auth.log`
  - RHEL/CentOS/Fedora: `/var/log/secure`
- If SELinux is enforcing, confirm policy allows loading/accessing the module path.
- Validate file ownership/permissions and architecture compatibility (`file libpam_webhook.so`).
- If PAM errors occur, revert `sshd` PAM file from your backup.

## Safe rollout checklist

- Keep at least one privileged session open.
- Test with a non-critical account first.
- Move from `optional` to stricter control flags only after validation.
