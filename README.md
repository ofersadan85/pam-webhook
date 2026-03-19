# pam-webhook

Rust PAM service module scaffold for `sshd`.

## Latest release assets

Download links that always point to assets from the most recent GitHub release:

- [`pam_webhook.so`](https://github.com/ofersadan85/pam-webhook/releases/latest/download/pam_webhook.so)
- [`pam_logging.so`](https://github.com/ofersadan85/pam-webhook/releases/latest/download/pam_logging.so)

## What this module exports

This module exports the standard Linux-PAM service hooks:

- `pam_sm_authenticate`
- `pam_sm_setcred`
- `pam_sm_acct_mgmt`
- `pam_sm_open_session`
- `pam_sm_close_session`
- `pam_sm_chauthtok`

Current behavior is feature-gated:

- no feature flags: null/no-op mode
- `--features=logging` with `--no-default-features`: logging mode
- `--features=webhook` (default): webhook mode
- `--all-features`: combined logging + webhook mode

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

Explicit feature builds:

```bash
# Logging mode
cargo build --release --no-default-features --features=logging

# Webhook mode
cargo build --release --features=webhook

# Combined logging + webhook mode
cargo build --release --all-features

# Null/no-op mode
cargo build --release --no-default-features
```

## Test matrix

Run tests in all supported build modes:

```bash
# Default webhook mode
cargo test

# Combined logging + webhook mode
cargo test --all-features

# Logging mode
cargo test --no-default-features --features logging

# Webhook-only mode (explicit)
cargo test --no-default-features --features webhook

# Null/no-op mode
cargo test --no-default-features
```

Integration tests include dynamic loading of the built `.so` and invocation of all exported PAM hooks.

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
# Auth stack: can trigger pam_sm_authenticate and pam_sm_setcred
auth    optional    pam_webhook.so

# Account stack: triggers pam_sm_acct_mgmt
account optional    pam_webhook.so

# Session stack: triggers pam_sm_open_session and pam_sm_close_session
session optional    pam_webhook.so config=/etc/pam-webhook.toml

# Password stack: triggers pam_sm_chauthtok
password optional   pam_webhook.so
```

Notes:

- PAM module names in config are typically written without the `lib` prefix and `.so` suffix (`pam_webhook.so`).
- Control flags (`required`, `requisite`, `sufficient`, `optional`) change behavior significantly. Start with `optional` while validating.
- PAM has 4 stack types (`auth`, `account`, `session`, `password`) but this module exports 6 hooks. `auth` maps to both authentication and credential-establish/reset behavior, and `session` maps to both open and close behavior.

## PAM hook behavior reference

`pam_webhook` exports six Linux-PAM service module hooks. A service calls different hooks at different phases of login/session/password workflows.

- `pam_sm_authenticate` (`auth` stack): user authentication step (for example, checking whether login should be allowed).
- `pam_sm_setcred` (`auth` stack): establish, refresh, or delete user credentials after/beside authentication (trigger depends on service behavior and `pam_setcred` usage).
- `pam_sm_acct_mgmt` (`account` stack): account policy checks (for example, account validity windows, lock status, authorization constraints).
- `pam_sm_open_session` (`session` stack): session start actions when a login session is opened.
- `pam_sm_close_session` (`session` stack): session teardown actions when a login session is closed.
- `pam_sm_chauthtok` (`password` stack): password/token update flow.

## Module configuration argument

The module accepts one actionable argument: `config=/path/to/file.toml`.

- If no `config=` argument is present, defaults are used.
- Unknown module arguments are ignored.
- If `config=` is present but the file cannot be read or parsed, the PAM hook returns an error.

Current TOML fields:

```toml
log_path = "/var/log/pam-webhook.log"
webhook_url = "https://example.internal/pam/events"
exclude_rhosts = ["192.0.2.10", "10.0.0.9"]
exclude_users = ["root", "svc-backup"]
```

- `log_path` controls where logging mode appends diagnostic entries.
- `webhook_url` is used by webhook mode as the destination URL for per-hook JSON POST requests.
- `exclude_rhosts` is a list of remote host/IP values; if PAM `rhost` matches any entry, webhook POST is skipped.
- `exclude_users` is a list of usernames; if PAM `user` matches any entry, webhook POST is skipped.
- Exclusion uses OR semantics: a request is skipped when either `rhost` matches `exclude_rhosts` or `user` matches `exclude_users`.

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
