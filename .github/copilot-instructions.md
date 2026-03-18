# Copilot instructions for `pam-webhook`

## Build, test, and lint commands

- Build release Linux PAM module:
  - `cargo build --release`
  - Output artifact: `target/release/libpam_webhook.so`
- Run all tests:
  - `cargo test`
- Run a single test (name filter):
  - `cargo test <test_name_substring>`
- Lint (if Clippy is available in the toolchain):
  - `cargo clippy --all-targets --all-features -- -D warnings`
- Format check:
  - `cargo fmt -- --check`

## High-level architecture

- This crate is a Rust `cdylib` intended to be loaded by Linux-PAM (configured in PAM as `pam_webhook.so`).
- `src/lib.rs` exports all six Linux-PAM service hooks:
  - `pam_sm_authenticate`, `pam_sm_setcred`, `pam_sm_acct_mgmt`, `pam_sm_open_session`, `pam_sm_close_session`, `pam_sm_chauthtok`.
- Every hook currently follows the same flow:
  - call `log_hook_call(...)` for diagnostics,
  - return a success status via `success_code()`.
- The crate is Linux-only and uses `pam-sys` directly:

## Key conventions in this repo

- Treat this as a scaffold: hooks intentionally return success while webhook/policy logic is added incrementally.
- Keep exported FFI hooks ABI-stable:
  - preserve `#[unsafe(no_mangle)] pub extern "C"` signatures and PAM hook names exactly.
- Reuse shared helpers (`log_hook_call`, `get_item`, `success_code`) instead of per-hook custom logic when adding behavior.
- Avoid logging secrets; existing diagnostics only include hook name, flags, and selected PAM metadata.
- Assume Linux-only operation; do not add non-Linux stubs or platform fallbacks.
- `handlers.rs` defines the `PamEventHandler` trait with default no-op implementations for all hooks, which can be overridden as needed for future logic.
