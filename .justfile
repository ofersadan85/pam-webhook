set shell := ["bash", "-euo", "pipefail", "-c"]

default:
  @just --list

# Run tests in all supported feature configurations.
test *tests:
  cargo test --quiet --all-features {{tests}}
  cargo test --quiet --no-default-features {{tests}}
  cargo test --quiet --no-default-features --features=logging {{tests}}
  cargo test --quiet --no-default-features --features=webhook {{tests}}
  cargo test --quiet --no-default-features --features=spool {{tests}}

# Alias for full feature matrix.
test-all *tests:
  just test {{tests}}

# Run all validation checks (format + lint + test matrix).
check:
  cargo fmt --check
  cargo clippy --no-default-features -- -D warnings
  cargo clippy --all-targets --all-features -- -D warnings
  just test

# Alias for full validation.
validate:
  just check

build +feature:
  @cargo build --no-default-features --features {{feature}}
