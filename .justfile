set shell := ["bash", "-euo", "pipefail", "-c"]

default:
  @just --list

# Run tests in all supported feature configurations.
test *tests:
  cargo test --quiet --all-features {{tests}}
  cargo test --quiet --no-default-features {{tests}}
  cargo test --quiet --no-default-features --features=logging {{tests}}
  cargo test --quiet --no-default-features --features=webhook {{tests}}

# Run all validation checks (format + lint + test matrix).
check:
  cargo fmt --check
  cargo clippy --all-targets --all-features -- -D warnings
  just test

build +feature:
  cargo build --no-default-features --features {{feature}}