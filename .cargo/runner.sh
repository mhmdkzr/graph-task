#!/bin/sh
# Cargo runner for `graph`.
#
# For the `graph` binary: loads it under sudo while preserving the developer's
# PATH and HOME. `sudo -E` alone is insufficient: sudo(8) resets PATH via
# secure_path, which breaks the eBPF build (bpf-linker lives under
# ~/.cargo/bin) and rustup's toolchain lookup (defaults to $HOME/.rustup).
#
# Test/bench harnesses (which live in target/debug/deps/) do not need root and
# are exec'd directly so that `cargo test` works without passwordless sudo.

case "$1" in
    *"/deps/"*) exec "$@" ;;
esac

exec sudo env "PATH=$PATH" "HOME=$HOME" "$@"
