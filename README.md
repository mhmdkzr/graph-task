# graph

A tiny file-telemetry and enforcement agent built with eBPF (Aya / Rust).

It hooks the kernel functions behind file **create**, **write** and **delete**
(`vfs_create`, `vfs_write`, `vfs_unlink`) and, for every matching operation,
reports the process binary path, the file path, PID, cgroup ID and parent PID.
Operations under `/var/secure` are additionally **blocked**: the offending
process is terminated with `SIGKILL`.

```
 user space (graph)                        kernel space (graph-ebpf)
┌──────────────────────────────┐           ┌─────────────────────────────────┐
│ load eBPF, attach probes     │           │ kprobe vfs_write  ─┐            │
│ read ring buffer, decode     │◄─events──►│ kprobe vfs_create ─┼─► ring buf │
│ display events               │  1 MiB    │ kprobe vfs_unlink ─┘            │
│ (observer PID in CONFIG map) │           │ + dentry-walk path resolution   │
│                              │           │ + prefix filter (3 dirs)        │
│                              │           │ + bpf_send_signal(SIGKILL)      │
└──────────────────────────────┘           └─────────────────────────────────┘
```

## What it does

* **Telemetry.** For each create/write/delete under `/opt/protected`,
  `/var/secure` or `/home/secure_area`, an event is pushed to a 1 MiB ring
  buffer carrying: operation type, process binary path, file path, PID,
  cgroup ID and parent PID. Only events under the monitored dirs are emitted,
  keeping overhead minimal.
* **Enforcement.** `/var/secure` is the protected directory. Any create, write
or delete under it requests termination of the offending process via
`bpf_send_signal(SIGKILL)` from inside the probe. The signal is requested at
probe entry, before the operation executes; signal delivery itself is
asynchronous, so this is termination rather than a synchronous access-denial
mechanism. The observer process
  itself is excluded via a PID stored in the `CONFIG` map.

Example output:

```
[create] pid=1234 ppid=1 cgroup=16761 exe=/usr/bin/dash path=/var/secure/evil
[write]  pid=1234 ppid=1 cgroup=16761 exe=/usr/bin/dash path=/var/secure/evil
```

## Prerequisites

* stable Rust toolchain
* nightly Rust toolchain with `rust-src` (used to build the eBPF program):
  `rustup toolchain install nightly --component rust-src`
* `bpf-linker` on `PATH`: `cargo install bpf-linker`
* a Linux kernel with eBPF enabled and (recommended) BTF at
  `/sys/kernel/btf/vmlinux`
* root privileges to load eBPF programs

## Build

```sh
cargo build                 # dev build
cargo build --release       # release build
```

The eBPF object is compiled by `graph/build.rs` during the build and embedded
into the `graph` binary, so no separate step is needed.

### Fully static binary

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

The resulting `target/x86_64-unknown-linux-musl/release/graph` is statically
linked and depends on nothing at runtime.

### Reproducible build (Docker)

```sh
docker build -t graph-builder .
docker run --rm -v "$PWD:/out" graph-builder cp /app/target/x86_64-unknown-linux-musl/release/graph /out/graph
```

## Run

`cargo run` uses `.cargo/runner.sh` to execute the binary under `sudo`, which
preserves your `PATH`/`HOME` (a plain `sudo -E` resets `PATH` via
`secure_path`, breaking `bpf-linker` and rustup lookups):

```sh
cargo run            # or: cargo run --release
```

or run the static binary directly:

```sh
sudo ./target/x86_64-unknown-linux-musl/release/graph
```

Then, in another terminal:

```sh
sudo mkdir -p /opt/protected /var/secure /home/secure_area
echo hello > /home/secure_area/log.txt   # reported (create + write)
echo evil  > /var/secure/pwned           # process is SIGKILLed
rm /home/secure_area/log.txt             # reported (delete)
echo hi    > /tmp/irrelevant.txt         # ignored
```

## Tests

Unit tests (no privileges needed):

```sh
cargo test -p graph-common
```

Integration test that loads the real eBPF program and exercises enforcement +
telemetry (needs root):

```sh
sudo -E cargo test -p graph --test enforcement -- --ignored
```

The integration test asserts that a writer under `/var/secure` is killed, that
monitored-but-not-enforced directories only report, that benign paths are never
reported, and that create/delete events are delivered.

## How it works

* **Probes.** `#[kprobe]` programs attach to `vfs_write` (arg 0 is
  `struct file *`) and `vfs_unlink` (arg 2 is `struct dentry *`). File
  **creation** is observed at the `sys_enter_openat`/`sys_enter_openat2`
  tracepoints, filtering on `O_CREAT` — a kprobe on `vfs_create` is unreliable
  because that function is inlined into its callers on modern kernels, so the
  probe is registered but never fires.
* **Path resolution.** There is no `struct path` for the create/unlink
  dentries, so paths are resolved by walking the dentry chain
  (`d_parent` -> `d_name`) up to the filesystem root (`s_root`). The same walk
  resolves the process binary via `current->mm->exe_file`. Paths are built
  directly into the ring-buffer record to respect the 512-byte eBPF stack.
  Create paths are the raw openat pathname (usually absolute).
* **Filtering** happens in-kernel: the file path is prefix-matched against the
  three monitored dirs (component-boundary aware, so `/var/secure_2` does not
  match `/var/secure`) and only matches are emitted.
* **Enforcement** requests `SIGKILL` in-kernel before the operation completes.

## Design notes & limitations

* Kernel struct offsets (`file`, `inode`, `dentry`, `qstr`, `super_block`,
  `task_struct`, `mm_struct`) are hardcoded for **Linux 6.12 x86_64**, taken
  from `/sys/kernel/btf/vmlinux`. They are version/arch specific and would
  need to be regenerated for other kernels (e.g. with BTF tooling).
* Dentry-walk paths are relative to the filesystem root (`s_root`). They are
  correct for the monitored dirs here because `/opt`, `/var` and `/home` live
  on the root filesystem; bind mounts or separate partitions would need a
  mount-prefix resolution step. Paths are emitted only when their complete
  dentry walk fits in the 256-byte record; longer paths (or paths exceeding
  128 components) are deliberately ignored rather than reported incorrectly.
* Create paths come from the openat(2) pathname argument (usually absolute).
  Relative openat paths under a monitored dir are not resolved in-kernel and
  are therefore not reported or enforced.
* Enforcement intentionally covers create *and* write *and* delete under the
  protected directory, not just write/delete.
* No LSM (Linux Security Module) is used anywhere.

## Workspace layout

| Crate          | Role                                                           |
|----------------|----------------------------------------------------------------|
| `graph-ebpf`   | kernel-side eBPF programs (Rust, `#![no_std]`)                 |
| `graph`        | user-space app: loads probes, reads events, prints them        |
| `graph-common` | shared `#[repr(C)]` event layout + matching logic + unit tests |
