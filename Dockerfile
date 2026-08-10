# Builds a fully static `graph` binary reproducibly.
#
# Usage:
#   docker build -t graph-builder .
#   CID=$(docker create graph-builder /graph)
#   docker cp "$CID":/graph ./graph
#   docker rm "$CID"
#
# The eBPF program is compiled with nightly + rust-src (via aya-build) and the
# result is embedded into the user-space binary; no kernel headers are needed.

FROM rust:1.97 AS builder

RUN rustup toolchain install nightly --component rust-src \
 && rustup target add x86_64-unknown-linux-musl \
 && cargo install bpf-linker --locked

WORKDIR /app
COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY .cargo ./cargo-config-files
COPY graph graph
COPY graph-common graph-common
COPY graph-ebpf graph-ebpf

# Build the static binary. The eBPF target is compiled by build.rs itself.
RUN cargo build --release --target x86_64-unknown-linux-musl --locked

FROM scratch AS export
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/graph /graph
