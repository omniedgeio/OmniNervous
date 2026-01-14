# eBPF Binary Directory

This directory contains the embedded eBPF/XDP program binary.

## CI Build
The CI workflow builds `omni-ebpf-core` and places it here before building `omni-daemon`.
This allows the binary to be embedded via `include_bytes!()`.

## Local Development
For local builds on non-Linux platforms, an empty placeholder file is created.
The daemon will detect this and skip XDP loading.

## Building eBPF Locally (Linux only)
```bash
rustup install nightly
cargo +nightly install bpf-linker
cargo +nightly build -p omni-ebpf-core --target bpfel-unknown-none -Z build-std=core --release
cp target/bpfel-unknown-none/release/omni-ebpf-core omni-daemon/ebpf/
```

Then rebuild the daemon to embed the eBPF program.
