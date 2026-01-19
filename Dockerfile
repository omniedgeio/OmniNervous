# OmniNervous Daemon Docker Image
# Simplified build - copy all sources at once

# Stage 1: Build eBPF Kernel Program
FROM --platform=linux/amd64 rustlang/rust:nightly AS ebpf-builder

WORKDIR /usr/src/omni

# Install dependencies for bpf-linker
RUN apt-get update && apt-get install -y llvm clang

# Ensure rust-src is available for build-std (may already be in image)
RUN rustup component add rust-src

# Install bpf-linker (pinned to match Aya 0.13.x stable)
RUN cargo install bpf-linker --version 0.9.15

# Copy eBPF source
COPY omni-ebpf ./omni-ebpf/
COPY omni-common ./omni-common/

# Build eBPF program (Target: Little Endian for x86_64)
WORKDIR /usr/src/omni/omni-ebpf/omni-ebpf-core
RUN cargo build --release --target bpfel-unknown-none -Z build-std=core

# Verify the ELF magic, machine type, and sections
RUN apt-get install -y binutils llvm \
    && readelf -h target/bpfel-unknown-none/release/omni-ebpf | grep -q "ELF" \
    && readelf -h target/bpfel-unknown-none/release/omni-ebpf | grep -q "Linux BPF" \
    && readelf -S target/bpfel-unknown-none/release/omni-ebpf | grep -q "maps" \
    && readelf -S target/bpfel-unknown-none/release/omni-ebpf | grep -q "\.BTF" \
    || (echo "Corrupted or Missing eBPF ELF sections (Need maps and .BTF)!" && exit 1)

# Stage 2: Build Userspace Daemon
FROM rustlang/rust:nightly AS builder

WORKDIR /usr/src/omni
ENV CACHE_BREAKER_TIMESTAMP=20260117_0550

# Install build-time dependencies for libbpf-sys and xsk-rs
RUN apt-get update && apt-get install -y \
    llvm \
    clang \
    pkg-config \
    libelf-dev \
    libbpf-dev \
    make \
    && rm -rf /var/lib/apt/lists/*

# Copy entire project
COPY Cargo.toml Cargo.lock ./
COPY omni-daemon ./omni-daemon/
COPY omni-common ./omni-common/
COPY omni-ebpf ./omni-ebpf/

# Copy compiled eBPF program from Stage 1
# This ensures include_bytes! in omni-daemon finds the real ELF
RUN mkdir -p omni-ebpf/omni-ebpf-core/target/bpfel-unknown-none/release
COPY --from=ebpf-builder /usr/src/omni/omni-ebpf/omni-ebpf-core/target/bpfel-unknown-none/release/omni-ebpf \
     ./omni-ebpf/omni-ebpf-core/target/bpfel-unknown-none/release/omni-ebpf

# Verify the file is not empty
RUN [ -s omni-ebpf/omni-ebpf-core/target/bpfel-unknown-none/release/omni-ebpf ] || (echo "eBPF binary is empty!" && exit 1)

# Build release binary
RUN cargo build -p omni-daemon --release

# Runtime stage - minimal image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    iperf3 \
    libbpf1 \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /usr/src/omni/target/release/omni-daemon /usr/local/bin/

# Default command
ENTRYPOINT ["/usr/local/bin/omni-daemon"]
CMD ["--mode", "nucleus", "--port", "51820"]
