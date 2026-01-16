# OmniNervous Daemon Docker Image
# Simplified build - copy all sources at once

# Stage 1: Build eBPF Kernel Program
FROM rustlang/rust:nightly AS ebpf-builder

WORKDIR /usr/src/omni

# Install bpf-linker
RUN cargo install bpf-linker

# Copy eBPF source
COPY omni-ebpf ./omni-ebpf/
COPY omni-common ./omni-common/

# Build eBPF program (Target: Little Endian for x86_64)
WORKDIR /usr/src/omni/omni-ebpf/omni-ebpf-core
RUN cargo build --release --target bpfel-unknown-none -Z build-std=core

# Stage 2: Build Userspace Daemon
FROM rust:1.79 AS builder

WORKDIR /usr/src/omni

# Copy entire project
COPY Cargo.toml Cargo.lock ./
COPY omni-daemon ./omni-daemon/
COPY omni-common ./omni-common/
COPY omni-ebpf ./omni-ebpf/

# Copy compiled eBPF program from Stage 1
# This replaces the placeholder creation
RUN mkdir -p omni-daemon/ebpf
COPY --from=ebpf-builder /usr/src/omni/omni-ebpf/omni-ebpf-core/target/bpfel-unknown-none/release/omni-ebpf-core omni-daemon/ebpf/omni-ebpf-core

# Build release binary
RUN cargo build -p omni-daemon --release

# Runtime stage - minimal image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    iperf3 \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /usr/src/omni/target/release/omni-daemon /usr/local/bin/

# Default command
ENTRYPOINT ["/usr/local/bin/omni-daemon"]
CMD ["--mode", "nucleus", "--port", "51820"]
