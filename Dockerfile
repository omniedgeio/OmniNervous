# OmniNervous Daemon Docker Image
# Simplified build - copy all sources at once

FROM rust:1.79 AS builder

WORKDIR /usr/src/omni

# Copy entire project (except what's in .dockerignore)
COPY Cargo.toml Cargo.lock ./
COPY omni-daemon ./omni-daemon/
COPY omni-common ./omni-common/
COPY omni-ebpf ./omni-ebpf/

# Create placeholder eBPF binary (for include_bytes! in main.rs)
RUN mkdir -p omni-daemon/ebpf && \
    echo "PLACEHOLDER_EBPF" > omni-daemon/ebpf/omni-ebpf-core

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
