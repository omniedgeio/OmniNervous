# OmniNervous Daemon Docker Image
# Simplified build - omni-daemon only (no eBPF for now)

# Build stage
FROM rust:1.79 AS builder

WORKDIR /usr/src/omni

# Copy workspace Cargo files
COPY Cargo.toml Cargo.lock ./

# Copy crate Cargo.toml files
COPY omni-daemon/Cargo.toml ./omni-daemon/
COPY omni-common/Cargo.toml ./omni-common/

# Create dummy source files for dependency caching
RUN mkdir -p omni-daemon/src omni-common/src && \
    echo "fn main() {}" > omni-daemon/src/main.rs && \
    echo "" > omni-common/src/lib.rs

# Build dependencies only (this layer is cached)
RUN cargo build -p omni-daemon --release 2>/dev/null || true

# Copy actual source code
COPY omni-daemon/src ./omni-daemon/src
COPY omni-common/src ./omni-common/src

# Touch to force rebuild with actual sources
RUN touch omni-daemon/src/main.rs

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

# Default command - run as nucleus
ENTRYPOINT ["/usr/local/bin/omni-daemon"]
CMD ["--mode", "nucleus", "--port", "51820"]
