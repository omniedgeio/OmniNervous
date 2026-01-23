# OmniNervous Daemon Docker Image
# Stage 1: Build Userspace Daemon
FROM rustlang/rust:nightly AS builder

WORKDIR /usr/src/omni
ENV CACHE_BREAKER_TIMESTAMP=20260117_0550

# Install build-time dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    make \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy entire project
COPY Cargo.toml ./
COPY crates/daemon ./crates/daemon/

# Build release binary
RUN cargo build -p omni-daemon --release

# Runtime stage - minimal image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    iperf3 \
    wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /usr/src/omni/target/release/omni-daemon /usr/local/bin/

# Default command
ENTRYPOINT ["/usr/local/bin/omni-daemon"]
CMD ["--mode", "nucleus", "--port", "51820"]
