# OmniNervous Daemon Docker Image
# Stage 1: Build Userspace Daemon
FROM rust:latest AS builder

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
ARG CARGO_FEATURES=""
RUN cargo build -p omninervous --release ${CARGO_FEATURES}


# Runtime stage - minimal image with compatible glibc
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    iperf3 \
    wireguard-tools \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /usr/src/omni/target/release/omninervous /usr/local/bin/

# Default command
ENTRYPOINT ["/usr/local/bin/omninervous"]
CMD ["--mode", "nucleus", "--port", "51820"]
