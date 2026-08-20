# syntax=docker/dockerfile:1
# Zorv tunnel server multi-stage build image
#
# Build: docker build -f deploy/Dockerfile -t zorvd:latest .
# Run: see deploy/README.md

# ---- UI build stage (Vue admin console) ----
FROM node:22-bookworm-slim AS ui-builder
WORKDIR /ui
COPY zorv-ui/package.json zorv-ui/pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile
COPY zorv-ui ./
# Outputs the built SPA to /html (see vite.config.ts: outDir = '../html')
RUN pnpm build

# ---- Build stage ----
FROM rust:1-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
COPY examples ./examples
COPY config ./config
# Embedded admin console assets (required by build.rs)
COPY --from=ui-builder /html ./html
# Full static dependencies (rustls pure Rust), can be copied directly
RUN cargo build --release --bin zorvd --bin zorv

# ---- Run stage ----
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/zorvd /usr/local/bin/zorvd
COPY --from=builder /build/target/release/zorv  /usr/local/bin/zorv
# Default config and self-signed certificate (for production, please mount a volume to replace)
COPY config/zorvd.example.toml /etc/zorv/zorvd.toml
COPY releases/server.crt /etc/zorv/server.crt
COPY releases/server.key /etc/zorv/server.key
# Expose Web management interface in the container (default listens on 127.0.0.1, please adjust in README)

RUN sed -i 's/127.0.0.1:9000/0.0.0.0:9000/' /etc/zorv/zorvd.toml \
    && echo 'data_dir = "/var/lib/zorv"' >> /etc/zorv/zorvd.toml
# Persistent data
RUN mkdir -p /var/lib/zorv
VOLUME ["/var/lib/zorv"]
# Tunnel port, Web management port (proxy port mapped as needed)
EXPOSE 8443 9000
WORKDIR /var/lib/zorv
ENTRYPOINT ["/usr/local/bin/zorvd", "--config", "/etc/zorv/zorvd.toml"]
