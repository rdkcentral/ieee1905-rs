# Build Stage
FROM rust:1-bookworm AS builder

# Build deps (bindgen needs libclang)
RUN apt-get -o Acquire::Retries=5 update \
    && apt-get -o Acquire::Retries=5 -o Acquire::http::Timeout=30 install -y --no-install-recommends \
    build-essential \
    libclang-dev \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Enable tokio-console support
ENV RUSTFLAGS="--cfg tokio_unstable"
ENV LIBCLANG_PATH="/usr/lib/llvm-14/lib"

# Install tokio-console (optional, but you were using it)
RUN cargo install tokio-console

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release -p ieee1905 || true

COPY . .
RUN cargo build --release -p ieee1905 \
    && cargo build --release -p ieee1905-tests --bin ieee1905-test-node

# Runtime Stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    htop \
    libgcc-s1 \
    libstdc++6 \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/ieee1905 /app/ieee1905
COPY --from=builder /app/target/release/ieee1905-test-node /app/ieee1905-test-node
COPY --from=builder /usr/local/cargo/bin/tokio-console /usr/local/bin/tokio-console

EXPOSE 8080 6669

# Tokio Console bind
ENV RUST_CONSOLE_BIND=0.0.0.0:6669
