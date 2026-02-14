# Build Stage
FROM rust:alpine AS builder

# Build deps (bindgen needs libclang)
RUN apk add --no-cache musl-dev openssl-dev pkgconfig build-base clang llvm-dev clang-dev

# Enable tokio-console support
ENV RUSTFLAGS="--cfg tokio_unstable"
ENV LIBCLANG_PATH="/usr/lib"

# Install tokio-console (optional, but you were using it)
RUN cargo install tokio-console

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release -p ieee1905 || true

COPY . .
RUN cargo build --release -p ieee1905

# Runtime Stage
FROM alpine:latest

RUN apk add --no-cache \
    htop \
    libgcc \
    libstdc++ \
    openssl

WORKDIR /app

COPY --from=builder /app/target/release/ieee1905 /app/ieee1905
COPY --from=builder /usr/local/cargo/bin/tokio-console /usr/local/bin/tokio-console

EXPOSE 8080 6669

# Tokio Console bind
ENV RUST_CONSOLE_BIND=0.0.0.0:6669

CMD ["/app/ieee1905"]
