# syntax=docker/dockerfile:1.7

FROM rust:1.89-slim AS chef

ARG APP_FEATURES=api-server,postgres-storage

ENV CARGO_TERM_COLOR=never \
    CARGO_NET_RETRY=10 \
    CARGO_HTTP_TIMEOUT=600

RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils \
    ca-certificates \
    curl \
    libpq-dev \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-chef --locked

WORKDIR /app

FROM chef AS planner

COPY . .

# Normalize the crate version so release bumps do not invalidate the cached
# dependency recipe when the dependency graph itself is unchanged.
RUN awk 'BEGIN { in_package=0 } \
    /^\[package\]/ { in_package=1; print; next } \
    /^\[/ { in_package=0; print; next } \
    { if (in_package && $1 == "version") sub(/=.*/, "= \"0.0.0\""); print }' \
    Cargo.toml > Cargo.toml.cargo-chef && \
    mv Cargo.toml.cargo-chef Cargo.toml && \
    cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

ARG APP_FEATURES=api-server,postgres-storage

COPY --from=planner /app/recipe.json recipe.json

RUN cargo chef cook --release --locked --recipe-path recipe.json --features "$APP_FEATURES" --bin auth-framework

COPY . .

RUN cargo build --release --locked --features "$APP_FEATURES" --bin auth-framework && \
    strip target/release/auth-framework

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libpq5 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r -g 1000 authfw && \
    useradd -r -g authfw -u 1000 -m -d /app authfw

WORKDIR /app

RUN mkdir -p /app/config /app/logs && \
    chown -R authfw:authfw /app

COPY --from=builder /app/target/release/auth-framework /usr/local/bin/auth-framework
COPY --chown=authfw:authfw config/ ./config/

USER authfw

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["auth-framework"]

EXPOSE 8080

FROM builder AS testing

RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
    redis-tools \
    && rm -rf /var/lib/apt/lists/*

CMD ["cargo", "test", "--all-features", "--release"]
