FROM lukemathwalker/cargo-chef:latest-rust-slim-bookworm AS chef
WORKDIR /build

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential clang cmake perl pkg-config \
    && rm -rf /var/lib/apt/lists/*
COPY --from=planner /build/recipe.json recipe.json
# Build and cache dependencies — this layer is only invalidated when recipe.json changes.
RUN cargo chef cook --release -p hyperion-vault-api --recipe-path recipe.json
COPY . .
RUN cargo build --release -p hyperion-vault-api

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -m -d /var/lib/hyperion-vault vault \
    && mkdir -p /data \
    && chown vault:vault /data

COPY --from=builder /build/target/release/hyperion-vault-api /usr/local/bin/hyperion-vault-api

USER vault

ENV VAULT_DB_PATH=/data/vault.redb

VOLUME ["/data"]

EXPOSE 8200 7400

ENTRYPOINT ["hyperion-vault-api"]
