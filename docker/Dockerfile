FROM rust:1.96-slim-bookworm AS builder
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      build-essential clang cmake perl pkg-config; \
    rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release -p hyperion-vault-api

FROM debian:bookworm-slim
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    useradd -r -u 10001 -m -d /var/lib/hyperion-vault vault; \
    mkdir -p /data; \
    chown vault:vault /data
COPY --from=builder /build/target/release/hyperion-vault-api /usr/local/bin/hyperion-vault-api
USER vault
ENV VAULT_DB_PATH=/data/vault.redb
EXPOSE 8200 7400
ENTRYPOINT ["/usr/local/bin/hyperion-vault-api"]
