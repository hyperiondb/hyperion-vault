ARG PG_REPLICA_IMAGE=pg-replica-paradedb:local

FROM ${PG_REPLICA_IMAGE} AS builder
USER root
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      build-essential clang libclang-dev pkg-config libssl-dev curl git ca-certificates; \
    PGVER="$(pg_config --version | grep -oE '[0-9]+' | head -1)"; \
    apt-get install -y --no-install-recommends "postgresql-server-dev-${PGVER}" \
      || echo "using image-provided server headers"; \
    rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo install --locked cargo-pgrx --version 0.18.1
WORKDIR /build
COPY . .
RUN set -eux; \
    PGVER="$(pg_config --version | grep -oE '[0-9]+' | head -1)"; \
    cd extension; \
    cargo pgrx init "--pg${PGVER}" "$(command -v pg_config)"; \
    cargo pgrx install --release --no-default-features --features "pg${PGVER}" --pg-config "$(command -v pg_config)"; \
    PKGLIB="$(pg_config --pkglibdir)"; SHARE="$(pg_config --sharedir)"; \
    mkdir -p /staging; \
    cp "${PKGLIB}/hyperion_vault.so" /staging/; \
    cp "${SHARE}/extension/hyperion_vault".* /staging/
RUN cargo build --release -p hyperion-vault-api

FROM ${PG_REPLICA_IMAGE}
USER root
COPY --from=builder /staging/ /staging/
COPY --from=builder /build/target/release/hyperion-vault-api /usr/local/bin/hyperion-vault-api
RUN set -eux; \
    PKGLIB="$(pg_config --pkglibdir)"; SHARE="$(pg_config --sharedir)"; \
    cp /staging/hyperion_vault.so "${PKGLIB}/"; \
    cp /staging/hyperion_vault.control "${SHARE}/extension/"; \
    cp /staging/hyperion_vault--*.sql "${SHARE}/extension/"; \
    rm -rf /staging
