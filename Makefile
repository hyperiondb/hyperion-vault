EXT = hyperion_vault
PG_CONFIG ?= pg_config
PGRX_FEATURES ?= pg18
CARGO_PGRX ?= cargo pgrx

.PHONY: all package install api test test-core test-security ext-test e2e deb fmt clippy clean docker-up docker-down

all: package api

package:
	cd extension && $(CARGO_PGRX) package --pg-config $(PG_CONFIG) --no-default-features --features $(PGRX_FEATURES)

install:
	cd extension && $(CARGO_PGRX) install --release --pg-config $(PG_CONFIG) --no-default-features --features $(PGRX_FEATURES)

api:
	cargo build --release -p hyperion-vault-api

test-core:
	cargo test -p hyperion-vault-core

test-security:
	cargo test -p hyperion-vault-core --test crypto_security --test auth_security --test ip_allowlist_security --test rotation_policy --test rbac_security

test:
	cargo test -p hyperion-vault-core -p hyperion-vault-api -p hyperion-vault

ext-test:
	cd extension && $(CARGO_PGRX) test --no-default-features --features $(PGRX_FEATURES)

e2e:
	bash scripts/e2e.sh

deb:
	bash packaging/build-deb.sh $(PGRX_FEATURES:pg%=%)

fmt:
	cargo fmt --all

clippy:
	cargo clippy -p hyperion-vault-core -p hyperion-vault-api -p hyperion-vault --all-targets -- -D warnings

clean:
	cargo clean

docker-up:
	cd docker && docker compose up --build

docker-down:
	cd docker && docker compose down -v
