.PHONY: all api test test-core test-security fuzz fuzz-build e2e fmt clippy clean docker-up docker-down

all: api

api:
	cargo build --release -p hyperion-vault-api

test-core:
	cargo test -p hyperion-vault-core

test-security:
	cargo test -p hyperion-vault-core --test crypto_security --test auth_security --test ip_allowlist_security --test rotation_policy --test rbac_security

test:
	cargo test --workspace

# Nightly-only; see fuzz/README.md. fuzz-build only checks that every target
# still compiles, fuzz sweeps them all for BUDGET seconds each (default 60).
BUDGET ?= 60

fuzz-build:
	cargo +nightly fuzz build --features api

fuzz:
	bash fuzz/run-all.sh $(BUDGET)

e2e:
	bash scripts/e2e.sh

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

clean:
	cargo clean

docker-up:
	cd docker && docker compose up --build

docker-down:
	cd docker && docker compose down -v
