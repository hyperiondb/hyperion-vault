.PHONY: all api test test-core test-security e2e fmt clippy clean docker-up docker-down

all: api

api:
	cargo build --release -p hyperion-vault-api

test-core:
	cargo test -p hyperion-vault-core

test-security:
	cargo test -p hyperion-vault-core --test crypto_security --test auth_security --test ip_allowlist_security --test rotation_policy --test rbac_security

test:
	cargo test --workspace

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
