# Hecate Makefile - build, test, run, and compose
# Requires: Go 1.24+, podman (or docker), podman-compose, openssl (for local certs)

APP_NAME := hecate
PKG := github.com/arencloud/hecate
BIN := $(APP_NAME)
MAIN := ./cmd/hecate
CFG := config/example.yaml
CERT_DIR := config
CERT := $(CERT_DIR)/cert.pem
KEY := $(CERT_DIR)/key.pem

CONTAINER_RUNTIME ?= podman
COMPOSE ?= podman-compose
IMAGE := ghcr.io/arencloud/$(APP_NAME):dev
PLATFORMS ?= linux/amd64,linux/arm64
DOCKERFILE ?= Dockerfile
COMPOSE_FILE ?= docker-compose.yml


GO := go
GOFLAGS :=
LDFLAGS := -s -w
TAGS :=

.PHONY: all build test unit fmt vet lint run run-http up down logs ps curl smoke clean image image-multi gen-certs help

# MaxMind GeoLite2 download (optional)
# Usage:
#   make geoip-download MAXMIND_LICENSE_KEY=xxxxxxxxxxxxxxxx
# Notes:
# - If MAXMIND_LICENSE_KEY is not set, this target will no-op gracefully.
# - Files will be placed into ./config as:
#     config/GeoLite2-Country.mmdb
#     config/GeoLite2-ASN.mmdb
.PHONY: geoip-download geoip-clean up-geo
geoip-download:
	@if [ -z "$(MAXMIND_LICENSE_KEY)" ]; then \
		echo "MAXMIND_LICENSE_KEY not set; skipping GeoIP download (no-op)"; \
		echo "Export it or pass on CLI: make geoip-download MAXMIND_LICENSE_KEY=..."; \
		exit 0; \
	fi; \
	set -e; \
	mkdir -p $(CERT_DIR); \
	TMPDIR="$$(mktemp -d)"; \
	echo "Downloading GeoLite2 databases into $$TMPDIR ..."; \
	for ed in GeoLite2-Country GeoLite2-ASN; do \
		URL="https://download.maxmind.com/app/geoip_download?edition_id=$${ed}&license_key=$(MAXMIND_LICENSE_KEY)&suffix=tar.gz"; \
		echo "Fetching $$ed ..."; \
		curl -fsSL "$$URL" -o "$$TMPDIR/$$ed.tgz"; \
		tar -xzf "$$TMPDIR/$$ed.tgz" -C "$$TMPDIR"; \
		MMDB_PATH="$$(find "$$TMPDIR" -type f -name "$${ed}.mmdb" | head -n1)"; \
		if [ -z "$$MMDB_PATH" ]; then \
			echo "Could not find $$ed.mmdb in archive; skipping $$ed"; \
			continue; \
		fi; \
		cp "$$MMDB_PATH" "$(CERT_DIR)/$${ed}.mmdb"; \
	done; \
	chmod 0644 $(CERT_DIR)/GeoLite2-*.mmdb || true; \
	rm -rf "$$TMPDIR"; \
	echo "GeoLite2 databases are ready under $(CERT_DIR)/"

# Convenience: run compose with a best-effort GeoIP download beforehand
up-geo: geoip-download up

# Clean downloaded mmdb databases
geoip-clean:
	rm -f $(CERT_DIR)/GeoLite2-*.mmdb


all: build

build:
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -tags '$(TAGS)' -o $(BIN) $(MAIN)

test: unit

unit:
	$(GO) test ./... -race -count=1

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

run: gen-certs
	@echo "Starting $(APP_NAME) with $(CFG)"
	$(GO) run $(MAIN) -config=$(CFG)

run-http:
	@echo "Starting $(APP_NAME) HTTP (remove tls section in config or ignore certs)"
	$(GO) run $(MAIN) -config=$(CFG)

# Ensure cert/key readable by non-root in containers
gen-certs:
	@mkdir -p $(CERT_DIR)
	@if [ ! -f "$(CERT)" ] || [ ! -f "$(KEY)" ]; then \
		echo "Generating self-signed TLS certs under $(CERT_DIR) ..."; \
		openssl req -x509 -newkey rsa:2048 -nodes -keyout $(KEY) -out $(CERT) -days 365 \
			-subj "/CN=localhost" >/dev/null 2>&1 || true; \
	fi
	@chmod 0644 $(CERT) $(KEY)

# Build an OCI-compliant image (single-arch)
image: gen-certs
	$(CONTAINER_RUNTIME) build -f $(DOCKERFILE) -t $(IMAGE) .

# Multi-arch (requires buildx for docker; podman can emulate via --arch loop)
image-multi:
	@echo "Building image using $(DOCKERFILE) for platforms: $(PLATFORMS)"
	$(CONTAINER_RUNTIME) build --jobs=2 -f $(DOCKERFILE) -t $(IMAGE) .

# Podman/Docker compose up/down with selected compose file
up: gen-certs image
	$(COMPOSE) -f $(COMPOSE_FILE) up -d --remove-orphans

down:
	$(COMPOSE) -f $(COMPOSE_FILE) down -v

logs:
	-$(CONTAINER_RUNTIME) logs -f $(APP_NAME) || $(COMPOSE) -f $(COMPOSE_FILE) logs -f $(APP_NAME)

ps:
	$(COMPOSE) -f $(COMPOSE_FILE) ps

# Quick cURL checks against the compose stack
curl:
	@echo "Health:" && curl -sf http://127.0.0.1:9000/healthz && echo
	@echo "Admin auth (expect 401):" && curl -si http://127.0.0.1:9000/debug/vars | head -n1
	@echo "Admin auth (with bearer):" && curl -sf -H "Authorization: Bearer my-admin-token" http://127.0.0.1:9000/debug/vars >/dev/null && echo "OK"
	@echo "Route api via TLS (self-signed; ignoring cert):" && \
	  curl -sk -H "Host: api.example.com" https://127.0.0.1:9443/ | head -n 1
	@echo "Route web via TLS (self-signed; ignoring cert):" && \
	  curl -sk -H "Host: www.example.com" https://127.0.0.1:9443/ | head -n 1
	@echo "Public route bearer auth (expect 401):" && \
	  curl -sk -o /dev/null -w "%{http_code}\n" -H "Host: api.example.com" https://127.0.0.1:9443/
	@echo "Public route bearer auth (authorized):" && \
	  curl -sk -H "Authorization: Bearer public-route-token" -H "Host: api.example.com" https://127.0.0.1:9443/ | head -n 1

# End-to-end smoke using local binary + two local upstreams via podman-compose
smoke: up
	@sleep 2
	$(MAKE) curl

clean:
	rm -f $(BIN)
