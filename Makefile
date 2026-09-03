BINARY := server
BIN_DIR := bin
PKG := ./cmd/server
IMAGE := ecosystem-auth
COMPOSE := docker compose
COMPOSE_DEV := docker compose -f compose.dev.yaml
ECOSYSTEM_NETWORK ?= ecosystem

# Containers read the ./keys mount, so run them as the host user.
export DOCKER_USER := $(shell id -u):$(shell id -g)

# Local development defaults. Override on the command line, e.g.
#   make run PORT=8081
DATABASE_URL ?= postgres://postgres:postgres@localhost:5432/auth?sslmode=disable
REDIS_URL ?= redis://localhost:6379/0
JWT_KEYS_DIR ?= keys
JWT_ACTIVE_KID ?=
KID ?=
PORT ?= 8080
GRPC_PORT ?= 9090

RUN_ENV := DATABASE_URL='$(DATABASE_URL)' REDIS_URL='$(REDIS_URL)' JWT_KEYS_DIR='$(JWT_KEYS_DIR)' JWT_ACTIVE_KID='$(JWT_ACTIVE_KID)' PORT='$(PORT)' GRPC_PORT='$(GRPC_PORT)'

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

## --- Development ---

.PHONY: run
run: keys ## Run the server on the host (needs ecosystem-infra or make deps-up)
	$(RUN_ENV) go run $(PKG)

## --- Signing keys ---

.PHONY: keygen
keygen: ## Generate an RS256 signing key (KID=key-2026-09 to name it)
	go run ./cmd/keygen -dir $(JWT_KEYS_DIR) $(if $(KID),-kid $(KID),)

.PHONY: keys
keys: ## Generate a signing key only if none exists yet
	@if [ -z "$$(ls $(JWT_KEYS_DIR)/*.pem 2>/dev/null | grep -v '\.pub\.pem$$')" ]; then \
		$(MAKE) --no-print-directory keygen; \
	fi

.PHONY: jwks
jwks: ## Print the JWKS served by a running server
	@curl -fsS http://localhost:$(PORT)/.well-known/jwks.json

.PHONY: build
build: ## Build the server binary into ./bin
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BIN_DIR)/$(BINARY) $(PKG)

.PHONY: test
test: ## Run all tests
	go test ./...

.PHONY: cover
cover: ## Run tests with a coverage report
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

.PHONY: fmt
fmt: ## Format Go sources
	go fmt ./...

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: tidy
tidy: ## Tidy go.mod/go.sum
	go mod tidy

.PHONY: check
check: fmt vet test ## Format, vet and test

.PHONY: clean
clean: ## Remove build and coverage artifacts
	rm -rf $(BIN_DIR) coverage.out

## --- Protobuf ---

.PHONY: proto
proto: ## Generate protobuf/gRPC code
	buf generate

.PHONY: proto-lint
proto-lint: ## Lint protobuf definitions
	buf lint

## --- Docker (shared ecosystem infra) ---

.PHONY: up start
start: up ## Alias for `make up`
up: keys check-network ## Build and start auth on the shared ecosystem network
	$(COMPOSE) up -d --build

.PHONY: down
down: ## Stop auth and remove its container
	$(COMPOSE) down

.PHONY: restart
restart: down up ## Restart auth (picks up new signing keys)

.PHONY: logs
logs: ## Tail auth logs
	$(COMPOSE) logs -f

.PHONY: ps
ps: ## Show auth container status
	$(COMPOSE) ps

.PHONY: check-network
check-network: ## Verify the shared ecosystem network exists
	@docker network inspect $(ECOSYSTEM_NETWORK) >/dev/null 2>&1 || { \
		echo "docker network '$(ECOSYSTEM_NETWORK)' not found."; \
		echo "Start ecosystem-infra first (make up in that repo), or use 'make dev-up'."; \
		exit 1; \
	}

## --- Docker (self-contained dev stack) ---

.PHONY: dev-up
dev-up: keys ## Start auth with its own throwaway postgres + redis
	$(COMPOSE_DEV) up -d --build

.PHONY: dev-down
dev-down: ## Stop the dev stack and remove containers
	$(COMPOSE_DEV) down

.PHONY: dev-reset
dev-reset: ## Stop the dev stack and delete its database volume
	$(COMPOSE_DEV) down -v

.PHONY: dev-logs
dev-logs: ## Tail dev stack logs
	$(COMPOSE_DEV) logs -f

.PHONY: dev-ps
dev-ps: ## Show dev stack status
	$(COMPOSE_DEV) ps

.PHONY: deps-up
deps-up: ## Start only the dev postgres + redis (no auth container)
	$(COMPOSE_DEV) up -d db redis

.PHONY: deps-down
deps-down: ## Stop the dev postgres + redis
	$(COMPOSE_DEV) stop db redis

.PHONY: docker-build
docker-build: ## Build the Docker image
	docker build -t $(IMAGE) .
