BINARY := server
BIN_DIR := bin
PKG := ./cmd/server
IMAGE := ecosystem-auth
COMPOSE := docker compose

# Containers read the ./keys mount, so run them as the host user.
export DOCKER_USER := $(shell id -u):$(shell id -g)

# Local development defaults. Override on the command line, e.g.
#   make run PORT=8081
DATABASE_URL ?= postgres://auth:auth@localhost:5432/auth?sslmode=disable
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
run: keys ## Run the server locally (requires deps: make deps-up)
	$(RUN_ENV) go run $(PKG)

.PHONY: start
start: deps-up run ## Start dependencies, then run the server locally

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

## --- Docker ---

.PHONY: deps-up
deps-up: ## Start Postgres and Redis only
	$(COMPOSE) up -d db redis

.PHONY: deps-down
deps-down: ## Stop Postgres and Redis
	$(COMPOSE) stop db redis

.PHONY: up
up: keys ## Start the full stack in the background
	$(COMPOSE) up -d --build

.PHONY: down
down: ## Stop the stack and remove containers
	$(COMPOSE) down

.PHONY: reset
reset: ## Stop the stack and delete database volumes
	$(COMPOSE) down -v

.PHONY: logs
logs: ## Tail logs of the stack
	$(COMPOSE) logs -f

.PHONY: ps
ps: ## Show stack status
	$(COMPOSE) ps

.PHONY: docker-build
docker-build: ## Build the Docker image
	docker build -t $(IMAGE) .
