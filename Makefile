MODULE   := github.com/DunkelCloud/ToolMesh
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS  := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.BuildDate=$(DATE)

BIN_DIR  := bin

.PHONY: all build test lint lint-go vet fmt lint-dadl clean docker docker-dev help

all: lint test build ## Run lint, test, and build

build: ## Build binaries
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/toolmesh ./cmd/toolmesh
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/lint-dadl ./cmd/lint-dadl

test: ## Run tests
	go test ./...

test-verbose: ## Run tests with verbose output
	go test -v ./...

test-cover: ## Run tests with coverage report
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

vet: ## Run go vet
	go vet ./...

fmt: ## Check formatting
	@test -z "$$(gofmt -l .)" || (echo "Run gofmt:" && gofmt -l . && exit 1)

lint-go: ## Run golangci-lint with the project config (matches CI)
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint is not installed. Install it from https://golangci-lint.run or run 'go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest'."; \
		exit 1; \
	}
	golangci-lint run ./...

lint: vet fmt lint-go ## Run all linters (matches CI)

DADL_DIR ?= dadl

lint-dadl: build ## Check DADL files (structure, unimplemented keys, composite security)
	$(BIN_DIR)/lint-dadl $(DADL_DIR)

# Point this at the DADL directory a deployment actually loads, which is the
# one nothing else checks — registry CI only sees what is published to it:
#   make lint-dadl DADL_DIR=/path/to/deployed/dadl

clean: ## Remove build artifacts
	rm -rf $(BIN_DIR) coverage.out coverage.html

# DOCKER_BUILDKIT=1: the Dockerfile pins its builder stage to $BUILDPLATFORM,
# which the legacy builder cannot parse. Distro packages (Ubuntu docker.io)
# still default to it, so set it explicitly rather than relying on the default.
docker: ## Build Docker image
	DOCKER_BUILDKIT=1 docker build -t toolmesh:$(VERSION) -t toolmesh:latest .

docker-dev: ## Build and push dev Docker image
	DOCKER_BUILDKIT=1 docker build -t ghcr.io/dunkelcloud/toolmesh:dev \
		--build-arg VERSION=$(shell git describe --always --dirty) \
		.
	docker push ghcr.io/dunkelcloud/toolmesh:dev

up: ## Start all services
	docker compose up -d

down: ## Stop all services
	docker compose down

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'
