MODULE   := github.com/DunkelCloud/ToolMesh
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS  := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.BuildDate=$(DATE)

BIN_DIR  := bin

.PHONY: all build test lint vet fmt lint-dadl clean docker docker-dev help

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

lint: vet fmt ## Run all linters

lint-dadl: build ## Scan DADL composites for security violations
	$(BIN_DIR)/lint-dadl dadl/*.dadl

clean: ## Remove build artifacts
	rm -rf $(BIN_DIR) coverage.out coverage.html

docker: ## Build Docker image
	docker build -t toolmesh:$(VERSION) -t toolmesh:latest .

docker-dev: ## Build and push dev Docker image
	docker build -t ghcr.io/dunkelcloud/toolmesh:dev \
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
