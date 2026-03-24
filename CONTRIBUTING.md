# Contributing to ToolMesh

Thank you for your interest in contributing to ToolMesh.

## Development Setup

### Prerequisites

- Go 1.25+
- Docker and Docker Compose v2

### Getting Started

```bash
git clone https://github.com/DunkelCloud/ToolMesh.git
cd ToolMesh
go mod download
go build ./...
go test ./...
```

### Running Locally

```bash
docker compose up -d
```

## Code Guidelines

### Language & Formatting

- **English only** — all code, comments, commit messages, documentation, variable names, error messages, and log output must be in English
- **`gofmt`** — all code must be formatted with `gofmt` (or `goimports`). Unformatted code will not be accepted
- **`go vet`** — code must pass `go vet ./...` without warnings

### Style

- **Go only** — no other languages for core logic
- **Stdlib preferred** — use `log/slog` for logging, avoid unnecessary dependencies
- **Context propagation** — every function takes `context.Context`
- **Error wrapping** — use `fmt.Errorf("...: %w", err)`
- **No `panic()`** — only in `main()` for unrecoverable errors
- **Table-driven tests** where appropriate
- **GoDoc comments** on all exported types and functions

## Branching & Workflow

### Branch Naming

- `feature/<name>` — new functionality
- `fix/<name>` — bug fixes
- `docs/<name>` — documentation changes

### Development Cycle

1. Create a feature branch from `main`
2. Commit freely — WIP commits are expected and welcome
3. Build and test locally with `make docker-dev` (builds and pushes a `:dev` image)
4. Test against the dev environment using the `:dev` tag
5. When ready: open a Pull Request

### Merging

- All PRs are **squash-merged** into `main`
- The squash commit message should clearly describe the change
- Delete the feature branch after merge
- Direct pushes to `main` are not allowed

## Pull Requests

1. Fork the repository
2. Create a feature branch from `main` (see naming conventions above)
3. Write tests for new functionality
4. Ensure `go test ./...` passes
5. Ensure `go vet ./...` reports no issues
6. Open a pull request with a clear description
7. PRs are squash-merged — your branch commits will be combined into one clean commit on `main`

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
