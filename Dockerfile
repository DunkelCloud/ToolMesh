FROM golang:1.25-alpine AS builder

ARG VERSION=dev
ARG COMMIT=unknown

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w \
      -X github.com/DunkelCloud/ToolMesh/internal/version.Version=${VERSION} \
      -X github.com/DunkelCloud/ToolMesh/internal/version.Commit=${COMMIT} \
      -X github.com/DunkelCloud/ToolMesh/internal/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /toolmesh ./cmd/toolmesh

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /tm-bootstrap ./cmd/tm-bootstrap

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /toolmesh /toolmesh
COPY --from=builder /tm-bootstrap /tm-bootstrap

EXPOSE 8080

ENTRYPOINT ["/toolmesh"]
