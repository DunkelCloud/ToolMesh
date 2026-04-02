FROM golang:1.25-alpine AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG TARGETARCH

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w \
      -X github.com/DunkelCloud/ToolMesh/internal/version.Version=${VERSION} \
      -X github.com/DunkelCloud/ToolMesh/internal/version.Commit=${COMMIT} \
      -X github.com/DunkelCloud/ToolMesh/internal/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /toolmesh ./cmd/toolmesh

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /toolmesh /toolmesh

EXPOSE 8080

ENTRYPOINT ["/toolmesh"]
