# syntax=docker/dockerfile:1.7
# Multi-stage OCI-compliant build

# builder
FROM golang:1.24 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o /out/hecate ./cmd/hecate

# runtime
FROM gcr.io/distroless/static:nonroot
USER 65532:65532
WORKDIR /app

# OCI image annotations
LABEL org.opencontainers.image.title="hecate" \
      org.opencontainers.image.description="Next-gen LB/GLB proxy" \
      org.opencontainers.image.source="https://github.com/arencloud/hecate" \
      org.opencontainers.image.licenses="MIT"

COPY --chown=65532:65532 --from=builder /out/hecate /app/hecate
COPY --chown=65532:65532 config /app/config

EXPOSE 8443 9000
ENTRYPOINT ["/app/hecate"]
CMD ["-config=/app/config/example.yaml"]
