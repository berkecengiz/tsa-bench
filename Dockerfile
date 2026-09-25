# Build stage.
FROM golang:1.27-alpine AS build

WORKDIR /src

# Dependencies first so the module layer caches independently of the source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=docker
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/tsa-bench ./cmd/tsa-bench

# Runtime stage.
#
# distroless/static carries no shell and no package manager, which keeps the
# attack surface of a host that holds TSA credentials small. The static build
# above needs nothing else; ca-certificates comes with the base image for TLS
# to system roots, though a provider CA should be mounted in explicitly.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/tsa-bench /usr/local/bin/tsa-bench

# Results are written here; mount a volume so they survive the container.
WORKDIR /work
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/tsa-bench"]
CMD ["--help"]

# Usage:
#
#   docker build -t tsa-bench .
#   docker run --rm \
#     -v "$PWD/configs:/work/configs:ro" \
#     -v "$PWD/results:/work/results" \
#     -e TSA_USER -e TSA_PASS \
#     tsa-bench validate --config configs/provider.yaml
#
# Secrets are passed as environment variables, never as arguments.
#
# Note: a container adds a network namespace hop. For a capacity measurement,
# prefer running the static binary directly on the test host, and use the image
# only where a container is mandated.
