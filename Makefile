# tsa-bench build and verification targets.

BINARY      := tsa-bench
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X main.version=$(VERSION)
GO          ?= go
BIN_DIR     := bin
DIST_DIR    := dist

# CGO is disabled so the result is a genuinely static binary with no libc
# dependency: it runs on any Linux of the same architecture, including
# distroless and scratch images.
export CGO_ENABLED = 0

.PHONY: all
all: check build

.PHONY: build
build:
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) ./cmd/tsa-bench

## release: static binaries for the supported deployment targets.
.PHONY: release
release: clean-dist
	@mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" \
		-o $(DIST_DIR)/$(BINARY)-linux-amd64 ./cmd/tsa-bench
	GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" \
		-o $(DIST_DIR)/$(BINARY)-linux-arm64 ./cmd/tsa-bench
	@cd $(DIST_DIR) && sha256sum * > SHA256SUMS 2>/dev/null || shasum -a 256 * > SHA256SUMS
	@echo "built:" && ls -1 $(DIST_DIR)

.PHONY: check
check: fmt-check vet test capacity

.PHONY: test
test:
	$(GO) test ./...

## race: the quota counter and the collector are concurrent; this must stay green.
.PHONY: race
race:
	$(GO) test -race ./...

## capacity: 300 TPS client capacity check against the local mock.
## Run in isolation (-p 1): it measures this machine, so parallel packages
## competing for the same cores would make the result meaningless.
.PHONY: capacity
capacity:
	TSA_BENCH_CAPACITY=1 $(GO) test -p 1 -count=1 -v \
		-run TestClientCapacity ./internal/load

.PHONY: test-short
test-short:
	$(GO) test -short ./...

.PHONY: cover
cover:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: fmt
fmt:
	gofmt -w $(shell find . -name '*.go' -not -path './vendor/*')

.PHONY: fmt-check
fmt-check:
	@unformatted=$$(gofmt -l $$(find . -name '*.go' -not -path './vendor/*')); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed for:"; echo "$$unformatted"; exit 1; \
	fi

## lint: staticcheck if it is installed; skipped otherwise so `make check` works
## on a clean machine.
.PHONY: lint
lint:
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "staticcheck not installed; install with:"; \
		echo "  go install honnef.co/go/tools/cmd/staticcheck@latest"; \
	fi

## verify: the full gate. Everything here must pass before a real test run.
.PHONY: verify
verify: fmt-check vet race capacity lint

## golden: regenerate report golden files after an intended layout change.
.PHONY: golden
golden:
	$(GO) test ./internal/report -update
	@echo "golden files regenerated; review the diff before committing"

## smoke: end-to-end check against the local mock. Contacts no provider.
.PHONY: smoke
smoke: build
	@./scripts/smoke.sh

## demo: one-command demonstration against the local mock. Contacts no
## provider; writes ./demo-results and prints where the report is.
.PHONY: demo
demo: build
	@./scripts/demo.sh

.PHONY: docker
docker:
	docker build -t $(BINARY):$(VERSION) .

.PHONY: clean
clean: clean-dist
	rm -rf $(BIN_DIR) coverage.out demo-results

.PHONY: clean-dist
clean-dist:
	rm -rf $(DIST_DIR)

.PHONY: help
help:
	@grep -E '^##' $(MAKEFILE_LIST) | sed 's/## //'
