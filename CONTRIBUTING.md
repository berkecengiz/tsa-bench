# Contributing

## The one rule that is not negotiable

**No test, example, CI job or default value may contact a real timestamp
provider.** Everything is exercised against the in-process mock responder on
loopback. There is no built-in default endpoint anywhere in this repository and
there must never be one: a live run consumes a customer's paid, irreversible
quota, and a default endpoint is how that happens by accident.

For the same reason, `run` requires `--max-requests` and
`--authorized-load-test` every time, and `--acknowledge-live-environment` on
top of that for a live target. Do not add a way to skip them.

## Before you open a pull request

```sh
make verify
```

That is the full gate: `gofmt`, `go vet`, `go test -race`, the client capacity
check, and `staticcheck` if it is installed. CI runs the same thing minus the
capacity check — that one measures the machine it runs on, so a shared runner
makes it meaningless.

Useful subsets while working:

```sh
make test          # go test ./...
make race          # the concurrency gate; the quota counter lives or dies here
make cover         # coverage summary
make smoke         # end-to-end against the local mock
make demo          # the same, but keeps its output for inspection
```

## Golden files

`internal/report` compares its output against committed golden files. After an
intended change to report layout:

```sh
make golden        # regenerates, then review the diff before committing
```

A golden diff you did not expect is a real finding, not noise.

## Test fixtures

Fixtures are **generated, never captured**. A signed RFC 3161 token embeds the
issuing TSA's certificate chain, so committing a real one publishes which
service was tested. `internal/testutil` builds throwaway PKI and
`internal/mock` issues genuine tokens over it; see
`internal/tsp/tolerant_ext_test.go` for the pattern.

## Things the code cares about that a reviewer might not expect

- **Quota is safety-critical.** The counter increments only when an attempt is
  actually handed to the transport, through an atomic compare-and-swap. One
  unit of quota is one physical attempt. Changes near `internal/load/quota.go`
  need a very good reason.
- **Retries are not implemented, deliberately.** `limits.retries` must be `0`.
  A retry spends another unit of someone's allowance.
- **The load generator is open-loop.** Request *n* is due at `start + n/rate`
  regardless of when *n-1* finished. Do not "fix" it into a closed-loop worker
  pool — that reintroduces coordinated omission, which is the specific bias
  this tool exists to avoid.
- **A check that cannot be performed is a failure.** There is no mode in which
  a verification step is skipped and the transaction still counts as a success.
- **Secrets are never arguments.** No `--password`, no `--token`, ever. See
  [SECURITY.md](SECURITY.md).

## Style

Standard Go, `gofmt`-clean, stdlib `testing` with no assertion library.
Comments explain *why*, not *what* — the surrounding code is written that way,
so match it.
