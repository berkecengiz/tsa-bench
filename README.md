# tsa-bench

[![CI](https://github.com/berkecengiz/tsa-bench/actions/workflows/ci.yml/badge.svg)](https://github.com/berkecengiz/tsa-bench/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/berkecengiz/tsa-bench.svg)](https://pkg.go.dev/github.com/berkecengiz/tsa-bench)
[![Go 1.27](https://img.shields.io/badge/go-1.27-00ADD8?logo=go&logoColor=white)](https://go.dev/dl/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

A capacity testing tool for RFC 3161 timestamp services.

It issues timestamp requests at a constant arrival rate, verifies every response
against the full RFC 3161 acceptance chain, and produces a report that states
plainly what was measured and what it does not prove.

**An HTTP 200 is never counted as a success.** A transaction is successful only
when the status, content type, PKIStatus, nonce, message imprint, CMS signature,
certificate chain, timeStamping key usage and genTime skew checks all pass.

---

## Try it in thirty seconds

No provider, no credentials, no quota — this runs entirely against a local mock
responder on loopback:

```sh
make build && make demo
```

It starts the mock, runs a four-stage rate ladder against it, verifies all
2,800 responses through the chain above, and prints where the report landed.

Prefer not to run anything? The same output is committed in
[`examples/sample-run/`](examples/sample-run/) — start with `report.html`.

> The mock signs in-process, so its latencies are the latency of a local
> signature. It measures **this client**, never a provider.

---

## Before you test a provider

This tool sends real traffic and consumes real, irreversible quota. Against a
live production service it also competes with real customer traffic. Work
through this list before the first run — every item, for every provider.

- [ ] **Written load-testing authorisation** from the provider, naming the
      endpoint and covering the dates of the test.
- [ ] **Endpoint confirmed** with the provider — the exact URL, in writing.
- [ ] **Rate limit confirmed**: the provider agrees 150 TPS is acceptable, and
      tells you what they will do if it is not.
- [ ] **Quota confirmed**: the allowance for the engagement (50,000 timestamps)
      and whether failed requests count against it.
- [ ] **Source IP allowlisted** by the provider, and you know which egress
      address you will actually leave from.
- [ ] **Test window agreed**, plus a named contact on the provider side who is
      on duty during it and can be reached immediately.
- [ ] **Stop procedure agreed**: how you abort and how you tell them you have.
- [ ] **NTP synchronised** on the test host (`chronyc tracking` or
      `timedatectl`). genTime skew is verified against your local clock; a host
      whose clock is wrong will report the provider as wrong.
- [ ] **Resource monitoring in place** for CPU, memory and network on the test
      host, so a client-side bottleneck is visible independently of this tool.
- [ ] **Same hardware and same network egress** for every provider. Results from
      different hosts or different network paths are not comparable.
- [ ] **Providers tested sequentially, never concurrently.** Running two at once
      makes the test host a shared bottleneck and invalidates both results.

See `docs/runbook.md` for the run-day procedure and `docs/linux-tuning.md` for
host preparation. [`docs/provider-onboarding.md`](docs/provider-onboarding.md)
records how a provider's trust and authentication configuration is established
before a run, and [`docs/capacity-findings.md`](docs/capacity-findings.md) what
three qualified providers turned out to do under load.

---

## Install

Requires Go 1.27 or newer to build (both `digitorus` dependencies declare it).

```sh
make build                # ./bin/tsa-bench
make release              # static linux/amd64 and linux/arm64 binaries in dist/
make verify               # gofmt, go vet, go test -race, staticcheck
```

The binary is static (`CGO_ENABLED=0`) and has no runtime dependencies.

---

## Commands

| Command    | What it does                                                          | Network |
|------------|-----------------------------------------------------------------------|---------|
| `validate` | Checks a configuration file and, optionally, a profile against limits. | none    |
| `doctor`   | DNS, TCP and TLS checks; `--send-one` sends exactly one request.       | yes     |
| `run`      | Executes a load profile.                                              | yes     |
| `report`   | Builds a comparative report from result directories.                  | none    |
| `mock`     | Runs a local RFC 3161 responder for client capacity checks.           | local   |

### validate

```sh
tsa-bench validate --config configs/provider.yaml --profile profiles/50k.yaml
```

Sends nothing. Checks the schema, the referenced environment variables (their
names, never their values), file paths, TLS settings, and the quota arithmetic
of the profile against the configured limits. Run this in CI.

### doctor

```sh
tsa-bench doctor --config configs/provider.yaml              # no quota consumed
tsa-bench doctor --config configs/provider.yaml --send-one   # consumes 1 unit
```

Run `--send-one` before every load test. It proves the trust configuration is
right — in particular that `tls.tsa_ca_file` contains the issuer of the TSA's
signing certificate — for the cost of a single timestamp. Getting this wrong
turns a 48,600-request run into 48,600 `untrusted_certificate` failures.

### run

```sh
tsa-bench run \
  --config configs/provider.yaml \
  --profile profiles/50k.yaml \
  --max-requests 48600 \
  --authorized-load-test \
  --acknowledge-live-environment
```

`--redact-host` masks the test host's name and the invoking command line in
`metadata.json`, for a report that will be published outside the organisation.

`--max-requests` and `--authorized-load-test` are always mandatory.
`--acknowledge-live-environment` is additionally mandatory when the
configuration declares `provider.environment: live`. There is no interactive
prompt, so the command works unattended in CI; the safety condition is carried
entirely by the flags.

The run banner — endpoint, target rate, duration and request ceiling — is
printed and written to `run.log` before the first request.

On `SIGINT`/`SIGTERM` the tool stops issuing immediately, lets in-flight
requests finish within `load.grace_period`, writes a partial report and exits
with status 130.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | completed |
| 1 | error (configuration, transport, verification setup) |
| 2 | usage error, including a missing safety flag |
| 3 | the run stopped itself because the endpoint was failing |
| 4 | the run finished but the per-request record on disk is incomplete |
| 130 | interrupted by a signal; a partial report was written |

### report

```sh
tsa-bench report --output results/ \
  results/Provider-A/20260314T090000Z-ab12 \
  results/Provider-B/20260314T100000Z-cd34 \
  results/Provider-C/20260314T110000Z-ef56
```

Produces `comparison.json`, `comparison.csv` and `comparison.html` with the
providers side by side.

### mock

```sh
tsa-bench mock --addr 127.0.0.1:8318 --write-ca /tmp/mock-ca.pem
```

Binds to loopback only; exposing it elsewhere requires `--bind-external`.
Development certificates are generated in memory.

**The mock does not represent any provider's performance.** Its latency is the
latency of a local signature. It exists to measure what this client can sustain
and to exercise the verification chain offline.

---

## Load model

The tool is an **open-loop, constant-arrival-rate** generator, not a concurrency
benchmark.

Request *n* is due at `start + n/rate`, regardless of when request *n-1*
finished. A closed-loop client ("keep N requests in flight") stops issuing while
the server is slow, so it never measures the latency its own backlog would have
seen — the *coordinated omission* problem, which systematically flatters a
struggling service. Here the schedule is absolute, and any inability to hold it
is reported as `schedule_lag` and `client_saturation` rather than being absorbed
into a quietly lower rate.

Two related guarantees:

- **No catch-up bursts.** When the client falls behind, releases are still
  spaced at least one interval apart, so a recovering client cannot dump its
  backlog onto a recovering TSA.
- **No hidden slowdown.** If the target rate cannot be held, the report says so
  and marks the result as a lower bound on the provider's capacity.

### Default profile (`profiles/50k.yaml`)

| Stage           | Rate    | Duration | Requests |
|-----------------|---------|----------|----------|
| `functional`    | serial  | —        | 100      |
| `ramp-25`       | 25 TPS  | 20 s     | 500      |
| `ramp-50`       | 50 TPS  | 20 s     | 1,000    |
| `ramp-100`      | 100 TPS | 20 s     | 2,000    |
| `sustained-150` | 150 TPS | 300 s    | 45,000   |
| **planned**     |         |          | **48,600** |
| reserve         |         |          | 1,400    |
| **total**       |         |          | **50,000** |

A successful run sends no more than 48,600 requests. The absolute protection
limit is 50,000, enforced by an atomic counter that is incremented only when an
attempt is actually handed to the HTTP transport. Every request is attempted
exactly once, so one unit of quota is always one physical attempt.

Stages are separated by `load.stage_pause`, which consumes no quota and lets the
provider's queues drain so the next stage measures the service rather than the
backlog of the previous one.

---

## Configuration

YAML with `${VAR}` interpolation for non-secret values.

**Secrets are never written in the file and never passed as command line
arguments** — the process table is readable by other users on the host. The
configuration names an environment variable; the value is read at use time and
never enters a printable structure. `validate` will tell you a variable is
missing without ever printing what is in it.

Start from `configs/*.example.yaml`, which contain placeholders only. Keep your
filled-in copy outside version control (`.gitignore` already excludes
`configs/*.yaml`).

Settings that matter most:

- `tls.tsa_ca_file` — the issuer chain of the TSA **signing certificate**. Set
  it. The system root store usually does not contain a qualified TSA's issuer.
- `tls.insecure_skip_verify` — defaults to `false`. Enabling it produces a loud
  warning and is recorded in the report.
- `provider.allow_plaintext` — defaults to `false`, which refuses an `http://`
  endpoint on any host but loopback. Set it only for a service that offers no
  TLS at all, reached over a private path; it warns loudly and is recorded in
  the report's limitations.
- `request.cert_req` — must stay `true`. Without the TSA certificate the
  signature cannot be checked against a trust chain.
- `limits.retries` — must be `0`. Retries are not implemented: a failed request
  is recorded as a failure and never re-sent.
- `limits.hard_cap` — the engagement quota, and the absolute ceiling enforced by
  the atomic counter at runtime. It varies per provider, so it is configured
  rather than compiled in; only an implausible value is rejected.
- `provider.auth.type` — `none`, `basic`, `digest`, `bearer`, `header` or
  `mtls`. Digest draws its challenge once before the run, so the load itself
  still costs one HTTP request per timestamp. A nonce that goes stale mid-run is
  re-answered.
- `provider.auth.challenge_per_request` — for a server that honours a nonce only
  once despite advertising `qop="auth"`. Each timestamp then draws its own
  challenge on its own session, so concurrent workers never invalidate each
  other. Extra authentication requests issue no timestamp and consume no quota;
  they are reported as `auth_requests` in `summary.json`.
- `limits.abort_on_error_rate` / `abort_on_consecutive_failures` — the run stops
  itself if the service is clearly failing, instead of burning the rest of the
  quota against a degraded endpoint. Disable with `--no-auto-abort` only for a
  deliberate reason.

---

## Output

```
results/<provider>/<UTC-timestamp>-<run-id>/
├── metadata.json    run environment, configuration (redacted), warnings
├── summary.json     all metrics, per stage and overall
├── requests.csv     one row per attempt, written as a stream
├── timeseries.csv   per-second throughput, errors and client resource use
├── errors.csv       failed attempts with their classification
├── run.log          structured JSON log
└── report.html      executive summary
```

Raw protocol bytes are written only with `--debug-artifacts`, into
`artifacts/` with `0600` permissions and an explicit warning on stderr.

**Write results to storage that no sync client touches.** `requests.csv` is held
open for the whole run and written in large buffered chunks. A folder-backup
client — Google Drive Desktop, Dropbox, OneDrive, iCloud Drive — will upload
such a file mid-write and then replace the local copy with its own version,
leaving an empty file behind. This was observed and reproduced with Google Drive
Desktop mirroring `~/Documents`: the file grew to 424 KB, and the moment the
handle closed the path pointed at a new, empty, 0600 file. Network filesystems
can behave the same way.

The aggregate metrics survive this, because they come from in-memory counters —
which is exactly what makes it dangerous. After each run the tool therefore
counts the rows in `requests.csv` against the quota consumed and **exits with
status 4** if they disagree, so a lost audit record cannot pass unnoticed. Keep
the working directory outside any synced folder, or point `--output` at a path
that is not synced.

### Error classes

`dns_error`, `connect_error`, `tls_error`, `request_timeout`,
`response_timeout`, `http_4xx`, `http_5xx`, `invalid_content_type`,
`tsp_rejection`, `invalid_nonce`, `invalid_imprint`, `invalid_signature`,
`untrusted_certificate`, `malformed_response`, `clock_skew_exceeded`,
`client_saturation`, `schedule_lag`, `quota_guard`, `cancelled`.

`tsp_rejection` is broken down by PKIStatus and `failInfo`
(`tsp_rejection.badAlg`, `.systemFailure`, …) so "our request is wrong" can be
told apart from "the TSA is overloaded". `http_4xx` and `http_5xx` carry the
status code as a sub-category.

### Percentile accuracy

Latencies are recorded into a fixed-size HDR-style histogram with three
significant figures: every reported percentile is the upper bound of a bucket at
most 1/2048 (about 0.05%) wide, and is never below a value that was actually
observed. Minimum, maximum and mean are exact. Memory use does not grow with the
number of requests.

---

## Verification chain

Applied in order; the first failure classifies the attempt.

1. HTTP status is 2xx
2. `Content-Type` is `application/timestamp-reply`
3. PKIStatus is `granted` or `grantedWithMods` (parsed directly, so `failInfo`
   survives as a sub-category)
4. The token parses as a TimeStampToken
5. The nonce matches the request
6. The message imprint algorithm and value match the request
7. The token carries the TSA certificate, the CMS signature verifies, and the
   ESS `SigningCertificateV2` attribute — when present — binds the actual signer
8. The certificate chains to a configured trust anchor, is valid at `genTime`,
   and carries `id-kp-timeStamping` as its only extended key usage, marked
   critical (RFC 3161 §2.3)
9. `genTime` lies within `request.max_clock_skew` of the request window

If a check cannot be performed, the attempt fails. There is no mode in which a
check is skipped and the transaction still counts as a success.

---

## Known limitations

- **The TSA CA bundle must be supplied by you.** The system root store often
  does not contain a qualified Turkish TSA's issuer.
- **ESS binding cannot be checked when the attribute is absent.** A TSA that
  emits no `SigningCertificate(V2)` produces a recorded warning, not a failure.
  Set `request.require_ess: true` to make its absence fatal once you have
  confirmed your provider emits it.
- **Revocation (CRL/OCSP) is not checked during a run.** Doing so would add
  network traffic that distorts the latency measurement. Check revocation
  separately, out of band.
- **The mock does not model provider performance.** It measures this client.
- **A live measurement is shared with real traffic.** Results describe the test
  window, not a guaranteed capacity, and are not exactly reproducible.
- **Resource metrics need a Unix host.** CPU and RSS come from `getrusage`; on
  other platforms they are reported as zero rather than guessed.

## Security

See [SECURITY.md](SECURITY.md), which covers secret handling, what is redacted,
and what to strip before publishing a results directory.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). In short: `make verify` must be green,
and no test or CI job may ever contact a real provider.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
