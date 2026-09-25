# Security

## Handling of secrets

**Secrets are never accepted as command line arguments.** There is no
`--password` or `--token` flag, and there will not be one: the process table is
readable by other users on the host, and arguments end up in shell history and
process supervisors.

Credentials are supplied in one of two ways:

1. **Environment variables**, named by the configuration (`username_env`,
   `password_env`, `token_env`, or `env:NAME` for a custom header).
2. **A file with restricted permissions**, read into an environment variable by
   the operator's own tooling before the run.

The value is read at the moment it is used. It is never stored in the parsed
configuration, never serialised, and the credential struct overrides `String`
and `GoString` so an accidental `%v` in a log statement cannot print it.

A configuration that embeds a literal secret in an auth header is **rejected**,
because such a file would end up in version control.

## What is redacted

| Item | Treatment |
|---|---|
| `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `API-Key`, `X-Auth-Token` | replaced entirely; no prefix or suffix survives |
| Custom auth headers from the configuration | replaced entirely |
| URL userinfo (`https://user:pass@host/`) | replaced with a mask |
| URL query strings | replaced with a mask |
| Environment variable values | never printed; only the variable name |
| Test host name and invoking command line | recorded by default as run provenance; suppressed by `run --redact-host` |

Redaction is applied to log lines, error details, `metadata.json`, CSV output
and the HTML report. Transport errors are redacted specifically because
`net/http` quotes the full request URL — credentials included — in its error
messages.

An endpoint that embeds credentials in the URL is rejected at validation time.

**The endpoint host itself is deliberately not masked.** `endpoint_redacted` in
`metadata.json` means the endpoint with its credentials removed, not the
endpoint hidden: a measurement that does not say what was measured is not a
measurement. If the target's identity is itself confidential, that is a matter
for how you handle the results directory — see the publishing note below.

## Publishing a result

A results directory records the endpoint, the test host's name and the command
line that produced it. All three are intentional — they are what makes a
capacity figure attributable and comparable — and all three may be more than
you want to hand to a third party.

Run with `--redact-host` when the report will be published outside the
organisation; it replaces the host name and command line with a mask while
leaving every measurement intact. The endpoint stays, so redact or anonymise
the provider name in the configuration if that is also confidential.

## Transport security

- TLS 1.2 is the default minimum; 1.3 is configurable.
- `tls.insecure_skip_verify` defaults to `false`. Enabling it produces a
  prominent warning on stderr, a warning entry in `metadata.json`, a badge on
  the HTML report and an explicit limitation in the report text. The
  measurement cannot be attributed to a verified endpoint, and the report says
  so.
- HTTP redirects are **not followed**. A redirect would move the load to another
  host and could forward the `Authorization` header there.
- Plaintext `http://` endpoints are rejected except on loopback, where the local
  mock runs.
- mTLS is supported through `tls.client_cert_file` and `tls.client_key_file`.

## Quota safety

Quota consumed against a live provider is irreversible, so the counter is
treated as safety-critical:

- Issuance goes through an atomic compare-and-swap; two goroutines racing at the
  boundary cannot both take the last unit. This is covered by a race test with
  200 concurrent goroutines.
- A unit is taken **before** the request reaches the transport, and is never
  returned. A request that fails after being sent still consumed provider-side
  budget.
- Every request is attempted exactly once; retries are not implemented.
- A plaintext `http://` endpoint is refused unless `provider.allow_plaintext`
  is set. That opt-in warns on every run and is written into the report's
  limitations, so credentials sent in the clear are never sent silently.
- Digest authentication may send one extra HTTP request when a nonce goes
  stale. It carries no timestamp request, so nothing is issued and no quota is
  consumed; the count is reported as `reauth_requests`.
- `limits.hard_cap` is an absolute ceiling that `--max-requests` cannot exceed,
  and validation refuses a cap above the engagement quota.
- The run stops itself when the endpoint is clearly failing, rather than
  spending the remaining budget on a degraded service.

## Debug artifacts

Raw RFC 3161 requests and responses are written **only** with
`--debug-artifacts`. When enabled:

- files are created with `0600` permissions in `<run-dir>/artifacts/`;
- an explicit warning is printed to stderr;
- the number of stored attempts is capped (`--debug-artifact-limit`).

Artifacts contain the data submitted for timestamping and the TSA's signatures
over it. Do not share a results directory that contains them.

File permissions elsewhere: result directories are `0700`; `requests.csv`,
`errors.csv`, `timeseries.csv`, the JSON documents and `run.log` are `0644`.

## No default endpoint

The tool contacts nothing that has not been configured. There is no built-in
endpoint for any provider, and the repository contains no real endpoint and no
real credential. `configs/*.example.yaml` hold placeholders only, and
`.gitignore` excludes `configs/*.yaml`, `*.pem`, `*.key` and `.env`.

## Authorisation gates

`run` refuses to start without:

- `--max-requests` — an explicit bound on quota consumption;
- `--authorized-load-test` — an assertion that written authorisation exists;
- `--acknowledge-live-environment` — additionally, when the configuration
  declares `provider.environment: live`.

These are flags rather than an interactive prompt so the tool works unattended
in CI. They are recorded in `metadata.json` via the command line, so a report
shows under what assertion the run was made.

The `mock` command binds to loopback only unless `--bind-external` is passed; a
mock TSA on a routable interface would hand out timestamps signed by a
throwaway key to anyone who can reach it.

## Verification integrity

The tool never reports an unverified response as a success. If a check cannot be
performed — no TSA certificate in the response, no trust anchor configured — the
attempt is classified as a failure rather than passed. `NewVerifier` refuses to
construct without trust anchors, so a run cannot start in a state where success
could not be established.

## Reporting a vulnerability

Report security issues privately to the repository owner rather than through a
public issue. Include the version (`tsa-bench version`) and a minimal
reproduction. Do not include real credentials or real endpoints in the report.
