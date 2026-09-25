# Run-day runbook

## Before the window

1. `make verify` — the full gate must be green on the host you will test from.
2. `tsa-bench validate --config <cfg> --profile profiles/50k.yaml` for each
   provider. No network traffic; do this well before the window.
3. Confirm NTP: `chronyc tracking` (offset well under a second) or
   `timedatectl status`. genTime skew is measured against this clock.
4. Apply the host limits in `docs/linux-tuning.md` and confirm with
   `ulimit -n` and `ss -s`.
5. Start independent resource monitoring (CPU, memory, network) so a client
   bottleneck is visible without relying on the tool's own view.
6. Export credentials into the environment. Never onto the command line.
7. Choose a results location that **no sync client touches**. A folder-backup
   client (Google Drive Desktop, Dropbox, OneDrive, iCloud Drive) will upload
   `requests.csv` while it is still open and then replace the local copy with
   its own, leaving an empty file; network filesystems can do the same. Verify
   with `tsa-bench run` against the local mock before the window, and pass
   `--output` to an unsynced path if the working directory is covered. The tool
   checks the row count after every run and exits 4 if the record is
   incomplete.

## Immediately before each provider

```sh
tsa-bench doctor --config configs/<provider>.yaml --send-one
```

This costs one unit of quota and must pass completely. If it reports
`untrusted_certificate`, fix `tls.tsa_ca_file` before going further — running
the full profile with a wrong trust anchor wastes 48,600 units.

Tell the provider contact you are starting.

## The run

```sh
tsa-bench run \
  --config configs/<provider>.yaml \
  --profile profiles/50k.yaml \
  --max-requests 48600 \
  --authorized-load-test \
  --acknowledge-live-environment
```

Expected wall-clock time: about 6 minutes of traffic plus the stage pauses
(4 × `load.stage_pause`, 30 s each by default) — roughly 8 minutes.

Watch the stage lines in the log. The two numbers that matter live are
`actual_send_tps` against the target, and the growing failure count.

## Stopping early

`Ctrl-C` once. The tool stops issuing immediately, lets in-flight requests
finish within the grace period, writes a complete partial report and exits 130.
Do not send a second signal: that would abandon in-flight requests whose quota
has already been spent, and the report would understate consumption.

Tell the provider contact you have stopped.

Exit code 4 means the run itself was fine but the per-request record on disk is
incomplete — almost always a sync client replacing the file, see the results
location note above. `summary.json` is still correct; rerun with `--output`
pointing at an unsynced path if you need the row-level record.

The run may also stop itself (exit code 3) if the failure rate crosses
`limits.abort_on_error_rate` or `abort_on_consecutive_failures`. That is a
signal to talk to the provider before spending more quota, not to rerun.

## Between providers

Wait for the queues to settle — a few minutes is usually enough — and never run
two providers at once. Testing concurrently makes the test host a shared
bottleneck and invalidates both results.

## After all providers

```sh
tsa-bench report --output results/ \
  results/<A>/<run> results/<B>/<run> results/<C>/<run>
```

## Reading the results

Start with `report.html`, in this order:

**1. Was the client the bottleneck?** If yes, every number below it is a lower
bound on that provider's capacity, not a measurement of it. Fix the client and
rerun before comparing providers. The usual causes are file descriptor limits,
an exhausted ephemeral port range, or CPU saturation — see
`docs/linux-tuning.md`.

**2. Achieved rate against target.** A stage that sent materially below its
target means the client could not hold the schedule; check `schedule_lag` and
`client_saturation` in the same row.

**3. Success rate.** This is stricter than HTTP availability: it requires the
full acceptance chain. A high rate of HTTP 200 with a low success rate points at
a verification problem, and the error class says which.

**4. The error distribution.** What each class is telling you:

| Class | Usually means |
|---|---|
| `untrusted_certificate` | wrong or missing `tls.tsa_ca_file`, or a certificate that is not a valid timestamping certificate. Check `doctor --send-one` first. |
| `tsp_rejection.systemFailure` | the TSA is overloaded or degraded — a capacity finding |
| `tsp_rejection.badAlg` / `.badRequest` | our request is wrong; a configuration problem, not a capacity finding |
| `response_timeout` | the TSA accepted the request but did not answer in time — a capacity finding |
| `request_timeout` / `connect_error` | the connection could not be established; may be the network path rather than the TSA |
| `http_4xx.429` | provider-side rate limiting: you are above what they will serve |
| `http_5xx` | provider-side failure |
| `invalid_nonce` / `invalid_imprint` | the TSA returned a token that does not match the request — serious, report it to the provider |
| `clock_skew_exceeded` | check NTP on the test host before blaming the TSA |
| `client_saturation` / `schedule_lag` | our problem, not theirs |
| `quota_guard` | the run hit its budget; the measurement is truncated |

**5. Latency.** Compare p95 and p99, not the mean: the mean hides the tail that
users actually notice. `latency_network` against `latency_verification` shows
how much of the end-to-end figure is the provider and how much is our own
cryptographic verification.

**6. What it does not prove.** The run measured a bounded window at a fixed
rate against a service shared with real traffic. It is evidence about that
window, not a capacity guarantee.

## Archiving

Keep the whole result directory: `summary.json` is the machine-readable record
and `requests.csv` allows any figure in the report to be recomputed. If
`--debug-artifacts` was used, treat the directory as sensitive.
