# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-09-25

First public release.

### Added

- `validate`, `doctor`, `run`, `report` and `mock` commands.
- Open-loop, constant-arrival-rate load generator with explicit `schedule_lag`
  and `client_saturation` reporting, so a client that cannot hold its schedule
  says so instead of quietly measuring a lower rate.
- Full RFC 3161 acceptance chain: status, content type, PKIStatus, nonce,
  message imprint, CMS signature, certificate chain, critical and exclusive
  `id-kp-timeStamping` EKU, ESS `SigningCertificateV2` binding, and `genTime`
  skew. An HTTP 200 is never counted as a success.
- Atomic quota counter with a configurable `hard_cap`, plus a post-run row
  count against consumed quota that exits 4 if the audit record on disk is
  incomplete.
- Auth types `none`, `basic`, `digest`, `bearer`, `header` and `mtls`, with
  `challenge_per_request` for servers that honour a digest nonce only once.
- HDR-style latency histogram: three significant figures, memory independent of
  request count.
- JSON, CSV and HTML reports, and a comparison report across runs.
- Local mock RFC 3161 responder, bound to loopback unless explicitly opted out.
- `run --redact-host`, which masks the test host name, the invoking command
  line and local file paths so a results directory can be published.
- `make demo` and a committed sample result set in `examples/sample-run/`.
- Apache-2.0 license, CI, and release workflow.

[Unreleased]: https://github.com/berkecengiz/tsa-bench/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/berkecengiz/tsa-bench/releases/tag/v0.1.0
