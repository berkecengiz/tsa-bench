---
name: Bug report
about: Something the tool did that it should not have
labels: bug
---

**Do not paste credentials, real endpoints, or an unredacted results
directory.** If you need to share output, run with `--redact-host` and remove
anything that identifies your provider.

## What happened

## What you expected

## How to reproduce

Ideally against the local mock:

```sh
make build && make demo
```

## Environment

- `tsa-bench version`:
- `go version`:
- OS / arch:

## Relevant output

Exit code, and the matching lines from `run.log` or `summary.json`.
