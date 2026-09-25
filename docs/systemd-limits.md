# Running under systemd

`/etc/security/limits.conf` does **not** apply to systemd services. A unit that
inherits the default 1024 file descriptors will bottleneck at a few hundred
concurrent requests and the results will describe your service manager rather
than the timestamp provider.

## Unit file

`/etc/systemd/system/tsa-bench.service`:

```ini
[Unit]
Description=RFC 3161 timestamp capacity test
After=network-online.target chronyd.service
Wants=network-online.target

[Service]
Type=oneshot
User=tsabench
Group=tsabench
WorkingDirectory=/var/lib/tsa-bench

# Descriptor limit. Must exceed load.max_concurrency with headroom;
# limits.conf has no effect here.
LimitNOFILE=65536

# Do not let the OOM killer take the process mid-run: a kill loses in-flight
# requests whose quota has already been spent, and no report is written.
OOMScoreAdjust=-500

# Credentials come from a 0600 file owned by the service user, never from the
# command line and never from the unit file itself.
EnvironmentFile=/etc/tsa-bench/credentials.env

ExecStart=/usr/local/bin/tsa-bench run \
    --config /etc/tsa-bench/provider.yaml \
    --profile /etc/tsa-bench/50k.yaml \
    --max-requests 48600 \
    --authorized-load-test \
    --acknowledge-live-environment

# Graceful shutdown: SIGTERM stops new requests, and the timeout must exceed
# load.grace_period so in-flight work settles and a partial report is written.
KillSignal=SIGTERM
TimeoutStopSec=120

# Hardening. The tool needs outbound network and its results directory.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/tsa-bench
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
```

## Credentials file

`/etc/tsa-bench/credentials.env`, owned by the service user, mode `0600`:

```
TSA_USER=...
TSA_PASS=...
```

```sh
chown tsabench:tsabench /etc/tsa-bench/credentials.env
chmod 600 /etc/tsa-bench/credentials.env
```

`systemd-analyze security tsa-bench.service` will show the file is referenced
but will not print its contents; `systemctl show` does not expose
`EnvironmentFile` values either.

## Verifying the limits actually applied

```sh
systemctl show tsa-bench.service -p LimitNOFILE
# and while it runs:
cat /proc/$(pgrep -f 'tsa-bench run')/limits | grep 'open files'
```

If this shows 1024, the unit is not being used — check that you edited the unit
rather than a drop-in that is overridden, and `systemctl daemon-reload`.

## Timers

For a scheduled run, prefer a `systemd.timer` over cron: it inherits the unit's
limits and hardening. Cron jobs run with the default descriptor limit, which is
exactly the problem this document exists to avoid.

```ini
# /etc/systemd/system/tsa-bench.timer
[Unit]
Description=Scheduled timestamp capacity test

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=false

[Install]
WantedBy=timers.target
```

Only schedule a run inside a test window the provider has agreed to.
