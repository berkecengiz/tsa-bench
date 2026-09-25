# Linux host preparation

A load generator that runs out of file descriptors or ephemeral ports reports
the *provider* as slow. Work through this before the test window and confirm
each value, so a client-side limit is never mistaken for a capacity finding.

All of it applies to the account that runs `tsa-bench`.

## Checklist

```sh
# 1. File descriptors. Each in-flight connection needs one.
ulimit -n                       # want >= 65536, default is often 1024
ulimit -n 65536                 # for the current shell

# 2. Ephemeral ports. 150 TPS with short-lived connections can exhaust these.
sysctl net.ipv4.ip_local_port_range      # want something like 10000 65535
sysctl net.ipv4.tcp_fin_timeout          # want <= 30

# 3. Sockets stuck in TIME_WAIT.
ss -s
sysctl net.ipv4.tcp_tw_reuse             # want 1 for outbound connections

# 4. Connection backlog and queue sizes.
sysctl net.core.somaxconn                # want >= 1024
sysctl net.ipv4.tcp_max_syn_backlog      # want >= 4096

# 5. Conntrack, if a firewall or NAT is in the path.
sysctl net.netfilter.nf_conntrack_max    # want >> peak concurrent connections
conntrack -C                             # current count, if conntrack is loaded

# 6. Clock. genTime skew is measured against this.
chronyc tracking                         # or: timedatectl status

# 7. CPU governor, on bare metal.
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor   # want performance
```

## Suggested sysctl values

Put these in `/etc/sysctl.d/99-tsa-bench.conf` and apply with
`sysctl --system`. They are conservative and appropriate for a dedicated test
host; review them against your own baseline before applying to a shared machine.

```conf
# Ephemeral port range for outbound connections.
net.ipv4.ip_local_port_range = 10000 65535

# Reuse sockets in TIME_WAIT for new outbound connections.
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15

# Accept queues.
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 8192

# Socket buffers.
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216

# Conntrack, only if netfilter is in the path.
net.netfilter.nf_conntrack_max = 262144
```

Do **not** set `net.ipv4.tcp_tw_recycle`: it was removed in Linux 4.12 and broke
connections from behind NAT.

## File descriptor limits

The tool's default `load.max_concurrency` is 500, so the descriptor requirement
is roughly 500 plus overhead. The generous limits above leave room for
connection churn and keep a burst from hitting the ceiling.

For an interactive session, `/etc/security/limits.d/99-tsa-bench.conf`:

```
<user>  soft  nofile  65536
<user>  hard  nofile  65536
```

`limits.conf` does not apply to systemd services — see `docs/systemd-limits.md`.

## Connection pooling

The HTTP transport is sized to `load.max_concurrency` for both total and
per-host connections, and HTTP/2 is deliberately disabled. HTTP/2 multiplexes
many requests onto one connection, which makes per-request latency depend on
head-of-line blocking in our own client rather than on the TSA.

Keep-alive is on. Check `conns_open` and `conns_reused` in `timeseries.csv`: if
`conns_open` tracks the request rate rather than staying flat, connections are
not being reused and you are measuring TCP and TLS handshakes rather than the
timestamp service.

## Verifying the host is not the bottleneck

Before testing a provider, measure the client against the local mock:

```sh
tsa-bench mock --addr 127.0.0.1:8318 --write-ca /tmp/mock-ca.pem &
# point a config at http://127.0.0.1:8318/ with tsa_ca_file=/tmp/mock-ca.pem
tsa-bench run --config /tmp/mock.yaml --profile profiles/50k.yaml \
  --max-requests 48600 --authorized-load-test
```

The report must show **no client bottleneck** at 150 TPS. The test suite also
asserts that the client sustains 300 TPS against the mock
(`go test -run TestClientCapacity ./internal/load`), which is the headroom that
makes a 150 TPS measurement trustworthy.

If the mock run shows saturation, fix the host before going near a provider —
otherwise the engagement's quota is spent measuring your own machine.
