# Capacity findings

What three qualified RFC 3161 timestamp services actually did under load, and
how the measurements were arrived at.

The providers are **A**, **B** and **C**; their identities are not published.
All three were measured on the same day, from the same host, over the same
network path, using the profiles in `profiles/`. Absolute latencies therefore
include a residential link and are not a property of the services. **Compare
the shapes, not the numbers** — the shapes are the finding.

> Every figure below describes one test window against a live service shared
> with real traffic. It is a measurement, not a guaranteed capacity, and it is
> not exactly reproducible. See "Known limitations" in the README.

---

## Summary

| | Sustainable rate | Failure mode under overload |
|---|---|---|
| **Provider A** | 100 TPS | **congestion collapse** — delivers *less* as it is pushed harder |
| **Provider B** | 50 TPS (p95 < 1 s) | **latency-bound** — keeps delivering, each request just takes longer |
| **Provider C** | ≥ 150 TPS, ceiling not found | none observed |

Three services, three entirely different behaviours at the limit. Naming the
sustainable rate without naming the failure mode would have been useless for
capacity planning — a service that degrades gracefully and one that collapses
need very different client-side safety margins.

---

## Provider A — sustainable at 100/s, congestion collapse at 150/s

| Offered | Delivered | Latency | Verdict |
|---|---|---|---|
| 75/s | 75/s | p95 127 ms | healthy |
| 100/s | 100/s | ~85 ms, flat over five minutes, zero failures | **sustainable** |
| 105–125/s | target met | degrades 27–33 s into each step | marginal |
| 150/s | ~70/s | climbs to the 10 s timeout, collapses in 18 s | fails |

The five-minute hold at 100/s (`profiles/endurance.yaml`) is the load-bearing
measurement: 30,000 requests, no failures, and after a first-minute transient
of 334 ms the mean settles at 70–120 ms and stays there. Connections peak at
207 during the transient and fall to around 30. Nothing drifts.

Between 100 and 150 the service is **marginal rather than broken**. A rate
ladder in five-TPS steps (`profiles/ceiling-fine.yaml`) met every target from
105 to 125, but each step began to queue partway through — 33 seconds in at
105, 27 at 115 — so a forty-second window flatters these rates. There is no
cliff; there is a rate above which a queue starts growing and never stops.

At 150/s that growth is fast enough to be fatal. In-flight climbs from 3 to
1,241 in eighteen seconds, mean latency from 150 ms to 8.8 s, and delivered
throughput falls to roughly 70/s — **less than the service delivers cleanly at
100/s**. Offering more produces less, which is congestion collapse.

**It never sheds load.** Across every overload run: zero 429s, zero 503s. The
service accepts everything and answers what it can, leaving the rest to time
out. There is no backpressure signal, so a client has to impose its own limit.
Worse, quota is spent on requests that return nothing — in a 200/s overload run,
1,220 of 2,881 requests, **42 %, bought nothing at all**.

### Isolating *what* the ceiling is

Because `challenge_per_request` sends two HTTP requests per timestamp, 125
timestamps/s is 250 requests/s — which made plain request handling the obvious
suspect. `scripts/challenge-probe` rules it out without spending any quota, by
sending only the unauthenticated POSTs that draw a 401: same TLS, same servlet,
same session and nonce creation, no timestamp issued.

| Requests/s | p50 | p95 | Errors |
|---|---|---|---|
| 100 | 5.7 ms | 59.9 ms | 0 |
| 200 | 5.8 ms | 64.4 ms | 0 |
| 400 | 6.8 ms | 69.0 ms | 0 |

Flat at 400/s, well past where timestamps collapse. **The limit is in issuing
timestamps — signing, or whatever guards it — not in handling requests.** So
fixing the single-use nonce would halve their request volume and shave a few
milliseconds, but would not raise the ceiling.

### Encoding

Roughly one token in ten carries a non-DER `genTime`: 4,463 of 45,000 in a
sustained stage, 16 of 160 in a smoke run. See the encoding section of
[provider-onboarding.md](provider-onboarding.md).

---

## Provider B — latency-bound, no cliff to find

| Rate | p50 | p95 | p99 | Failures |
|---|---|---|---|---|
| ~0 (sequential) | 271.8 ms | 441.5 ms | 547.4 ms | 0 |
| 25/s | 367.5 ms | 703.1 ms | 800.1 ms | 0 |
| 50/s | 452.7 ms | 628.6 ms | 723.0 ms | 0 |
| 60/s | 738.7 ms | 1082.1 ms | 1175.5 ms | 0 |
| 70/s | 772.3 ms | 1562.4 ms | 1650.5 ms | 0 |
| 80/s | 777.5 ms | 1070.1 ms | 1146.1 ms | 0 |
| 100/s | 4848.6 ms | 10007.6 ms | 10007.6 ms | 1,260 |

**50 timestamps/s is the rate to plan against.** It held flat for three
minutes — 474, 472 and 433 ms by minute — with no failures and a p95 of 629 ms.

`client_bottleneck_observed` was false and `client_saturation_events` zero at
every step, with connections peaking at 39 against a pool of 2,500, so none of
this is the client.

Two properties distinguish this provider, and both matter more than the ceiling.

**The floor is high.** With a single request in flight the median is 272 ms,
against 35 ms for Provider A over the same link on the same day. That is not
load, it is the service's own speed, and it sets a lower bound no amount of
capacity planning removes.

**It is latency-bound, not throughput-bound.** Even at 100/s, where the median
reached 4.8 seconds and 5 % of requests timed out, it still delivered 94.7
timestamps/s. Offered load is met; what gives way is how long each one takes.
Provider A fails the other way, delivering less as it is pushed harder. So
there is no cliff here to find, and the rate depends entirely on the latency
budget:

| Requirement | Rate |
|---|---|
| No queueing at all (flat p50) | below 25/s |
| p95 under one second | **50/s** |
| No failures | up to 80/s, at a 1–1.6 s p95 |
| Throughput alone | ~95/s, at a 4.8 s median |

**Resolution is about ±10 TPS and no better.** p95 came out *higher* at 25/s
(703 ms) than at 50/s (629 ms), and higher at 70/s (1562 ms) than at 80/s
(1070 ms): the service varies by more than the gap between adjacent steps.
Repeatability across runs is good where it counts, though — 50/s measured
474/626 ms in one run and 453/629 ms in another.

---

## Provider C — flat to 150/s, ceiling not found

| Rate | p50 | p95 | p99 | Failures |
|---|---|---|---|---|
| ~0 (sequential) | 63.7 ms | 130.9 ms | 187.7 ms | 0 |
| 25/s | 72.6 ms | 148.4 ms | 184.0 ms | 0 |
| 50/s | 65.8 ms | 141.2 ms | 185.3 ms | 0 |
| 100/s, 4 min | 63.4 ms | 150.2 ms | 206.3 ms | 1 |
| 150/s, 2 min | 65.5 ms | 182.7 ms | 301.5 ms | 0 |

**The median does not move between an idle service and 150/s**, and nothing in
the run suggests a queue beginning to form. One failure in 43,600 requests, a
single timeout during the four-minute hold. `client_bottleneck_observed` false,
zero saturation events, connections peaked at 52 against a pool of 2,500 — the
client was never close to involved, so the flatness is the service's.

This is the only one of the three that took the 50k profile's 150 TPS target
without complaint. At that rate Provider A collapsed in eighteen seconds, and
Provider B was already past its limit at 100.

### The probe that ran out of allowance, not out of service

A 30-second probe at 200/s (`profiles/probe-200.yaml`) was tried with what
remained of the allowance. After the connection pool filled — latency climbed to
2.3 s while connections went 0 → 482, then fell back — the service settled at
roughly 80 ms with only 10 to 30 requests in flight and served 200/s
comfortably for eight seconds.

It stopped because **the account ran out, not because the service did**. Every
one of the 89 failures arrived in the final second as a protocol-level
rejection, and the `failInfo` text said exactly what had happened: the account
had been deactivated and the monthly request allowance exhausted.

Two things follow. The allowance appears to **reset monthly** rather than being
a single grant, so the ceiling can be measured properly in the next period. And
the account was left **inactive** with units still remaining on paper, which is
a question for the provider rather than a measurement.

**The two counters disagreed.** The tool believed 6,000 units remained, having
counted only what it sent itself; the provider cut the account off around
48,429. Confirm the provider's own figure before sizing any run — never the
client's.

### Encoding

**Correct**, which was not the expectation. `genTime` carries seven fractional
digits — the widest precision of the three — and a trailing zero there would be
non-minimal DER. At Provider A's rate of one in ten that should have appeared
around 4,400 times. It appeared **zero** times in 43,600 tokens.

---

## Two measurements that were wrong, and why

Both were initially read as provider behaviour when the **client** was partly
responsible. `MaxConnsPerHost` is set to `load.max_concurrency`, and
`detectBottleneck` does not look at the connection pool at all, so neither run
was flagged.

**The 50k profile at 150 TPS.** It reported 115 TPS achieved with p95 at 7.8 s.
It ran with `max_concurrency: 500` and sat pinned at 500 connections for the
whole stage — so the client could not offer 150/s at all; it offered 115. The
pool was acting as accidental backpressure, and the service limped through a
load it would otherwise have failed. Removing the limit did not improve
matters: at a true 150/s the service collapsed in eighteen seconds.
**A client-side concurrency limit protects this provider**, which is worth
knowing when sizing a real integration.

**An earlier ladder put a cliff at 125 TPS**, with a 5.3-second median and 401
timeouts. It ran with `max_concurrency: 1600` and reached 1,599 connections, so
requests were waiting on the client's own pool — and that wait is *inside* the
measured latency. Repeated with 4,000, the same 125 TPS step completed with 33
failures instead of 401. The cliff was ours.

**Rule:** give the pool several times the expected in-flight count — `rate ×
timeout` is the worst case — and check `conns_open` against it per stage.
`client_saturation_events: 0` does not cover this.

---

## Choosing a profile when the allowance is small

The standard `profiles/50k.yaml` puts 45,000 of its 48,600 requests into a
single sustained stage at the target rate. That is the right shape only when
you are reasonably confident the target is achievable.

With a 50,000-unit allowance and an unknown service, it is the wrong shape: if
the rate turns out to be wrong, the whole allowance buys one degraded
measurement and there is nothing left to repeat it with.

Use `profiles/oneshot.yaml` instead — **the rate most likely to succeed is
measured first and banked; the target rate is attempted last, where failing
costs only itself.**
