package load_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/berkecengiz/tsa-bench/internal/errclass"
	"github.com/berkecengiz/tsa-bench/internal/load"
)

// capacityResult is one measurement of the client against the local mock.
type capacityResult struct {
	achieved float64
	lagP99   time.Duration
	lagMax   time.Duration
	saturate int64
	verified int
	sent     int64
}

// TestClientCapacity300TPS establishes that the load generator itself can hold
// twice the engagement's target rate.
//
// This is a property of the *client*, measured against a local mock, and says
// nothing about any provider. Its purpose is to make the tool's own capacity a
// known quantity: if the client could only manage 160 TPS, a 150 TPS result
// against a real TSA would be meaningless.
func TestClientCapacity300TPS(t *testing.T) {
	// The test measures the machine it runs on, so it is only meaningful in
	// isolation. Under `go test ./...` the other packages compete for the same
	// cores and the result would describe that contention rather than the
	// client. It is therefore opt-in:
	//
	//	make capacity          (runs it alone, with -p 1)
	//	TSA_BENCH_CAPACITY=1 go test -run TestClientCapacity ./internal/load
	if os.Getenv("TSA_BENCH_CAPACITY") == "" {
		t.Skip("set TSA_BENCH_CAPACITY=1 to run the client capacity test (needs an idle machine); " +
			"`make capacity` does this")
	}
	if testing.Short() {
		t.Skip("capacity test skipped in short mode")
	}

	const targetTPS = 300.0

	// The race detector roughly halves throughput. Under it the test still
	// proves the client clears the 150 TPS engagement target with headroom;
	// the full 300 TPS assertion belongs to a normal build.
	minRate, maxLag := targetTPS*0.97, 50*time.Millisecond
	if raceEnabled {
		minRate, maxLag = 200, 500*time.Millisecond
	}

	// A single OS-level stall — power management, another process waking, a
	// thermal event — shows up as one ~200ms gap and drags a 4-second
	// measurement below the bar. That is a property of the host at that
	// instant, not of the client, so one retry is allowed. A client that
	// genuinely cannot hold the rate fails both attempts.
	const attempts = 2
	var last capacityResult
	for i := 1; i <= attempts; i++ {
		last = measureCapacity(t, targetTPS, 4*time.Second)
		t.Logf("attempt %d/%d: achieved %.1f TPS (target %.0f), lag p99 %v, max %v, saturation events %d",
			i, attempts, last.achieved, targetTPS, last.lagP99, last.lagMax, last.saturate)

		if int64(last.verified) != last.sent {
			t.Fatalf("%d of %d attempts verified; the client must not fail its own requests under load",
				last.verified, last.sent)
		}
		if last.achieved >= minRate && last.lagP99 <= maxLag {
			return
		}
		if i < attempts {
			t.Logf("below the bar; retrying once in case the host stalled")
			time.Sleep(time.Second)
		}
	}

	if last.achieved < minRate {
		t.Errorf("client sustained only %.1f TPS over %d attempts (minimum %.0f, target %.0f); "+
			"a 150 TPS measurement would not have adequate headroom",
			last.achieved, attempts, minRate, targetTPS)
	}
	if last.lagP99 > maxLag {
		t.Errorf("p99 schedule lag %v against a local mock over %d attempts; the client is the bottleneck",
			last.lagP99, attempts)
	}
}

func measureCapacity(t *testing.T, tps float64, d time.Duration) capacityResult {
	t.Helper()

	planned := int64(tps * d.Seconds())
	r := newRig(t, rigOptions{
		profile: rateProfile("capacity", tps, d),
		maxReq:  planned + 100,
	})
	r.cfg.Load.MaxConcurrency = 500

	outcome, err := r.runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if outcome.Reason != load.StopCompleted {
		t.Fatalf("run did not complete: %s (%s)", outcome.Reason, outcome.ReasonDetail)
	}

	overall := r.runner.Collector.Overall()
	lag := overall.Lag.Snapshot()

	return capacityResult{
		achieved: overall.AchievedTPS(),
		lagP99:   lag.P99,
		lagMax:   lag.Max,
		saturate: overall.Saturated.Load(),
		verified: r.sink.countsByClass()[errclass.OK],
		sent:     outcome.QuotaUsed,
	}
}
