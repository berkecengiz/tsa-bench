package metrics_test

import (
	"math/rand"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/berkecengiz/tsa-bench/internal/metrics"
)

// TestHistogramPrecision checks the documented accuracy claim against an exact
// sorted-sample reference.
func TestHistogramPrecision(t *testing.T) {
	h := metrics.NewHistogram()
	rng := rand.New(rand.NewSource(1))

	const n = 200000
	exact := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		// A lognormal-ish spread from ~1ms to ~3s, similar to real TSA latency.
		v := time.Duration((1 + rng.ExpFloat64()*40) * float64(time.Millisecond))
		h.RecordDuration(v)
		exact = append(exact, float64(v))
	}
	sort.Float64s(exact)

	snap := h.Snapshot()
	if snap.Count != n {
		t.Fatalf("count = %d, want %d", snap.Count, n)
	}

	check := func(name string, q float64, got time.Duration) {
		t.Helper()
		want := exact[int(q*float64(n))-1]
		rel := (float64(got) - want) / want
		if rel < 0 || rel > 0.01 {
			t.Errorf("%s: got %v, exact %v, relative error %.4f (must be within [0, 1%%])",
				name, got, time.Duration(want), rel)
		}
	}
	check("p50", 0.50, snap.P50)
	check("p90", 0.90, snap.P90)
	check("p95", 0.95, snap.P95)
	check("p99", 0.99, snap.P99)

	if snap.Min > snap.P50 || snap.P50 > snap.P99 || snap.P99 > snap.Max {
		t.Errorf("percentiles are not monotonic: %+v", snap)
	}
}

func TestHistogramConcurrentRecording(t *testing.T) {
	h := metrics.NewHistogram()

	const workers, each = 64, 5000
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(seed)))
			for i := 0; i < each; i++ {
				h.RecordDuration(time.Duration(rng.Intn(1000000)) * time.Microsecond)
			}
		}(w)
	}
	wg.Wait()

	if got := h.Count(); got != workers*each {
		t.Errorf("count = %d, want %d", got, workers*each)
	}
}

func TestHistogramEmptyAndExtremes(t *testing.T) {
	h := metrics.NewHistogram()
	if snap := h.Snapshot(); snap.Count != 0 || snap.P99 != 0 {
		t.Errorf("empty snapshot = %+v", snap)
	}

	h.Record(0)
	h.RecordDuration(2 * time.Hour) // beyond the trackable range
	snap := h.Snapshot()
	if snap.Overflows != 1 {
		t.Errorf("overflows = %d, want 1", snap.Overflows)
	}
	if snap.Max < time.Duration(0) {
		t.Errorf("max = %v", snap.Max)
	}
}
