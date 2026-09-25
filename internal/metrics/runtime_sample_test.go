package metrics

import (
	"runtime"
	"testing"
	"time"
)

// TestReadRuntimeMetrics checks that the non-stop-the-world sampler reports a
// live heap and a GC pause total, and that the pause total is cumulative. It
// guards the switch away from runtime.ReadMemStats: a wrong metric name yields
// a zero Value of the wrong Kind and would otherwise silently report 0.
func TestReadRuntimeMetrics(t *testing.T) {
	r := NewResourceSampler(time.Now(), nil)

	runtime.GC()
	heap, pause := r.readRuntimeMetrics()
	if heap == 0 {
		t.Fatalf("heap bytes = 0, want the live heap (metric name %q wrong?)", metricHeapObjects)
	}
	if pause <= 0 {
		t.Fatalf("gc pause = %v after an explicit GC, want > 0 (metric name %q wrong?)", pause, metricGCPauses)
	}

	// Hold an allocation across the second GC so the heap reading cannot be
	// optimised away, and confirm the pause total only ever grows.
	ballast := make([]byte, 8<<20)
	runtime.GC()
	heap2, pause2 := r.readRuntimeMetrics()
	runtime.KeepAlive(ballast)

	if pause2 < pause {
		t.Errorf("gc pause total went backwards: %v then %v", pause, pause2)
	}
	if heap2 == 0 {
		t.Error("heap bytes = 0 on second read")
	}
}
