package metrics

import (
	"math"
	"runtime"
	runtimemetrics "runtime/metrics"
	"sync"
	"sync/atomic"
	"time"
)

// ResourceSample is a per-second view of the test client's own resource use.
// It exists to answer the question every capacity test must answer: was the
// bottleneck the provider, or us?
//
// Every field is point-in-time except RSSPeakMB, which the OS only reports as
// a high-water mark; see peakResidentMemoryMB.
type ResourceSample struct {
	Second        int64   `json:"second"`
	Goroutines    int     `json:"goroutines"`
	HeapMB        float64 `json:"heap_mb"`
	RSSPeakMB     float64 `json:"rss_peak_mb"`
	CPUPercent    float64 `json:"cpu_percent"`
	InFlight      int64   `json:"in_flight"`
	ConnsOpen     int64   `json:"conns_open"`
	ConnsReused   int64   `json:"conns_reused"`
	GCPauseTotalM float64 `json:"gc_pause_total_ms"`
}

// ConnStats counts connection lifecycle events. Dialed and Closed are
// counted by the transport's dialer, which observes every teardown; Reused
// and InFlight come from httptrace and the runner.
type ConnStats struct {
	Dialed   atomic.Int64
	Reused   atomic.Int64
	Closed   atomic.Int64
	InFlight atomic.Int64
}

// Open returns the number of connections currently established.
func (c *ConnStats) Open() int64 { return c.Dialed.Load() - c.Closed.Load() }

// ResourceSampler polls process resource usage once per second.
type ResourceSampler struct {
	startedAt time.Time
	conns     *ConnStats

	mu      sync.Mutex
	samples []ResourceSample

	lastCPU  time.Duration
	lastWall time.Time
	stop     chan struct{}
	done     chan struct{}

	// metrics is the Read buffer, allocated once and reused every tick so the
	// sampler does not allocate in a process it is trying not to perturb. Only
	// the sampling goroutine touches it.
	metrics []runtimemetrics.Sample
}

// NewResourceSampler creates a sampler; call Start to begin collection.
func NewResourceSampler(startedAt time.Time, conns *ConnStats) *ResourceSampler {
	return &ResourceSampler{
		startedAt: startedAt,
		conns:     conns,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
		metrics: []runtimemetrics.Sample{
			{Name: metricHeapObjects},
			{Name: metricGCPauses},
		},
	}
}

// Start begins sampling at a one-second cadence.
func (r *ResourceSampler) Start() {
	r.lastWall = time.Now()
	r.lastCPU = processCPUTime()

	go func() {
		defer close(r.done)
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-r.stop:
				r.sample()
				return
			case <-t.C:
				r.sample()
			}
		}
	}()
}

// Stop halts sampling and waits for the final sample.
func (r *ResourceSampler) Stop() {
	select {
	case <-r.stop:
	default:
		close(r.stop)
	}
	<-r.done
}

// Samples returns everything collected so far.
func (r *ResourceSampler) Samples() []ResourceSample {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ResourceSample(nil), r.samples...)
}

func (r *ResourceSampler) sample() {
	heapBytes, gcPause := r.readRuntimeMetrics()

	now := time.Now()
	cpu := processCPUTime()

	var pct float64
	if wall := now.Sub(r.lastWall); wall > 0 {
		pct = float64(cpu-r.lastCPU) / float64(wall) * 100
	}
	r.lastWall, r.lastCPU = now, cpu

	s := ResourceSample{
		Second:        int64(now.Sub(r.startedAt) / time.Second),
		Goroutines:    runtime.NumGoroutine(),
		HeapMB:        float64(heapBytes) / (1 << 20),
		RSSPeakMB:     peakResidentMemoryMB(),
		CPUPercent:    pct,
		GCPauseTotalM: float64(gcPause) / float64(time.Millisecond),
	}
	if r.conns != nil {
		s.InFlight = r.conns.InFlight.Load()
		s.ConnsOpen = r.conns.Open()
		s.ConnsReused = r.conns.Reused.Load()
	}

	r.mu.Lock()
	r.samples = append(r.samples, s)
	r.mu.Unlock()
}

// Peak summarises the worst observed values, which is what the report needs to
// state whether the client saturated.
type Peak struct {
	MaxGoroutines int     `json:"max_goroutines"`
	MaxRSSMB      float64 `json:"max_rss_mb"`
	MaxCPUPercent float64 `json:"max_cpu_percent"`
	MaxInFlight   int64   `json:"max_in_flight"`
	MaxConnsOpen  int64   `json:"max_conns_open"`
}

// Peak computes the maxima across all samples.
func (r *ResourceSampler) Peak() Peak {
	var p Peak
	for _, s := range r.Samples() {
		if s.Goroutines > p.MaxGoroutines {
			p.MaxGoroutines = s.Goroutines
		}
		if s.RSSPeakMB > p.MaxRSSMB {
			p.MaxRSSMB = s.RSSPeakMB
		}
		if s.CPUPercent > p.MaxCPUPercent {
			p.MaxCPUPercent = s.CPUPercent
		}
		if s.InFlight > p.MaxInFlight {
			p.MaxInFlight = s.InFlight
		}
		if s.ConnsOpen > p.MaxConnsOpen {
			p.MaxConnsOpen = s.ConnsOpen
		}
	}
	return p
}

// Metric names read every second. They are deliberately the only ones sampled:
// runtime/metrics.Read costs time proportional to the slice it is given.
const (
	metricHeapObjects = "/memory/classes/heap/objects:bytes"
	metricGCPauses    = "/sched/pauses/total/gc:seconds"
)

// readRuntimeMetrics returns live heap bytes and cumulative GC stop-the-world
// time. It deliberately avoids runtime.ReadMemStats, which stops the world on
// every call: sampling once a second inside the process whose tail latency is
// being measured would put the tool's own pauses into the p99 it reports.
//
// The pause total is summed from a histogram, so it is accurate to the width of
// the runtime's pause buckets rather than exact. It is a diagnostic for "was
// the client the bottleneck", and bucket error is far below the threshold at
// which that answer changes.
func (r *ResourceSampler) readRuntimeMetrics() (heapBytes uint64, gcPause time.Duration) {
	r.metrics[0].Value = runtimemetrics.Value{}
	r.metrics[1].Value = runtimemetrics.Value{}
	runtimemetrics.Read(r.metrics)

	if r.metrics[0].Value.Kind() == runtimemetrics.KindUint64 {
		heapBytes = r.metrics[0].Value.Uint64()
	}
	if r.metrics[1].Value.Kind() == runtimemetrics.KindFloat64Histogram {
		gcPause = histogramTotal(r.metrics[1].Value.Float64Histogram())
	}
	return heapBytes, gcPause
}

// histogramTotal estimates the sum of every observation in a runtime/metrics
// histogram by charging each bucket its midpoint. Buckets is one longer than
// Counts and its ends may be infinite; an infinite edge is folded onto its
// finite neighbour so an outlier cannot contribute an infinite total.
func histogramTotal(h *runtimemetrics.Float64Histogram) time.Duration {
	if h == nil {
		return 0
	}
	total := 0.0
	for i, count := range h.Counts {
		if count == 0 {
			continue
		}
		lo, hi := h.Buckets[i], h.Buckets[i+1]
		switch {
		case math.IsInf(lo, -1) && math.IsInf(hi, 1):
			continue
		case math.IsInf(lo, -1):
			lo = hi
		case math.IsInf(hi, 1):
			hi = lo
		}
		total += float64(count) * (lo + hi) / 2
	}
	return time.Duration(total * float64(time.Second))
}
