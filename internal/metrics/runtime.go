package metrics

import (
	"runtime"
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
}

// NewResourceSampler creates a sampler; call Start to begin collection.
func NewResourceSampler(startedAt time.Time, conns *ConnStats) *ResourceSampler {
	return &ResourceSampler{
		startedAt: startedAt,
		conns:     conns,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
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
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

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
		HeapMB:        float64(ms.HeapAlloc) / (1 << 20),
		RSSPeakMB:     peakResidentMemoryMB(),
		CPUPercent:    pct,
		GCPauseTotalM: float64(ms.PauseTotalNs) / float64(time.Millisecond),
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
