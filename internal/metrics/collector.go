package metrics

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/berkecengiz/tsa-bench/internal/errclass"
)

// Attempt is the record of one physical request attempt. Exactly one Attempt is
// produced per unit of quota consumed.
type Attempt struct {
	Stage string
	// Sequence is the global attempt number, starting at 1.
	Sequence int64
	// ScheduledAt is when the scheduler intended to start the request.
	ScheduledAt time.Time
	// StartedAt is when the request was actually handed to the transport.
	StartedAt time.Time
	// CompletedAt is when the response finished being verified.
	CompletedAt time.Time
	// ScheduleLag is StartedAt - ScheduledAt: the client's own delay.
	ScheduleLag time.Duration
	// Total is the end-to-end time including verification.
	Total time.Duration
	// Network is the HTTP round trip alone.
	Network time.Duration
	// Verify is the RFC 3161/CMS verification time alone.
	Verify time.Duration
	// HTTPStatus is 0 when no response was received.
	HTTPStatus int
	// Err is nil on a fully verified timestamp.
	Err *errclass.Error
	// ClockSkew is the observed genTime offset, when measurable.
	ClockSkew time.Duration
	// Warnings are non-fatal verification observations.
	Warnings []string
}

// Succeeded reports whether every acceptance check passed.
func (a Attempt) Succeeded() bool { return a.Err == nil }

// ErrorKey returns the report grouping key.
func (a Attempt) ErrorKey() string {
	if a.Err == nil {
		return string(errclass.OK)
	}
	return a.Err.Key()
}

// Second is one row of the per-second time series.
type Second struct {
	Second     int64   `json:"second"`
	Sent       int64   `json:"sent"`
	Completed  int64   `json:"completed"`
	Success    int64   `json:"success"`
	Failure    int64   `json:"failure"`
	Timeouts   int64   `json:"timeouts"`
	MeanMS     float64 `json:"mean_ms"`
	latencySum int64
}

// StageStats accumulates everything measured for one load stage.
type StageStats struct {
	Name      string
	TargetTPS float64
	Planned   int64
	Duration  time.Duration
	StartedAt time.Time
	EndedAt   time.Time

	Sent      atomic.Int64
	Completed atomic.Int64
	// firstSentAt/lastSentAt bracket the actual arrival window in Unix nanos.
	// The achieved rate must be measured over the span between the first and
	// last arrival: N requests at rate R span (N-1)/R seconds, not N/R, and
	// dividing by the wrong window makes every stage look 1-8% slow.
	firstSentAt atomic.Int64
	lastSentAt  atomic.Int64
	Success     atomic.Int64
	Failure     atomic.Int64
	Timeouts    atomic.Int64
	Saturated   atomic.Int64

	Total   *Histogram
	Network *Histogram
	Verify  *Histogram
	Lag     *Histogram

	mu     sync.Mutex
	errors map[string]int64
	// warnings counts non-fatal verification observations by text. A response
	// can verify and still say something about the provider worth reporting -
	// a non-DER encoding, for instance - and without this the observation
	// would exist only on the Attempt and never reach the report.
	warnings map[string]int64
}

// NewStageStats creates the accumulator for a stage.
func NewStageStats(name string, targetTPS float64, planned int64, duration time.Duration) *StageStats {
	return &StageStats{
		Name:      name,
		TargetTPS: targetTPS,
		Planned:   planned,
		Duration:  duration,
		Total:     NewHistogram(),
		Network:   NewHistogram(),
		Verify:    NewHistogram(),
		Lag:       NewHistogram(),
		errors:    map[string]int64{},
		warnings:  map[string]int64{},
	}
}

// SendWindow returns the first and last arrival times and how many arrived.
func (s *StageStats) SendWindow() (first, last time.Time, n int64) {
	f, l := s.firstSentAt.Load(), s.lastSentAt.Load()
	if f == 0 {
		return time.Time{}, time.Time{}, 0
	}
	return time.Unix(0, f), time.Unix(0, l), s.Sent.Load()
}

// AchievedTPS is the measured arrival rate over the actual send window.
func (s *StageStats) AchievedTPS() float64 {
	first, last, n := s.SendWindow()
	if n < 2 {
		return 0
	}
	span := last.Sub(first).Seconds()
	if span <= 0 {
		return 0
	}
	return float64(n-1) / span
}

// markSent records an arrival into the send window.
func (s *StageStats) markSent(at time.Time) {
	ns := at.UnixNano()
	s.firstSentAt.CompareAndSwap(0, ns)
	for {
		cur := s.lastSentAt.Load()
		if ns <= cur || s.lastSentAt.CompareAndSwap(cur, ns) {
			return
		}
	}
}

// Warnings returns a copy of the verification-warning distribution.
func (s *StageStats) Warnings() map[string]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int64, len(s.warnings))
	for k, v := range s.warnings {
		out[k] = v
	}
	return out
}

// recordOutcome files an attempt's error class and any warnings together, so
// the accumulator shared by every worker is locked once per attempt.
func (s *StageStats) recordOutcome(key string, warnings []string) {
	s.mu.Lock()
	s.errors[key]++
	for _, w := range warnings {
		s.warnings[w]++
	}
	s.mu.Unlock()
}

// Errors returns a copy of the error distribution.
func (s *StageStats) Errors() map[string]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int64, len(s.errors))
	for k, v := range s.errors {
		out[k] = v
	}
	return out
}

// Collector aggregates attempts across all stages and maintains the per-second
// series used by the report.
type Collector struct {
	startedAt time.Time

	mu      sync.Mutex
	stages  []*StageStats
	byName  map[string]*StageStats
	seconds map[int64]*Second

	overall *StageStats
}

// NewCollector creates a collector anchored at the run start time.
func NewCollector(startedAt time.Time) *Collector {
	return &Collector{
		startedAt: startedAt,
		byName:    map[string]*StageStats{},
		seconds:   map[int64]*Second{},
		overall:   NewStageStats("overall", 0, 0, 0),
	}
}

// Stage registers (or returns) the accumulator for a stage.
func (c *Collector) Stage(name string, targetTPS float64, planned int64, duration time.Duration) *StageStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s, ok := c.byName[name]; ok {
		return s
	}
	s := NewStageStats(name, targetTPS, planned, duration)
	c.byName[name] = s
	c.stages = append(c.stages, s)
	return s
}

// Stages returns the registered stages in declaration order.
func (c *Collector) Stages() []*StageStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*StageStats(nil), c.stages...)
}

// Overall returns the accumulator spanning every stage.
func (c *Collector) Overall() *StageStats { return c.overall }

// RecordSent counts an attempt at the moment it is handed to the transport.
// This is the same moment quota is consumed, so the two can be reconciled.
func (c *Collector) RecordSent(stage *StageStats, at time.Time) {
	stage.Sent.Add(1)
	stage.markSent(at)
	c.overall.Sent.Add(1)
	c.overall.markSent(at)

	c.mu.Lock()
	c.secondLocked(at).Sent++
	c.mu.Unlock()
}

// RecordSaturation counts a moment where the client could not keep up.
func (c *Collector) RecordSaturation(stage *StageStats) {
	stage.Saturated.Add(1)
	c.overall.Saturated.Add(1)
}

// Record files a completed attempt.
func (c *Collector) Record(stage *StageStats, a Attempt) {
	for _, s := range []*StageStats{stage, c.overall} {
		s.Completed.Add(1)
		s.Total.RecordDuration(a.Total)
		s.Network.RecordDuration(a.Network)
		s.Verify.RecordDuration(a.Verify)
		s.Lag.RecordDuration(a.ScheduleLag)
		s.recordOutcome(a.ErrorKey(), a.Warnings)
		if a.Succeeded() {
			s.Success.Add(1)
		} else {
			s.Failure.Add(1)
			if a.Err.Class == errclass.RequestTimeout || a.Err.Class == errclass.ResponseTimeout {
				s.Timeouts.Add(1)
			}
		}
	}

	c.mu.Lock()
	sec := c.secondLocked(a.CompletedAt)
	sec.Completed++
	sec.latencySum += int64(a.Total)
	if a.Succeeded() {
		sec.Success++
	} else {
		sec.Failure++
		if a.Err.Class == errclass.RequestTimeout || a.Err.Class == errclass.ResponseTimeout {
			sec.Timeouts++
		}
	}
	c.mu.Unlock()
}

func (c *Collector) secondLocked(at time.Time) *Second {
	idx := int64(at.Sub(c.startedAt) / time.Second)
	if idx < 0 {
		idx = 0
	}
	s, ok := c.seconds[idx]
	if !ok {
		s = &Second{Second: idx}
		c.seconds[idx] = s
	}
	return s
}

// TimeSeries returns the per-second rows in chronological order.
func (c *Collector) TimeSeries() []Second {
	c.mu.Lock()
	defer c.mu.Unlock()

	var maxIdx int64 = -1
	for idx := range c.seconds {
		if idx > maxIdx {
			maxIdx = idx
		}
	}
	out := make([]Second, 0, maxIdx+1)
	for i := int64(0); i <= maxIdx; i++ {
		s, ok := c.seconds[i]
		if !ok {
			out = append(out, Second{Second: i})
			continue
		}
		row := *s
		if row.Completed > 0 {
			row.MeanMS = float64(row.latencySum) / float64(row.Completed) / float64(time.Millisecond)
		}
		out = append(out, row)
	}
	return out
}
