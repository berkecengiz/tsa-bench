package load

import (
	"fmt"
	"sync"
)

// Breaker stops a run that is going badly.
//
// Against a live TSA this is a courtesy to the provider as much as a protection
// for the operator: continuing to push 150 TPS at a service that is already
// failing three quarters of the requests helps nobody and burns the remaining
// quota for nothing.
type Breaker struct {
	// ErrorRate is the failure fraction (0..1) that trips the breaker.
	ErrorRate float64
	// Window is the number of recent outcomes the rate is measured over.
	Window int
	// ConsecutiveFailures trips the breaker regardless of the rate.
	ConsecutiveFailures int

	mu          sync.Mutex
	recent      []bool // true = failure
	pos         int
	filled      int
	failures    int
	consecutive int
	tripped     bool
	reason      string
}

// NewBreaker builds a breaker. A zero ErrorRate and zero ConsecutiveFailures
// disable it entirely.
func NewBreaker(errorRate float64, window, consecutive int) *Breaker {
	if window < 1 {
		window = 1
	}
	return &Breaker{
		ErrorRate:           errorRate,
		Window:              window,
		ConsecutiveFailures: consecutive,
		recent:              make([]bool, window),
	}
}

// Disabled reports whether the breaker can never trip.
func (b *Breaker) Disabled() bool {
	return b.ErrorRate <= 0 && b.ConsecutiveFailures <= 0
}

// Record files one outcome and reports whether the breaker has now tripped.
func (b *Breaker) Record(failed bool) bool {
	if b.Disabled() {
		return false
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tripped {
		return true
	}

	if b.filled == b.Window && b.recent[b.pos] {
		b.failures--
	}
	b.recent[b.pos] = failed
	b.pos = (b.pos + 1) % b.Window
	if b.filled < b.Window {
		b.filled++
	}
	if failed {
		b.failures++
		b.consecutive++
	} else {
		b.consecutive = 0
	}

	switch {
	case b.ConsecutiveFailures > 0 && b.consecutive >= b.ConsecutiveFailures:
		b.tripped = true
		b.reason = fmt.Sprintf("%d consecutive failures", b.consecutive)
	case b.ErrorRate > 0 && b.filled == b.Window &&
		float64(b.failures)/float64(b.filled) >= b.ErrorRate:
		b.tripped = true
		b.reason = fmt.Sprintf("error rate %.1f%% over the last %d attempts exceeded the %.1f%% limit",
			float64(b.failures)/float64(b.filled)*100, b.filled, b.ErrorRate*100)
	}
	return b.tripped
}

// Tripped reports whether the breaker has fired.
func (b *Breaker) Tripped() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tripped
}

// Reason explains why the breaker fired.
func (b *Breaker) Reason() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reason
}
