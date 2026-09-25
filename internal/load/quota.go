package load

import (
	"errors"
	"sync/atomic"
)

// ErrQuotaExhausted is returned when the hard cap has been reached.
var ErrQuotaExhausted = errors.New("quota guard: request budget exhausted")

// Quota is the atomic budget of physical request attempts.
//
// This is the single most safety-critical object in the tool. Against a live
// TSA, every unit it hands out is irreversibly consumed from the provider's
// allowance, so the counter must be exact under concurrency: no double issue,
// no issue past the cap, and no issue after the budget closes.
//
// A unit is taken *before* the request is handed to the transport, and is never
// returned. A request that fails after being sent still consumed provider-side
// budget, and pretending otherwise would let a failing run overshoot.
type Quota struct {
	// budget is the number of attempts this run may make.
	budget int64
	// hardCap is the absolute engagement limit; budget may never exceed it.
	hardCap int64
	used    atomic.Int64
	closed  atomic.Bool
}

// NewQuota creates a budget. budget is clamped to hardCap.
func NewQuota(budget, hardCap int64) *Quota {
	if hardCap > 0 && budget > hardCap {
		budget = hardCap
	}
	return &Quota{budget: budget, hardCap: hardCap}
}

// Budget returns the number of attempts this run may make.
func (q *Quota) Budget() int64 { return q.budget }

// HardCap returns the absolute protection limit.
func (q *Quota) HardCap() int64 { return q.hardCap }

// Used returns how many attempts have been issued.
func (q *Quota) Used() int64 { return q.used.Load() }

// Remaining returns the unissued budget.
func (q *Quota) Remaining() int64 {
	r := q.budget - q.used.Load()
	if r < 0 {
		return 0
	}
	return r
}

// Close stops further issuance, e.g. on shutdown or auto-abort.
func (q *Quota) Close() { q.closed.Store(true) }

// Closed reports whether issuance has been stopped.
func (q *Quota) Closed() bool { return q.closed.Load() }

// Acquire reserves exactly one attempt. It returns the 1-based sequence number
// of the reserved attempt, or ErrQuotaExhausted.
//
// The compare-and-swap loop is what makes the guarantee hold: two goroutines
// racing at the boundary cannot both observe the last unit as available.
func (q *Quota) Acquire() (int64, error) {
	if q.closed.Load() {
		return 0, ErrQuotaExhausted
	}
	for {
		cur := q.used.Load()
		if cur >= q.budget {
			return 0, ErrQuotaExhausted
		}
		if q.hardCap > 0 && cur >= q.hardCap {
			return 0, ErrQuotaExhausted
		}
		if q.used.CompareAndSwap(cur, cur+1) {
			return cur + 1, nil
		}
	}
}
