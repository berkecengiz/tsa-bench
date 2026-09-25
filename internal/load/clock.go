// Package load implements the open-loop, constant-arrival-rate engine.
//
// This is deliberately not a concurrency benchmark. A concurrency benchmark
// ("keep N requests in flight") lets the client slow down when the server slows
// down, which hides exactly the degradation a capacity test is looking for —
// the coordinated omission problem. Here, request n is due at start + n/rate
// regardless of how long request n-1 took, and any inability to hold that pace
// is recorded as schedule lag or client saturation instead of being silently
// absorbed.
package load

import (
	"context"
	"sync"
	"time"
)

// Clock abstracts time so scheduler behaviour can be tested without sleeping.
//
// All scheduling decisions use a monotonic reading (Since), never wall-clock
// arithmetic, so an NTP step during a run cannot distort the arrival rate.
type Clock interface {
	// Now returns the current time.
	Now() time.Time
	// Since returns monotonic elapsed time from t.
	Since(t time.Time) time.Duration
	// SleepUntil blocks until the deadline or ctx is done. It returns ctx.Err()
	// if the context finished first.
	SleepUntil(ctx context.Context, deadline time.Time) error
	// Sleep blocks for d or until ctx is done.
	Sleep(ctx context.Context, d time.Duration) error
}

// RealClock is the production clock.
type RealClock struct{}

func (RealClock) Now() time.Time                  { return time.Now() }
func (RealClock) Since(t time.Time) time.Duration { return time.Since(t) }
func (c RealClock) Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c RealClock) SleepUntil(ctx context.Context, deadline time.Time) error {
	return c.Sleep(ctx, time.Until(deadline))
}

// FakeClock is a virtual clock for tests.
//
// In auto-advance mode every sleep jumps straight to its deadline, so a
// simulated five-minute stage runs instantly while still exercising the exact
// arithmetic the real scheduler performs.
type FakeClock struct {
	mu          sync.Mutex
	now         time.Time
	autoAdvance bool
	overshoot   time.Duration
	// Slept records every sleep duration, so tests can assert on pacing.
	Slept []time.Duration
}

// NewFakeClock returns a clock starting at t.
func NewFakeClock(t time.Time, autoAdvance bool) *FakeClock {
	return &FakeClock{now: t, autoAdvance: autoAdvance}
}

// SetOvershoot makes every auto-advanced sleep wake late by d, which is what a
// real timer does. Modelling this is what makes a scheduler drift test
// meaningful: a clock that wakes exactly on time hides every pacing bug that
// depends on lateness.
func (f *FakeClock) SetOvershoot(d time.Duration) {
	f.mu.Lock()
	f.overshoot = d
	f.mu.Unlock()
}

func (f *FakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *FakeClock) Since(t time.Time) time.Duration {
	return f.Now().Sub(t)
}

// Advance moves the virtual clock forward.
func (f *FakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

func (f *FakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	f.Slept = append(f.Slept, d)
	if f.autoAdvance && d > 0 {
		f.now = f.now.Add(d + f.overshoot)
	}
	f.mu.Unlock()
	return nil
}

func (f *FakeClock) SleepUntil(ctx context.Context, deadline time.Time) error {
	return f.Sleep(ctx, deadline.Sub(f.Now()))
}

// Sleeps returns a copy of the recorded sleep durations.
func (f *FakeClock) Sleeps() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Duration(nil), f.Slept...)
}
