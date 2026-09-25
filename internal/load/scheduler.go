package load

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Tick describes one scheduled request slot.
type Tick struct {
	// Sequence is the 1-based index within the stage.
	Sequence int64
	// Scheduled is the ideal arrival time derived from the target rate.
	Scheduled time.Time
	// Actual is when the slot was actually released.
	Actual time.Time
	// Lag is Actual - Scheduled, clamped at zero. It is the honest measure of
	// how far the client fell behind its own plan.
	Lag time.Duration
}

// catchUpFactor bounds how fast a backlog may drain, as a multiple of the
// target rate.
//
// The value is a compromise between two failure modes. Releasing a backlog at
// full speed would hit a recovering TSA with a burst far above the agreed rate.
// Refusing to exceed the target rate at all is worse in a subtler way: a
// scheduler whose maximum release rate equals its target can never recover from
// being late, because every wake-up costs a little more than the interval. Lag
// then ratchets upward for the rest of the run and the achieved rate settles
// permanently below target — the client reporting itself as the bottleneck
// while sitting at 12% CPU.
//
// Draining at twice the target is still a hard rate cap, well short of a burst,
// and it lets a transient stall be absorbed instead of becoming permanent.
const catchUpFactor = 2

// Scheduler releases request slots at a constant arrival rate.
type Scheduler struct {
	// Rate is the target arrivals per second. Must be > 0.
	Rate float64
	// Clock is the time source; RealClock in production.
	Clock Clock
	// LagThreshold is the lag above which a tick is flagged as saturated.
	LagThreshold time.Duration
}

// Interval returns the nominal spacing between arrivals.
func (s *Scheduler) Interval() time.Duration {
	return time.Duration(float64(time.Second) / s.Rate)
}

// Run releases count slots, invoking emit for each one.
//
// Two properties matter and are both tested:
//
//   - The ideal schedule is absolute, computed as start + n/rate from a single
//     origin. Errors therefore do not accumulate: a slow tick does not push
//     every later tick back.
//   - The tool never fires a catch-up burst. When it falls behind, releases are
//     capped at catchUpFactor times the target rate, so a stalled client cannot
//     dump hundreds of requests onto a recovering TSA at once, but a transient
//     stall can still be absorbed rather than becoming permanent. Whatever
//     shortfall remains surfaces as lag, which is what the operator needs to
//     see.
func (s *Scheduler) Run(ctx context.Context, start time.Time, count int64, emit func(Tick) error) error {
	if s.Rate <= 0 {
		return fmt.Errorf("scheduler rate must be positive, got %v", s.Rate)
	}
	if s.Clock == nil {
		return errors.New("scheduler requires a clock")
	}

	interval := s.Interval()
	minGap := interval / catchUpFactor

	var lastRelease time.Time

	for i := int64(0); i < count; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		// Absolute schedule from a single origin: no error accumulation.
		scheduled := start.Add(time.Duration(float64(i) * float64(time.Second) / s.Rate))

		deadline := scheduled

		// Anti-burst floor, measured from the previous actual release so that it
		// genuinely throttles a drain in wall-clock terms.
		//
		// It binds only once lag exceeds half an interval. Below that — which
		// includes the ordinary case of a timer waking a few hundred
		// microseconds late — the absolute schedule wins and no error
		// accumulates. Above it, releases are paced at minGap, draining the
		// backlog at twice the target rate until the schedule is met again.
		if !lastRelease.IsZero() {
			if floor := lastRelease.Add(minGap); floor.After(deadline) {
				deadline = floor
			}
		}

		if now := s.Clock.Now(); now.Before(deadline) {
			if err := s.Clock.SleepUntil(ctx, deadline); err != nil {
				return err
			}
		}

		actual := s.Clock.Now()
		lastRelease = actual

		lag := actual.Sub(scheduled)
		if lag < 0 {
			lag = 0
		}

		if err := emit(Tick{
			Sequence:  i + 1,
			Scheduled: scheduled,
			Actual:    actual,
			Lag:       lag,
		}); err != nil {
			return err
		}
	}
	return nil
}
