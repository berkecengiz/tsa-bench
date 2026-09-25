package load_test

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/berkecengiz/tsa-bench/internal/load"
)

// TestSchedulerIdealSchedule proves the arrival plan is exact and, crucially,
// that errors do not accumulate across a long stage.
func TestSchedulerIdealSchedule(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := load.NewFakeClock(start, true)
	s := &load.Scheduler{Rate: 150, Clock: clock}

	const count = 45000 // the 150 TPS x 300 s stage
	var ticks []load.Tick
	err := s.Run(context.Background(), start, count, func(tk load.Tick) error {
		ticks = append(ticks, tk)
		return nil
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(ticks) != count {
		t.Fatalf("emitted %d ticks, want %d", len(ticks), count)
	}

	// The last request of a 150 TPS, 300 s stage is due at t+299.993s.
	lastOffset := float64(count-1) / 150.0 * float64(time.Second)
	wantLast := start.Add(time.Duration(lastOffset))
	if got := ticks[count-1].Scheduled; !within(got, wantLast, time.Microsecond) {
		t.Errorf("last scheduled = %v, want %v", got, wantLast)
	}

	// Every interval must equal 1/150 s to within a nanosecond of rounding.
	interval := float64(time.Second) / 150
	for i := 1; i < len(ticks); i++ {
		d := float64(ticks[i].Scheduled.Sub(ticks[i-1].Scheduled))
		if math.Abs(d-interval) > 1 {
			t.Fatalf("interval %d = %v ns, want %v ns", i, d, interval)
		}
	}
}

// TestSchedulerNeverBursts is the anti-burst guarantee: after an artificial
// stall, the scheduler must not release the backlog all at once.
func TestSchedulerNeverBursts(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := load.NewFakeClock(start, true)
	s := &load.Scheduler{Rate: 100, Clock: clock}

	var releases []time.Time
	err := s.Run(context.Background(), start, 50, func(tk load.Tick) error {
		releases = append(releases, tk.Actual)
		if tk.Sequence == 10 {
			clock.Advance(2 * time.Second) // simulate a two-second client stall
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	interval := time.Second / 100
	// Releases may drain a backlog at up to twice the target rate, never faster.
	minGap := interval / 2
	for i := 1; i < len(releases); i++ {
		gap := releases[i].Sub(releases[i-1])
		if gap < 0 {
			t.Fatalf("release %d went backwards", i)
		}
		if i > 11 && gap < minGap-time.Microsecond {
			t.Errorf("release %d came %v after the previous one, closer than the %v floor: this is a catch-up burst",
				i, gap, minGap)
		}
	}
}

// TestSchedulerRecoversFromAStall is the regression test for the ratchet.
//
// An earlier version floored releases at exactly one interval after the
// previous *actual* release. Once lag exceeded a single interval the floor
// engaged permanently, and because every wake-up costs slightly more than the
// interval, the achieved rate settled below target and the lag grew for the
// rest of the run. A 150 TPS, 5-minute stage finished 28 seconds late at 137
// TPS while the client sat at 12% CPU, and the tool blamed itself for
// saturation that it had created.
func TestSchedulerRecoversFromAStall(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := load.NewFakeClock(start, true)
	clock.SetOvershoot(700 * time.Microsecond) // a real timer wakes late
	s := &load.Scheduler{Rate: 150, Clock: clock}

	const count = 4000
	var lags []time.Duration
	err := s.Run(context.Background(), start, count, func(tk load.Tick) error {
		if tk.Sequence == 100 {
			clock.Advance(2 * time.Second) // one transient stall
		}
		lags = append(lags, tk.Lag)
		return nil
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	peak := lags[100]
	if peak < time.Second {
		t.Fatalf("the injected stall produced only %v of lag; the test is not exercising recovery", peak)
	}

	final := lags[len(lags)-1]
	if final > 10*time.Millisecond {
		t.Errorf("lag was still %v at the end of the run (peaked at %v): "+
			"the scheduler never recovered from a transient stall", final, peak)
	}
}

// TestSchedulerHoldsRateOverALongStage reproduces the shape of the real
// 150 TPS x 300 s stage with a realistically late timer.
func TestSchedulerHoldsRateOverALongStage(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := load.NewFakeClock(start, true)
	clock.SetOvershoot(700 * time.Microsecond)
	s := &load.Scheduler{Rate: 150, Clock: clock}

	const count = 45000
	var first, last time.Time
	var maxLag time.Duration
	err := s.Run(context.Background(), start, count, func(tk load.Tick) error {
		if first.IsZero() {
			first = tk.Actual
		}
		last = tk.Actual
		if tk.Lag > maxLag {
			maxLag = tk.Lag
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	span := last.Sub(first)
	achieved := float64(count-1) / span.Seconds()
	if achieved < 149 {
		t.Errorf("achieved %.2f TPS over %v against a 150 TPS target (max lag %v)",
			achieved, span, maxLag)
	}
	if maxLag > 10*time.Millisecond {
		t.Errorf("max lag %v over a 5-minute stage: lag is accumulating", maxLag)
	}
}

// TestSchedulerReportsLag proves a client that cannot keep up is visible rather
// than silently running at a lower rate.
func TestSchedulerReportsLag(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := load.NewFakeClock(start, true)
	s := &load.Scheduler{Rate: 1000, Clock: clock}

	var maxLag time.Duration
	var lagged int
	err := s.Run(context.Background(), start, 20, func(tk load.Tick) error {
		if tk.Sequence == 5 {
			clock.Advance(500 * time.Millisecond)
		}
		if tk.Lag > 0 {
			lagged++
		}
		if tk.Lag > maxLag {
			maxLag = tk.Lag
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if lagged == 0 {
		t.Fatal("a 500ms stall produced no reported lag; saturation would be invisible")
	}
	if maxLag < 400*time.Millisecond {
		t.Errorf("max lag = %v, expected to reflect the 500ms stall", maxLag)
	}
}

// TestSchedulerRealClockAccuracy checks the real clock path end to end.
func TestSchedulerRealClockAccuracy(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test skipped in short mode")
	}

	s := &load.Scheduler{Rate: 200, Clock: load.RealClock{}}
	start := time.Now()

	const count = 200 // one second of work
	var n int
	if err := s.Run(context.Background(), start, count, func(load.Tick) error {
		n++
		return nil
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	elapsed := time.Since(start)
	wantNS := float64(count-1) / 200.0 * float64(time.Second)
	want := time.Duration(wantNS)
	// Allow generous slack: CI machines are noisy, but a systematic error would
	// show up as a multiple of the expected duration, not a few milliseconds.
	if elapsed < want || elapsed > want+300*time.Millisecond {
		t.Errorf("200 ticks at 200 TPS took %v, expected about %v", elapsed, want)
	}
	if n != count {
		t.Errorf("emitted %d ticks, want %d", n, count)
	}
}

func TestSchedulerRespectsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &load.Scheduler{Rate: 10, Clock: load.RealClock{}}

	var emitted int
	err := s.Run(ctx, time.Now(), 1000, func(load.Tick) error {
		emitted++
		if emitted == 3 {
			cancel()
		}
		return nil
	})
	if err == nil {
		t.Fatal("expected a context error")
	}
	if emitted > 4 {
		t.Errorf("scheduler emitted %d ticks after cancellation", emitted)
	}
}

func within(a, b time.Time, tol time.Duration) bool {
	d := a.Sub(b)
	if d < 0 {
		d = -d
	}
	return d <= tol
}

// TestSchedulerDoesNotAccumulateDrift is a regression test.
//
// A timer always wakes slightly late. An earlier version applied the anti-burst
// floor unconditionally, so each late wake-up pushed the next release a further
// tick back and the error compounded: a 100 TPS stage measured 92 TPS and the
// tool blamed itself for saturation that did not exist. The absolute schedule
// must win whenever the client is on time.
func TestSchedulerDoesNotAccumulateDrift(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := load.NewFakeClock(start, true)
	s := &load.Scheduler{Rate: 100, Clock: clock}

	const overshoot = 900 * time.Microsecond
	const count = 500

	var lags []time.Duration
	err := s.Run(context.Background(), start, count, func(tk load.Tick) error {
		lags = append(lags, tk.Lag)
		// Every wake-up lands slightly late, as a real timer does.
		clock.Advance(overshoot)
		return nil
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Lag must stay bounded by roughly one overshoot, not grow with the
	// sequence number.
	limit := 3 * overshoot
	for i, lag := range lags {
		if lag > limit {
			t.Fatalf("lag at tick %d is %v, above the %v bound: drift is accumulating", i, lag, limit)
		}
	}

	last := lags[len(lags)-1]
	first := lags[0]
	if last > first+overshoot {
		t.Errorf("lag grew from %v at the first tick to %v at the last: drift is accumulating", first, last)
	}
}

// TestSchedulerHoldsRateUnderOvershoot checks the achieved rate directly.
func TestSchedulerHoldsRateUnderOvershoot(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := load.NewFakeClock(start, true)
	s := &load.Scheduler{Rate: 150, Clock: clock}

	const count = 3000
	var firstRelease, lastRelease time.Time
	err := s.Run(context.Background(), start, count, func(tk load.Tick) error {
		if firstRelease.IsZero() {
			firstRelease = tk.Actual
		}
		lastRelease = tk.Actual
		clock.Advance(700 * time.Microsecond)
		return nil
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	span := lastRelease.Sub(firstRelease).Seconds()
	achieved := float64(count-1) / span
	if achieved < 150*0.99 || achieved > 150*1.01 {
		t.Errorf("achieved %.2f TPS against a 150 TPS target; must stay within 1%%", achieved)
	}
}
