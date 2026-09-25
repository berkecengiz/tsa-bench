package load_test

import (
	"testing"

	"github.com/berkecengiz/tsa-bench/internal/load"
)

func TestBreakerConsecutiveFailures(t *testing.T) {
	b := load.NewBreaker(0, 100, 5)

	for i := 0; i < 4; i++ {
		if b.Record(true) {
			t.Fatalf("tripped after %d consecutive failures, threshold is 5", i+1)
		}
	}
	if !b.Record(true) {
		t.Fatal("did not trip on the fifth consecutive failure")
	}
	if b.Reason() == "" {
		t.Error("a tripped breaker must explain itself for the report")
	}
}

func TestBreakerConsecutiveResetsOnSuccess(t *testing.T) {
	b := load.NewBreaker(0, 100, 3)
	b.Record(true)
	b.Record(true)
	b.Record(false) // resets the streak
	b.Record(true)
	b.Record(true)
	if b.Tripped() {
		t.Error("a success in the middle must reset the consecutive counter")
	}
	if !b.Record(true) {
		t.Error("did not trip after three consecutive failures following the reset")
	}
}

func TestBreakerErrorRate(t *testing.T) {
	b := load.NewBreaker(0.25, 20, 0)

	// 19 successes and 1 failure: 5%, well under the limit.
	for i := 0; i < 19; i++ {
		b.Record(false)
	}
	if b.Record(true) {
		t.Fatal("tripped at a 5% error rate against a 25% limit")
	}

	// Push the window to 25% failures.
	for i := 0; i < 4; i++ {
		if b.Record(true) {
			return // tripped as expected
		}
	}
	t.Error("did not trip once the windowed error rate reached the limit")
}

func TestBreakerNeedsFullWindowForRate(t *testing.T) {
	b := load.NewBreaker(0.5, 50, 0)
	// Two failures out of two is 100%, but the window is not full yet. Tripping
	// here would abort a run on the strength of two samples.
	//
	// Each Record call is made separately: || would short-circuit and the
	// second failure would never be recorded.
	first := b.Record(true)
	second := b.Record(true)
	if first || second {
		t.Error("tripped on an incomplete window")
	}
}

func TestBreakerDisabled(t *testing.T) {
	b := load.NewBreaker(0, 1, 0)
	if !b.Disabled() {
		t.Fatal("a breaker with no thresholds must report itself disabled")
	}
	for i := 0; i < 1000; i++ {
		if b.Record(true) {
			t.Fatal("a disabled breaker tripped")
		}
	}
}
