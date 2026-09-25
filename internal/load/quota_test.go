package load_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/berkecengiz/tsa-bench/internal/load"
)

// TestQuotaNeverOverIssues is the safety-critical race test: against a live TSA
// an over-issue is an irreversible overspend of the provider's allowance.
func TestQuotaNeverOverIssues(t *testing.T) {
	const budget = 4321
	q := load.NewQuota(budget, load.DefaultHardCapForTest)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		granted  = map[int64]bool{}
		refusals int
	)

	for w := 0; w < 200; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				seq, err := q.Acquire()
				if err != nil {
					mu.Lock()
					refusals++
					mu.Unlock()
					continue
				}
				mu.Lock()
				if granted[seq] {
					t.Errorf("sequence %d was issued twice", seq)
				}
				granted[seq] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(granted) != budget {
		t.Errorf("issued %d units, want exactly %d", len(granted), budget)
	}
	if q.Used() != budget {
		t.Errorf("Used() = %d, want %d", q.Used(), budget)
	}
	if refusals != 200*100-budget {
		t.Errorf("refusals = %d, want %d", refusals, 200*100-budget)
	}
	for i := int64(1); i <= budget; i++ {
		if !granted[i] {
			t.Fatalf("sequence %d was never issued; the counter has a gap", i)
		}
	}
}

func TestQuotaClampsToHardCap(t *testing.T) {
	q := load.NewQuota(90000, 50000)
	if q.Budget() != 50000 {
		t.Errorf("budget = %d, want it clamped to the 50000 hard cap", q.Budget())
	}
}

func TestQuotaCloseStopsIssuance(t *testing.T) {
	q := load.NewQuota(100, 100)
	if _, err := q.Acquire(); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	q.Close()
	if _, err := q.Acquire(); !errors.Is(err, load.ErrQuotaExhausted) {
		t.Errorf("acquire after close returned %v, want ErrQuotaExhausted", err)
	}
	if q.Used() != 1 {
		t.Errorf("used = %d, want 1", q.Used())
	}
}

func TestQuotaRemaining(t *testing.T) {
	q := load.NewQuota(3, 10)
	for i := 0; i < 3; i++ {
		if _, err := q.Acquire(); err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
	}
	if q.Remaining() != 0 {
		t.Errorf("remaining = %d, want 0", q.Remaining())
	}
	if _, err := q.Acquire(); err == nil {
		t.Error("acquire past the budget succeeded")
	}
}
