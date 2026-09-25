package load_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/berkecengiz/tsa-bench/internal/load"
	"github.com/berkecengiz/tsa-bench/internal/report"
)

// TestRunnerWritesEveryAttemptToDisk wires the real report.Writer to the runner.
// Metrics counters and the on-disk record must agree: a run that reports 3000
// completed attempts and writes an empty requests.csv is unauditable.
func TestRunnerWritesEveryAttemptToDisk(t *testing.T) {
	cases := []struct {
		name    string
		profile *load.Profile
	}{
		{"rate only", rateProfile("r", 200, 2*time.Second)},
		{"sequential only", seqProfile(50)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "run")
			w, err := report.NewWriter(dir)
			if err != nil {
				t.Fatalf("NewWriter: %v", err)
			}

			r := newRig(t, rigOptions{profile: tc.profile, maxReq: 1000})
			r.runner.Sink = w

			outcome, err := r.runner.Run(context.Background())
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			body, err := os.ReadFile(filepath.Join(dir, "requests.csv"))
			if err != nil {
				t.Fatalf("read requests.csv: %v", err)
			}
			rows := strings.Count(strings.TrimRight(string(body), "\n"), "\n") // header excluded
			want := w.Rows()
			if int64(rows) != want {
				t.Errorf("requests.csv has %d rows, want %d (%d units of quota consumed)",
					rows, want, outcome.QuotaUsed)
			}
		})
	}
}
