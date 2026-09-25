package report_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/berkecengiz/tsa-bench/internal/errclass"
	"github.com/berkecengiz/tsa-bench/internal/metrics"
	"github.com/berkecengiz/tsa-bench/internal/report"
)

// TestWriterStreamsEveryAttempt is the accounting guarantee: every unit of
// quota consumed must appear as a row, however many there are. A run that
// spends 48,600 units and reports none of them is unauditable.
func TestWriterStreamsEveryAttempt(t *testing.T) {
	for _, n := range []int{1, 160, 3000, 48600} {
		t.Run(itoa(n), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "run")
			w, err := report.NewWriter(dir)
			if err != nil {
				t.Fatalf("NewWriter: %v", err)
			}

			for i := 1; i <= n; i++ {
				a := metrics.Attempt{
					Stage:       "sustained-150",
					Sequence:    int64(i),
					ScheduledAt: time.Now(),
					StartedAt:   time.Now(),
					CompletedAt: time.Now(),
					Total:       time.Millisecond,
					HTTPStatus:  200,
				}
				if i%100 == 0 {
					a.Err = errclass.New(errclass.ResponseTimeout, "injected")
				}
				if err := w.Write(a); err != nil {
					t.Fatalf("Write %d: %v", i, err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			body, err := os.ReadFile(filepath.Join(dir, "requests.csv"))
			if err != nil {
				t.Fatalf("read requests.csv: %v", err)
			}
			lines := countLines(body)
			if lines != n+1 { // +1 for the header
				t.Errorf("requests.csv has %d lines, want %d (header + %d attempts)", lines, n+1, n)
			}

			errBody, err := os.ReadFile(filepath.Join(dir, "errors.csv"))
			if err != nil {
				t.Fatalf("read errors.csv: %v", err)
			}
			wantErrs := n / 100
			if got := countLines(errBody) - 1; got != wantErrs {
				t.Errorf("errors.csv has %d rows, want %d", got, wantErrs)
			}
		})
	}
}

// TestWriterFlushIsVisibleBeforeClose covers the interrupted-run path: a
// partial report must already be on disk when the process is killed.
func TestWriterFlushIsVisibleBeforeClose(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	w, err := report.NewWriter(dir)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	for i := 1; i <= 50; i++ {
		if err := w.Write(metrics.Attempt{Stage: "s", Sequence: int64(i), HTTPStatus: 200}); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(dir, "requests.csv"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := countLines(body); got != 51 {
		t.Errorf("after Flush the file has %d lines, want 51", got)
	}
}

func TestWriterFilePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	w, err := report.NewWriter(dir)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Errorf("run directory mode = %o, want 700", perm)
	}

	for _, name := range []string{"requests.csv", "errors.csv", "run.log"} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if perm := fi.Mode().Perm(); perm != 0o644 {
			t.Errorf("%s mode = %o, want 644", name, perm)
		}
	}
}

func countLines(b []byte) int {
	s := strings.TrimRight(string(b), "\n")
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var out []byte
	for n > 0 {
		out = append([]byte{byte('0' + n%10)}, out...)
		n /= 10
	}
	return string(out)
}

// TestCountDataRows backs the post-run integrity check.
func TestCountDataRows(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	w, err := report.NewWriter(dir)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	const n = 1234
	for i := 1; i <= n; i++ {
		if err := w.Write(metrics.Attempt{Stage: "s", Sequence: int64(i), HTTPStatus: 200}); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	path := filepath.Join(dir, "requests.csv")
	got, err := report.CountDataRows(path)
	if err != nil {
		t.Fatalf("CountDataRows: %v", err)
	}
	if got != n {
		t.Errorf("CountDataRows = %d, want %d", got, n)
	}

	// An emptied file must report zero rather than succeed silently: this is
	// exactly the corruption the post-run check exists to catch.
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if got, err := report.CountDataRows(path); err != nil || got != 0 {
		t.Errorf("CountDataRows on an empty file = %d, %v; want 0, nil", got, err)
	}

	if _, err := report.CountDataRows(filepath.Join(dir, "absent.csv")); err == nil {
		t.Error("a missing file must be reported as an error")
	}
}
