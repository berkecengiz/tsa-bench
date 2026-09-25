package report

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/berkecengiz/tsa-bench/internal/metrics"
)

// File permissions. Result directories are private to the operator: a run log
// records endpoints and timing that need not be world-readable, and debug
// artifacts contain raw protocol bytes.
const (
	dirPerm           os.FileMode = 0o700
	filePerm          os.FileMode = 0o644
	sensitiveFilePerm os.FileMode = 0o600
)

// RunDir builds the canonical output path:
//
//	<output>/<provider>/<UTC timestamp>-<run id>/
func RunDir(outputDir, provider string, startedAt time.Time, runID string) string {
	return filepath.Join(outputDir, sanitizePath(provider),
		startedAt.UTC().Format("20060102T150405Z")+"-"+runID)
}

// Writer owns every output file for a single run.
//
// requests.csv is written as a stream: rows are flushed as attempts complete,
// so a run that is killed still leaves a usable record, and 48,600 rows never
// accumulate in memory.
type Writer struct {
	Dir string

	mu       sync.Mutex
	requests *csv.Writer
	reqFile  *os.File
	reqBuf   *bufio.Writer
	errors   *csv.Writer
	errFile  *os.File
	errBuf   *bufio.Writer
	logFile  *os.File
	// rows counts request rows accepted by Write, under the same mutex that
	// serialises the writes themselves. It is the number the audit record on
	// disk is checked against, so the check compares rows handed to the writer
	// with rows that survived - not a figure reconstructed from counters in
	// another package.
	rows int64

	closed bool
}

// NewWriter creates the run directory and opens the streaming outputs.
func NewWriter(dir string) (*Writer, error) {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, fmt.Errorf("create run directory: %w", err)
	}

	w := &Writer{Dir: dir}

	// Every failure below must close what has already been opened: NewWriter
	// returns nil, so the caller has no handle to clean up with.
	closeOpened := func() {
		for _, f := range []*os.File{w.reqFile, w.errFile, w.logFile} {
			if f != nil {
				_ = f.Close()
			}
		}
	}

	var err error
	if w.reqFile, err = os.OpenFile(filepath.Join(dir, "requests.csv"),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, filePerm); err != nil {
		return nil, fmt.Errorf("create requests.csv: %w", err)
	}
	w.reqBuf = bufio.NewWriterSize(w.reqFile, 256<<10)
	w.requests = csv.NewWriter(w.reqBuf)
	if err := w.requests.Write(requestHeader); err != nil {
		closeOpened()
		return nil, err
	}

	if w.errFile, err = os.OpenFile(filepath.Join(dir, "errors.csv"),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, filePerm); err != nil {
		closeOpened()
		return nil, fmt.Errorf("create errors.csv: %w", err)
	}
	w.errBuf = bufio.NewWriterSize(w.errFile, 64<<10)
	w.errors = csv.NewWriter(w.errBuf)
	if err := w.errors.Write(errorHeader); err != nil {
		closeOpened()
		return nil, err
	}

	if w.logFile, err = os.OpenFile(filepath.Join(dir, "run.log"),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, filePerm); err != nil {
		closeOpened()
		return nil, fmt.Errorf("create run.log: %w", err)
	}

	return w, nil
}

// LogFile exposes the run log for the structured logger.
func (w *Writer) LogFile() *os.File { return w.logFile }

var requestHeader = []string{
	"sequence", "stage", "scheduled_at", "started_at", "completed_at",
	"schedule_lag_ms", "total_ms", "network_ms", "verify_ms",
	"http_status", "outcome", "error_class", "clock_skew_ms",
}

var errorHeader = []string{
	"sequence", "stage", "started_at", "error_class", "http_status", "detail",
}

// Write records one attempt. It satisfies load.Sink.
func (w *Writer) Write(a metrics.Attempt) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}

	outcome := "verified"
	class := ""
	if !a.Succeeded() {
		outcome = "failed"
		class = a.ErrorKey()
	}

	if err := w.requests.Write([]string{
		strconv.FormatInt(a.Sequence, 10),
		a.Stage,
		ts(a.ScheduledAt),
		ts(a.StartedAt),
		ts(a.CompletedAt),
		ms(a.ScheduleLag),
		ms(a.Total),
		ms(a.Network),
		ms(a.Verify),
		strconv.Itoa(a.HTTPStatus),
		outcome,
		class,
		ms(a.ClockSkew),
	}); err != nil {
		return err
	}
	w.rows++

	if !a.Succeeded() {
		if err := w.errors.Write([]string{
			strconv.FormatInt(a.Sequence, 10),
			a.Stage,
			ts(a.StartedAt),
			class,
			strconv.Itoa(a.HTTPStatus),
			a.Err.Detail,
		}); err != nil {
			return err
		}
	}
	return nil
}

// Rows returns how many request rows have been written. It counts every row
// handed to Write, whether or not it consumed quota.
func (w *Writer) Rows() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.rows
}

// WriteTimeSeries writes the per-second throughput and error series.
func (w *Writer) WriteTimeSeries(rows []metrics.Second, res []metrics.ResourceSample) (err error) {
	f, err := os.OpenFile(filepath.Join(w.Dir, "timeseries.csv"),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, filePerm)
	if err != nil {
		return err
	}

	bySecond := make(map[int64]metrics.ResourceSample, len(res))
	for _, r := range res {
		bySecond[r.Second] = r
	}

	buf := bufio.NewWriter(f)
	cw := csv.NewWriter(buf)
	defer closeCSV(f, cw, buf, &err)

	if err := cw.Write([]string{
		"second", "sent", "completed", "success", "failure", "timeouts",
		"error_rate", "mean_latency_ms", "goroutines", "rss_peak_mb", "cpu_percent",
		"in_flight", "conns_open",
	}); err != nil {
		return err
	}

	for _, row := range rows {
		errRate := 0.0
		if row.Completed > 0 {
			errRate = float64(row.Failure) / float64(row.Completed)
		}
		r := bySecond[row.Second]
		if err := cw.Write([]string{
			strconv.FormatInt(row.Second, 10),
			strconv.FormatInt(row.Sent, 10),
			strconv.FormatInt(row.Completed, 10),
			strconv.FormatInt(row.Success, 10),
			strconv.FormatInt(row.Failure, 10),
			strconv.FormatInt(row.Timeouts, 10),
			strconv.FormatFloat(errRate, 'f', 4, 64),
			strconv.FormatFloat(row.MeanMS, 'f', 3, 64),
			strconv.Itoa(r.Goroutines),
			strconv.FormatFloat(r.RSSPeakMB, 'f', 1, 64),
			strconv.FormatFloat(r.CPUPercent, 'f', 1, 64),
			strconv.FormatInt(r.InFlight, 10),
			strconv.FormatInt(r.ConnsOpen, 10),
		}); err != nil {
			return err
		}
	}
	return nil
}

// closeCSV flushes every buffer stacked on a file and then closes it,
// reporting the first failure through err.
//
// The order is the point. The rows sit in buffers above the file, so a
// deferred plain Flush runs after the return value has been evaluated and a
// failure on the last block - a full results volume, say - is reported as
// success. buf may be nil when the writer sits straight on the file.
func closeCSV(f *os.File, cw *csv.Writer, buf *bufio.Writer, err *error) {
	cw.Flush()
	if werr := cw.Error(); werr != nil && *err == nil {
		*err = werr
	}
	if buf != nil {
		if ferr := buf.Flush(); ferr != nil && *err == nil {
			*err = ferr
		}
	}
	if cerr := f.Close(); cerr != nil && *err == nil {
		*err = cerr
	}
}

// WriteJSON writes a document with indentation, for diffing and review.
func (w *Writer) WriteJSON(name string, v any) error {
	return WriteJSONFile(filepath.Join(w.Dir, name), v)
}

// WriteJSONFile writes any document as pretty JSON.
func WriteJSONFile(path string, v any) (err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, filePerm)
	if err != nil {
		return err
	}
	// A close error on a written file can mean the data never reached the
	// disk, so it must surface rather than be discarded by a bare defer.
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// Flush persists buffered rows without closing the files.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flushLocked()
}

func (w *Writer) flushLocked() error {
	w.requests.Flush()
	if err := w.requests.Error(); err != nil {
		return err
	}
	w.errors.Flush()
	if err := w.errors.Error(); err != nil {
		return err
	}
	if err := w.reqBuf.Flush(); err != nil {
		return err
	}
	return w.errBuf.Flush()
}

// Close flushes and closes every open file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true

	err := w.flushLocked()
	for _, f := range []*os.File{w.reqFile, w.errFile, w.logFile} {
		if f == nil {
			continue
		}
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// msFloat converts a duration to milliseconds. Every latency the report
// publishes - JSON number or CSV string - goes through here, so the two
// renderings cannot round differently.
func msFloat(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func ms(d time.Duration) string {
	return strconv.FormatFloat(msFloat(d), 'f', 3, 64)
}

func sanitizePath(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			out = append(out, r)
		default:
			out = append(out, '-')
		}
	}
	if len(out) == 0 {
		return "unknown"
	}
	return string(out)
}

// CountDataRows counts the data rows (excluding the header) of a CSV file
// written by this package.
//
// It exists so a run can verify that what it believes it recorded actually
// reached the disk. Results are an audit record of irreversible quota
// consumption; a file that silently ends up empty — a synced or network
// filesystem interfering with an open file handle is the usual cause — must be
// reported, not discovered months later.
func CountDataRows(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var lines int64
	buf := make([]byte, 64<<10)
	for {
		n, err := f.Read(buf)
		for _, b := range buf[:n] {
			if b == '\n' {
				lines++
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return 0, err
		}
	}
	if lines == 0 {
		return 0, nil
	}
	return lines - 1, nil // the header is not a data row
}
