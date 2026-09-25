package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

// ComparisonEntry is one provider's column in the comparison.
type ComparisonEntry struct {
	Provider    string    `json:"provider"`
	Environment string    `json:"environment"`
	RunID       string    `json:"run_id"`
	Directory   string    `json:"directory"`
	StartedAt   time.Time `json:"started_at"`
	DurationS   float64   `json:"duration_seconds"`

	TargetTPS   float64 `json:"peak_target_tps"`
	AchievedTPS float64 `json:"achieved_tps"`

	TotalRequests int64   `json:"total_requests"`
	Verified      int64   `json:"verified_requests"`
	Failed        int64   `json:"failed_requests"`
	SuccessRate   float64 `json:"success_rate"`
	TimeoutRate   float64 `json:"timeout_rate"`

	MinMS  float64 `json:"min_ms"`
	MeanMS float64 `json:"mean_ms"`
	P95MS  float64 `json:"p95_ms"`
	P99MS  float64 `json:"p99_ms"`
	MaxMS  float64 `json:"max_ms"`

	ClientBottleneck bool         `json:"client_bottleneck_observed"`
	BottleneckDetail string       `json:"client_bottleneck_detail,omitempty"`
	Partial          bool         `json:"partial"`
	StopReason       string       `json:"stop_reason"`
	Errors           []ErrorCount `json:"errors"`

	// SustainedStage describes the headline stage, i.e. the longest stage at
	// the highest target rate. The executive summary must not quote a number
	// without saying which stage produced it.
	SustainedStage   string  `json:"sustained_stage"`
	SustainedSeconds float64 `json:"sustained_seconds"`
	SustainedTPS     float64 `json:"sustained_target_tps"`
}

// Comparison is the cross-provider document.
type Comparison struct {
	Schema      string            `json:"schema"`
	GeneratedAt time.Time         `json:"generated_at"`
	Entries     []ComparisonEntry `json:"entries"`
	Notes       []string          `json:"notes"`
	Limitations []string          `json:"limitations"`
	AnyLive     bool              `json:"any_live_environment"`
}

// LoadSummary reads a summary.json from a run directory.
func LoadSummary(dir string) (*Summary, error) {
	path := filepath.Join(dir, "summary.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var s Summary
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if s.Schema != SchemaVersion {
		return nil, fmt.Errorf("%s has schema %q, this build understands %q",
			path, s.Schema, SchemaVersion)
	}
	return &s, nil
}

// BuildComparison assembles the cross-provider view from loaded summaries.
func BuildComparison(dirs []string, summaries []*Summary, generatedAt time.Time) *Comparison {
	c := &Comparison{
		Schema:      SchemaVersion,
		GeneratedAt: generatedAt,
	}

	for i, s := range summaries {
		e := ComparisonEntry{
			Provider:         s.Metadata.Provider.Name,
			Environment:      s.Metadata.Provider.Environment,
			RunID:            s.Metadata.RunID,
			Directory:        dirs[i],
			StartedAt:        s.Metadata.StartedAt,
			DurationS:        s.DurationS,
			AchievedTPS:      s.Overall.ActualSendTPS,
			TotalRequests:    s.Overall.Sent,
			Verified:         s.Overall.Verified,
			Failed:           s.Overall.Failed,
			SuccessRate:      s.Overall.SuccessRate,
			TimeoutRate:      s.Overall.TimeoutRate,
			MinMS:            s.Overall.Latency.MinMS,
			MeanMS:           s.Overall.Latency.MeanMS,
			P95MS:            s.Overall.Latency.P95MS,
			P99MS:            s.Overall.Latency.P99MS,
			MaxMS:            s.Overall.Latency.MaxMS,
			ClientBottleneck: s.ClientBottleneck,
			BottleneckDetail: s.ClientBottleneckWhy,
			Partial:          s.Partial,
			StopReason:       s.StopReason,
			Errors:           s.Overall.Errors,
		}

		// The headline stage is the one with the highest target rate; ties are
		// broken by duration.
		for _, st := range s.Stages {
			if st.TargetTPS > e.SustainedTPS ||
				(st.TargetTPS == e.SustainedTPS && st.DurationS > e.SustainedSeconds) {
				e.SustainedTPS = st.TargetTPS
				e.SustainedSeconds = st.DurationS
				e.SustainedStage = st.Name
				e.TargetTPS = st.TargetTPS
			}
		}
		if s.Metadata.Provider.Environment == "live" {
			c.AnyLive = true
		}
		c.Entries = append(c.Entries, e)
	}

	sort.Slice(c.Entries, func(i, j int) bool {
		return c.Entries[i].Provider < c.Entries[j].Provider
	})

	c.Notes = []string{
		HistogramPrecisionNote,
		CoordinatedOmissionNote,
		"Providers must be tested sequentially, not concurrently, and from the same host and network " +
			"egress. Runs made under different conditions are not comparable.",
	}
	c.Limitations = []string{
		"Each figure describes one bounded test window at a fixed target rate; it is not a guarantee of " +
			"sustained production capacity.",
		"Where a run is marked as client-bottlenecked, that provider's figures are a lower bound on its " +
			"capacity, not a measurement of it.",
		"Success requires the full RFC 3161 acceptance chain to pass, so these success rates are stricter " +
			"than an HTTP-level availability figure.",
	}
	if c.AnyLive {
		c.Limitations = append(c.Limitations,
			"At least one run targeted a live production service shared with real customer traffic; "+
				"concurrent third-party load is an uncontrolled variable.")
	}
	return c
}

// WriteComparisonCSV writes the machine-readable comparison table.
func WriteComparisonCSV(path string, c *Comparison) (err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, filePerm)
	if err != nil {
		return err
	}

	w := csv.NewWriter(f)
	defer closeCSV(f, w, nil, &err)

	if err := w.Write([]string{
		"provider", "environment", "run_id", "sustained_stage", "sustained_target_tps",
		"sustained_seconds", "achieved_tps", "total_requests", "verified", "failed",
		"success_rate", "timeout_rate", "min_ms", "mean_ms", "p95_ms", "p99_ms", "max_ms",
		"client_bottleneck", "partial", "stop_reason",
	}); err != nil {
		return err
	}

	for _, e := range c.Entries {
		if err := w.Write([]string{
			e.Provider, e.Environment, e.RunID, e.SustainedStage,
			strconv.FormatFloat(e.SustainedTPS, 'f', 2, 64),
			strconv.FormatFloat(e.SustainedSeconds, 'f', 1, 64),
			strconv.FormatFloat(e.AchievedTPS, 'f', 2, 64),
			strconv.FormatInt(e.TotalRequests, 10),
			strconv.FormatInt(e.Verified, 10),
			strconv.FormatInt(e.Failed, 10),
			strconv.FormatFloat(e.SuccessRate, 'f', 6, 64),
			strconv.FormatFloat(e.TimeoutRate, 'f', 6, 64),
			strconv.FormatFloat(e.MinMS, 'f', 2, 64),
			strconv.FormatFloat(e.MeanMS, 'f', 2, 64),
			strconv.FormatFloat(e.P95MS, 'f', 2, 64),
			strconv.FormatFloat(e.P99MS, 'f', 2, 64),
			strconv.FormatFloat(e.MaxMS, 'f', 2, 64),
			strconv.FormatBool(e.ClientBottleneck),
			strconv.FormatBool(e.Partial),
			e.StopReason,
		}); err != nil {
			return err
		}
	}
	return nil
}

// comparisonData is the template context.
type comparisonData struct {
	Comparison *Comparison
	// ErrorClasses is the union of error classes across providers, so the table
	// has one row per class and one column per provider.
	ErrorClasses []string
	ErrorMatrix  map[string]map[string]int64
}

// WriteComparisonHTML renders the executive comparison.
func WriteComparisonHTML(path string, c *Comparison) (err error) {
	tmpl, err := parseTemplates("comparison.html.tmpl")
	if err != nil {
		return fmt.Errorf("parse comparison template: %w", err)
	}

	matrix := map[string]map[string]int64{}
	classSet := map[string]bool{}
	for _, e := range c.Entries {
		for _, ec := range e.Errors {
			if ec.Class == "ok" {
				continue
			}
			classSet[ec.Class] = true
			if matrix[ec.Class] == nil {
				matrix[ec.Class] = map[string]int64{}
			}
			matrix[ec.Class][e.Provider] = ec.Count
		}
	}
	classes := make([]string, 0, len(classSet))
	for k := range classSet {
		classes = append(classes, k)
	}
	sort.Strings(classes)

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

	return tmpl.ExecuteTemplate(f, "comparison.html.tmpl", comparisonData{
		Comparison:   c,
		ErrorClasses: classes,
		ErrorMatrix:  matrix,
	})
}
