package report_test

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/berkecengiz/tsa-bench/internal/metrics"
	"github.com/berkecengiz/tsa-bench/internal/report"
)

var update = flag.Bool("update", false, "rewrite golden files")

// fixedSummary builds a deterministic summary so golden files are stable.
func fixedSummary(provider, env string, bottleneck bool) *report.Summary {
	started := time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)
	return &report.Summary{
		Schema: report.SchemaVersion,
		Metadata: report.Metadata{
			Schema:    report.SchemaVersion,
			RunID:     "0123456789ab",
			Tool:      "tsa-bench",
			Version:   "v0.0.0-test",
			GoVersion: "go1.27.1",
			OS:        "linux",
			Arch:      "amd64",
			Hostname:  "bench-host",
			StartedAt: started,
			EndedAt:   started.Add(400 * time.Second),
			Provider: report.ProviderInfo{
				Name:        provider,
				Endpoint:    "https://tsa.example.com/timestamp",
				Environment: env,
				AuthType:    "basic",
			},
			ProfileName:   "50k",
			RequestConfig: report.RequestInfo{HashAlgorithm: "sha256", PayloadSize: 64, CertReq: true, TimeoutMS: 10000, MaxClockSkewS: 60},
			LoadConfig:    report.LoadInfo{MaxConcurrency: 500, StagePauseS: 30, LagThresholdMS: 250, GracePeriodS: 30},
			QuotaConfig:   report.QuotaInfo{MaxRequests: 48600, HardCap: 50000, ProfilePlanned: 48600, ProfileReserve: 1400},
			TLSConfig:     report.TLSInfo{MinVersion: "1.2", TSATrustSource: "/etc/tsa/ca.pem"},
		},
		StopReason:     "completed",
		DurationS:      400,
		QuotaUsed:      48600,
		QuotaBudget:    48600,
		QuotaRemaining: 0,
		Stages: []report.StageSummary{
			{
				Name: "functional", Planned: 100, Sent: 100, Completed: 100, Verified: 100,
				SuccessRate: 1, DurationS: 12, ActualSendTPS: 8.3,
				Latency: report.LatencyStats{Count: 100, MinMS: 41, MeanMS: 52, P50MS: 50, P90MS: 62, P95MS: 68, P99MS: 79, MaxMS: 91},
				Errors:  []report.ErrorCount{{Class: "ok", Count: 100, Share: 1}},
			},
			{
				Name: "sustained-150", TargetTPS: 150, Planned: 45000, Sent: 45000,
				Completed: 45000, Verified: 44950, Failed: 50, Timeouts: 20,
				SuccessRate: 0.998889, TimeoutRate: 0.000444,
				DurationS: 300, ActualSendTPS: 149.87, CompletedTPS: 149.8,
				Latency:     report.LatencyStats{Count: 45000, MinMS: 38, MeanMS: 61, P50MS: 57, P90MS: 84, P95MS: 96, P99MS: 148, MaxMS: 902},
				ScheduleLag: report.LatencyStats{Count: 45000, MinMS: 0, MeanMS: 0.4, P99MS: 1.9, MaxMS: 4.2},
				Errors: []report.ErrorCount{
					{Class: "ok", Count: 44950, Share: 0.998889},
					{Class: "response_timeout", Count: 20, Share: 0.000444},
					{Class: "http_5xx.503", Count: 18, Share: 0.0004},
					{Class: "tsp_rejection.systemFailure", Count: 12, Share: 0.000267},
				},
			},
		},
		Overall: report.StageSummary{
			Name: "overall", Planned: 48600, Sent: 48600, Completed: 48600,
			Verified: 48550, Failed: 50, Timeouts: 20,
			SuccessRate: 0.998971, TimeoutRate: 0.000412,
			DurationS: 380, ActualSendTPS: 127.9, CompletedTPS: 127.8,
			Latency:        report.LatencyStats{Count: 48600, MinMS: 38, MeanMS: 60, P50MS: 56, P90MS: 83, P95MS: 95, P99MS: 146, MaxMS: 902},
			NetworkLatency: report.LatencyStats{Count: 48600, MinMS: 36, MeanMS: 57, P50MS: 53, P90MS: 80, P95MS: 92, P99MS: 142, MaxMS: 898},
			VerifyLatency:  report.LatencyStats{Count: 48600, MinMS: 0.4, MeanMS: 0.9, P50MS: 0.8, P90MS: 1.2, P95MS: 1.4, P99MS: 2.1, MaxMS: 11},
			ScheduleLag:    report.LatencyStats{Count: 48600, MinMS: 0, MeanMS: 0.4, P99MS: 1.9, MaxMS: 4.2},
			Errors: []report.ErrorCount{
				{Class: "ok", Count: 48550, Share: 0.998971},
				{Class: "response_timeout", Count: 20, Share: 0.000412},
				{Class: "http_5xx.503", Count: 18, Share: 0.00037},
				{Class: "tsp_rejection.systemFailure", Count: 12, Share: 0.000247},
			},
		},
		Resources:           metrics.Peak{MaxGoroutines: 620, MaxRSSMB: 143.2, MaxCPUPercent: 88.4, MaxInFlight: 42, MaxConnsOpen: 60},
		ClientBottleneck:    bottleneck,
		ClientBottleneckWhy: bottleneckDetail(bottleneck),
		Notes:               []string{report.HistogramPrecisionNote, report.CoordinatedOmissionNote},
		Limitations:         []string{"Results describe the service during this test window only."},
	}
}

func bottleneckDetail(b bool) string {
	if b {
		return "p99 schedule lag exceeded the configured threshold"
	}
	return ""
}

func fixedSeries() []metrics.Second {
	rows := make([]metrics.Second, 0, 30)
	for i := 0; i < 30; i++ {
		completed := int64(150 - (i % 7))
		failure := int64(i % 3)
		rows = append(rows, metrics.Second{
			Second: int64(i), Sent: 150, Completed: completed,
			Success: completed - failure, Failure: failure,
			MeanMS: 55 + float64(i%5),
		})
	}
	return rows
}

// checkGolden compares generated output against a committed reference. Golden
// files make an accidental change to a report layout visible in review rather
// than discovered by a reader of the report.
func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)

	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run: go test ./internal/report -update)", path, err)
	}
	if string(want) != string(got) {
		t.Errorf("%s differs from the golden file. If the change is intended, run:\n"+
			"  go test ./internal/report -update\nand review the diff.", name)
	}
}

func TestGoldenHTMLReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")

	generated := time.Date(2026, 3, 14, 9, 10, 0, 0, time.UTC)
	if err := report.WriteHTML(path, fixedSummary("Provider A", "live", false), fixedSeries(), generated); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	checkGolden(t, "report.golden.html", got)
}

func TestGoldenComparison(t *testing.T) {
	summaries := []*report.Summary{
		fixedSummary("Provider C", "live", false),
		fixedSummary("Provider A", "live", true),
		fixedSummary("Provider B", "live", false),
	}
	dirs := []string{"results/provider-c/run", "results/provider-a/run", "results/provider-b/run"}

	cmp := report.BuildComparison(dirs, summaries, time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC))

	jsonBytes, err := json.MarshalIndent(cmp, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	checkGolden(t, "comparison.golden.json", append(jsonBytes, '\n'))

	dir := t.TempDir()
	csvPath := filepath.Join(dir, "comparison.csv")
	if err := report.WriteComparisonCSV(csvPath, cmp); err != nil {
		t.Fatalf("WriteComparisonCSV: %v", err)
	}
	csvBytes, _ := os.ReadFile(csvPath)
	checkGolden(t, "comparison.golden.csv", csvBytes)

	htmlPath := filepath.Join(dir, "comparison.html")
	if err := report.WriteComparisonHTML(htmlPath, cmp); err != nil {
		t.Fatalf("WriteComparisonHTML: %v", err)
	}
	htmlBytes, _ := os.ReadFile(htmlPath)
	checkGolden(t, "comparison.golden.html", htmlBytes)
}

// TestHTMLReportSurfacesMandatoryCaveats: the executive summary must never omit
// the context that makes the numbers safe to act on.
func TestHTMLReportSurfacesMandatoryCaveats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")
	if err := report.WriteHTML(path, fixedSummary("Provider A", "live", true), fixedSeries(), time.Now()); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	body, _ := os.ReadFile(path)
	html := string(body)

	for _, must := range []string{
		"LIVE PRODUCTION",
		"coordinated omission",
		"Limitations",
		"client bottleneck",
		"HTTP 200 alone is never treated as success",
	} {
		if !strings.Contains(strings.ToLower(html), strings.ToLower(must)) {
			t.Errorf("report omits required context: %q", must)
		}
	}
}

func TestComparisonHTMLMarksBottleneckedRun(t *testing.T) {
	summaries := []*report.Summary{
		fixedSummary("Alpha", "live", true),
		fixedSummary("Beta", "test", false),
	}
	cmp := report.BuildComparison([]string{"a", "b"}, summaries, time.Now())

	if !cmp.AnyLive {
		t.Error("a live target must be flagged on the comparison")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "comparison.html")
	if err := report.WriteComparisonHTML(path, cmp); err != nil {
		t.Fatalf("WriteComparisonHTML: %v", err)
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "lower bound") {
		t.Error("a client-bottlenecked run must be labelled as a lower bound")
	}
}

func TestRunDirLayout(t *testing.T) {
	at := time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)
	got := report.RunDir("results", "Provider A", at, "abc123")
	want := filepath.Join("results", "Provider-A", "20260314T090000Z-abc123")
	if got != want {
		t.Errorf("RunDir = %q, want %q", got, want)
	}
}
