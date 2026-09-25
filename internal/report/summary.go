// Package report renders run results to JSON, CSV and HTML.
//
// Every number in a report is traceable to a counter in the metrics package.
// Where a measurement is approximate (percentiles come from a bucketed
// histogram) or conditional (resource metrics are unavailable on some
// platforms), the report says so rather than presenting a confident number.
package report

import (
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/berkecengiz/tsa-bench/internal/config"
	"github.com/berkecengiz/tsa-bench/internal/load"
	"github.com/berkecengiz/tsa-bench/internal/metrics"
)

// SchemaVersion identifies the JSON layout, so downstream tooling can detect a
// format change instead of silently misreading a field.
const SchemaVersion = "tsa-bench/v1"

// HistogramPrecisionNote documents the accuracy of every reported percentile.
const HistogramPrecisionNote = "Percentiles come from a fixed-size HDR-style histogram with 3 significant " +
	"figures: each reported value is the upper bound of a bucket at most 1/2048 (about 0.05%) wide. " +
	"Minimum, maximum and mean are exact."

// CoordinatedOmissionNote explains the measurement model.
const CoordinatedOmissionNote = "Requests are issued on an open-loop constant-arrival-rate schedule: request n is " +
	"due at start + n/rate regardless of when request n-1 finished. This avoids coordinated omission, " +
	"where a closed-loop client stops issuing requests while the server is slow and so never measures " +
	"the latency its own backlog would have seen. Any inability to hold the schedule is reported as " +
	"schedule lag and client saturation rather than being absorbed into a quietly lower rate."

// Metadata describes the run environment. It never contains secrets.
type Metadata struct {
	Schema      string    `json:"schema"`
	RunID       string    `json:"run_id"`
	Tool        string    `json:"tool"`
	Version     string    `json:"version"`
	GoVersion   string    `json:"go_version"`
	OS          string    `json:"os"`
	Arch        string    `json:"arch"`
	Hostname    string    `json:"hostname"`
	StartedAt   time.Time `json:"started_at"`
	EndedAt     time.Time `json:"ended_at"`
	CommandLine string    `json:"command_line"`

	Provider    ProviderInfo `json:"provider"`
	ProfileName string       `json:"profile_name"`
	ProfileNote string       `json:"profile_note,omitempty"`

	RequestConfig RequestInfo `json:"request"`
	LoadConfig    LoadInfo    `json:"load"`
	QuotaConfig   QuotaInfo   `json:"quota"`
	TLSConfig     TLSInfo     `json:"tls"`

	Warnings []string `json:"warnings,omitempty"`
}

// ProviderInfo identifies the target. The endpoint is redacted.
type ProviderInfo struct {
	Name        string `json:"name"`
	Endpoint    string `json:"endpoint_redacted"`
	Environment string `json:"environment"`
	AuthType    string `json:"auth_type"`
}

// RequestInfo records how requests were built.
type RequestInfo struct {
	HashAlgorithm string `json:"hash_algorithm"`
	PayloadSize   int    `json:"payload_size_bytes"`
	CertReq       bool   `json:"cert_req"`
	TimeoutMS     int64  `json:"timeout_ms"`
	MaxClockSkewS int64  `json:"max_clock_skew_seconds"`
	RequireESS    bool   `json:"require_ess"`
}

// LoadInfo records the load configuration.
type LoadInfo struct {
	MaxConcurrency int   `json:"max_concurrency"`
	StagePauseS    int64 `json:"stage_pause_seconds"`
	LagThresholdMS int64 `json:"lag_threshold_ms"`
	GracePeriodS   int64 `json:"grace_period_seconds"`
}

// QuotaInfo records the budget arithmetic.
type QuotaInfo struct {
	MaxRequests    int64 `json:"max_requests"`
	HardCap        int64 `json:"hard_cap"`
	ProfilePlanned int64 `json:"profile_planned"`
	ProfileReserve int64 `json:"profile_reserve"`
	Retries        int   `json:"retries"`
}

// TLSInfo records the transport trust settings.
type TLSInfo struct {
	MinVersion         string `json:"min_version"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	CAFile             string `json:"ca_file,omitempty"`
	TSATrustSource     string `json:"tsa_trust_source"`
	ServerName         string `json:"server_name,omitempty"`
}

// LatencyStats is a reported latency distribution in milliseconds.
type LatencyStats struct {
	Count     int64   `json:"count"`
	MinMS     float64 `json:"min_ms"`
	MeanMS    float64 `json:"mean_ms"`
	P50MS     float64 `json:"p50_ms"`
	P90MS     float64 `json:"p90_ms"`
	P95MS     float64 `json:"p95_ms"`
	P99MS     float64 `json:"p99_ms"`
	MaxMS     float64 `json:"max_ms"`
	Overflows int64   `json:"overflows"`
}

func latencyFrom(s metrics.Snapshot) LatencyStats {
	return LatencyStats{
		Count:     s.Count,
		MinMS:     msFloat(s.Min),
		MeanMS:    msFloat(s.Mean),
		P50MS:     msFloat(s.P50),
		P90MS:     msFloat(s.P90),
		P95MS:     msFloat(s.P95),
		P99MS:     msFloat(s.P99),
		MaxMS:     msFloat(s.Max),
		Overflows: s.Overflows,
	}
}

// ErrorCount is one row of the error distribution.
type ErrorCount struct {
	Class string  `json:"class"`
	Count int64   `json:"count"`
	Share float64 `json:"share"`
}

// StageSummary is the per-stage result.
type StageSummary struct {
	Name      string  `json:"name"`
	TargetTPS float64 `json:"target_tps"`

	Planned   int64 `json:"planned_requests"`
	Sent      int64 `json:"sent_requests"`
	Completed int64 `json:"completed_requests"`
	Verified  int64 `json:"verified_requests"`
	Failed    int64 `json:"failed_requests"`
	Timeouts  int64 `json:"timeout_requests"`

	SuccessRate float64 `json:"success_rate"`
	TimeoutRate float64 `json:"timeout_rate"`

	DurationS     float64 `json:"duration_seconds"`
	ActualSendTPS float64 `json:"actual_send_tps"`
	CompletedTPS  float64 `json:"completed_tps"`

	Latency        LatencyStats `json:"latency_total"`
	NetworkLatency LatencyStats `json:"latency_network"`
	VerifyLatency  LatencyStats `json:"latency_verification"`
	ScheduleLag    LatencyStats `json:"schedule_lag"`

	SaturationEvents int64        `json:"client_saturation_events"`
	Errors           []ErrorCount `json:"errors"`
	// VerificationWarnings counts responses that verified but said something
	// about the provider worth recording, such as a non-DER encoding. A run
	// can be 100% successful and still carry these.
	VerificationWarnings []WarningCount `json:"verification_warnings,omitempty"`
}

// WarningCount is one non-fatal verification observation and how often it
// occurred.
type WarningCount struct {
	Message string `json:"message"`
	Count   int64  `json:"count"`
}

// Summary is the top-level result document.
type Summary struct {
	Schema   string   `json:"schema"`
	Metadata Metadata `json:"metadata"`

	StopReason string  `json:"stop_reason"`
	StopDetail string  `json:"stop_detail,omitempty"`
	Partial    bool    `json:"partial"`
	DurationS  float64 `json:"duration_seconds"`

	QuotaUsed int64 `json:"quota_used"`
	// AuthRequests are extra HTTP requests spent on authentication - drawing
	// a digest challenge, or re-answering a stale nonce. They issue no
	// timestamp and consume no quota, so HTTP traffic exceeds quota usage by
	// this many requests.
	AuthRequests   int64 `json:"auth_requests"`
	QuotaBudget    int64 `json:"quota_budget"`
	QuotaRemaining int64 `json:"quota_remaining"`

	Stages  []StageSummary `json:"stages"`
	Overall StageSummary   `json:"overall"`

	Resources    metrics.Peak             `json:"resource_peak"`
	ResourceRows []metrics.ResourceSample `json:"-"`

	ClientBottleneck    bool   `json:"client_bottleneck_observed"`
	ClientBottleneckWhy string `json:"client_bottleneck_detail,omitempty"`

	Notes       []string `json:"notes"`
	Limitations []string `json:"limitations"`
}

// BuildSummary assembles the result document from the live collectors.
func BuildSummary(meta Metadata, c *metrics.Collector, outcome *load.Outcome,
	sampler *metrics.ResourceSampler, cfg *config.Config) *Summary {

	s := &Summary{
		Schema:         SchemaVersion,
		Metadata:       meta,
		StopReason:     string(outcome.Reason),
		StopDetail:     outcome.ReasonDetail,
		Partial:        outcome.Partial,
		DurationS:      outcome.EndedAt.Sub(outcome.StartedAt).Seconds(),
		QuotaUsed:      outcome.QuotaUsed,
		AuthRequests:   outcome.AuthRequests,
		QuotaBudget:    outcome.QuotaBudget,
		QuotaRemaining: outcome.QuotaBudget - outcome.QuotaUsed,
	}

	for _, st := range c.Stages() {
		s.Stages = append(s.Stages, stageSummary(st))
	}
	s.Overall = stageSummary(c.Overall())
	s.Overall.Name = "overall"

	if sampler != nil {
		s.Resources = sampler.Peak()
		s.ResourceRows = sampler.Samples()
	}

	s.ClientBottleneck, s.ClientBottleneckWhy = detectBottleneck(s, cfg)

	s.Notes = []string{HistogramPrecisionNote, CoordinatedOmissionNote}
	s.Limitations = limitations(cfg)
	return s
}

func stageSummary(st *metrics.StageStats) StageSummary {
	sent := st.Sent.Load()
	completed := st.Completed.Load()
	success := st.Success.Load()
	failure := st.Failure.Load()
	timeouts := st.Timeouts.Load()

	out := StageSummary{
		Name:             st.Name,
		TargetTPS:        st.TargetTPS,
		Planned:          st.Planned,
		Sent:             sent,
		Completed:        completed,
		Verified:         success,
		Failed:           failure,
		Timeouts:         timeouts,
		Latency:          latencyFrom(st.Total.Snapshot()),
		NetworkLatency:   latencyFrom(st.Network.Snapshot()),
		VerifyLatency:    latencyFrom(st.Verify.Snapshot()),
		ScheduleLag:      latencyFrom(st.Lag.Snapshot()),
		SaturationEvents: st.Saturated.Load(),
	}
	if completed > 0 {
		out.SuccessRate = float64(success) / float64(completed)
		out.TimeoutRate = float64(timeouts) / float64(completed)
	}
	// The achieved arrival rate is measured between the first and last actual
	// send, which is the window the target rate describes. Using the stage's
	// wall-clock duration instead would understate every stage, because a stage
	// only ends once its last in-flight response has settled.
	out.ActualSendTPS = st.AchievedTPS()
	if first, last, n := st.SendWindow(); n >= 2 {
		if span := last.Sub(first).Seconds(); span > 0 {
			out.DurationS = span
			out.CompletedTPS = float64(completed) / span
		}
	}
	if out.DurationS == 0 && !st.StartedAt.IsZero() && st.EndedAt.After(st.StartedAt) {
		out.DurationS = st.EndedAt.Sub(st.StartedAt).Seconds()
	}

	errs := st.Errors()
	for class, n := range errs {
		share := 0.0
		if completed > 0 {
			share = float64(n) / float64(completed)
		}
		out.Errors = append(out.Errors, ErrorCount{Class: class, Count: n, Share: share})
	}
	sort.Slice(out.Errors, func(i, j int) bool {
		if out.Errors[i].Count != out.Errors[j].Count {
			return out.Errors[i].Count > out.Errors[j].Count
		}
		return out.Errors[i].Class < out.Errors[j].Class
	})

	for msg, n := range st.Warnings() {
		out.VerificationWarnings = append(out.VerificationWarnings,
			WarningCount{Message: msg, Count: n})
	}
	sort.Slice(out.VerificationWarnings, func(i, j int) bool {
		if out.VerificationWarnings[i].Count != out.VerificationWarnings[j].Count {
			return out.VerificationWarnings[i].Count > out.VerificationWarnings[j].Count
		}
		return out.VerificationWarnings[i].Message < out.VerificationWarnings[j].Message
	})
	return out
}

// detectBottleneck decides whether the *client* limited the measurement. This
// question must be answered explicitly: a capacity number produced by a
// saturated load generator says nothing about the provider.
func detectBottleneck(s *Summary, cfg *config.Config) (bool, string) {
	var reasons []string

	if s.Overall.SaturationEvents > 0 {
		reasons = append(reasons, "the scheduler could not release requests on time")
	}
	lagThreshold := float64(cfg.Load.LagThreshold) / float64(time.Millisecond)
	if s.Overall.ScheduleLag.P99MS > lagThreshold {
		reasons = append(reasons, "p99 schedule lag exceeded the configured threshold")
	}
	if s.Resources.MaxCPUPercent >= float64(runtime.NumCPU())*90 {
		reasons = append(reasons, "the client process approached full CPU saturation")
	}
	for _, st := range s.Stages {
		if st.TargetTPS > 0 && st.ActualSendTPS > 0 && st.ActualSendTPS < st.TargetTPS*0.95 {
			reasons = append(reasons, "at least one stage sent more than 5% below its target rate")
			break
		}
	}

	if len(reasons) == 0 {
		return false, ""
	}
	return true, strings.Join(reasons, "; ")
}

func limitations(cfg *config.Config) []string {
	out := []string{
		"Results describe the service during this test window only. A live TSA is shared with real " +
			"customer traffic, so the same test at another time may produce different numbers.",
		"The highest sustained rate exercised is bounded by the profile; a stage that was not run " +
			"says nothing about behaviour at that rate.",
		"Certificate revocation (CRL/OCSP) is not checked during the run; doing so would add network " +
			"traffic that would distort the latency measurement.",
	}
	// The conditional limitations are the report-facing half of the operator
	// warnings, so both are decided once, in config.Warnings.
	for _, w := range cfg.Warnings() {
		if w.Limitation != "" {
			out = append(out, w.Limitation)
		}
	}
	return out
}
