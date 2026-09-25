package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/berkecengiz/tsa-bench/internal/config"
	"github.com/berkecengiz/tsa-bench/internal/load"
	"github.com/berkecengiz/tsa-bench/internal/metrics"
	"github.com/berkecengiz/tsa-bench/internal/redact"
	"github.com/berkecengiz/tsa-bench/internal/report"
	"github.com/berkecengiz/tsa-bench/internal/transport"
	"github.com/berkecengiz/tsa-bench/internal/tsp"
)

// runFlags holds the parsed command line. It is a struct rather than a bag of
// pointers so the safety gates below read as conditions on a run, not as
// dereferences.
type runFlags struct {
	cfgPath        string
	profilePath    string
	maxRequests    int64
	ackLive        bool
	debugArtifacts bool
	artifactLimit  int64
	noAutoAbort    bool
	outputDir      string
	redactHost     bool
}

// parseRunFlags parses the command line and applies every safety gate that can
// be checked before anything is loaded from disk.
//
// These gates carry the whole safety condition of the command: there is no
// interactive prompt, so that `run` works unattended in CI. Adding a way past
// them is how a customer's paid, irreversible quota gets spent by accident.
func parseRunFlags(args []string) (*runFlags, error) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var f runFlags
	fs.StringVar(&f.cfgPath, "config", "", "path to the configuration file (required)")
	fs.StringVar(&f.profilePath, "profile", "", "path to the load profile (required)")
	fs.Int64Var(&f.maxRequests, "max-requests", 0,
		"absolute upper bound on physical requests this run may send (required)")
	authorized := fs.Bool("authorized-load-test", false,
		"confirm that written load-testing authorisation exists for this endpoint (required)")
	fs.BoolVar(&f.ackLive, "acknowledge-live-environment", false,
		"confirm the target is a live production service; required when provider.environment is live")
	fs.BoolVar(&f.debugArtifacts, "debug-artifacts", false,
		"write raw RFC 3161 requests and responses to disk (0600); off by default")
	fs.Int64Var(&f.artifactLimit, "debug-artifact-limit", 100,
		"maximum number of attempts to store raw bytes for")
	fs.BoolVar(&f.noAutoAbort, "no-auto-abort", false,
		"disable the automatic stop on sustained failure; not recommended against a live service")
	fs.StringVar(&f.outputDir, "output", "", "override output.directory from the configuration")
	fs.BoolVar(&f.redactHost, "redact-host", false,
		"omit the test host's name and the invoking command line from metadata.json")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "tsa-bench run — execute a load profile against a configured provider.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "This command sends real traffic and consumes real provider quota.")
		fmt.Fprintln(os.Stderr, "Both --max-requests and --authorized-load-test are mandatory, and a")
		fmt.Fprintln(os.Stderr, "live target additionally requires --acknowledge-live-environment.")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if f.cfgPath == "" {
		return nil, fail(2, "--config is required")
	}
	if f.profilePath == "" {
		return nil, fail(2, "--profile is required")
	}
	if f.maxRequests <= 0 {
		return nil, fail(2, "--max-requests is required and must be greater than zero; "+
			"it is the hard bound on how much provider quota this run may consume")
	}
	if !*authorized {
		return nil, fail(2, "--authorized-load-test is required; pass it only if you hold written "+
			"authorisation from the provider to load test this endpoint")
	}
	return &f, nil
}

func runLoad(ctx context.Context, args []string) error {
	f, err := parseRunFlags(args)
	if err != nil {
		return err
	}
	cfg, profile, err := loadInputs(f)
	if err != nil {
		return err
	}

	// --- verification prerequisites, resolved before any request is sent ---
	roots, trustSource, err := cfg.TSARoots()
	if err != nil {
		return fail(1, "%v", err)
	}
	verifier, err := tsp.NewVerifier(roots, cfg.Request.MaxClockSkew, cfg.Request.RequireESS)
	if err != nil {
		return fail(1, "cannot build verifier: %v", err)
	}
	builder, err := tsp.NewBuilder(tsp.BuilderOptions{
		HashName:    cfg.Request.HashAlgorithm,
		PayloadSize: cfg.Request.PayloadSize,
		CertReq:     *cfg.Request.CertReq,
		PolicyOID:   cfg.Request.PolicyOID,
	})
	if err != nil {
		return fail(1, "%v", err)
	}
	conns := &metrics.ConnStats{}
	client, _, err := transport.New(cfg, conns)
	if err != nil {
		return fail(1, "%v", err)
	}
	creds, err := cfg.ResolveCredentials()
	if err != nil {
		return fail(1, "credentials: %v", err)
	}

	// --- output ---
	runID, err := newRunID()
	if err != nil {
		return fail(1, "%v", err)
	}
	startedAt := time.Now()
	dir := report.RunDir(cfg.Output.Directory, cfg.Provider.Name, startedAt, runID)
	writer, err := report.NewWriter(dir)
	if err != nil {
		return fail(1, "%v", err)
	}
	defer writer.Close()

	logger := slog.New(slog.NewJSONHandler(
		io.MultiWriter(os.Stderr, writer.LogFile()),
		&slog.HandlerOptions{Level: slog.LevelInfo}))

	var artifacts *report.ArtifactStore
	if f.debugArtifacts {
		fmt.Fprintln(os.Stderr, report.ArtifactWarning)
		artifacts, err = report.NewArtifactStore(dir, f.artifactLimit)
		if err != nil {
			return fail(1, "%v", err)
		}
	}

	warnings := cfg.Warnings()
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "WARNING [%s]: %s\n", w.Field, w.Message)
		logger.Warn("configuration warning", "field", w.Field, "message", w.Message)
	}

	// --- the banner: what is about to happen, on screen and in the log ---
	banner(cfg, profile, f.maxRequests, runID, dir, trustSource)
	logger.Info("run starting",
		"run_id", runID,
		"provider", cfg.Provider.Name,
		"endpoint", cfg.RedactedEndpoint(),
		"environment", string(cfg.Provider.Environment),
		"profile", profile.Name,
		"planned_requests", profile.TotalPlanned(),
		"max_requests", f.maxRequests,
		"hard_cap", cfg.Limits.HardCap,
		"peak_target_tps", peakTPS(profile),
		"total_duration_seconds", profileDuration(profile).Seconds(),
		"max_concurrency", cfg.Load.MaxConcurrency,
		"retries", cfg.Limits.Retries,
		"trust_anchor", localPath(trustSource, f.redactHost))

	// --- wiring ---
	collector := metrics.NewCollector(startedAt)
	sampler := metrics.NewResourceSampler(startedAt, conns)
	sampler.Start()

	breaker := load.NewBreaker(cfg.Limits.AbortOnErrorRate, cfg.Limits.AbortWindow,
		cfg.Limits.AbortOnConsecutiveFailures)
	if f.noAutoAbort {
		breaker = load.NewBreaker(0, 1, 0)
		logger.Warn("automatic abort disabled by --no-auto-abort")
	}

	runner := &load.Runner{
		Cfg:       cfg,
		Profile:   profile,
		Builder:   builder,
		Verifier:  verifier,
		Client:    client,
		Creds:     creds,
		Collector: collector,
		Quota:     load.NewQuota(f.maxRequests, int64(cfg.Limits.HardCap)),
		Breaker:   breaker,
		Clock:     load.RealClock{},
		Sink:      writer,
		Conns:     conns,
		Log:       logger,
	}
	if artifacts != nil {
		runner.Artifacts = artifacts
	}

	outcome, runErr := runner.Run(ctx)
	sampler.Stop()

	// --- results are written even when the run was interrupted ---
	meta := buildMetadata(f, cfg, profile, runID, trustSource, outcome, warnings)
	summary := report.BuildSummary(meta, collector, outcome, sampler, cfg)
	series := collector.TimeSeries()
	writeResults(dir, writer, meta, summary, series, sampler, logger)

	printOutcome(summary, dir)

	// Verify before closing: the diagnostics below are written through logger,
	// which holds run.log open. Closing first would drop them from the log.
	recordsOK := verifyRecordIntegrity(dir, outcome.QuotaUsed+outcome.GuardRecords, logger)

	if err := writer.Close(); err != nil {
		logger.Error("cannot close result files", "error", err.Error())
	}

	if runErr != nil {
		return fail(1, "%v", runErr)
	}
	if !recordsOK {
		return fail(4, "the per-request record is incomplete; see the warning above")
	}
	switch outcome.Reason {
	case load.StopSignal:
		return fail(130, "run interrupted; a partial report was written to %s", dir)
	case load.StopBreaker:
		return fail(3, "run aborted automatically: %s", outcome.ReasonDetail)
	case load.StopError:
		return fail(1, "run failed: %s", outcome.ReasonDetail)
	}
	return nil
}

// loadInputs reads the configuration and the profile, and applies the safety
// gates that need one or both of them.
//
// The quota arithmetic is checked here rather than at the first request
// because a profile that cannot fit its budget must never send anything at
// all: the point of the ceiling is that it is never approached.
func loadInputs(f *runFlags) (*config.Config, *load.Profile, error) {
	cfg, err := config.LoadFile(f.cfgPath)
	if err != nil {
		return nil, nil, fail(1, "%v", err)
	}
	if f.outputDir != "" {
		cfg.Output.Directory = f.outputDir
	}
	if cfg.Provider.Environment == config.EnvLive && !f.ackLive {
		return nil, nil, fail(2, "provider.environment is \"live\": pass --acknowledge-live-environment to confirm "+
			"you intend to send load to a production service shared with real customer traffic")
	}
	if f.maxRequests > int64(cfg.Limits.HardCap) {
		return nil, nil, fail(2, "--max-requests (%d) exceeds the configured hard cap of %d",
			f.maxRequests, cfg.Limits.HardCap)
	}
	// validate uses limits.max_requests as the budget it checks profiles
	// against, so run must respect the same ceiling or the two commands
	// disagree about what fits.
	if cfg.Limits.MaxRequests > 0 && f.maxRequests > int64(cfg.Limits.MaxRequests) {
		return nil, nil, fail(2, "--max-requests (%d) exceeds limits.max_requests (%d) from the config",
			f.maxRequests, cfg.Limits.MaxRequests)
	}

	profile, err := load.LoadProfile(f.profilePath)
	if err != nil {
		return nil, nil, fail(1, "%v", err)
	}
	if err := profile.CheckAgainstQuota(f.maxRequests, int64(cfg.Limits.HardCap)); err != nil {
		return nil, nil, fail(2, "%v", err)
	}
	return cfg, profile, nil
}

// buildMetadata records everything needed to interpret the run afterwards:
// what was measured, against what, with which configuration, and what the tool
// warned about while doing it.
func buildMetadata(f *runFlags, cfg *config.Config, profile *load.Profile,
	runID, trustSource string, outcome *load.Outcome, warnings []config.Warning) report.Metadata {

	meta := report.Metadata{
		Schema:      report.SchemaVersion,
		RunID:       runID,
		Tool:        "tsa-bench",
		Version:     version,
		GoVersion:   runtime.Version(),
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		Hostname:    hostname(f.redactHost),
		StartedAt:   outcome.StartedAt,
		EndedAt:     outcome.EndedAt,
		CommandLine: commandLine(f.redactHost),
		Provider: report.ProviderInfo{
			Name:        cfg.Provider.Name,
			Endpoint:    cfg.RedactedEndpoint(),
			Environment: string(cfg.Provider.Environment),
			AuthType:    string(cfg.Provider.Auth.Type),
		},
		ProfileName: profile.Name,
		ProfileNote: profile.Note,
		RequestConfig: report.RequestInfo{
			HashAlgorithm: cfg.Request.HashAlgorithm,
			PayloadSize:   cfg.Request.PayloadSize,
			CertReq:       *cfg.Request.CertReq,
			TimeoutMS:     cfg.Request.Timeout.Milliseconds(),
			MaxClockSkewS: int64(cfg.Request.MaxClockSkew.Seconds()),
			RequireESS:    cfg.Request.RequireESS,
		},
		LoadConfig: report.LoadInfo{
			MaxConcurrency: cfg.Load.MaxConcurrency,
			StagePauseS:    int64(cfg.Load.StagePause.Seconds()),
			LagThresholdMS: cfg.Load.LagThreshold.Milliseconds(),
			GracePeriodS:   int64(cfg.Load.GracePeriod.Seconds()),
		},
		QuotaConfig: report.QuotaInfo{
			MaxRequests:    f.maxRequests,
			HardCap:        int64(cfg.Limits.HardCap),
			ProfilePlanned: profile.TotalPlanned(),
			ProfileReserve: profile.Reserve,
			Retries:        cfg.Limits.Retries,
		},
		TLSConfig: report.TLSInfo{
			MinVersion:         cfg.TLS.MinVersion,
			InsecureSkipVerify: cfg.TLS.InsecureSkipVerify,
			CAFile:             localPath(cfg.TLS.CAFile, f.redactHost),
			TSATrustSource:     localPath(trustSource, f.redactHost),
			ServerName:         cfg.TLS.ServerName,
		},
	}
	for _, w := range warnings {
		meta.Warnings = append(meta.Warnings, w.Field+": "+w.Message)
	}
	return meta
}

// writeResults persists every output file.
//
// A failure to write one file is logged and the rest are still attempted: a
// run has already spent irreversible quota by this point, so salvaging what
// can be salvaged beats abandoning the lot over one bad path.
func writeResults(dir string, writer *report.Writer, meta report.Metadata,
	summary *report.Summary, series []metrics.Second,
	sampler *metrics.ResourceSampler, logger *slog.Logger) {

	if err := writer.Flush(); err != nil {
		logger.Error("cannot flush attempt records", "error", err.Error())
	}
	if err := writer.WriteJSON("metadata.json", meta); err != nil {
		logger.Error("cannot write metadata.json", "error", err.Error())
	}
	if err := writer.WriteJSON("summary.json", summary); err != nil {
		logger.Error("cannot write summary.json", "error", err.Error())
	}
	if err := writer.WriteTimeSeries(series, sampler.Samples()); err != nil {
		logger.Error("cannot write timeseries.csv", "error", err.Error())
	}
	if err := report.WriteHTML(filepath.Join(dir, "report.html"), summary, series, time.Now()); err != nil {
		logger.Error("cannot write report.html", "error", err.Error())
	}
}

// verifyRecordIntegrity checks that requests.csv really holds one row per unit
// of quota consumed.
//
// The metrics in summary.json come from in-memory counters, so they can look
// perfect while the detailed record on disk is truncated or empty. That has a
// real cause worth catching: writing results onto a synced folder (iCloud
// Drive, Dropbox, OneDrive) or a network filesystem can leave a file that was
// held open and written in large buffered chunks silently empty.
// wantRows is the number of data rows the run should have produced: one per
// unit of quota consumed, plus the quota-guard markers, which are recorded but
// consume no quota.
func verifyRecordIntegrity(dir string, wantRows int64, logger *slog.Logger) bool {
	path := filepath.Join(dir, "requests.csv")

	rows, err := report.CountDataRows(path)
	if err != nil {
		logger.Error("cannot verify the per-request record", "path", path, "error", err.Error())
		fmt.Fprintf(os.Stderr, "\nWARNING: could not verify %s: %v\n", path, err)
		return false
	}
	if rows == wantRows {
		return true
	}

	logger.Error("per-request record is incomplete",
		"path", path, "rows", rows, "want_rows", wantRows)
	fmt.Fprintf(os.Stderr, "\nWARNING: %s holds %d rows but %d were expected.\n",
		path, rows, wantRows)
	fmt.Fprintln(os.Stderr,
		"The aggregate metrics in summary.json are still correct, but the per-request\n"+
			"audit record is incomplete. This usually means the results directory is on a\n"+
			"synced folder (iCloud Drive, Dropbox, OneDrive) or a network filesystem, which\n"+
			"can truncate a file that is held open during the run. Write results to local\n"+
			"storage with --output and rerun if you need the detailed record.")
	return false
}

func banner(cfg *config.Config, p *load.Profile, maxReq int64, runID, dir, trust string) {
	line := strings.Repeat("=", 72)
	fmt.Fprintln(os.Stderr, line)
	if cfg.Provider.Environment == config.EnvLive {
		fmt.Fprintln(os.Stderr, "  LIVE PRODUCTION LOAD TEST — quota consumed here is real and irreversible")
	} else {
		fmt.Fprintln(os.Stderr, "  LOAD TEST (test environment)")
	}
	fmt.Fprintln(os.Stderr, line)
	fmt.Fprintf(os.Stderr, "  provider          %s\n", cfg.Provider.Name)
	fmt.Fprintf(os.Stderr, "  endpoint          %s\n", cfg.RedactedEndpoint())
	fmt.Fprintf(os.Stderr, "  profile           %s (%d stages)\n", p.Name, len(p.Stages))
	fmt.Fprintf(os.Stderr, "  peak target rate  %.0f TPS\n", peakTPS(p))
	fmt.Fprintf(os.Stderr, "  planned duration  %s (excluding stage pauses)\n", profileDuration(p))
	fmt.Fprintf(os.Stderr, "  planned requests  %d\n", p.TotalPlanned())
	fmt.Fprintf(os.Stderr, "  max requests      %d (hard cap %d, reserve %d)\n",
		maxReq, cfg.Limits.HardCap, p.Reserve)
	fmt.Fprintf(os.Stderr, "  max concurrency   %d\n", cfg.Load.MaxConcurrency)
	fmt.Fprintf(os.Stderr, "  retries           %d\n", cfg.Limits.Retries)
	fmt.Fprintf(os.Stderr, "  TSA trust anchor  %s\n", trust)
	fmt.Fprintf(os.Stderr, "  run id            %s\n", runID)
	fmt.Fprintf(os.Stderr, "  results           %s\n", dir)
	fmt.Fprintln(os.Stderr, line)
}

func printOutcome(s *report.Summary, dir string) {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "stop reason       %s %s\n", s.StopReason, s.StopDetail)
	fmt.Fprintf(os.Stderr, "quota used        %d of %d (%d remaining)\n",
		s.QuotaUsed, s.QuotaBudget, s.QuotaRemaining)
	fmt.Fprintf(os.Stderr, "sent / verified   %d / %d\n", s.Overall.Sent, s.Overall.Verified)
	fmt.Fprintf(os.Stderr, "success rate      %.3f%%\n", s.Overall.SuccessRate*100)
	fmt.Fprintf(os.Stderr, "achieved rate     %.2f TPS\n", s.Overall.ActualSendTPS)
	fmt.Fprintf(os.Stderr, "latency p95/p99   %.1f / %.1f ms\n",
		s.Overall.Latency.P95MS, s.Overall.Latency.P99MS)
	if s.ClientBottleneck {
		fmt.Fprintf(os.Stderr, "client bottleneck YES — %s\n", s.ClientBottleneckWhy)
	} else {
		fmt.Fprintln(os.Stderr, "client bottleneck no")
	}
	fmt.Fprintf(os.Stderr, "results           %s\n", dir)
}

func peakTPS(p *load.Profile) float64 {
	var max float64
	for _, s := range p.Stages {
		if s.TPS > max {
			max = s.TPS
		}
	}
	return max
}

func profileDuration(p *load.Profile) time.Duration {
	var d time.Duration
	for _, s := range p.Stages {
		d += s.Duration
	}
	return d
}

func newRunID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate run id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// hostname records which machine produced the measurement, which matters
// because a capacity result is only comparable against others from the same
// host. --redact-host drops it for a run whose report will be published.
func hostname(redactHost bool) string {
	if redactHost {
		return redact.Mask
	}
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

// commandLine records how the tool was invoked, so a report can be traced back
// to the exact profile and flags that produced it. Secrets are never accepted
// as arguments, so this is safe to record verbatim - but the paths in it name
// the operator's own filesystem, which --redact-host suppresses for a report
// that will leave the organisation.
// localPath keeps a configured file path readable in a published report
// without naming the operator's filesystem: which anchor was used is part of
// the measurement, where it is kept on disk is not.
func localPath(p string, redactHost bool) string {
	if !redactHost || p == "" {
		return p
	}
	return filepath.Base(p)
}

func commandLine(redactHost bool) string {
	if redactHost {
		return redact.Mask
	}
	return strings.Join(os.Args, " ")
}
