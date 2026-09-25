package load

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"

	"github.com/berkecengiz/tsa-bench/internal/config"
	"github.com/berkecengiz/tsa-bench/internal/errclass"
	"github.com/berkecengiz/tsa-bench/internal/metrics"
	"github.com/berkecengiz/tsa-bench/internal/transport"
	"github.com/berkecengiz/tsa-bench/internal/tsp"
)

// Sink receives every completed attempt, in completion order.
type Sink interface {
	Write(metrics.Attempt) error
}

// StopReason explains why a run ended.
type StopReason string

const (
	StopCompleted StopReason = "completed"
	StopSignal    StopReason = "signal"
	StopQuota     StopReason = "quota_exhausted"
	StopBreaker   StopReason = "auto_abort"
	StopError     StopReason = "error"
)

// Outcome summarises a finished run.
type Outcome struct {
	Reason       StopReason
	ReasonDetail string
	StartedAt    time.Time
	EndedAt      time.Time
	QuotaUsed    int64
	QuotaBudget  int64
	// AuthRequests counts extra HTTP requests spent on authentication: the
	// initial challenge, a per-request challenge, or re-answering a stale
	// nonce. They issue no timestamp and consume no quota, so they are the
	// difference between the run's HTTP traffic and its quota usage.
	AuthRequests int64
	Partial      bool
}

// Runner executes a profile against a provider.
type Runner struct {
	Cfg       *config.Config
	Profile   *Profile
	Builder   *tsp.Builder
	Verifier  *tsp.Verifier
	Client    *http.Client
	Auth      *transport.Authenticator
	Collector *metrics.Collector
	Quota     *Quota
	Breaker   *Breaker
	Clock     Clock
	Sink      Sink
	Conns     *metrics.ConnStats
	Log       *slog.Logger
	// Artifacts, when non-nil, receives raw request/response bodies. It is only
	// wired up under --debug-artifacts.
	Artifacts ArtifactWriter

	// reqCtx bounds requests that are already in flight. It is deliberately
	// detached from the context passed to Run: that one stops the *issuing*
	// of new requests, while in-flight requests are given the grace period.
	reqCtx context.Context
	sem    chan struct{}
	wg     sync.WaitGroup
	// stopped is read on every dispatch and every sequential iteration,
	// including from the scheduler goroutine, so it is an atomic rather than a
	// field behind stopMu: a stop check must never queue behind a worker.
	// stopMu still guards reason and detail, which are written once and read
	// after the run.
	stopped atomic.Bool
	stopMu  sync.Mutex
	reason  StopReason
	detail  string
}

// ArtifactWriter stores raw protocol bytes for debugging.
type ArtifactWriter interface {
	WriteAttempt(seq int64, requestDER, responseBody []byte) error
}

// Run executes every stage in order and returns once all in-flight work has
// settled.
//
// ctx cancels the *issuing* of new requests. Requests already in flight are
// given the configured grace period to finish so the report is not littered
// with self-inflicted cancellations.
func (r *Runner) Run(ctx context.Context) (*Outcome, error) {
	if r.Clock == nil {
		r.Clock = RealClock{}
	}
	if r.Log == nil {
		r.Log = slog.Default()
	}
	r.sem = make(chan struct{}, r.Cfg.Load.MaxConcurrency)

	// Requests already handed to the transport must survive the cancellation
	// of ctx; otherwise a Ctrl-C aborts every one of them, their quota is
	// spent on records classed "cancelled", and drain has nothing left to
	// wait for. cancelRequests is what finally ends the grace period.
	reqCtx, cancelRequests := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelRequests()
	r.reqCtx = reqCtx

	out := &Outcome{
		StartedAt:   r.Clock.Now(),
		QuotaBudget: r.Quota.Budget(),
		Reason:      StopCompleted,
	}

	// Draw the first digest challenge before any quota is at stake, so the
	// load itself runs at one HTTP request per timestamp.
	if err := r.primeAuth(reqCtx); err != nil {
		out.Reason = StopError
		out.ReasonDetail = err.Error()
		out.Partial = true
		out.EndedAt = r.Clock.Now()
		return out, nil
	}

	for i, stage := range r.Profile.Stages {
		if r.isStopped() || ctx.Err() != nil {
			break
		}

		planned := stage.Planned()
		remaining := r.Quota.Remaining()
		if remaining <= 0 {
			r.stop(StopQuota, "no quota remaining before stage "+stage.Name)
			break
		}

		// Plan within the remaining budget rather than relying on the guard to
		// catch the overrun. The guard still backs this up at issue time, but a
		// run that knowingly walks into its own ceiling is a bug, not a safety
		// feature.
		truncated := false
		if planned > remaining {
			r.Log.Warn("stage truncated by remaining quota",
				"stage", stage.Name, "requested", planned, "remaining", remaining)
			planned = remaining
			truncated = true
		}

		stats := r.Collector.Stage(stage.Name, stage.TPS, planned)
		stats.StartedAt = r.Clock.Now()

		r.Log.Info("stage starting",
			"stage", stage.Name, "mode", string(stage.Mode),
			"target_tps", stage.TPS, "planned_requests", planned,
			"quota_remaining", remaining)

		err := r.runStage(ctx, stage, planned, stats)
		stats.EndedAt = r.Clock.Now()

		actualTPS := 0.0
		if d := stats.EndedAt.Sub(stats.StartedAt).Seconds(); d > 0 {
			actualTPS = float64(stats.Sent.Load()) / d
		}
		r.Log.Info("stage finished",
			"stage", stage.Name,
			"sent", stats.Sent.Load(),
			"completed", stats.Completed.Load(),
			"success", stats.Success.Load(),
			"failure", stats.Failure.Load(),
			"actual_send_tps", fmt.Sprintf("%.2f", actualTPS))

		// A truncated stage means the profile did not fit the budget. Report it
		// as quota-limited: calling such a run "completed" would misrepresent a
		// partial measurement as a full one.
		if truncated && !r.isStopped() {
			detail := fmt.Sprintf("stage %s was truncated to %d requests by the remaining budget",
				stage.Name, planned)
			r.stop(StopQuota, detail)
			r.recordQuotaGuard(stats)
		}

		if err != nil && !errors.Is(err, errStopped) {
			if ctx.Err() == nil {
				r.stop(StopError, err.Error())
				out.Reason = StopError
				out.ReasonDetail = err.Error()
				break
			}
		}
		if r.isStopped() || ctx.Err() != nil {
			break
		}

		// Pause between stages. This consumes no quota and gives the provider's
		// queues time to drain, so the next stage measures the service rather
		// than the backlog of the previous one.
		if i < len(r.Profile.Stages)-1 {
			pause := r.Cfg.Load.StagePause
			if stage.PauseAfter != nil {
				pause = *stage.PauseAfter
			}
			if pause > 0 {
				r.Log.Info("pausing between stages", "duration", pause.String())
				if err := r.Clock.Sleep(ctx, pause); err != nil {
					break
				}
			}
		}
	}

	// Drain: stop issuing, let in-flight requests finish within the grace
	// period, then cut off whatever is still hanging.
	drained := r.drain(r.Cfg.Load.GracePeriod)
	cancelRequests()

	out.EndedAt = r.Clock.Now()
	out.QuotaUsed = r.Quota.Used()
	out.AuthRequests = r.Auth.Requests()

	r.stopMu.Lock()
	if r.stopped.Load() && r.reason != "" {
		out.Reason = r.reason
		out.ReasonDetail = r.detail
	}
	r.stopMu.Unlock()

	if ctx.Err() != nil && out.Reason == StopCompleted {
		out.Reason = StopSignal
		out.ReasonDetail = "interrupted by signal"
	}
	out.Partial = out.Reason != StopCompleted
	if !drained {
		// Quota was consumed for those requests and their records may never
		// have reached the sink, so the measurement is incomplete regardless
		// of why issuing stopped.
		out.Partial = true
		out.ReasonDetail += " (grace period elapsed with requests still in flight)"
	}
	return out, nil
}

var errStopped = errors.New("run stopped")

func (r *Runner) runStage(ctx context.Context, stage Stage, planned int64, stats *metrics.StageStats) error {
	if planned <= 0 {
		return nil
	}

	if stage.Mode == ModeSequential {
		return r.runSequential(ctx, planned, stats)
	}

	sched := &Scheduler{
		Rate:         stage.TPS,
		Clock:        r.Clock,
		LagThreshold: r.Cfg.Load.LagThreshold,
	}
	return sched.Run(ctx, r.Clock.Now(), planned, func(tk Tick) error {
		return r.dispatch(ctx, stats, tk)
	})
}

// runSequential issues one request at a time and waits for each. It exists to
// prove the full verification chain works before any load is applied: if the
// first hundred requests cannot be verified, running 48,500 more would only
// waste the provider's quota.
func (r *Runner) runSequential(ctx context.Context, count int64, stats *metrics.StageStats) error {
	for i := int64(0); i < count; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if r.isStopped() {
			return errStopped
		}

		seq, err := r.acquire(stats)
		if err != nil {
			return err
		}

		now := r.Clock.Now()
		r.Collector.RecordSent(stats, now)
		if r.perform(seq, stats, now, now, 0) {
			return errStopped
		}
	}
	return nil
}

// dispatch releases one scheduled request into the worker pool.
func (r *Runner) dispatch(ctx context.Context, stats *metrics.StageStats, tk Tick) error {
	if r.isStopped() {
		return errStopped
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Saturation detection: if no worker slot is free at the scheduled moment,
	// the client - not the TSA - is the constraint. Record it, then wait. The
	// request is never silently dropped and the rate is never silently lowered.
	select {
	case r.sem <- struct{}{}:
	default:
		r.Collector.RecordSaturation(stats)
		select {
		case r.sem <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if tk.Lag > r.Cfg.Load.LagThreshold {
		r.Collector.RecordSaturation(stats)
	}

	seq, err := r.acquire(stats)
	if err != nil {
		<-r.sem
		return err
	}

	startedAt := r.Clock.Now()
	r.Collector.RecordSent(stats, startedAt)

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer func() { <-r.sem }()

		r.perform(seq, stats, tk.Scheduled, startedAt, tk.Lag)
	}()
	return nil
}

// acquire takes one unit of the engagement budget, stopping the run and
// marking the audit record at the point the budget ran out.
func (r *Runner) acquire(stats *metrics.StageStats) (int64, error) {
	seq, err := r.Quota.Acquire()
	if err != nil {
		r.stop(StopQuota, "quota exhausted during "+stats.Name)
		r.recordQuotaGuard(stats)
		return 0, errStopped
	}
	return seq, nil
}

// perform runs one attempt and files it everywhere it belongs - the collector,
// the audit sink and the circuit breaker - reporting whether the breaker
// tripped on this attempt. Both the sequential and the scheduled path go
// through here so the accounting order cannot drift between them.
func (r *Runner) perform(seq int64, stats *metrics.StageStats, scheduled, startedAt time.Time, lag time.Duration) bool {
	a := r.attempt(r.requestContext(), seq, stats.Name, scheduled, startedAt, lag)
	r.Collector.Record(stats, a)
	r.writeSink(a)

	if r.Breaker != nil && !selfInflicted(a) && r.Breaker.Record(!a.Succeeded()) {
		r.stop(StopBreaker, r.Breaker.Reason())
		return true
	}
	return false
}

// attempt performs exactly one physical request: build, send, verify.
func (r *Runner) attempt(ctx context.Context, seq int64, stage string, scheduled, startedAt time.Time, lag time.Duration) metrics.Attempt {
	a := metrics.Attempt{
		Stage:       stage,
		Sequence:    seq,
		ScheduledAt: scheduled,
		StartedAt:   startedAt,
		ScheduleLag: lag,
	}

	req, err := r.Builder.Build()
	if err != nil {
		a.Err = errclass.New(errclass.UnknownError, "build request: "+err.Error())
		a.CompletedAt = r.Clock.Now()
		a.Total = a.CompletedAt.Sub(startedAt)
		return a
	}

	netStart := time.Now()
	status, contentType, body, httpErr := r.send(ctx, req.DER)
	a.Network = time.Since(netStart)
	a.HTTPStatus = status

	if httpErr != nil {
		a.Err = httpErr
		a.CompletedAt = r.Clock.Now()
		a.Total = a.CompletedAt.Sub(startedAt)
		return a
	}

	verifyStart := time.Now()
	res, verr := r.Verifier.Verify(req, tsp.HTTPResponse{
		StatusCode:  status,
		ContentType: contentType,
		Body:        body,
		SentAt:      netStart,
		ReceivedAt:  netStart.Add(a.Network),
	})
	a.Verify = time.Since(verifyStart)
	a.Err = verr
	if res != nil {
		a.ClockSkew = res.ClockSkew
		a.Warnings = res.Warnings
	}

	a.CompletedAt = r.Clock.Now()
	a.Total = a.CompletedAt.Sub(startedAt)

	if r.Artifacts != nil {
		if err := r.Artifacts.WriteAttempt(seq, req.DER, body); err != nil {
			r.Log.Warn("cannot write debug artifact", "error", err.Error())
		}
	}
	return a
}

// send performs the HTTP round trip and returns a classified error on failure.
func (r *Runner) send(ctx context.Context, der []byte) (int, string, []byte, *errclass.Error) {
	reqCtx, cancel := context.WithTimeout(ctx, r.Cfg.Request.Timeout)
	defer cancel()

	// wroteRequest is set from net/http's write goroutine and read on this
	// one, so it must be atomic. The trace is installed unconditionally:
	// without it every timeout would be classified as a request timeout, even
	// when the request was fully sent and the TSA simply never answered.
	var wroteRequest atomic.Bool
	trace := &httptrace.ClientTrace{
		WroteRequest: func(httptrace.WroteRequestInfo) { wroteRequest.Store(true) },
	}
	if r.Conns != nil {
		r.Conns.InFlight.Add(1)
		defer r.Conns.InFlight.Add(-1)
		// Dialed and Closed are counted in the transport's dialer, which sees
		// every connection teardown; httptrace does not.
		trace.GotConn = func(info httptrace.GotConnInfo) {
			if info.Reused {
				r.Conns.Reused.Add(1)
			}
		}
	}

	resp, err := transport.PostTimestamp(
		reqCtx, r.Client, r.Auth, r.Cfg.Provider.Endpoint, der, trace)
	if err != nil {
		return 0, "", nil, classifySendError(err, wroteRequest.Load())
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, transport.MaxResponseBytes))
	if err != nil {
		return resp.StatusCode, resp.Header.Get("Content-Type"), nil,
			errclass.Classify(err, true)
	}
	return resp.StatusCode, resp.Header.Get("Content-Type"), body, nil
}

// drawChallenge fetches one digest challenge and the session it belongs to,
// counting the request. It carries no timestamp request, so the server issues
// nothing and no quota is spent.
// classifySendError sorts the three things that can go wrong before a response
// exists: a request that could not be built, a challenge that could not be
// answered - a credential or configuration fault, not the service's - and
// everything else, which is the network.
func classifySendError(err error, wroteRequest bool) *errclass.Error {
	var ae *transport.AuthError
	if errors.As(err, &ae) {
		return errclass.New(errclass.HTTP4xx, ae.Error())
	}
	var re *transport.RequestError
	if errors.As(err, &re) {
		return errclass.New(errclass.UnknownError, re.Error())
	}
	return errclass.Classify(err, wroteRequest)
}

// primeAuth obtains the first challenge, if the scheme needs one, before the
// run starts. The exchange itself belongs to the Authenticator; the runner
// only decides when it happens and reports it.
func (r *Runner) primeAuth(ctx context.Context) error {
	reqCtx, cancel := context.WithTimeout(ctx, r.Cfg.Request.Timeout)
	defer cancel()

	before := r.Auth.Requests()
	if err := r.Auth.Prime(reqCtx); err != nil {
		return err
	}
	if r.Auth.Requests() > before {
		r.Log.Info("digest challenge obtained", "endpoint", r.Cfg.RedactedEndpoint())
	}
	return nil
}

// requestContext returns the context in-flight requests run under. It falls
// back to Background for callers that drive a Runner without Run.
func (r *Runner) requestContext() context.Context {
	if r.reqCtx == nil {
		return context.Background()
	}
	return r.reqCtx
}

// selfInflicted reports whether an attempt failed only because we cancelled
// it. Feeding these to the breaker would let an operator's Ctrl-C look like a
// provider outage and turn exit 130 into an "automatic abort".
func selfInflicted(a metrics.Attempt) bool {
	return a.Err != nil && !a.Err.Class.CountsAgainstProvider()
}

// recordQuotaGuard writes an audit row marking the point where the budget ran
// out. It is deliberately kept out of the collector: nothing was sent, so
// counting it as a completed failure would understate the success rate and
// push Completed above Sent.
func (r *Runner) recordQuotaGuard(stats *metrics.StageStats) {
	now := r.Clock.Now()
	a := metrics.Attempt{
		Stage:       stats.Name,
		ScheduledAt: now,
		StartedAt:   now,
		CompletedAt: now,
		Err:         errclass.New(errclass.QuotaGuard, "request budget exhausted; no further requests were sent"),
	}
	r.writeSink(a)
}

func (r *Runner) writeSink(a metrics.Attempt) {
	if r.Sink == nil {
		return
	}
	if err := r.Sink.Write(a); err != nil {
		r.Log.Warn("cannot write attempt record", "error", err.Error())
	}
}

// drain waits for in-flight requests, up to the grace period.
func (r *Runner) drain(grace time.Duration) bool {
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	if grace <= 0 {
		grace = 30 * time.Second
	}
	t := time.NewTimer(grace)
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C:
		r.Log.Warn("grace period elapsed with requests still in flight")
		return false
	}
}

func (r *Runner) stop(reason StopReason, detail string) {
	r.stopMu.Lock()
	defer r.stopMu.Unlock()
	// CompareAndSwap under stopMu, so the first caller to win also becomes the
	// one whose reason is recorded.
	if !r.stopped.CompareAndSwap(false, true) {
		return
	}
	r.reason = reason
	r.detail = detail
	r.Quota.Close()
	r.Log.Warn("run stopping", "reason", string(reason), "detail", detail)
}

func (r *Runner) isStopped() bool { return r.stopped.Load() }
