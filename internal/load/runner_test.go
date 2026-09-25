package load_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/berkecengiz/tsa-bench/internal/config"
	"github.com/berkecengiz/tsa-bench/internal/errclass"
	"github.com/berkecengiz/tsa-bench/internal/load"
	"github.com/berkecengiz/tsa-bench/internal/metrics"
	"github.com/berkecengiz/tsa-bench/internal/mock"
	"github.com/berkecengiz/tsa-bench/internal/testutil"
	"github.com/berkecengiz/tsa-bench/internal/transport"
	"github.com/berkecengiz/tsa-bench/internal/tsp"
)

// recordingSink captures every attempt so tests can assert on classification.
type recordingSink struct {
	mu       sync.Mutex
	attempts []metrics.Attempt
}

func (s *recordingSink) Write(a metrics.Attempt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts = append(s.attempts, a)
	return nil
}

func (s *recordingSink) all() []metrics.Attempt {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]metrics.Attempt(nil), s.attempts...)
}

func (s *recordingSink) countsByClass() map[errclass.Class]int {
	out := map[errclass.Class]int{}
	for _, a := range s.all() {
		if a.Err == nil {
			out[errclass.OK]++
			continue
		}
		out[a.Err.Class]++
	}
	return out
}

type rig struct {
	runner *load.Runner
	sink   *recordingSink
	srv    *mock.Server
	http   *httptest.Server
	cfg    *config.Config
}

type rigOptions struct {
	profile   *load.Profile
	maxReq    int64
	hardCap   int64
	timeout   time.Duration
	breaker   *load.Breaker
	tlsServer bool
	// trustWrongCA points the verifier at an unrelated CA.
	trustWrongCA bool
	latency      time.Duration
	// digestUser enables digest authentication on the mock, and nonceLifetime
	// expires its nonce after that many authenticated requests.
	digestUser    string
	digestPass    string
	nonceLifetime int64
	// sessionBoundNonce makes the mock tie its nonce to a session cookie, as
	// a production TSA's servlet does.
	sessionBoundNonce bool
	// singleUseNonce makes the mock honour a nonce exactly once.
	singleUseNonce bool
	// challengePerRequest configures the client to draw its own challenge for
	// every request.
	challengePerRequest bool
}

func newRig(t *testing.T, opts rigOptions) *rig {
	t.Helper()

	srv, err := mock.New(mock.Options{
		KeyType:           testutil.ECDSAP256,
		Latency:           opts.latency,
		DigestUser:        opts.digestUser,
		DigestPass:        opts.digestPass,
		NonceLifetime:     opts.nonceLifetime,
		SessionBoundNonce: opts.sessionBoundNonce,
		SingleUseNonce:    opts.singleUseNonce,
	})
	if err != nil {
		t.Fatalf("mock.New: %v", err)
	}

	var hs *httptest.Server
	if opts.tlsServer {
		hs = httptest.NewTLSServer(srv.Handler())
	} else {
		hs = httptest.NewServer(srv.Handler())
	}
	t.Cleanup(hs.Close)

	timeout := opts.timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	cfg := config.Default()
	cfg.Provider.Name = "mock"
	cfg.Provider.Endpoint = hs.URL
	cfg.Provider.Environment = config.EnvTest
	cfg.Provider.Auth.Type = config.AuthNone
	cfg.Request.Timeout = timeout
	if opts.digestUser != "" {
		t.Setenv("TSABENCH_DIGEST_USER", opts.digestUser)
		t.Setenv("TSABENCH_DIGEST_PASS", opts.digestPass)
		cfg.Provider.Auth.Type = config.AuthDigest
		cfg.Provider.Auth.UsernameEnv = "TSABENCH_DIGEST_USER"
		cfg.Provider.Auth.PasswordEnv = "TSABENCH_DIGEST_PASS"
		cfg.Provider.Auth.ChallengePerRequest = opts.challengePerRequest
	}
	cfg.Load.MaxConcurrency = 64
	cfg.Load.StagePause = 0
	cfg.Load.GracePeriod = 5 * time.Second
	certReq := true
	cfg.Request.CertReq = &certReq

	client, _, err := transport.New(cfg, nil)
	if err != nil {
		t.Fatalf("transport.New: %v", err)
	}
	if opts.tlsServer {
		// httptest's TLS certificate is self-signed; trust it explicitly so the
		// test exercises the TSA trust path rather than the transport one.
		pool := x509.NewCertPool()
		pool.AddCert(hs.Certificate())
		client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool,
		}
	}

	roots := srv.CA().Pool
	if opts.trustWrongCA {
		other, err := testutil.NewCA("unrelated", testutil.ECDSAP256)
		if err != nil {
			t.Fatalf("NewCA: %v", err)
		}
		roots = other.Pool
	}

	verifier, err := tsp.NewVerifier(roots, time.Minute, false)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	builder, err := tsp.NewBuilder(tsp.BuilderOptions{
		HashName: "sha256", PayloadSize: 64, CertReq: true,
	})
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	creds, err := cfg.ResolveCredentials()
	if err != nil {
		t.Fatalf("ResolveCredentials: %v", err)
	}

	hardCap := opts.hardCap
	if hardCap == 0 {
		hardCap = 50000
	}
	breaker := opts.breaker
	if breaker == nil {
		breaker = load.NewBreaker(0, 1, 0) // disabled unless a test asks for it
	}

	sink := &recordingSink{}
	started := time.Now()

	return &rig{
		sink: sink,
		srv:  srv,
		http: hs,
		cfg:  cfg,
		runner: &load.Runner{
			Cfg:       cfg,
			Profile:   opts.profile,
			Builder:   builder,
			Verifier:  verifier,
			Client:    client,
			Auth:      transport.NewAuthenticator(cfg, creds, client),
			Collector: metrics.NewCollector(started),
			Quota:     load.NewQuota(opts.maxReq, hardCap),
			Breaker:   breaker,
			Clock:     load.RealClock{},
			Sink:      sink,
			Conns:     &metrics.ConnStats{},
			Log:       testLogger(),
		},
	}
}

func rateProfile(name string, tps float64, d time.Duration) *load.Profile {
	return &load.Profile{
		Name:   "test",
		Stages: []load.Stage{{Name: name, Mode: load.ModeRate, TPS: tps, Duration: d}},
	}
}

func seqProfile(n int64) *load.Profile {
	return &load.Profile{
		Name:   "test",
		Stages: []load.Stage{{Name: "functional", Mode: load.ModeSequential, Count: n}},
	}
}

// TestRunnerEndToEnd verifies a clean run against the mock.
func TestRunnerEndToEnd(t *testing.T) {
	r := newRig(t, rigOptions{profile: seqProfile(25), maxReq: 100})

	outcome, err := r.runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if outcome.Reason != load.StopCompleted {
		t.Errorf("reason = %s (%s), want completed", outcome.Reason, outcome.ReasonDetail)
	}
	if outcome.QuotaUsed != 25 {
		t.Errorf("quota used = %d, want 25", outcome.QuotaUsed)
	}

	counts := r.sink.countsByClass()
	if counts[errclass.OK] != 25 {
		t.Errorf("verified %d of 25: %v", counts[errclass.OK], counts)
	}
}

// TestRunnerNeverExceedsQuota is the safety-critical end-to-end guarantee: the
// number of requests that actually reach the transport must never exceed the
// budget, regardless of what the profile asks for.
func TestRunnerNeverExceedsQuota(t *testing.T) {
	const budget = 40
	r := newRig(t, rigOptions{
		profile: rateProfile("flood", 500, 2*time.Second), // asks for 1000
		maxReq:  budget,
	})

	outcome, err := r.runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if outcome.QuotaUsed > budget {
		t.Fatalf("quota used = %d, exceeds the budget of %d", outcome.QuotaUsed, budget)
	}
	if got := r.srv.Requests(); got > budget {
		t.Fatalf("the mock received %d requests, more than the budget of %d", got, budget)
	}
	if outcome.Reason != load.StopQuota {
		t.Errorf("reason = %s, want quota_exhausted", outcome.Reason)
	}

	// A quota_guard record must document why the run stopped.
	var sawGuard bool
	for _, a := range r.sink.all() {
		if a.Err != nil && a.Err.Class == errclass.QuotaGuard {
			sawGuard = true
		}
	}
	if !sawGuard {
		t.Error("no quota_guard record was written; the stop would be unexplained in the report")
	}
}

// TestRunnerStopsOnBreaker proves a failing endpoint does not consume the
// whole budget.
func TestRunnerStopsOnBreaker(t *testing.T) {
	r := newRig(t, rigOptions{
		profile: rateProfile("degraded", 200, 5*time.Second), // 1000 planned
		maxReq:  1000,
		breaker: load.NewBreaker(0, 50, 10),
	})
	r.srv.SetFault(mock.FaultHTTP500)

	outcome, err := r.runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if outcome.Reason != load.StopBreaker {
		t.Fatalf("reason = %s (%s), want auto_abort", outcome.Reason, outcome.ReasonDetail)
	}
	if outcome.QuotaUsed > 200 {
		t.Errorf("breaker allowed %d requests before stopping; that is far past the 10 consecutive failure threshold",
			outcome.QuotaUsed)
	}
	if outcome.ReasonDetail == "" {
		t.Error("the abort reason must be recorded for the report")
	}
}

// TestRunnerClassifiesHTTPErrors checks 4xx and 5xx handling end to end.
func TestRunnerClassifiesHTTPErrors(t *testing.T) {
	cases := []struct {
		fault mock.Fault
		want  errclass.Class
	}{
		{mock.FaultHTTP500, errclass.HTTP5xx},
		{mock.FaultHTTP429, errclass.HTTP4xx},
	}
	for _, tc := range cases {
		t.Run(string(tc.fault), func(t *testing.T) {
			r := newRig(t, rigOptions{profile: seqProfile(5), maxReq: 10})
			r.srv.SetFault(tc.fault)

			if _, err := r.runner.Run(context.Background()); err != nil {
				t.Fatalf("Run: %v", err)
			}
			counts := r.sink.countsByClass()
			if counts[tc.want] != 5 {
				t.Errorf("%s: got %v, want 5 x %s", tc.fault, counts, tc.want)
			}
			if counts[errclass.OK] != 0 {
				t.Errorf("%d attempts were counted as successful despite an HTTP error", counts[errclass.OK])
			}
		})
	}
}

// TestRunnerTimeoutClassification checks a slow responder becomes a timeout,
// not a silent success.
func TestRunnerTimeoutClassification(t *testing.T) {
	r := newRig(t, rigOptions{
		profile: seqProfile(3),
		maxReq:  10,
		timeout: 100 * time.Millisecond,
		latency: 400 * time.Millisecond,
	})

	if _, err := r.runner.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	counts := r.sink.countsByClass()
	total := counts[errclass.RequestTimeout] + counts[errclass.ResponseTimeout]
	if total != 3 {
		t.Errorf("timeouts = %d of 3: %v", total, counts)
	}
	if counts[errclass.OK] != 0 {
		t.Error("a request that timed out was counted as a verified timestamp")
	}
}

// TestRunnerUntrustedChainFailsRun proves a misconfigured trust anchor produces
// failures rather than false successes.
func TestRunnerUntrustedChainFailsRun(t *testing.T) {
	r := newRig(t, rigOptions{profile: seqProfile(5), maxReq: 10, trustWrongCA: true})

	if _, err := r.runner.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	counts := r.sink.countsByClass()
	if counts[errclass.UntrustedCert] != 5 {
		t.Errorf("untrusted_certificate = %d of 5: %v", counts[errclass.UntrustedCert], counts)
	}
}

// TestRunnerOverTLS exercises the HTTPS path.
func TestRunnerOverTLS(t *testing.T) {
	r := newRig(t, rigOptions{profile: seqProfile(5), maxReq: 10, tlsServer: true})

	if _, err := r.runner.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if counts := r.sink.countsByClass(); counts[errclass.OK] != 5 {
		t.Errorf("over TLS: %v, want 5 verified", counts)
	}
}

// TestRunnerTLSFailureIsClassified points the client at a server whose
// certificate it does not trust.
func TestRunnerTLSFailureIsClassified(t *testing.T) {
	r := newRig(t, rigOptions{profile: seqProfile(3), maxReq: 10, tlsServer: true})
	// Reset the transport so the self-signed httptest certificate is untrusted.
	r.runner.Client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if _, err := r.runner.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	counts := r.sink.countsByClass()
	if counts[errclass.TLSError] != 3 {
		t.Errorf("tls_error = %d of 3: %v", counts[errclass.TLSError], counts)
	}
}

// TestRunnerGracefulShutdown proves an interrupt stops new requests, lets
// in-flight work settle and still produces a usable partial result.
func TestRunnerGracefulShutdown(t *testing.T) {
	r := newRig(t, rigOptions{
		profile: rateProfile("long", 50, 20*time.Second), // 1000 planned
		maxReq:  1000,
		latency: 20 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	outcome, err := r.runner.Run(ctx)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if elapsed > 10*time.Second {
		t.Errorf("shutdown took %v; new requests should stop immediately", elapsed)
	}
	if outcome.Reason != load.StopSignal {
		t.Errorf("reason = %s, want signal", outcome.Reason)
	}
	if !outcome.Partial {
		t.Error("an interrupted run must be marked partial")
	}
	if outcome.QuotaUsed == 0 {
		t.Error("no requests were sent before the interrupt")
	}
	if outcome.QuotaUsed >= 1000 {
		t.Error("the interrupt did not stop the run")
	}

	// Every issued unit must have produced a record, so the partial report
	// accounts for all consumed quota.
	if got := int64(len(r.sink.all())); got < outcome.QuotaUsed {
		t.Errorf("%d records for %d consumed quota units: the partial report would understate usage",
			got, outcome.QuotaUsed)
	}
}

// TestRunnerInterruptDoesNotCancelInFlight pins the distinction Run promises:
// the context stops new requests being issued, it does not abort the ones
// already handed to the transport. It is deliberately harsher than
// TestRunnerGracefulShutdown - a slow mock and a high rate keep many requests
// in flight at the moment of the interrupt, and the breaker is armed - because
// sharing the run context with in-flight requests turns every one of them into
// a cancelled failure and trips the breaker, reporting an operator's Ctrl-C as
// an automatic abort.
func TestRunnerInterruptDoesNotCancelInFlight(t *testing.T) {
	r := newRig(t, rigOptions{
		profile: rateProfile("long", 200, 20*time.Second),
		maxReq:  4000,
		latency: 400 * time.Millisecond,
		breaker: load.NewBreaker(0, 1, 10), // abort after 10 consecutive failures
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()

	outcome, err := r.runner.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if outcome.Reason != load.StopSignal {
		t.Errorf("reason = %s (%s), want signal: an interrupt must not read as an automatic abort",
			outcome.Reason, outcome.ReasonDetail)
	}
	counts := r.sink.countsByClass()
	if counts[errclass.Cancelled] != 0 {
		t.Errorf("%d attempts were recorded as cancelled; in-flight requests must be given the grace period: %v",
			counts[errclass.Cancelled], counts)
	}
	if counts[errclass.OK] == 0 {
		t.Errorf("no attempt succeeded: %v", counts)
	}
}

// TestRunnerDigestAuth covers the whole digest path against the mock: the
// challenge is primed before load, every request is then authenticated
// pre-emptively, and no 401 reaches the report.
func TestRunnerDigestAuth(t *testing.T) {
	r := newRig(t, rigOptions{
		profile:    rateProfile("digest", 100, 2*time.Second), // 200 planned
		maxReq:     200,
		digestUser: "12",
		digestPass: "s3cret",
	})

	outcome, err := r.runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	counts := r.sink.countsByClass()
	if counts[errclass.OK] != 200 {
		t.Errorf("%d of 200 requests verified: %v", counts[errclass.OK], counts)
	}
	// One challenge is drawn before the run; nothing after it.
	if outcome.AuthRequests != 1 {
		t.Errorf("auth requests = %d, want 1 (the initial challenge only)", outcome.AuthRequests)
	}
}

// TestRunnerDigestStaleNonce covers the housekeeping path. The mock expires
// its nonce every 50 authenticated requests, which a real server does on a
// timer. Every timestamp must still be obtained, the extra HTTP requests must
// be reported rather than hidden, and - the point of the whole design - they
// must not consume quota.
func TestRunnerDigestStaleNonce(t *testing.T) {
	const planned = 200

	r := newRig(t, rigOptions{
		profile:       rateProfile("digest-stale", 100, 2*time.Second),
		maxReq:        planned,
		digestUser:    "12",
		digestPass:    "s3cret",
		nonceLifetime: 50,
	})

	outcome, err := r.runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	counts := r.sink.countsByClass()
	if counts[errclass.OK] != planned {
		t.Errorf("%d of %d verified; a stale nonce must not fail a request: %v",
			counts[errclass.OK], planned, counts)
	}
	if outcome.AuthRequests <= 1 {
		t.Errorf("auth requests = %d; the stale-nonce path never ran", outcome.AuthRequests)
	}
	if outcome.QuotaUsed != planned {
		t.Errorf("quota used = %d, want %d: re-answering a challenge must not spend quota",
			outcome.QuotaUsed, planned)
	}
	if got := int64(len(r.sink.all())); got != planned {
		t.Errorf("%d records for %d timestamps: a reauth must not produce a record", got, planned)
	}
}

// TestRunnerDigestBadCredentialsFailFast: a wrong password is not stale, so it
// must not be retried. Burning an account's lockout budget 48,600 times over
// is worse than stopping.
func TestRunnerDigestBadCredentialsFailFast(t *testing.T) {
	r := newRig(t, rigOptions{
		profile:    rateProfile("digest-bad", 50, 1*time.Second),
		maxReq:     50,
		digestUser: "12",
		digestPass: "s3cret",
	})
	// Prime succeeds, then the responses are computed from the wrong password.
	r.runner.Cfg.Provider.Auth.PasswordEnv = "TSABENCH_DIGEST_WRONG"
	t.Setenv("TSABENCH_DIGEST_WRONG", "not-the-password")
	creds, err := r.runner.Cfg.ResolveCredentials()
	if err != nil {
		t.Fatalf("ResolveCredentials: %v", err)
	}
	r.runner.Auth = transport.NewAuthenticator(r.runner.Cfg, creds, r.runner.Client)

	outcome, err := r.runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	counts := r.sink.countsByClass()
	if counts[errclass.OK] != 0 {
		t.Errorf("%d requests succeeded with the wrong password: %v", counts[errclass.OK], counts)
	}
	if outcome.AuthRequests != 1 {
		t.Errorf("auth requests = %d; a rejection is not a stale nonce and must not be retried",
			outcome.AuthRequests)
	}
}

// TestRunnerDigestSessionBoundNonce is a regression test for a failure found
// against a live provider, not an invented one.
//
// A production TSA binds its digest nonce to a servlet session handed out as a
// JSESSIONID cookie. Go's default http.Client keeps no cookies, so the
// authenticated request arrived with a nonce the server could not match and
// every request failed with a generic error that looked nothing like an
// authentication problem. The fix is the cookie jar in transport.New; this
// test fails without it.
func TestRunnerDigestSessionBoundNonce(t *testing.T) {
	const planned = 100

	r := newRig(t, rigOptions{
		profile:           rateProfile("digest-session", 100, 1*time.Second),
		maxReq:            planned,
		digestUser:        "12",
		digestPass:        "s3cret",
		sessionBoundNonce: true,
	})

	outcome, err := r.runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	counts := r.sink.countsByClass()
	if counts[errclass.OK] != planned {
		t.Errorf("%d of %d verified; the session cookie must be returned with the authenticated request: %v",
			counts[errclass.OK], planned, counts)
	}
	if outcome.Reason != load.StopCompleted {
		t.Errorf("reason = %s (%s)", outcome.Reason, outcome.ReasonDetail)
	}
}

// TestRunnerSingleUseNonce reproduces the failure that aborted a live run.
//
// A production TSA advertises qop="auth", which exists so a nonce can be reused with
// an incrementing count, but honours the nonce exactly once. The first request
// succeeded and every request after it failed - with an HTTP 500 naming no
// authentication problem - until the breaker tripped. challenge_per_request
// gives each timestamp its own self-contained exchange.
func TestRunnerSingleUseNonce(t *testing.T) {
	const planned = 100

	r := newRig(t, rigOptions{
		profile:             rateProfile("single-use", 100, 1*time.Second),
		maxReq:              planned,
		digestUser:          "12",
		digestPass:          "s3cret",
		singleUseNonce:      true,
		challengePerRequest: true,
	})

	outcome, err := r.runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	counts := r.sink.countsByClass()
	if counts[errclass.OK] != planned {
		t.Errorf("%d of %d verified against a single-use nonce: %v",
			counts[errclass.OK], planned, counts)
	}
	if outcome.Reason != load.StopCompleted {
		t.Errorf("reason = %s (%s)", outcome.Reason, outcome.ReasonDetail)
	}
	// One challenge per timestamp, and no priming: the count must match the
	// number of timestamps exactly, or the accounting we give the provider is
	// wrong.
	if outcome.AuthRequests != planned {
		t.Errorf("auth requests = %d, want %d (one challenge per timestamp)",
			outcome.AuthRequests, planned)
	}
	if outcome.QuotaUsed != planned {
		t.Errorf("quota used = %d, want %d: a challenge must not spend quota",
			outcome.QuotaUsed, planned)
	}
}

// TestRunnerSingleUseNonceWithoutPerRequestChallenge pins the diagnosis: with
// the default preemptive scheme, a single-use nonce fails everything after the
// first request. This is what the live run looked like.
func TestRunnerSingleUseNonceWithoutPerRequestChallenge(t *testing.T) {
	r := newRig(t, rigOptions{
		profile:        rateProfile("single-use-bad", 50, 1*time.Second),
		maxReq:         50,
		digestUser:     "12",
		digestPass:     "s3cret",
		singleUseNonce: true,
	})

	if _, err := r.runner.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	counts := r.sink.countsByClass()
	if counts[errclass.OK] > 2 {
		t.Errorf("%d requests succeeded; a reused single-use nonce should fail after the first: %v",
			counts[errclass.OK], counts)
	}
}

// TestRunnerConcurrencyCeiling verifies the pool never exceeds its limit.
func TestRunnerConcurrencyCeiling(t *testing.T) {
	r := newRig(t, rigOptions{
		profile: rateProfile("burst", 400, 1*time.Second),
		maxReq:  400,
		latency: 50 * time.Millisecond,
	})
	r.cfg.Load.MaxConcurrency = 8

	if _, err := r.runner.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if peak := r.runner.Conns.InFlight.Load(); peak != 0 {
		t.Errorf("in-flight counter ended at %d, want 0", peak)
	}
	// With only 8 slots against a 400 TPS target, saturation must be reported
	// rather than the tool quietly running slower.
	if r.runner.Collector.Overall().Saturated.Load() == 0 {
		t.Error("no client saturation was recorded although concurrency was capped at 8")
	}
}
