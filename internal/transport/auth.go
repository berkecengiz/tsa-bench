package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"

	"github.com/berkecengiz/tsa-bench/internal/config"
	"github.com/berkecengiz/tsa-bench/internal/tsp"
)

// Authenticator applies the configured authentication scheme to timestamp
// requests.
//
// It is the single owner of the digest state machine. Digest is not one
// behaviour but three - prime a shared challenge before the run, draw a fresh
// challenge per request when the server invalidates its nonce after one use,
// and re-answer a challenge the server declares stale - and each of them has
// to agree with the others about cookies, counters and which credential is in
// play. Spread across the load runner and the doctor command they drifted:
// doctor did not implement the stale-nonce retry at all, so the pre-flight
// check did not exercise the path the run depends on.
//
// Keeping it here also means the load generator does not need to know what a
// WWW-Authenticate header is, and a future scheme is added in one place.
type Authenticator struct {
	creds      *config.Credentials
	authType   config.AuthType
	perRequest bool
	endpoint   string
	client     *http.Client

	// requests counts HTTP requests spent purely on authentication. They issue
	// no timestamp and consume no quota, so they are the difference between
	// the run's HTTP traffic and its quota usage.
	requests atomic.Int64
}

// AuthError marks a failure to answer a challenge, as distinct from a
// transport failure reaching the server. Callers classify the two differently:
// one is a configuration or credential problem, the other is the network.
type AuthError struct{ Err error }

func (e *AuthError) Error() string { return e.Err.Error() }
func (e *AuthError) Unwrap() error { return e.Err }

// UsesPerRequestChallenge reports whether each request carries its own digest
// exchange. NewClient consults it too: a cookie jar must not be installed in
// that mode, because net/http appends jar cookies to the Cookie header the
// Authenticator has already set, and one jar shared by every worker races.
func UsesPerRequestChallenge(cfg *config.Config) bool {
	return cfg.Provider.Auth.Type == config.AuthDigest && cfg.Provider.Auth.ChallengePerRequest
}

// NewAuthenticator builds the authenticator for a configuration. client is the
// client its own authentication requests are sent on, which is the same client
// the timestamp requests use.
func NewAuthenticator(cfg *config.Config, creds *config.Credentials, client *http.Client) *Authenticator {
	return &Authenticator{
		creds:      creds,
		authType:   cfg.Provider.Auth.Type,
		perRequest: cfg.Provider.Auth.ChallengePerRequest,
		endpoint:   cfg.Provider.Endpoint,
		client:     client,
	}
}

// Requests returns how many HTTP requests were spent on authentication.
func (a *Authenticator) Requests() int64 { return a.requests.Load() }

// Prime obtains the first challenge, when the scheme needs one before it can
// authenticate anything.
//
// Digest cannot sign a request until the server has issued a nonce, so without
// this every worker would draw its own 401 in the opening moments of the run.
// One request here gets the challenge for all of them. It carries no timestamp
// request, so the server issues nothing and no quota is consumed. In
// per-request mode there is nothing to prime: each exchange is self-contained.
func (a *Authenticator) Prime(ctx context.Context) error {
	if a.authType != config.AuthDigest || a.perRequest || a.creds.HasChallenge() {
		return nil
	}
	challenge, _, err := a.draw(ctx, nil)
	if err != nil {
		return fmt.Errorf("prime digest authentication: %w", err)
	}
	if err := a.creds.SetChallenge(challenge); err != nil {
		return fmt.Errorf("prime digest authentication: %w", err)
	}
	return nil
}

// Authorize prepares one request for sending.
//
// In per-request digest mode the exchange is self-contained: the challenge and
// the session cookie it belongs to are carried on this request alone, so
// concurrent workers never overwrite each other's nonce. Otherwise the shared
// credential is applied.
func (a *Authenticator) Authorize(ctx context.Context, req *http.Request, trace *httptrace.ClientTrace) error {
	if !a.perRequest || a.authType != config.AuthDigest {
		a.creds.Apply(req, a.authType)
		return nil
	}

	challenge, cookie, err := a.draw(ctx, trace)
	if err != nil {
		return err
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if err := a.creds.AuthorizeOnce(req, challenge); err != nil {
		return &AuthError{Err: fmt.Errorf("cannot answer digest challenge: %w", err)}
	}
	return nil
}

// RetryStale reports whether resp is a 401 carrying a fresh challenge that
// should be answered and the request re-sent.
//
// A stale nonce is housekeeping, not a failure of the service: the server
// issued no timestamp and no quota was spent. On true, the new challenge has
// been stored and the caller should rebuild the request, call Authorize and
// send it once more. The caller must not have consumed resp.Body first.
func (a *Authenticator) RetryStale(resp *http.Response) (bool, error) {
	if resp.StatusCode != http.StatusUnauthorized ||
		a.authType != config.AuthDigest || a.perRequest ||
		!config.IsStaleChallenge(resp) {
		return false, nil
	}
	if err := a.creds.SetChallenge(resp.Header.Get("WWW-Authenticate")); err != nil {
		return true, &AuthError{Err: fmt.Errorf("cannot answer digest challenge: %w", err)}
	}
	a.requests.Add(1)
	return true, nil
}

// draw fetches a challenge and counts the request it cost.
func (a *Authenticator) draw(ctx context.Context, trace *httptrace.ClientTrace) (challenge, cookie string, err error) {
	challenge, cookie, err = DrawDigestChallenge(ctx, a.client, a.endpoint, tsp.ContentTypeRequest, trace)
	a.requests.Add(1)
	return challenge, cookie, err
}

// MaxResponseBytes caps how much of a response body is read. A timestamp token
// is a few kilobytes; anything approaching this is a misconfigured endpoint,
// and reading it unbounded would let one bad response exhaust memory.
const MaxResponseBytes = 1 << 20

// RequestError marks a failure to construct the HTTP request, as distinct from
// a failure to send it. It cannot arise from a well-formed endpoint.
type RequestError struct{ Err error }

func (e *RequestError) Error() string { return e.Err.Error() }
func (e *RequestError) Unwrap() error { return e.Err }

// PostTimestamp builds, authenticates and sends one timestamp POST, answering
// a stale digest challenge and re-sending if the server issues one.
//
// It is the single definition of what a timestamp request looks like on the
// wire. run and doctor both go through it, so the pre-flight check cannot
// exercise a different exchange from the one the run performs - which is what
// happened when each built its own request and only one implemented the
// stale-nonce retry.
//
// The returned response's body has not been read; the caller closes it.
func PostTimestamp(ctx context.Context, client *http.Client, auth *Authenticator,
	endpoint string, der []byte, trace *httptrace.ClientTrace) (*http.Response, error) {

	build := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(der))
		if err != nil {
			return nil, &RequestError{Err: fmt.Errorf("build HTTP request: %w", err)}
		}
		req.Header.Set("Content-Type", tsp.ContentTypeRequest)
		req.Header.Set("Accept", tsp.ContentTypeResponse)
		req.ContentLength = int64(len(der))
		if err := auth.Authorize(ctx, req, trace); err != nil {
			return nil, err
		}
		if trace != nil {
			req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
		}
		return req, nil
	}

	req, err := build()
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	stale, serr := auth.RetryStale(resp)
	if !stale {
		return resp, nil
	}
	// The body is drained so the connection can be reused for the retry.
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if serr != nil {
		return nil, serr
	}

	retry, err := build()
	if err != nil {
		return nil, err
	}
	return client.Do(retry)
}
