// Package transport builds the HTTP client used for timestamp requests.
//
// The client is configured for an open-loop load test: connection pools are
// sized to the target concurrency so that connection churn does not masquerade
// as provider latency.
package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"sync/atomic"
	"time"

	"github.com/berkecengiz/tsa-bench/internal/config"
	"github.com/berkecengiz/tsa-bench/internal/metrics"
)

// countedConn reports its own teardown. httptrace has no close event: it
// only signals a connection being refused by the idle pool, which misses
// every connection the server drops, the idle timeout reaps, or a failed
// request tears down. Counting here is the only way ConnStats.Open() can
// come back down.
type countedConn struct {
	net.Conn
	conns  *metrics.ConnStats
	closed atomic.Bool
}

func (c *countedConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.conns.Closed.Add(1)
	}
	return c.Conn.Close()
}

// New returns an *http.Client and the TLS configuration it uses. conns, when
// non-nil, receives the connection open/close counts.
func New(cfg *config.Config, conns *metrics.ConnStats) (*http.Client, *tls.Config, error) {
	tlsCfg, err := TLSConfig(cfg)
	if err != nil {
		return nil, nil, err
	}

	conc := cfg.Load.MaxConcurrency
	dialer := &net.Dialer{
		Timeout:   cfg.Request.Timeout,
		KeepAlive: 30 * time.Second,
	}
	dial := dialer.DialContext
	if conns != nil {
		dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			conns.Dialed.Add(1)
			return &countedConn{Conn: c, conns: conns}, nil
		}
	}
	tr := &http.Transport{
		TLSClientConfig: tlsCfg,
		DialContext:     dial,
		// No MaxConnsPerHost. Deriving it from max_concurrency put a second,
		// invisible limit beside the runner's semaphore, and the two do not
		// count the same thing: a connection is held through dialling, the TLS
		// handshake and the return to idle, so N concurrent requests
		// transiently need more than N connections. The pool filled before the
		// semaphore did and silently inflated the latency of two real
		// measurements. The semaphore is the limit; the idle caps stay as a
		// reuse hint.
		MaxIdleConns:          conc,
		MaxIdleConnsPerHost:   conc,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   cfg.Request.Timeout,
		ExpectContinueTimeout: 1 * time.Second,
		// HTTP/2 multiplexes many requests onto one connection, which makes
		// per-request latency depend on head-of-line blocking rather than on
		// the TSA. RFC 3161 over HTTP is a request/response protocol; keep it
		// on HTTP/1.1 so the measurement reflects the service.
		ForceAttemptHTTP2:  false,
		DisableCompression: true,
	}

	// A cookie jar is not optional for every provider. One production TSA
	// binds its digest nonce to a servlet session and hands the session out as a
	// JSESSIONID cookie: without returning it, the authenticated request
	// carries a nonce the server cannot match, and every request fails with a
	// generic error that looks nothing like an authentication problem. Go's
	// default client keeps no cookies at all.
	//
	// cookiejar.New(nil) uses no public suffix list, which the standard
	// library warns about for general-purpose clients. This one talks to a
	// single configured endpoint, so there is no third-party host to protect
	// against.
	// The exception is a per-request digest challenge, where each exchange
	// carries its own session cookie explicitly. A jar there is actively
	// harmful twice over: net/http *appends* jar cookies to a Cookie header
	// the caller already set, so the server receives two JSESSIONIDs and picks
	// the wrong one, and the single jar is shared by every worker, so the
	// value it holds races between them.
	var jar http.CookieJar
	if !UsesPerRequestChallenge(cfg) {
		j, err := cookiejar.New(nil)
		if err != nil {
			return nil, nil, fmt.Errorf("create cookie jar: %w", err)
		}
		jar = j
	}

	return &http.Client{
		Transport: tr,
		Jar:       jar,
		Timeout:   cfg.Request.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// A redirect would silently move the load to another host and could
			// forward the Authorization header there.
			return http.ErrUseLastResponse
		},
	}, tlsCfg, nil
}

// TLSConfig builds the TLS configuration, including optional client
// certificates for mTLS.
func TLSConfig(cfg *config.Config) (*tls.Config, error) {
	minVer, err := cfg.MinTLSVersion()
	if err != nil {
		return nil, err
	}

	roots, err := config.LoadCertPool(cfg.TLS.CAFile)
	if err != nil {
		return nil, err
	}

	out := &tls.Config{
		MinVersion:         minVer,
		RootCAs:            roots,
		ServerName:         cfg.TLS.ServerName,
		InsecureSkipVerify: cfg.TLS.InsecureSkipVerify, //nolint:gosec // operator opt-in, warned and recorded
	}

	if cfg.TLS.ClientCertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.ClientCertFile, cfg.TLS.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		out.Certificates = []tls.Certificate{cert}
	}

	return out, nil
}
