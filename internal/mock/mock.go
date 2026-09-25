// Package mock implements a minimal RFC 3161 responder for local use.
//
// Its purpose is to measure what *this client* can sustain, and to exercise the
// verification chain end to end without touching a provider. It performs a real
// CMS signature over a real TSTInfo, so a token it issues genuinely verifies.
//
// It is NOT a simulation of any provider. Its latency profile is the latency of
// a local signature, and it must never be used to make claims about the
// capacity of a real TSA.
package mock

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/digitorus/timestamp"

	"github.com/berkecengiz/tsa-bench/internal/config"
	"github.com/berkecengiz/tsa-bench/internal/testutil"
	"github.com/berkecengiz/tsa-bench/internal/tsp"
)

// Fault injects a deliberate protocol violation so tests can prove that the
// verifier rejects what it must reject.
type Fault string

const (
	FaultNone            Fault = ""
	FaultWrongNonce      Fault = "wrong_nonce"
	FaultWrongImprint    Fault = "wrong_imprint"
	FaultBadContentType  Fault = "bad_content_type"
	FaultRejection       Fault = "rejection"
	FaultNoCertificate   Fault = "no_certificate"
	FaultBrokenSignature Fault = "broken_signature"
	FaultSkewedTime      Fault = "skewed_time"
	FaultMalformedBody   Fault = "malformed_body"
	FaultHTTP500         Fault = "http_500"
	FaultHTTP429         Fault = "http_429"
)

// Options configures the responder.
type Options struct {
	// CA issues the TSA certificate. Generated when nil.
	CA *testutil.CA
	// KeyType for generated material.
	KeyType testutil.KeyType
	// Fault applies to every request when set.
	Fault Fault
	// Latency is added before responding, to emulate a slower responder.
	Latency time.Duration
	// TimeOffset is added to genTime; used with FaultSkewedTime.
	TimeOffset time.Duration
	// Now allows tests to pin the clock.
	Now func() time.Time
	// DigestUser and DigestPass enable RFC 7616 digest authentication. Set
	// them to exercise the digest client path without a real provider.
	DigestUser string
	DigestPass string
	// NonceLifetime expires the digest nonce after this many authenticated
	// requests, so the stale-challenge path can be tested. Zero never expires.
	NonceLifetime int64
	// SessionBoundNonce ties the digest nonce to a session cookie, the way a
	// production TSA's servlet does. A client that does not return the cookie can
	// never authenticate, which is a failure mode no amount of protocol
	// correctness will fix.
	SessionBoundNonce bool
	// SingleUseNonce rejects any nonce count above 1, as a production TSA does
	// despite advertising qop="auth". A client that reuses a nonce with an
	// incrementing count then succeeds exactly once and fails forever after.
	SingleUseNonce bool
}

// Server is an RFC 3161 responder.
type Server struct {
	opts    Options
	ca      *testutil.CA
	tsaCert *x509.Certificate
	tsaKey  crypto.Signer
	digest  crypto.Hash
	auth    digestAuth

	requests atomic.Int64
	fault    atomic.Value // Fault
}

// New builds a responder with freshly generated development certificates.
func New(opts Options) (*Server, error) {
	ca := opts.CA
	if ca == nil {
		var err error
		ca, err = testutil.NewCA("tsa-bench development CA", opts.KeyType)
		if err != nil {
			return nil, fmt.Errorf("generate development CA: %w", err)
		}
	}
	leaf, err := ca.IssueTSA(testutil.TSAOptions{KeyType: opts.KeyType})
	if err != nil {
		return nil, fmt.Errorf("issue development TSA certificate: %w", err)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	s := &Server{
		opts:    opts,
		ca:      ca,
		tsaCert: leaf.Cert,
		tsaKey:  leaf.Key,
		digest:  crypto.SHA256,
	}
	s.fault.Store(opts.Fault)
	return s, nil
}

// CA exposes the issuing authority so a client can trust it.
func (s *Server) CA() *testutil.CA { return s.ca }

// Requests returns the number of requests served.
func (s *Server) Requests() int64 { return s.requests.Load() }

// SetFault changes the injected fault at runtime.
func (s *Server) SetFault(f Fault) { s.fault.Store(f) }

func (s *Server) currentFault() Fault {
	f, _ := s.fault.Load().(Fault)
	return f
}

// Handler returns the HTTP handler implementing the responder.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.serve)
	return mux
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.requests.Add(1)
	fault := s.currentFault()

	if s.opts.Latency > 0 {
		select {
		case <-time.After(s.opts.Latency):
		case <-r.Context().Done():
			return
		}
	}

	if r.Method != http.MethodPost {
		http.Error(w, "only POST is supported", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.DigestUser != "" && !s.authorised(w, r) {
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != tsp.ContentTypeRequest {
		http.Error(w, "unexpected content type", http.StatusUnsupportedMediaType)
		return
	}

	switch fault {
	case FaultHTTP500:
		http.Error(w, "injected server error", http.StatusInternalServerError)
		return
	case FaultHTTP429:
		w.Header().Set("Retry-After", "1")
		http.Error(w, "injected rate limit", http.StatusTooManyRequests)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, "cannot read request", http.StatusBadRequest)
		return
	}

	resp, err := s.respond(body, fault)
	if err != nil {
		http.Error(w, "cannot build response", http.StatusInternalServerError)
		return
	}

	contentType := tsp.ContentTypeResponse
	if fault == FaultBadContentType {
		contentType = "text/html; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", fmt.Sprint(len(resp)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

// respond builds the DER response for a parsed request, applying any fault.
func (s *Server) respond(reqDER []byte, fault Fault) ([]byte, error) {
	if fault == FaultMalformedBody {
		return []byte{0x30, 0x03, 0x02, 0x01}, nil
	}
	if fault == FaultRejection {
		return timestamp.CreateErrorResponse(timestamp.Rejection, timestamp.SystemFailure)
	}

	req, err := timestamp.ParseRequest(reqDER)
	if err != nil {
		return timestamp.CreateErrorResponse(timestamp.Rejection, timestamp.BadDataFormat)
	}

	genTime := s.opts.Now().UTC()
	if fault == FaultSkewedTime {
		offset := s.opts.TimeOffset
		if offset == 0 {
			offset = 24 * time.Hour
		}
		genTime = genTime.Add(offset)
	}

	nonce := req.Nonce
	if fault == FaultWrongNonce {
		nonce = new(big.Int).Add(orZero(req.Nonce), big.NewInt(1))
	}

	imprint := req.HashedMessage
	if fault == FaultWrongImprint {
		imprint = append([]byte(nil), req.HashedMessage...)
		if len(imprint) == 0 {
			return nil, errors.New("empty imprint")
		}
		imprint[0] ^= 0xff
	}

	ts := &timestamp.Timestamp{
		HashAlgorithm:     req.HashAlgorithm,
		HashedMessage:     imprint,
		Time:              genTime,
		Accuracy:          time.Second,
		Nonce:             nonce,
		Policy:            req.TSAPolicyOID,
		Ordering:          false,
		AddTSACertificate: fault != FaultNoCertificate,
	}
	if ts.Policy == nil {
		ts.Policy = []int{1, 3, 6, 1, 4, 1, 99999, 1, 1}
	}

	out, err := ts.CreateResponseWithOpts(s.tsaCert, s.tsaKey, s.digest)
	if err != nil {
		return nil, err
	}

	if fault == FaultBrokenSignature {
		// Flip a byte deep inside the token so the CMS signature no longer
		// matches, while the ASN.1 structure stays decodable.
		out = append([]byte(nil), out...)
		out[len(out)-1] ^= 0xff
	}
	return out, nil
}

func orZero(n *big.Int) *big.Int {
	if n == nil {
		return big.NewInt(0)
	}
	return n
}

// ListenAndServe starts the responder. Binding to anything other than a
// loopback address requires the caller to have opted in explicitly; a mock TSA
// on a routable interface would happily hand out bogus timestamps to anyone.
func (s *Server) ListenAndServe(addr string, allowExternal bool) (net.Listener, *http.Server, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid address %q: %w", addr, err)
	}
	if !allowExternal && !config.IsLoopbackHost(host) {
		return nil, nil, fmt.Errorf("refusing to bind mock TSA to non-loopback address %q; pass --bind-external to override", host)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return ln, srv, nil
}

// UseSigner replaces the generated signing material. It exists so tests can
// issue tokens with deliberately defective certificates.
func (s *Server) UseSigner(cert *x509.Certificate, key crypto.Signer) {
	s.tsaCert = cert
	s.tsaKey = key
}
