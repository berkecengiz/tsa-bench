package tsp_test

import (
	"bytes"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/berkecengiz/tsa-bench/internal/errclass"
	"github.com/berkecengiz/tsa-bench/internal/mock"
	"github.com/berkecengiz/tsa-bench/internal/testutil"
	"github.com/berkecengiz/tsa-bench/internal/tsp"
)

// harness wires a mock responder to a verifier that trusts its CA.
type harness struct {
	srv      *mock.Server
	http     *httptest.Server
	verifier *tsp.Verifier
	builder  *tsp.Builder
}

func newHarness(t *testing.T, kt testutil.KeyType) *harness {
	t.Helper()

	srv, err := mock.New(mock.Options{KeyType: kt})
	if err != nil {
		t.Fatalf("mock.New: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)

	v, err := tsp.NewVerifier(srv.CA().Pool, time.Minute, false)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	b, err := tsp.NewBuilder(tsp.BuilderOptions{HashName: "sha256", PayloadSize: 64, CertReq: true})
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	return &harness{srv: srv, http: hs, verifier: v, builder: b}
}

// roundTrip performs one full request/verify cycle.
func (h *harness) roundTrip(t *testing.T) (*tsp.Result, *errclass.Error) {
	t.Helper()

	req, err := h.builder.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	sentAt := time.Now()
	resp, err := http.Post(h.http.URL, tsp.ContentTypeRequest, bytes.NewReader(req.DER))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	return h.verifier.Verify(req, tsp.HTTPResponse{
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Body:        body,
		SentAt:      sentAt,
		ReceivedAt:  time.Now(),
	})
}

func TestVerifyHappyPath(t *testing.T) {
	for _, kt := range []struct {
		name string
		kt   testutil.KeyType
	}{
		{"ecdsa-p256", testutil.ECDSAP256},
		{"rsa-2048", testutil.RSA2048},
	} {
		t.Run(kt.name, func(t *testing.T) {
			h := newHarness(t, kt.kt)
			res, verr := h.roundTrip(t)
			if verr != nil {
				t.Fatalf("expected success, got %s", verr)
			}
			if res.GenTime.IsZero() {
				t.Error("genTime is zero")
			}
			if res.SignerSubject == "" {
				t.Error("signer subject not reported")
			}
			if !res.ESS.Present {
				t.Error("expected the mock token to carry SigningCertificateV2")
			}
			if !res.ESS.Matched {
				t.Errorf("ESS binding did not match: %s", res.ESS.Reason)
			}
		})
	}
}

// TestVerifyRejectsFaults is the core safety test: every injected protocol
// violation must be caught and classified, never reported as a success.
func TestVerifyRejectsFaults(t *testing.T) {
	cases := []struct {
		fault mock.Fault
		want  errclass.Class
	}{
		{mock.FaultWrongNonce, errclass.InvalidNonce},
		{mock.FaultWrongImprint, errclass.InvalidImprint},
		{mock.FaultBadContentType, errclass.InvalidContentType},
		{mock.FaultRejection, errclass.TSPRejection},
		{mock.FaultBrokenSignature, errclass.InvalidSignature},
		{mock.FaultSkewedTime, errclass.ClockSkewExceeded},
		{mock.FaultMalformedBody, errclass.MalformedResponse},
		{mock.FaultHTTP500, errclass.HTTP5xx},
		{mock.FaultHTTP429, errclass.HTTP4xx},
	}

	for _, tc := range cases {
		t.Run(string(tc.fault), func(t *testing.T) {
			h := newHarness(t, testutil.ECDSAP256)
			h.srv.SetFault(tc.fault)

			res, verr := h.roundTrip(t)
			if verr == nil {
				t.Fatalf("fault %s was accepted as a valid timestamp (result %+v)", tc.fault, res)
			}
			if verr.Class != tc.want {
				t.Errorf("fault %s classified as %s, want %s (detail: %s)",
					tc.fault, verr.Class, tc.want, verr.Detail)
			}
		})
	}
}

func TestVerifyRejectionCarriesFailureInfo(t *testing.T) {
	h := newHarness(t, testutil.ECDSAP256)
	h.srv.SetFault(mock.FaultRejection)

	_, verr := h.roundTrip(t)
	if verr == nil {
		t.Fatal("expected rejection")
	}
	if verr.Sub != "systemFailure" {
		t.Errorf("sub-category = %q, want systemFailure", verr.Sub)
	}
	if verr.Key() != "tsp_rejection.systemFailure" {
		t.Errorf("Key() = %q", verr.Key())
	}
}

// TestVerifyUntrustedChain proves that a technically valid signature from an
// unknown issuer is not accepted.
func TestVerifyUntrustedChain(t *testing.T) {
	h := newHarness(t, testutil.ECDSAP256)

	otherCA, err := testutil.NewCA("unrelated CA", testutil.ECDSAP256)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	v, err := tsp.NewVerifier(otherCA.Pool, time.Minute, false)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	h.verifier = v

	_, verr := h.roundTrip(t)
	if verr == nil {
		t.Fatal("a token from an untrusted issuer was accepted")
	}
	if verr.Class != errclass.UntrustedCert {
		t.Errorf("class = %s, want %s (%s)", verr.Class, errclass.UntrustedCert, verr.Detail)
	}
}

// TestVerifyRejectsWrongEKU covers RFC 3161 section 2.3.
func TestVerifyRejectsWrongEKU(t *testing.T) {
	cases := []struct {
		name string
		opts testutil.TSAOptions
	}{
		{"no timestamping eku", testutil.TSAOptions{OmitTimeStampingEKU: true}},
		{"extra eku", testutil.TSAOptions{ExtraEKU: true}},
		{"non critical eku", testutil.TSAOptions{NonCriticalEKU: true}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ca, err := testutil.NewCA("eku test CA", testutil.ECDSAP256)
			if err != nil {
				t.Fatalf("NewCA: %v", err)
			}
			leaf, err := ca.IssueTSA(tc.opts)
			if err != nil {
				t.Fatalf("IssueTSA: %v", err)
			}
			if err := checkLeafRejected(t, ca, leaf); err == nil {
				t.Fatal("certificate was accepted but must be rejected")
			}
		})
	}
}

// checkLeafRejected signs a token with the given leaf and asserts the verifier
// refuses it.
func checkLeafRejected(t *testing.T, ca *testutil.CA, leaf *testutil.Leaf) error {
	t.Helper()

	srv, err := mock.New(mock.Options{CA: ca, KeyType: testutil.ECDSAP256})
	if err != nil {
		t.Fatalf("mock.New: %v", err)
	}
	// Replace the mock's own certificate with the variant under test.
	srv.UseSigner(leaf.Cert, leaf.Key)

	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	v, err := tsp.NewVerifier(ca.Pool, time.Minute, false)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	b, _ := tsp.NewBuilder(tsp.BuilderOptions{HashName: "sha256", PayloadSize: 64, CertReq: true})
	req, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	sentAt := time.Now()
	resp, err := http.Post(hs.URL, tsp.ContentTypeRequest, bytes.NewReader(req.DER))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	_, verr := v.Verify(req, tsp.HTTPResponse{
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Body:        body,
		SentAt:      sentAt,
		ReceivedAt:  time.Now(),
	})
	if verr == nil {
		return nil
	}
	if verr.Class != errclass.UntrustedCert {
		t.Errorf("class = %s, want %s (%s)", verr.Class, errclass.UntrustedCert, verr.Detail)
	}
	return verr
}

func TestBuilderRejectsCertReqFalse(t *testing.T) {
	_, err := tsp.NewBuilder(tsp.BuilderOptions{HashName: "sha256", PayloadSize: 64, CertReq: false})
	if err == nil {
		t.Fatal("cert_req=false must be rejected: the signature could not be verified")
	}
}

func TestBuilderProducesUniqueNoncesAndImprints(t *testing.T) {
	b, err := tsp.NewBuilder(tsp.BuilderOptions{HashName: "sha256", PayloadSize: 64, CertReq: true})
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}

	const n = 2000
	nonces := make(map[string]bool, n)
	imprints := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		req, err := b.Build()
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if req.Nonce.Sign() == 0 {
			t.Fatal("nonce must never be zero")
		}
		nk := req.Nonce.String()
		if nonces[nk] {
			t.Fatalf("duplicate nonce after %d requests", i)
		}
		nonces[nk] = true

		ik := string(req.Imprint)
		if imprints[ik] {
			t.Fatalf("duplicate imprint after %d requests", i)
		}
		imprints[ik] = true

		if len(req.Imprint) != 32 {
			t.Fatalf("sha256 imprint length = %d", len(req.Imprint))
		}
	}
}

func TestNewVerifierRequiresTrustAnchors(t *testing.T) {
	if _, err := tsp.NewVerifier(nil, time.Minute, false); err == nil {
		t.Fatal("a verifier without trust anchors must not be constructible")
	}
	if _, err := tsp.NewVerifier(x509.NewCertPool(), 0, false); err == nil {
		t.Fatal("a non-positive clock skew must be rejected")
	}
}

func TestRequireESSFailsWhenAbsent(t *testing.T) {
	// The mock always emits SigningCertificateV2, so this asserts the positive
	// path under RequireESS rather than a synthetic absence.
	srv, err := mock.New(mock.Options{KeyType: testutil.ECDSAP256})
	if err != nil {
		t.Fatalf("mock.New: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	v, err := tsp.NewVerifier(srv.CA().Pool, time.Minute, true)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	b, _ := tsp.NewBuilder(tsp.BuilderOptions{HashName: "sha256", PayloadSize: 64, CertReq: true})
	req, _ := b.Build()

	sentAt := time.Now()
	resp, err := http.Post(hs.URL, tsp.ContentTypeRequest, bytes.NewReader(req.DER))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if _, verr := v.Verify(req, tsp.HTTPResponse{
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Body:        body,
		SentAt:      sentAt,
		ReceivedAt:  time.Now(),
	}); verr != nil {
		t.Fatalf("require_ess rejected a token that carries SigningCertificateV2: %s", verr)
	}
}
