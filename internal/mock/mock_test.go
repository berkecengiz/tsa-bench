package mock_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/berkecengiz/tsa-bench/internal/mock"
	"github.com/berkecengiz/tsa-bench/internal/testutil"
	"github.com/berkecengiz/tsa-bench/internal/tsp"
)

// TestMockRefusesExternalBindWithoutOptIn: a mock TSA reachable from the
// network would hand out timestamps signed by a throwaway key to anyone.
func TestMockRefusesExternalBindWithoutOptIn(t *testing.T) {
	srv, err := mock.New(mock.Options{KeyType: testutil.ECDSAP256})
	if err != nil {
		t.Fatalf("mock.New: %v", err)
	}

	if _, _, err := srv.ListenAndServe("0.0.0.0:0", false); err == nil {
		t.Fatal("binding to 0.0.0.0 was allowed without --bind-external")
	}

	ln, _, err := srv.ListenAndServe("127.0.0.1:0", false)
	if err != nil {
		t.Fatalf("loopback bind was refused: %v", err)
	}
	_ = ln.Close()
}

func TestMockRejectsWrongMethodAndContentType(t *testing.T) {
	srv, err := mock.New(mock.Options{KeyType: testutil.ECDSAP256})
	if err != nil {
		t.Fatalf("mock.New: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	resp, err := http.Get(hs.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET returned %d, want 405", resp.StatusCode)
	}

	resp2, err := http.Post(hs.URL, "text/plain", bytes.NewReader([]byte("x")))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("wrong content type returned %d, want 415", resp2.StatusCode)
	}
}

// TestMockIntegration is the end-to-end offline check: a request built by the
// tool, answered by the mock, and accepted by the tool's own verifier.
func TestMockIntegration(t *testing.T) {
	srv, err := mock.New(mock.Options{KeyType: testutil.ECDSAP256})
	if err != nil {
		t.Fatalf("mock.New: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	builder, err := tsp.NewBuilder(tsp.BuilderOptions{HashName: "sha256", PayloadSize: 64, CertReq: true})
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	verifier, err := tsp.NewVerifier(srv.CA().Pool, time.Minute, false)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	const n = 50
	for i := 0; i < n; i++ {
		req, err := builder.Build()
		if err != nil {
			t.Fatalf("Build: %v", err)
		}

		sentAt := time.Now()
		httpReq, _ := http.NewRequest(http.MethodPost, hs.URL, bytes.NewReader(req.DER))
		httpReq.Header.Set("Content-Type", tsp.ContentTypeRequest)
		httpReq.Header.Set("Accept", tsp.ContentTypeResponse)

		resp, err := http.DefaultClient.Do(httpReq)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		res, verr := verifier.Verify(req, tsp.HTTPResponse{
			StatusCode:  resp.StatusCode,
			ContentType: resp.Header.Get("Content-Type"),
			Body:        body,
			SentAt:      sentAt,
			ReceivedAt:  time.Now(),
		})
		if verr != nil {
			t.Fatalf("request %d failed verification: %s", i, verr)
		}
		if res.SerialNumber == nil {
			t.Fatalf("request %d: no serial number", i)
		}
	}

	if got := srv.Requests(); got != n {
		t.Errorf("mock served %d requests, want %d", got, n)
	}
}

// TestMockSerialNumbersAreUnique: a responder reusing serials would make the
// verification results meaningless.
func TestMockSerialNumbersAreUnique(t *testing.T) {
	srv, err := mock.New(mock.Options{KeyType: testutil.ECDSAP256})
	if err != nil {
		t.Fatalf("mock.New: %v", err)
	}
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	builder, _ := tsp.NewBuilder(tsp.BuilderOptions{HashName: "sha256", PayloadSize: 64, CertReq: true})
	verifier, _ := tsp.NewVerifier(srv.CA().Pool, time.Minute, false)

	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		req, _ := builder.Build()
		sentAt := time.Now()
		resp, err := http.Post(hs.URL, tsp.ContentTypeRequest, bytes.NewReader(req.DER))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		res, verr := verifier.Verify(req, tsp.HTTPResponse{
			StatusCode: resp.StatusCode, ContentType: resp.Header.Get("Content-Type"),
			Body: body, SentAt: sentAt, ReceivedAt: time.Now(),
		})
		if verr != nil {
			t.Fatalf("verify: %s", verr)
		}
		s := res.SerialNumber.String()
		if seen[s] {
			t.Fatalf("serial %s was reused", s)
		}
		seen[s] = true
	}
}
