package errclass_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/berkecengiz/tsa-bench/internal/errclass"
)

func TestClassifyTransportErrors(t *testing.T) {
	cases := []struct {
		name           string
		err            error
		requestWritten bool
		want           errclass.Class
	}{
		{
			name: "dns failure",
			err:  &url.Error{Op: "Post", URL: "https://x", Err: &net.DNSError{Err: "no such host", Name: "x"}},
			want: errclass.DNSError,
		},
		{
			name: "connection refused",
			err:  &url.Error{Op: "Post", URL: "https://x", Err: &net.OpError{Op: "dial", Err: errors.New("connection refused")}},
			want: errclass.ConnectError,
		},
		{
			name: "certificate verification",
			err:  &url.Error{Op: "Post", URL: "https://x", Err: &tls.CertificateVerificationError{Err: errors.New("bad chain")}},
			want: errclass.TLSError,
		},
		{
			name: "hostname mismatch",
			err:  &url.Error{Op: "Post", URL: "https://x", Err: x509.HostnameError{Host: "wrong"}},
			want: errclass.TLSError,
		},
		{
			name:           "timeout before request written",
			err:            &url.Error{Op: "Post", URL: "https://x", Err: context.DeadlineExceeded},
			requestWritten: false,
			want:           errclass.RequestTimeout,
		},
		{
			name:           "timeout after request written",
			err:            &url.Error{Op: "Post", URL: "https://x", Err: context.DeadlineExceeded},
			requestWritten: true,
			want:           errclass.ResponseTimeout,
		},
		{
			name: "cancelled",
			err:  context.Canceled,
			want: errclass.Cancelled,
		},
		{
			name:           "os deadline",
			err:            os.ErrDeadlineExceeded,
			requestWritten: true,
			want:           errclass.ResponseTimeout,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := errclass.Classify(tc.err, tc.requestWritten)
			if got == nil {
				t.Fatal("Classify returned nil for a non-nil error")
			}
			if got.Class != tc.want {
				t.Errorf("class = %s, want %s (detail %q)", got.Class, tc.want, got.Detail)
			}
		})
	}
}

func TestClassifyNilIsNil(t *testing.T) {
	if errclass.Classify(nil, false) != nil {
		t.Error("Classify(nil) must return nil")
	}
}

// TestClassifyRedactsURLs: classified errors are written into errors.csv.
func TestClassifyRedactsURLs(t *testing.T) {
	err := &url.Error{
		Op:  "Post",
		URL: "https://user:hunter2@tsa.example.com/ts?key=SECRET",
		Err: errors.New("connection reset"),
	}
	got := errclass.Classify(err, false)
	for _, secret := range []string{"hunter2", "SECRET"} {
		if strings.Contains(got.Detail, secret) {
			t.Errorf("classified detail leaks %q: %s", secret, got.Detail)
		}
	}
}

func TestClassifyPassesThroughVerificationErrors(t *testing.T) {
	original := errclass.NewSub(errclass.TSPRejection, "badAlg", "rejected")
	got := errclass.Classify(fmt.Errorf("wrapped: %w", original), true)
	if got != original {
		t.Errorf("a pre-classified error was reclassified: %v", got)
	}
}

func TestFromHTTPStatus(t *testing.T) {
	cases := []struct {
		code int
		want errclass.Class
		sub  string
	}{
		{200, "", ""},
		{204, "", ""},
		{400, errclass.HTTP4xx, "400"},
		{401, errclass.HTTP4xx, "401"},
		{429, errclass.HTTP4xx, "429"},
		{500, errclass.HTTP5xx, "500"},
		{503, errclass.HTTP5xx, "503"},
	}

	for _, tc := range cases {
		got := errclass.FromHTTPStatus(tc.code)
		if tc.want == "" {
			if got != nil {
				t.Errorf("status %d classified as %s, want success", tc.code, got.Class)
			}
			continue
		}
		if got == nil {
			t.Fatalf("status %d was accepted as success", tc.code)
		}
		if got.Class != tc.want || got.Sub != tc.sub {
			t.Errorf("status %d = %s/%s, want %s/%s", tc.code, got.Class, got.Sub, tc.want, tc.sub)
		}
	}
}

func TestErrorKeyFormat(t *testing.T) {
	if got := errclass.New(errclass.InvalidNonce, "x").Key(); got != "invalid_nonce" {
		t.Errorf("Key() = %q", got)
	}
	if got := errclass.NewSub(errclass.TSPRejection, "systemFailure", "x").Key(); got != "tsp_rejection.systemFailure" {
		t.Errorf("Key() = %q", got)
	}
}

// TestAllClassesAreUnique guards the report schema: two classes sharing a
// string would silently merge in every CSV and chart.
func TestAllClassesAreUnique(t *testing.T) {
	seen := map[errclass.Class]bool{}
	for _, c := range errclass.All() {
		if seen[c] {
			t.Errorf("duplicate error class %q", c)
		}
		seen[c] = true
	}
	if len(errclass.All()) < 20 {
		t.Errorf("only %d error classes defined; the taxonomy looks incomplete", len(errclass.All()))
	}
	if errclass.OK.IsFailure() {
		t.Error("OK must not count as a failure")
	}
}
