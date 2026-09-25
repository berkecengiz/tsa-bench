package redact_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/berkecengiz/tsa-bench/internal/redact"
)

func TestURLStripsCredentialsAndQuery(t *testing.T) {
	cases := []struct {
		in       string
		mustNot  []string
		mustHave string
	}{
		{
			in:       "https://alice:s3cr3t@tsa.example.com/timestamp?token=abcdef123",
			mustNot:  []string{"alice", "s3cr3t", "abcdef123", "token=abc"},
			mustHave: "tsa.example.com",
		},
		{
			in:       "https://tsa.example.com/ts?apikey=LEAKME",
			mustNot:  []string{"LEAKME"},
			mustHave: "tsa.example.com",
		},
		{
			in:       "https://tsa.example.com/timestamp",
			mustHave: "https://tsa.example.com/timestamp",
		},
	}

	for _, tc := range cases {
		got := redact.URL(tc.in)
		for _, secret := range tc.mustNot {
			if strings.Contains(got, secret) {
				t.Errorf("URL(%q) = %q, still contains %q", tc.in, got, secret)
			}
		}
		if !strings.Contains(got, tc.mustHave) {
			t.Errorf("URL(%q) = %q, expected it to keep %q", tc.in, got, tc.mustHave)
		}
	}
}

// TestErrorRedactsEmbeddedURL matters because net/http quotes the full request
// URL in its errors, credentials included.
func TestErrorRedactsEmbeddedURL(t *testing.T) {
	err := errors.New(`Post "https://bob:hunter2@tsa.example.com/ts?k=SECRET": dial tcp: timeout`)
	got := redact.Error(err)

	for _, secret := range []string{"hunter2", "SECRET", "bob"} {
		if strings.Contains(got, secret) {
			t.Errorf("Error() = %q, still leaks %q", got, secret)
		}
	}
	if !strings.Contains(got, "dial tcp") {
		t.Errorf("Error() = %q, lost the diagnostic part of the message", got)
	}
}

func TestSensitiveHeadersAreFullyMasked(t *testing.T) {
	in := map[string]string{
		"Authorization": "Basic dXNlcjpwYXNz",
		"Cookie":        "session=abc",
		"X-Api-Key":     "key-123",
		"Accept":        "application/timestamp-reply",
	}
	out := redact.Headers(in)

	for _, name := range []string{"Authorization", "Cookie", "X-Api-Key"} {
		if out[name] != redact.Mask {
			t.Errorf("header %s = %q, want a full mask", name, out[name])
		}
	}
	if out["Accept"] != "application/timestamp-reply" {
		t.Errorf("non-sensitive header was altered: %q", out["Accept"])
	}
}

func TestSensitiveHeaderMatchIsCaseInsensitive(t *testing.T) {
	for _, name := range []string{"authorization", "AUTHORIZATION", "Authorization", " cookie "} {
		if !redact.IsSensitiveHeader(name) {
			t.Errorf("%q was not recognised as sensitive", name)
		}
	}
}

func TestTextRedactsMultipleURLs(t *testing.T) {
	in := `tried https://a:b@one.example.com/x?q=1 then https://c:d@two.example.com/y?q=2`
	got := redact.Text(in)
	for _, secret := range []string{"a:b", "c:d", "q=1", "q=2"} {
		if strings.Contains(got, secret) {
			t.Errorf("Text() = %q, leaks %q", got, secret)
		}
	}
}

func TestURLParseFailureIsFullyMasked(t *testing.T) {
	// A string that cannot be parsed must not be echoed back verbatim: it might
	// itself be the secret.
	if got := redact.URL("ht!tp://\x7f:bad"); strings.Contains(got, "bad") {
		t.Errorf("unparsable URL was echoed: %q", got)
	}
}
