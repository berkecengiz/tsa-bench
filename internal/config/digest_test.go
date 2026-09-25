package config

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// newDigestCreds builds credentials directly, bypassing the environment.
func newDigestCreds(user, pass string) *Credentials {
	return &Credentials{username: user, password: pass, digest: &digestState{}}
}

// TestDigestResponseMatchesRFC2617 checks the response computation against the
// worked example in RFC 2617 section 3.5. Getting this wrong fails against a
// real provider with an indistinguishable 401, so it is pinned to a published
// vector rather than to our own output.
func TestDigestResponseMatchesRFC2617(t *testing.T) {
	const (
		user   = "Mufasa"
		pass   = "Circle Of Life"
		realm  = "testrealm@host.com"
		nonce  = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
		cnonce = "0a4f113b"
		nc     = "00000001"
		uri    = "/dir/index.html"
		want   = "6629fae49393a05397450978507c4ef1"
	)

	ha1 := digestHash("MD5", user+":"+realm+":"+pass)
	ha2 := digestHash("MD5", "GET:"+uri)
	got := digestHash("MD5", strings.Join([]string{ha1, nonce, nc, cnonce, "auth", ha2}, ":"))

	if got != want {
		t.Errorf("response = %s, want %s (RFC 2617 section 3.5)", got, want)
	}
}

func TestParseDigestChallenge(t *testing.T) {
	// A real nonce is base64 and can carry characters that a naive split on
	// commas would corrupt.
	const header = `Digest realm="timestampserver", qop="auth", ` +
		`nonce="MTc5MDIyODM4NjM1NjoxMzJjZDJhMDU0ZGI3ODllNTMzYzRlNWI1NzEyMjc4Mw==", stale=TRUE`

	p, err := parseDigestChallenge(header)
	if err != nil {
		t.Fatalf("parseDigestChallenge: %v", err)
	}
	for field, want := range map[string]string{
		"realm": "timestampserver",
		"qop":   "auth",
		"nonce": "MTc5MDIyODM4NjM1NjoxMzJjZDJhMDU0ZGI3ODllNTMzYzRlNWI1NzEyMjc4Mw==",
		"stale": "TRUE",
	} {
		if p[field] != want {
			t.Errorf("%s = %q, want %q", field, p[field], want)
		}
	}
}

func TestApplyDigestIsNoOpWithoutChallenge(t *testing.T) {
	cr := newDigestCreds("12", "secret")
	req := &http.Request{Method: http.MethodPost, URL: mustURL(t, "https://tsa.example/"), Header: http.Header{}}

	cr.Apply(req, AuthDigest)

	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q before any challenge; the first request must draw one", got)
	}
	if cr.HasChallenge() {
		t.Error("HasChallenge is true before any challenge was set")
	}
}

// TestDigestNonceCountIsUniquePerRequest guards the replay defence: a server
// that sees the same nc twice against one nonce is entitled to reject it, so
// concurrent workers must never share a count.
func TestDigestNonceCountIsUniquePerRequest(t *testing.T) {
	cr := newDigestCreds("12", "secret")
	if err := cr.SetChallenge(`Digest realm="r", qop="auth", nonce="abc"`); err != nil {
		t.Fatalf("SetChallenge: %v", err)
	}

	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		req := &http.Request{Method: http.MethodPost, URL: mustURL(t, "https://tsa.example/"), Header: http.Header{}}
		cr.Apply(req, AuthDigest)
		nc := paramOf(req.Header.Get("Authorization"), "nc")
		if nc == "" {
			t.Fatalf("request %d carries no nc", i)
		}
		if seen[nc] {
			t.Fatalf("nc %s reused at request %d", nc, i)
		}
		seen[nc] = true
	}
}

// TestSetChallengeResetsCount covers the stale path: a new nonce restarts the
// count, because nc is scoped to the nonce it was issued against.
func TestSetChallengeResetsCount(t *testing.T) {
	cr := newDigestCreds("12", "secret")
	if err := cr.SetChallenge(`Digest realm="r", qop="auth", nonce="first"`); err != nil {
		t.Fatalf("SetChallenge: %v", err)
	}
	req := &http.Request{Method: http.MethodPost, URL: mustURL(t, "https://tsa.example/"), Header: http.Header{}}
	cr.Apply(req, AuthDigest)

	if err := cr.SetChallenge(`Digest realm="r", qop="auth", nonce="second"`); err != nil {
		t.Fatalf("SetChallenge: %v", err)
	}
	req2 := &http.Request{Method: http.MethodPost, URL: mustURL(t, "https://tsa.example/"), Header: http.Header{}}
	cr.Apply(req2, AuthDigest)

	if nc := paramOf(req2.Header.Get("Authorization"), "nc"); nc != "00000001" {
		t.Errorf("nc = %s after a new nonce, want 00000001", nc)
	}
	if n := paramOf(req2.Header.Get("Authorization"), "nonce"); n != "second" {
		t.Errorf("nonce = %s, want second", n)
	}
}

func TestSetChallengeRejectsUnsupported(t *testing.T) {
	cases := map[string]string{
		"no realm":      `Digest qop="auth", nonce="abc"`,
		"no nonce":      `Digest realm="r", qop="auth"`,
		"auth-int only": `Digest realm="r", qop="auth-int", nonce="abc"`,
		"session":       `Digest realm="r", qop="auth", nonce="abc", algorithm=MD5-sess`,
		"not digest":    `Basic realm="r"`,
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			cr := newDigestCreds("12", "secret")
			if err := cr.SetChallenge(header); err == nil {
				t.Errorf("SetChallenge accepted %q", header)
			}
		})
	}
}

// TestCredentialsStillHideSecrets guards the property the whole type exists
// for: adding digest must not open a path for the password to be printed.
func TestCredentialsStillHideSecrets(t *testing.T) {
	cr := newDigestCreds("12", "hunter2")
	if err := cr.SetChallenge(`Digest realm="r", qop="auth", nonce="abc"`); err != nil {
		t.Fatalf("SetChallenge: %v", err)
	}
	for _, s := range []string{cr.String(), cr.GoString()} {
		if strings.Contains(s, "hunter2") {
			t.Errorf("credentials rendered as %q, which leaks the password", s)
		}
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", raw, err)
	}
	return u
}

func paramOf(header, key string) string {
	for _, kv := range strings.Split(strings.TrimPrefix(header, "Digest "), ",") {
		eq := strings.Index(kv, "=")
		if eq < 0 {
			continue
		}
		if strings.TrimSpace(kv[:eq]) == key {
			return strings.Trim(strings.TrimSpace(kv[eq+1:]), `"`)
		}
	}
	return ""
}
