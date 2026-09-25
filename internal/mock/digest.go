package mock

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/berkecengiz/tsa-bench/internal/config"
)

// Digest authentication for the mock responder.
//
// It exists so the digest client path can be exercised without spending a real
// provider's quota, including the two behaviours that a live service turned
// out to have and no specification would have predicted: a nonce bound to a
// session cookie, and a nonce that is valid for exactly one request despite
// qop="auth" being advertised.

const (
	digestRealm   = "timestampserver"
	sessionCookie = "JSESSIONID"
)

// digestAuth holds the state for all three modes. They are mutually
// exclusive - nonce and served serve NonceLifetime, sessID serves
// SessionBoundNonce, sessions serves SingleUseNonce - and no two are ever live
// in one configuration.
type digestAuth struct {
	mu     sync.Mutex
	nonce  string
	sessID string
	// sessions holds one nonce per session, used when nonces are single use.
	// A shared nonce would make concurrent callers invalidate each other,
	// which is not how the real service behaves.
	sessions map[string]string
	served   atomic.Int64
}

func (d *digestAuth) current() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.nonce == "" {
		d.nonce = randomNonce()
	}
	return d.nonce
}

func (d *digestAuth) session() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sessID == "" {
		d.sessID = randomNonce()
	}
	return d.sessID
}

// rotate expires the shared nonce and issues a new one.
func (d *digestAuth) rotate() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.nonce = randomNonce()
	d.served.Store(0)
}

// issue creates a session with a nonce of its own.
func (d *digestAuth) issue() (sessID, nonce string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sessions == nil {
		d.sessions = map[string]string{}
	}
	sessID, nonce = randomNonce(), randomNonce()
	d.sessions[sessID] = nonce
	return sessID, nonce
}

// consume checks a session's nonce and spends it. The second attempt with the
// same nonce finds nothing.
func (d *digestAuth) consume(sessID, nonce string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	want, ok := d.sessions[sessID]
	if !ok || want != nonce {
		return false
	}
	delete(d.sessions, sessID)
	return true
}

func randomNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "static-nonce"
	}
	return hex.EncodeToString(b)
}

// authorised reports whether the request carries a valid digest response. When
// it does not, it writes the challenge itself and returns false.
func (s *Server) authorised(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(auth), "digest ") {
		s.challenge(w, false)
		return false
	}
	p, perr := config.ParseDigestParams(auth)
	if perr != nil {
		s.challenge(w, false)
		return false
	}

	if s.opts.SingleUseNonce {
		return s.authorisedSingleUse(w, r, p)
	}

	nonce := s.auth.current()
	if p["nonce"] != nonce {
		// A nonce we no longer recognise is stale, not wrong: the client
		// should answer the new challenge rather than give up.
		s.challenge(w, true)
		return false
	}
	// With a session-bound nonce, a client that dropped the cookie is simply
	// unauthenticated however well formed its digest response is.
	if s.opts.SessionBoundNonce {
		c, err := r.Cookie(sessionCookie)
		if err != nil || c.Value != s.auth.session() {
			s.challenge(w, false)
			return false
		}
	}
	if !s.responseMatches(p, r.Method, nonce) {
		s.reject(w)
		return false
	}
	if n := s.opts.NonceLifetime; n > 0 && s.auth.served.Add(1) >= n {
		s.auth.rotate()
	}
	return true
}

// authorisedSingleUse implements a behaviour observed on a production TSA:
// every nonce
// belongs to one session and is valid for exactly one request.
func (s *Server) authorisedSingleUse(w http.ResponseWriter, r *http.Request, p map[string]string) bool {
	// A client that sends two session cookies has lost track of which session
	// it is in, and a real server picks one - usually not the one the client
	// meant. Reject it outright so the mistake surfaces here rather than as a
	// puzzling failure rate against a live provider.
	if cs := r.CookiesNamed(sessionCookie); len(cs) != 1 {
		s.challenge(w, false)
		return false
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		s.challenge(w, false)
		return false
	}
	if p["nc"] != "" && p["nc"] != "00000001" {
		s.challenge(w, false)
		return false
	}
	if !s.responseMatches(p, r.Method, p["nonce"]) {
		s.reject(w)
		return false
	}
	if !s.auth.consume(c.Value, p["nonce"]) {
		s.challenge(w, false)
		return false
	}
	return true
}

func (s *Server) responseMatches(p map[string]string, method, nonce string) bool {
	ha1 := config.DigestHash("MD5", s.opts.DigestUser+":"+digestRealm+":"+s.opts.DigestPass)
	ha2 := config.DigestHash("MD5", method+":"+p["uri"])
	var want string
	if p["qop"] == "auth" {
		want = config.DigestHash("MD5", strings.Join([]string{ha1, nonce, p["nc"], p["cnonce"], "auth", ha2}, ":"))
	} else {
		want = config.DigestHash("MD5", strings.Join([]string{ha1, nonce, ha2}, ":"))
	}
	return p["response"] == want && p["username"] == s.opts.DigestUser
}

func (s *Server) reject(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf(`Digest realm=%q, qop="auth", nonce=%q`, digestRealm, s.auth.current()))
	http.Error(w, "bad credentials", http.StatusUnauthorized)
}

func (s *Server) challenge(w http.ResponseWriter, stale bool) {
	var nonce string
	switch {
	case s.opts.SingleUseNonce:
		sessID, n := s.auth.issue()
		nonce = n
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: sessID, Path: "/", HttpOnly: true})
	case s.opts.SessionBoundNonce:
		nonce = s.auth.current()
		http.SetCookie(w, &http.Cookie{
			Name: sessionCookie, Value: s.auth.session(), Path: "/", HttpOnly: true,
		})
	default:
		nonce = s.auth.current()
	}
	v := fmt.Sprintf(`Digest realm=%q, qop="auth", nonce=%q`, digestRealm, nonce)
	if stale {
		v += `, stale=true`
	}
	w.Header().Set("WWW-Authenticate", v)
	http.Error(w, "authentication required", http.StatusUnauthorized)
}
