package config

import (
	"crypto/md5" //nolint:gosec // RFC 7616 names MD5 as the default algorithm; the server chooses
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

// HTTP Digest access authentication (RFC 7616, and RFC 2617 for the MD5
// default that older servers still speak).
//
// Unlike Basic, Digest is a conversation: the client cannot authenticate
// anything until the server has issued a challenge carrying a nonce. Once one
// is held, every subsequent request can be authenticated pre-emptively, which
// is what keeps a load test at one HTTP request per timestamp. The nonce is
// primed once before load starts; see Runner.primeAuth.
//
// A nonce eventually goes stale. The server then answers 401 with stale=true,
// the challenge is replaced and the request is sent again. That second HTTP
// request issues no timestamp and consumes no quota; it is counted separately
// and reported as reauth_requests so the run's HTTP traffic and its quota
// usage can still be reconciled.

// digestState holds the current challenge and the counter that makes each
// response unique. One instance is shared by every worker.
type digestState struct {
	mu        sync.RWMutex
	challenge challenge
	// ha1 is MD5(username:realm:password), valid only for the realm it was
	// computed against. Holding it here means the password is hashed once and
	// the plaintext never leaves Credentials.
	ha1 string
	// nc counts responses sent against the current nonce. It must be unique
	// and increasing per nonce: it is the replay defence, and 150 concurrent
	// workers each need their own value.
	nc atomic.Uint64
}

// HasChallenge reports whether a challenge has been received and a request can
// be authenticated.
func (cr *Credentials) HasChallenge() bool {
	if cr == nil || cr.digest == nil {
		return false
	}
	cr.digest.mu.RLock()
	defer cr.digest.mu.RUnlock()
	return cr.digest.challenge.nonce != ""
}

// SetChallenge parses a WWW-Authenticate header and replaces the stored
// challenge. It is safe to call concurrently; the last writer wins, which is
// what should happen when several workers race on the same stale nonce.
func (cr *Credentials) SetChallenge(header string) error {
	if cr == nil || cr.digest == nil {
		return fmt.Errorf("digest authentication is not configured")
	}
	c, err := parseChallenge(header)
	if err != nil {
		return err
	}

	d := cr.digest
	d.mu.Lock()
	defer d.mu.Unlock()
	d.challenge = c
	d.ha1 = digestHash(c.algorithm, cr.username+":"+c.realm+":"+cr.password)
	d.nc.Store(0)
	return nil
}

// challenge holds the parameters of one WWW-Authenticate challenge, already
// checked for the parts this client can answer.
type challenge struct {
	realm     string
	nonce     string
	opaque    string
	qop       string
	algorithm string
}

// parseChallenge reads a challenge and rejects what cannot be answered. Both
// authentication modes go through it, so neither can drift into accepting an
// algorithm the other refuses.
func parseChallenge(header string) (challenge, error) {
	p, err := parseDigestChallenge(header)
	if err != nil {
		return challenge{}, err
	}

	algo := p["algorithm"]
	if strings.HasSuffix(strings.ToUpper(algo), "-SESS") {
		return challenge{}, fmt.Errorf("digest algorithm %q (session variant) is not supported", algo)
	}
	switch strings.ToUpper(algo) {
	case "", "MD5", "SHA-256":
	default:
		return challenge{}, fmt.Errorf("unsupported digest algorithm %q", algo)
	}
	realm, ok := p["realm"]
	if !ok {
		return challenge{}, fmt.Errorf("digest challenge has no realm")
	}
	nonce, ok := p["nonce"]
	if !ok {
		return challenge{}, fmt.Errorf("digest challenge has no nonce")
	}
	// qop is optional in RFC 2617. When offered it may be a list; only "auth"
	// is implemented, and "auth-int" would require hashing the body.
	qop := ""
	for _, v := range strings.Split(p["qop"], ",") {
		if strings.TrimSpace(v) == "auth" {
			qop = "auth"
			break
		}
	}
	if p["qop"] != "" && qop == "" {
		return challenge{}, fmt.Errorf("digest challenge offers qop=%q; only auth is supported", p["qop"])
	}

	return challenge{realm: realm, nonce: nonce, opaque: p["opaque"], qop: qop, algorithm: algo}, nil
}

// IsStaleChallenge reports whether a 401 indicates an expired nonce rather
// than bad credentials. A stale challenge is worth answering; a rejection is
// not, and retrying it would only burn the account's lockout budget.
func IsStaleChallenge(resp *http.Response) bool {
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		return false
	}
	p, err := parseDigestChallenge(resp.Header.Get("WWW-Authenticate"))
	if err != nil {
		return false
	}
	return strings.EqualFold(p["stale"], "true")
}

// applyDigest sets the Authorization header for one request. It is a no-op
// when no challenge is held yet, which lets the very first request draw one.
func (cr *Credentials) applyDigest(req *http.Request) {
	d := cr.digest
	if d == nil {
		return
	}
	d.mu.RLock()
	c, ha1 := d.challenge, d.ha1
	d.mu.RUnlock()
	if c.nonce == "" {
		return
	}

	req.Header.Set("Authorization",
		cr.digestHeader(req, c, ha1, fmt.Sprintf("%08x", d.nc.Add(1))))
}

// digestHeader builds one Authorization header. Both modes share it so the
// wire format has a single definition; they differ only in where the nonce
// count comes from.
func (cr *Credentials) digestHeader(req *http.Request, c challenge, ha1, ncHex string) string {
	uri := req.URL.RequestURI()
	ha2 := digestHash(c.algorithm, req.Method+":"+uri)

	var response, cnonce string
	if c.qop == "auth" {
		cnonce = randomHex(16)
		response = digestHash(c.algorithm, strings.Join(
			[]string{ha1, c.nonce, ncHex, cnonce, c.qop, ha2}, ":"))
	} else {
		// RFC 2617 without qop: no nc, no cnonce.
		response = digestHash(c.algorithm, strings.Join([]string{ha1, c.nonce, ha2}, ":"))
	}

	var b strings.Builder
	b.WriteString(`Digest username=`)
	b.WriteString(quoteDigest(cr.username))
	b.WriteString(`, realm=`)
	b.WriteString(quoteDigest(c.realm))
	b.WriteString(`, nonce=`)
	b.WriteString(quoteDigest(c.nonce))
	b.WriteString(`, uri=`)
	b.WriteString(quoteDigest(uri))
	b.WriteString(`, response=`)
	b.WriteString(quoteDigest(response))
	if c.algorithm != "" {
		b.WriteString(`, algorithm=`)
		b.WriteString(c.algorithm)
	}
	if c.opaque != "" {
		b.WriteString(`, opaque=`)
		b.WriteString(quoteDigest(c.opaque))
	}
	if c.qop == "auth" {
		b.WriteString(`, qop=auth, nc=`)
		b.WriteString(ncHex)
		b.WriteString(`, cnonce=`)
		b.WriteString(quoteDigest(cnonce))
	}
	return b.String()
}

// digestHash applies the algorithm named by the challenge. RFC 7616 §3.3
// makes MD5 the default when the server names none.
func digestHash(algorithm, s string) string {
	if strings.EqualFold(strings.TrimSuffix(algorithm, "-sess"), "SHA-256") {
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])
	}
	sum := md5.Sum([]byte(s)) //nolint:gosec // the server's choice of algorithm, not ours
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand does not fail in practice, and a predictable cnonce
		// weakens only this client's side of the exchange.
		return strings.Repeat("0", n*2)
	}
	return hex.EncodeToString(b)
}

// quoteDigest wraps a value in quotes, escaping what RFC 7230 requires. The
// values here are hex digests, a realm and a username, so this is belt and
// braces rather than a live concern.
// strings.Replacer is safe for concurrent use, so these are built once
// rather than per call - quoteDigest runs six times per request.
var (
	digestQuoter   = strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	digestUnquoter = strings.NewReplacer(`\"`, `"`, `\\`, `\`)
)

func quoteDigest(s string) string {
	return `"` + digestQuoter.Replace(s) + `"`
}

// parseDigestChallenge reads the parameters of a Digest WWW-Authenticate
// header. Values may be quoted or bare, and a server may offer several
// schemes; only the Digest one is read.
func parseDigestChallenge(header string) (map[string]string, error) {
	h := strings.TrimSpace(header)
	if h == "" {
		return nil, fmt.Errorf("no WWW-Authenticate header")
	}
	i := strings.Index(strings.ToLower(h), "digest")
	if i < 0 {
		return nil, fmt.Errorf("server does not offer Digest authentication")
	}
	h = strings.TrimSpace(h[i+len("digest"):])

	out := map[string]string{}
	for _, kv := range splitDigestParams(h) {
		eq := strings.Index(kv, "=")
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[:eq]))
		val := strings.TrimSpace(kv[eq+1:])
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = digestUnquoter.Replace(val[1 : len(val)-1])
		}
		out[key] = val
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("digest challenge has no parameters")
	}
	return out, nil
}

// splitDigestParams splits on commas that are not inside a quoted string. A
// nonce is base64 and can legitimately contain a comma once unquoted values
// are in play, so a plain Split would corrupt it.
func splitDigestParams(s string) []string {
	var parts []string
	var cur strings.Builder
	inQuotes, escaped := false, false
	for _, r := range s {
		switch {
		case escaped:
			escaped = false
			cur.WriteRune(r)
		case r == '\\' && inQuotes:
			escaped = true
			cur.WriteRune(r)
		case r == '"':
			inQuotes = !inQuotes
			cur.WriteRune(r)
		case r == ',' && !inQuotes:
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if strings.TrimSpace(cur.String()) != "" {
		parts = append(parts, cur.String())
	}
	return parts
}

// AuthorizeOnce answers one challenge for one request, holding no state.
//
// It exists for servers that invalidate a nonce after a single use. Every
// request then carries its own challenge and its own nonce count of 1, so
// there is nothing to share between workers and nothing to go stale.
func (cr *Credentials) AuthorizeOnce(req *http.Request, header string) error {
	if cr == nil {
		return fmt.Errorf("no credentials")
	}
	c, err := parseChallenge(header)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", cr.digestHeader(req, c, cr.ha1For(c), "00000001"))
	return nil
}

// ha1For returns the credential hash for a realm, computing it only when the
// realm changes. A server that issues a fresh challenge per request repeats
// the same realm every time, so this keeps the password out of a new heap
// string on every one of them.
func (cr *Credentials) ha1For(c challenge) string {
	d := cr.digest
	if d == nil {
		return digestHash(c.algorithm, cr.username+":"+c.realm+":"+cr.password)
	}

	d.mu.RLock()
	if d.ha1 != "" && d.challenge.realm == c.realm && d.challenge.algorithm == c.algorithm {
		ha1 := d.ha1
		d.mu.RUnlock()
		return ha1
	}
	d.mu.RUnlock()

	ha1 := digestHash(c.algorithm, cr.username+":"+c.realm+":"+cr.password)
	d.mu.Lock()
	d.challenge.realm, d.challenge.algorithm, d.ha1 = c.realm, c.algorithm, ha1
	d.mu.Unlock()
	return ha1
}
