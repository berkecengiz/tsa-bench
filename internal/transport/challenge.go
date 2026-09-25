package transport

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
)

// DrawDigestChallenge sends an unauthenticated POST and returns the digest
// challenge the server answers with, together with any session cookie it set.
//
// The request carries no body, so a timestamp service has nothing to issue and
// no quota is spent. The cookie is returned rather than left to a jar because
// one provider binds its nonce to a session and invalidates it after a single
// use: two workers sharing a jar would overwrite each other. Callers that do
// share a session can ignore it.
//
// This is the single definition of that exchange. Both the load runner and
// doctor use it, so a pre-flight check cannot drift from what a run does.
func DrawDigestChallenge(ctx context.Context, client *http.Client, endpoint, contentType string,
	trace *httptrace.ClientTrace) (challenge, cookie string, err error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, http.NoBody)
	if err != nil {
		return "", "", fmt.Errorf("build challenge request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.ContentLength = 0
	if trace != nil {
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusUnauthorized {
		return "", "", fmt.Errorf("expected a 401 digest challenge, got HTTP %d", resp.StatusCode)
	}
	challenge = resp.Header.Get("WWW-Authenticate")
	if challenge == "" {
		return "", "", fmt.Errorf("the 401 carried no WWW-Authenticate header")
	}

	for _, c := range resp.Cookies() {
		if cookie != "" {
			cookie += "; "
		}
		cookie += c.Name + "=" + c.Value
	}
	return challenge, cookie, nil
}
