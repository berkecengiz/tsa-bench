package transport_test

// These tests pin the decisions in transport.New that are invisible from the
// outside and expensive to get wrong: each one was a real failure against a
// real provider before it was a test.

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/berkecengiz/tsa-bench/internal/config"
	"github.com/berkecengiz/tsa-bench/internal/metrics"
	"github.com/berkecengiz/tsa-bench/internal/testutil"
	"github.com/berkecengiz/tsa-bench/internal/transport"
)

// baseConfig is the smallest configuration transport.New accepts. Validation
// lives in internal/config; this package only consumes the result.
func baseConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Request.Timeout = 3 * time.Second
	cfg.Load.MaxConcurrency = 8
	cfg.TLS.MinVersion = "1.2"
	return cfg
}

func TestClientTimeoutAndRedirectPolicy(t *testing.T) {
	client, _, err := transport.New(baseConfig(), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if client.Timeout != 3*time.Second {
		t.Errorf("client timeout = %v, want the configured request timeout", client.Timeout)
	}

	// A redirect would move the load to another host and could forward the
	// Authorization header there, so it must never be followed.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the client followed a redirect to a second host")
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer origin.Close()

	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want the 302 returned unfollowed", resp.StatusCode)
	}
}

// TestCookieJarPolicy: a jar is required for a provider that binds its digest
// nonce to a session cookie, and actively harmful when every request carries
// its own challenge — net/http appends jar cookies to a Cookie header the
// caller already set, so the server receives two sessions and picks the wrong
// one, and the single jar races between workers.
func TestCookieJarPolicy(t *testing.T) {
	for name, tc := range map[string]struct {
		authType   config.AuthType
		perRequest bool
		wantJar    bool
	}{
		"no auth":                     {config.AuthNone, false, true},
		"basic":                       {config.AuthBasic, false, true},
		"digest, shared challenge":    {config.AuthDigest, false, true},
		"digest, challenge per reqst": {config.AuthDigest, true, false},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := baseConfig()
			cfg.Provider.Auth.Type = tc.authType
			cfg.Provider.Auth.ChallengePerRequest = tc.perRequest

			client, _, err := transport.New(cfg, nil)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if got := client.Jar != nil; got != tc.wantJar {
				t.Errorf("jar present = %t, want %t", got, tc.wantJar)
			}
		})
	}
}

// TestConnStatsCountsOpenAndClose: ConnStats.Open() can only come back down if
// closes are counted, and httptrace has no close event.
func TestConnStatsCountsOpenAndClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var conns metrics.ConnStats
	client, _, err := transport.New(baseConfig(), &conns)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	if conns.Dialed.Load() != 1 {
		t.Fatalf("dialed = %d, want 1", conns.Dialed.Load())
	}
	if conns.Closed.Load() != 0 {
		t.Errorf("closed = %d before teardown, want 0", conns.Closed.Load())
	}

	client.CloseIdleConnections()
	if conns.Closed.Load() != 1 {
		t.Errorf("closed = %d after teardown, want 1", conns.Closed.Load())
	}
}

func TestTLSConfigMinVersion(t *testing.T) {
	for in, want := range map[string]uint16{
		"":    tls.VersionTLS12,
		"1.2": tls.VersionTLS12,
		"1.3": tls.VersionTLS13,
	} {
		cfg := baseConfig()
		cfg.TLS.MinVersion = in
		got, err := transport.TLSConfig(cfg)
		if err != nil {
			t.Fatalf("TLSConfig(%q): %v", in, err)
		}
		if got.MinVersion != want {
			t.Errorf("min version for %q = %x, want %x", in, got.MinVersion, want)
		}
	}

	cfg := baseConfig()
	cfg.TLS.MinVersion = "1.1"
	if _, err := transport.TLSConfig(cfg); err == nil {
		t.Error("an unsupported TLS version was accepted")
	}
}

func TestTLSConfigCarriesOperatorOptIns(t *testing.T) {
	cfg := baseConfig()
	cfg.TLS.InsecureSkipVerify = true
	cfg.TLS.ServerName = "tsa.example.invalid"

	got, err := transport.TLSConfig(cfg)
	if err != nil {
		t.Fatalf("TLSConfig: %v", err)
	}
	if !got.InsecureSkipVerify {
		t.Error("insecure_skip_verify did not reach the TLS configuration")
	}
	if got.ServerName != "tsa.example.invalid" {
		t.Errorf("server name = %q, want the configured override", got.ServerName)
	}

	// The client must also end up holding this configuration, not a copy that
	// silently drops it.
	cfg.Provider.Auth.Type = config.AuthNone
	_, fromClient, err := transport.New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !fromClient.InsecureSkipVerify {
		t.Error("New returned a TLS configuration without the operator's opt-in")
	}
}

// TestTLSConfigLoadsCABundle: getting tls.ca_file wrong is the difference
// between a clean run and every request failing, so both the success and the
// failure path are pinned.
func TestTLSConfigLoadsCABundle(t *testing.T) {
	dir := t.TempDir()

	ca, err := testutil.NewCA("transport-test", testutil.ECDSAP256)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	good := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(good, ca.PEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}

	cfg := baseConfig()
	cfg.TLS.CAFile = good
	got, err := transport.TLSConfig(cfg)
	if err != nil {
		t.Fatalf("TLSConfig: %v", err)
	}
	if got.RootCAs == nil {
		t.Fatal("a configured ca_file produced no root pool")
	}

	// An empty ca_file means the system store, which is nil here by design.
	cfg.TLS.CAFile = ""
	sys, err := transport.TLSConfig(cfg)
	if err != nil {
		t.Fatalf("TLSConfig: %v", err)
	}
	if sys.RootCAs != nil {
		t.Error("an empty ca_file should fall through to the system store")
	}

	// A file that is not PEM must fail loudly rather than leave an empty pool
	// that rejects every response as untrusted_certificate.
	bad := filepath.Join(dir, "not-pem.txt")
	if err := os.WriteFile(bad, []byte("this is not a certificate"), 0o600); err != nil {
		t.Fatalf("write junk: %v", err)
	}
	cfg.TLS.CAFile = bad
	if _, err := transport.TLSConfig(cfg); err == nil {
		t.Error("a CA bundle with no usable PEM was accepted")
	}

	cfg.TLS.CAFile = filepath.Join(dir, "absent.pem")
	if _, err := transport.TLSConfig(cfg); err == nil {
		t.Error("a missing CA bundle was accepted")
	}
}

func TestTLSConfigClientCertificate(t *testing.T) {
	dir := t.TempDir()

	ca, err := testutil.NewCA("mtls-test", testutil.ECDSAP256)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	leaf, err := ca.ServerCert([]string{"client.example.invalid"}, testutil.ECDSAP256)
	if err != nil {
		t.Fatalf("ServerCert: %v", err)
	}
	keyPEM, err := leaf.KeyPEM()
	if err != nil {
		t.Fatalf("KeyPEM: %v", err)
	}

	certPath := filepath.Join(dir, "client.pem")
	keyPath := filepath.Join(dir, "client.key")
	if err := os.WriteFile(certPath, leaf.PEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	cfg := baseConfig()
	cfg.TLS.ClientCertFile = certPath
	cfg.TLS.ClientKeyFile = keyPath

	got, err := transport.TLSConfig(cfg)
	if err != nil {
		t.Fatalf("TLSConfig: %v", err)
	}
	if len(got.Certificates) != 1 {
		t.Fatalf("%d client certificates, want 1", len(got.Certificates))
	}
	if _, err := x509.ParseCertificate(got.Certificates[0].Certificate[0]); err != nil {
		t.Errorf("the loaded client certificate does not parse: %v", err)
	}

	// A mismatched pair must be rejected at setup, not at the first request.
	cfg.TLS.ClientKeyFile = filepath.Join(dir, "absent.key")
	if _, err := transport.TLSConfig(cfg); err == nil {
		t.Error("a client certificate with a missing key was accepted")
	}
}
