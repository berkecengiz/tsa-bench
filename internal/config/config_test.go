package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/berkecengiz/tsa-bench/internal/config"
)

const validYAML = `
provider:
  name: test-provider
  endpoint: "https://tsa.example.com/timestamp"
  environment: test
  auth:
    type: basic
    username_env: TSABENCH_TEST_USER
    password_env: TSABENCH_TEST_PASS
tls:
  insecure_skip_verify: false
  min_version: "1.2"
request:
  hash_algorithm: sha256
  payload_size: 64
  timeout: 10s
  cert_req: true
  max_clock_skew: 60s
load:
  max_concurrency: 500
  stage_pause: 30s
  grace_period: 30s
limits:
  max_requests: 48600
  hard_cap: 50000
  retries: 0
output:
  directory: results
`

func withCreds(t *testing.T) {
	t.Helper()
	t.Setenv("TSABENCH_TEST_USER", "someone")
	t.Setenv("TSABENCH_TEST_PASS", "a-secret-value")
}

func TestParseValid(t *testing.T) {
	withCreds(t)

	cfg, err := config.Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Provider.Name != "test-provider" {
		t.Errorf("name = %q", cfg.Provider.Name)
	}
	if cfg.Limits.HardCap != 50000 {
		t.Errorf("hard_cap = %d", cfg.Limits.HardCap)
	}
	if cfg.TLS.InsecureSkipVerify {
		t.Error("insecure_skip_verify must default to false")
	}
	if cfg.Limits.Retries != 0 {
		t.Error("retries must default to 0: each retry consumes quota")
	}
}

// TestConfigDumpNeverLeaksSecrets is the central privacy guarantee: the
// configuration dump is printed by `validate` and written into logs.
func TestConfigDumpNeverLeaksSecrets(t *testing.T) {
	withCreds(t)

	yaml := strings.Replace(validYAML,
		`endpoint: "https://tsa.example.com/timestamp"`,
		`endpoint: "https://tsa.example.com/timestamp?apikey=QUERYSECRET"`, 1)

	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	dump := cfg.String()
	for _, secret := range []string{"a-secret-value", "someone", "QUERYSECRET"} {
		if strings.Contains(dump, secret) {
			t.Errorf("config dump leaks %q:\n%s", secret, dump)
		}
	}
	// The variable *names* are useful and must survive.
	if !strings.Contains(dump, "TSABENCH_TEST_PASS") {
		t.Error("dump should name the environment variable it reads")
	}
}

// TestCredentialsHideThemselvesFromFormatting guards against an accidental
// %v on the credential struct in a log line.
func TestCredentialsHideThemselvesFromFormatting(t *testing.T) {
	withCreds(t)

	cfg, err := config.Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	creds, err := cfg.ResolveCredentials()
	if err != nil {
		t.Fatalf("ResolveCredentials: %v", err)
	}

	for _, rendered := range []string{
		creds.String(),
		strings.TrimSpace(sprintf("%v", creds)),
		strings.TrimSpace(sprintf("%#v", creds)),
		strings.TrimSpace(sprintf("%s", creds)),
	} {
		if strings.Contains(rendered, "a-secret-value") || strings.Contains(rendered, "someone") {
			t.Errorf("credentials leaked through formatting: %q", rendered)
		}
	}
}

func TestValidationRejectsUnsafeConfigurations(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(string) string
		wantErr string
	}{
		{"missing environment", func(s string) string {
			return strings.Replace(s, "  environment: test\n", "", 1)
		}, "provider.environment"},
		{"credentials in url", func(s string) string {
			return strings.Replace(s, "https://tsa.example.com/timestamp",
				"https://user:pass@tsa.example.com/timestamp", 1)
		}, "must not embed credentials"},
		{"plaintext http", func(s string) string {
			return strings.Replace(s, "https://tsa.example.com", "http://tsa.example.com", 1)
		}, "use https"},
		{"cert_req false", func(s string) string {
			return strings.Replace(s, "cert_req: true", "cert_req: false", 1)
		}, "request.cert_req"},
		{"sha1 rejected", func(s string) string {
			return strings.Replace(s, "hash_algorithm: sha256", "hash_algorithm: sha1", 1)
		}, "sha1"},
		// hard_cap is the engagement quota and varies per provider, so a
		// larger value is legitimate; only a stray digit is caught.
		{"hard cap with a stray digit", func(s string) string {
			return strings.Replace(s, "hard_cap: 50000", "hard_cap: 500000000", 1)
		}, "sanity limit"},
		{"max_requests above hard cap", func(s string) string {
			return strings.Replace(s, "max_requests: 48600", "max_requests: 60000", 1)
		}, "hard_cap"},
		{"too many retries", func(s string) string {
			return strings.Replace(s, "retries: 0", "retries: 9", 1)
		}, "retries"},
		{"unknown field", func(s string) string {
			return s + "\nunexpected_key: 1\n"
		}, "unexpected_key"},
		{"no endpoint", func(s string) string {
			return strings.Replace(s, `  endpoint: "https://tsa.example.com/timestamp"`, `  endpoint: ""`, 1)
		}, "provider.endpoint"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withCreds(t)
			_, err := config.Parse([]byte(tc.mutate(validYAML)))
			if err == nil {
				t.Fatalf("configuration was accepted but should be rejected")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, expected it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestPlaintextNeedsExplicitOptIn covers the safety rule and its escape hatch:
// a plaintext endpoint is refused by default, and permitted only when the
// operator says so in the configuration.
func TestPlaintextNeedsExplicitOptIn(t *testing.T) {
	withCreds(t)

	plain := strings.Replace(validYAML, "https://tsa.example.com", "http://tsa.example.com", 1)

	if _, err := config.Parse([]byte(plain)); err == nil {
		t.Fatal("a plaintext endpoint was accepted without an opt-in")
	}

	opted := strings.Replace(plain, "  environment: test",
		"  allow_plaintext: true\n  environment: test", 1)
	cfg, err := config.Parse([]byte(opted))
	if err != nil {
		t.Fatalf("allow_plaintext did not permit the endpoint: %v", err)
	}
	if !cfg.Provider.AllowPlaintext {
		t.Error("allow_plaintext did not survive parsing")
	}
}

// TestPlaintextIsWarnedAndRecorded: the opt-in must be impossible to use
// quietly. A run made this way has to be distinguishable from an
// authenticated one afterwards.
func TestPlaintextIsWarnedAndRecorded(t *testing.T) {
	withCreds(t)

	yaml := strings.Replace(validYAML, "https://tsa.example.com", "http://tsa.example.com", 1)
	yaml = strings.Replace(yaml, "  environment: test", "  allow_plaintext: true\n  environment: test", 1)

	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	var found bool
	for _, w := range cfg.Warnings() {
		if w.Field == "provider.allow_plaintext" {
			found = true
		}
	}
	if !found {
		t.Error("a plaintext endpoint produced no warning")
	}
	if !strings.Contains(cfg.String(), "provider.allow_plaintext=true") {
		t.Error("the configuration dump hides that the endpoint was plaintext")
	}
}

// TestLoopbackPlaintextNeedsNoOptIn: the local mock must keep working without
// ceremony, and without a warning that would cry wolf on every smoke test.
func TestLoopbackPlaintextNeedsNoOptIn(t *testing.T) {
	withCreds(t)

	yaml := strings.Replace(validYAML, "https://tsa.example.com/timestamp", "http://127.0.0.1:8318/", 1)
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("a loopback endpoint was rejected: %v", err)
	}
	for _, w := range cfg.Warnings() {
		if w.Field == "provider.allow_plaintext" {
			t.Error("a loopback mock produced a plaintext warning")
		}
	}
}

// TestMissingCredentialEnvIsRejected makes a misconfigured secret fail before
// the run rather than mid-flight.
func TestMissingCredentialEnvIsRejected(t *testing.T) {
	t.Setenv("TSABENCH_TEST_USER", "someone")
	os.Unsetenv("TSABENCH_TEST_PASS")

	_, err := config.Parse([]byte(validYAML))
	if err == nil {
		t.Fatal("a configuration referencing an unset password variable was accepted")
	}
	if !strings.Contains(err.Error(), "TSABENCH_TEST_PASS") {
		t.Errorf("error should name the missing variable: %v", err)
	}
}

// TestLiteralSecretInAuthHeaderIsRejected: a literal in the file would end up
// in version control.
func TestLiteralSecretInAuthHeaderIsRejected(t *testing.T) {
	yaml := strings.Replace(validYAML, `    type: basic
    username_env: TSABENCH_TEST_USER
    password_env: TSABENCH_TEST_PASS`, `    type: header
    headers:
      X-Api-Key: "literal-secret"`, 1)

	if _, err := config.Parse([]byte(yaml)); err == nil {
		t.Fatal("a literal secret in an auth header was accepted")
	}
}

func TestEnvInterpolation(t *testing.T) {
	withCreds(t)
	t.Setenv("TSABENCH_TEST_HOST", "tsa.interpolated.example.com")

	yaml := strings.Replace(validYAML, "https://tsa.example.com/timestamp",
		"https://${TSABENCH_TEST_HOST}/timestamp", 1)

	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !strings.Contains(cfg.Provider.Endpoint, "tsa.interpolated.example.com") {
		t.Errorf("endpoint = %q", cfg.Provider.Endpoint)
	}
}

func TestEnvInterpolationRejectsUnsetVariable(t *testing.T) {
	withCreds(t)
	os.Unsetenv("TSABENCH_TEST_ABSENT")

	yaml := strings.Replace(validYAML, "https://tsa.example.com",
		"https://${TSABENCH_TEST_ABSENT}", 1)

	_, err := config.Parse([]byte(yaml))
	if err == nil {
		t.Fatal("an unset interpolation variable was silently substituted with an empty string")
	}
	if !strings.Contains(err.Error(), "TSABENCH_TEST_ABSENT") {
		t.Errorf("error should name the variable: %v", err)
	}
}

func TestWarningsSurfaceDangerousSettings(t *testing.T) {
	withCreds(t)

	yaml := strings.Replace(validYAML, "insecure_skip_verify: false", "insecure_skip_verify: true", 1)
	yaml = strings.Replace(yaml, "environment: test", "environment: live", 1)

	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	var sawTLS, sawLive bool
	for _, w := range cfg.Warnings() {
		if strings.Contains(w.Field, "insecure_skip_verify") {
			sawTLS = true
		}
		if strings.Contains(w.Field, "environment") {
			sawLive = true
		}
	}
	if !sawTLS {
		t.Error("disabling TLS verification produced no warning")
	}
	if !sawLive {
		t.Error("a live production target produced no warning")
	}
}

func TestLoadFileMissing(t *testing.T) {
	if _, err := config.LoadFile(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("a missing config file was accepted")
	}
}
