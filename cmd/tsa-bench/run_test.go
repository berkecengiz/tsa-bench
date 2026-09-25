package main

// The safety gates on `run` are the whole reason this command cannot spend a
// customer's quota by accident. There is no interactive prompt — the condition
// is carried entirely by the flags — so each gate is pinned here, along with
// the exit code it must produce.
//
// Exit code 2 means "usage error, including a missing safety flag", and a
// caller script is entitled to rely on that.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// exitCode reports the status an error would exit with, or -1 if it carries
// none.
func exitCode(err error) int {
	var e *exitError
	if errors.As(err, &e) {
		return e.code
	}
	return -1
}

func TestParseRunFlagsRequiresEverySafetyFlag(t *testing.T) {
	const (
		cfg     = "--config=x.yaml"
		profile = "--profile=p.yaml"
		maxReq  = "--max-requests=100"
		auth    = "--authorized-load-test"
	)

	for name, args := range map[string][]string{
		"no flags at all":            {},
		"no config":                  {profile, maxReq, auth},
		"no profile":                 {cfg, maxReq, auth},
		"no max-requests":            {cfg, profile, auth},
		"max-requests of zero":       {cfg, profile, "--max-requests=0", auth},
		"negative max-requests":      {cfg, profile, "--max-requests=-1", auth},
		"no authorisation flag":      {cfg, profile, maxReq},
		"authorisation set to false": {cfg, profile, maxReq, "--authorized-load-test=false"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parseRunFlags(args)
			if err == nil {
				t.Fatalf("a run was accepted without its safety flags: %+v", got)
			}
			if code := exitCode(err); code != 2 {
				t.Errorf("exit code = %d, want 2 for a usage error", code)
			}
		})
	}
}

func TestParseRunFlagsAcceptsAComplete(t *testing.T) {
	f, err := parseRunFlags([]string{
		"--config=x.yaml", "--profile=p.yaml",
		"--max-requests=100", "--authorized-load-test",
		"--redact-host",
	})
	if err != nil {
		t.Fatalf("parseRunFlags: %v", err)
	}
	if f.cfgPath != "x.yaml" || f.profilePath != "p.yaml" || f.maxRequests != 100 {
		t.Errorf("flags not parsed as expected: %+v", f)
	}
	if !f.redactHost {
		t.Error("--redact-host did not take effect")
	}
	// Defaults that matter: the automatic abort stays on unless asked off, and
	// raw protocol bytes are never written unless asked for.
	if f.noAutoAbort {
		t.Error("the automatic abort defaulted to disabled")
	}
	if f.debugArtifacts {
		t.Error("debug artifacts defaulted to on")
	}
}

// TestLoadInputsRequiresLiveAcknowledgement: a configuration that declares a
// live production target needs one more flag than a test bed does.
func TestLoadInputsRequiresLiveAcknowledgement(t *testing.T) {
	dir := t.TempDir()

	write := func(name, body string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}

	profilePath := write("profile.yaml", `name: t
reserve: 0
stages:
  - name: functional
    mode: sequential
    count: 10
`)

	configBody := func(env string) string {
		return `provider:
  name: t
  endpoint: "http://127.0.0.1:8318/"
  environment: ` + env + `
  auth:
    type: none
tls:
  min_version: "1.2"
request:
  hash_algorithm: sha256
  payload_size: 64
  timeout: 10s
  cert_req: true
  max_clock_skew: 60s
load:
  max_concurrency: 8
  stage_pause: 1s
  lag_threshold: 250ms
  grace_period: 5s
limits:
  max_requests: 100
  hard_cap: 1000
  retries: 0
  abort_on_error_rate: 0.25
  abort_window: 200
  abort_on_consecutive_failures: 50
output:
  directory: results
`
	}

	live := write("live.yaml", configBody("live"))
	test := write("test.yaml", configBody("test"))

	base := func(cfgPath string, ack bool) *runFlags {
		return &runFlags{
			cfgPath: cfgPath, profilePath: profilePath,
			maxRequests: 10, ackLive: ack,
		}
	}

	if _, _, err := loadInputs(base(live, false)); err == nil {
		t.Error("a live target was accepted without --acknowledge-live-environment")
	} else if code := exitCode(err); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}

	if _, _, err := loadInputs(base(live, true)); err != nil {
		t.Errorf("an acknowledged live target was rejected: %v", err)
	}

	// A test bed needs no acknowledgement.
	if _, _, err := loadInputs(base(test, false)); err != nil {
		t.Errorf("a test target was rejected: %v", err)
	}
}

// TestLoadInputsEnforcesQuotaCeilings: --max-requests may never exceed the
// configured hard cap, nor the budget `validate` checks profiles against, or
// the two commands would disagree about what fits.
func TestLoadInputsEnforcesQuotaCeilings(t *testing.T) {
	dir := t.TempDir()

	profilePath := filepath.Join(dir, "profile.yaml")
	if err := os.WriteFile(profilePath, []byte(`name: t
reserve: 0
stages:
  - name: functional
    mode: sequential
    count: 10
`), 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}

	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`provider:
  name: t
  endpoint: "http://127.0.0.1:8318/"
  environment: test
  auth:
    type: none
tls:
  min_version: "1.2"
request:
  hash_algorithm: sha256
  payload_size: 64
  timeout: 10s
  cert_req: true
  max_clock_skew: 60s
load:
  max_concurrency: 8
  stage_pause: 1s
  lag_threshold: 250ms
  grace_period: 5s
limits:
  max_requests: 100
  hard_cap: 1000
  retries: 0
  abort_on_error_rate: 0.25
  abort_window: 200
  abort_on_consecutive_failures: 50
output:
  directory: results
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	for name, max := range map[string]int64{
		"above the hard cap":        5000,
		"above limits.max_requests": 500,
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := loadInputs(&runFlags{
				cfgPath: cfgPath, profilePath: profilePath, maxRequests: max,
			})
			if err == nil {
				t.Fatal("a run exceeding its configured ceiling was accepted")
			}
			if code := exitCode(err); code != 2 {
				t.Errorf("exit code = %d, want 2", code)
			}
		})
	}

	if _, _, err := loadInputs(&runFlags{
		cfgPath: cfgPath, profilePath: profilePath, maxRequests: 50,
	}); err != nil {
		t.Errorf("a run inside every ceiling was rejected: %v", err)
	}
}
