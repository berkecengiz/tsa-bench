package config

import (
	"fmt"
	"hash"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/berkecengiz/tsa-bench/internal/tsp"

	"github.com/berkecengiz/tsa-bench/internal/redact"
)

// Problem is a single validation failure.
type Problem struct {
	Field  string
	Reason string
}

func (p Problem) Error() string { return p.Field + ": " + p.Reason }

// ProblemList aggregates every validation failure so the operator can fix them
// in one pass instead of one per run.
type ProblemList []Problem

func (pl ProblemList) Error() string {
	parts := make([]string, len(pl))
	for i, p := range pl {
		parts[i] = p.Error()
	}
	return "invalid configuration:\n  - " + strings.Join(parts, "\n  - ")
}

// Warnings are non-fatal but must be surfaced prominently and recorded in the
// report (notably a disabled TLS verification).
type Warning struct {
	Field   string
	Message string
	// Limitation is the same fact in the past tense, for the report's
	// limitations list. A warning carries one when the setting it describes
	// bounds what the run's results can be taken to prove; the operator-facing
	// Message and this share a single condition, so the report cannot disclaim
	// something the operator was never warned about, or stay silent about
	// something they were.
	Limitation string
}

// Validate checks every field. It performs no network I/O and never reads the
// value of a referenced environment variable beyond checking that it is set.
func (c *Config) Validate() error {
	var pl ProblemList
	add := func(field, reason string) { pl = append(pl, Problem{field, reason}) }

	// --- provider ---
	if strings.TrimSpace(c.Provider.Name) == "" {
		add("provider.name", "must not be empty")
	}
	if c.Provider.Endpoint == "" {
		add("provider.endpoint", "must not be empty; there is no default endpoint")
	} else {
		u, err := url.Parse(c.Provider.Endpoint)
		switch {
		case err != nil:
			add("provider.endpoint", "is not a valid URL")
		case u.Scheme != "http" && u.Scheme != "https":
			add("provider.endpoint", "scheme must be http or https")
		case u.Host == "":
			add("provider.endpoint", "must include a host")
		case u.User != nil:
			add("provider.endpoint", "must not embed credentials in the URL; use auth.*_env instead")
		case u.Scheme == "http" && !IsLoopbackHost(u.Hostname()) && !c.Provider.AllowPlaintext:
			// Plaintext is tolerated for a local mock, where there is no
			// network path to eavesdrop on and no real credential to expose,
			// and otherwise only when the operator opts in explicitly for a
			// service that offers no TLS at all.
			add("provider.endpoint",
				"plaintext http exposes credentials and timestamps; use https, "+
					"or set provider.allow_plaintext if the service offers no TLS and the path is private")
		}
	}
	switch c.Provider.Environment {
	case EnvLive, EnvTest:
	case "":
		add("provider.environment", `must be set explicitly to "live" or "test"`)
	default:
		add("provider.environment", `must be "live" or "test"`)
	}

	// --- auth ---
	switch c.Provider.Auth.Type {
	case AuthNone, "":
		if c.Provider.Auth.Type == "" {
			add("provider.auth.type", `must be set explicitly (none, basic, digest, bearer, header, mtls)`)
		}
	case AuthBasic, AuthDigest:
		requireEnv(add, "provider.auth.username_env", c.Provider.Auth.UsernameEnv)
		requireEnv(add, "provider.auth.password_env", c.Provider.Auth.PasswordEnv)
		if c.Provider.Auth.Type == AuthBasic && c.Provider.Auth.ChallengePerRequest {
			add("provider.auth.challenge_per_request", "applies only to digest authentication")
		}
	case AuthBearer:
		requireEnv(add, "provider.auth.token_env", c.Provider.Auth.TokenEnv)
	case AuthHeader:
		if len(c.Provider.Auth.Headers) == 0 {
			add("provider.auth.headers", "must define at least one header for auth type header")
		}
		for name, ref := range c.Provider.Auth.Headers {
			if !envRef.MatchString(ref) && !strings.HasPrefix(ref, "env:") {
				add("provider.auth.headers."+name,
					`must reference an environment variable as "env:NAME"; literal secrets are not accepted`)
				continue
			}
			if strings.HasPrefix(ref, "env:") {
				requireEnv(add, "provider.auth.headers."+name, strings.TrimPrefix(ref, "env:"))
			}
		}
	case AuthMTLS:
		if c.TLS.ClientCertFile == "" || c.TLS.ClientKeyFile == "" {
			add("tls.client_cert_file", "mTLS auth requires both client_cert_file and client_key_file")
		}
	default:
		add("provider.auth.type", fmt.Sprintf("unknown auth type %q", c.Provider.Auth.Type))
	}

	// --- tls ---
	for field, path := range map[string]string{
		"tls.ca_file":          c.TLS.CAFile,
		"tls.tsa_ca_file":      c.TLS.TSACAFile,
		"tls.client_cert_file": c.TLS.ClientCertFile,
		"tls.client_key_file":  c.TLS.ClientKeyFile,
	} {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			add(field, "file is not readable: "+redact.Text(err.Error()))
		}
	}
	if (c.TLS.ClientCertFile == "") != (c.TLS.ClientKeyFile == "") {
		add("tls.client_cert_file", "client_cert_file and client_key_file must be set together")
	}
	if _, err := c.MinTLSVersion(); err != nil {
		add("tls.min_version", err.Error())
	}

	// --- request ---
	if _, err := HashByName(c.Request.HashAlgorithm); err != nil {
		add("request.hash_algorithm", err.Error())
	}
	if c.Request.PayloadSize < 16 || c.Request.PayloadSize > 1<<20 {
		add("request.payload_size", "must be between 16 and 1048576 bytes")
	}
	if c.Request.Timeout <= 0 {
		add("request.timeout", "must be greater than zero")
	}
	if c.Request.MaxClockSkew <= 0 {
		add("request.max_clock_skew", "must be greater than zero")
	}
	if c.Request.CertReq != nil && !*c.Request.CertReq {
		add("request.cert_req", "must be true; without the TSA certificate the signature cannot be verified")
	}
	if c.Request.PolicyOID != "" && !validOID(c.Request.PolicyOID) {
		add("request.policy_oid", "is not a valid dotted OID")
	}

	// --- load ---
	if c.Load.MaxConcurrency < 1 {
		add("load.max_concurrency", "must be at least 1")
	}
	if c.Load.MaxConcurrency > 20000 {
		add("load.max_concurrency", "exceeds a sane client limit (20000)")
	}
	if c.Load.StagePause < 0 {
		add("load.stage_pause", "must not be negative")
	}
	if c.Load.GracePeriod <= 0 {
		add("load.grace_period", "must be greater than zero")
	}
	// A zero threshold makes every tick look late, which would mark every run
	// as client-bottlenecked and invalidate the headline result.
	if c.Load.LagThreshold <= 0 {
		add("load.lag_threshold", "must be greater than zero")
	}

	// --- limits ---
	if c.Limits.HardCap < 1 {
		add("limits.hard_cap", "must be at least 1")
	}
	// hard_cap is the engagement quota and belongs to the provider's own
	// configuration; only an implausible value is rejected here.
	if c.Limits.HardCap > MaxConfigurableHardCap {
		add("limits.hard_cap", fmt.Sprintf("exceeds the sanity limit of %d; check for a stray digit",
			MaxConfigurableHardCap))
	}
	if c.Limits.MaxRequests < 0 {
		add("limits.max_requests", "must not be negative")
	}
	if c.Limits.MaxRequests > c.Limits.HardCap {
		add("limits.max_requests", "must not exceed limits.hard_cap")
	}
	// Retries are not implemented: the runner issues exactly one attempt per
	// unit of quota. Accepting a non-zero value here would make the banner and
	// the report describe behaviour that never happens.
	if c.Limits.Retries != 0 {
		add("limits.retries", "must be 0; retries are not implemented and every request is attempted exactly once")
	}
	if c.Limits.AbortOnErrorRate < 0 || c.Limits.AbortOnErrorRate > 1 {
		add("limits.abort_on_error_rate", "must be a fraction between 0 and 1")
	}
	if c.Limits.AbortWindow < 10 {
		add("limits.abort_window", "must be at least 10 for a meaningful error rate")
	}

	// --- output ---
	if strings.TrimSpace(c.Output.Directory) == "" {
		add("output.directory", "must not be empty")
	}

	if len(pl) > 0 {
		return pl
	}
	return nil
}

// Warnings returns non-fatal issues that must be shown to the operator and
// recorded in the run metadata.
func (c *Config) Warnings() []Warning {
	var w []Warning
	if c.TLS.InsecureSkipVerify {
		w = append(w, Warning{
			Field: "tls.insecure_skip_verify",
			Message: "TLS certificate verification is DISABLED. The connection is not " +
				"authenticated and is vulnerable to interception. This is recorded in the report.",
			Limitation: "TLS certificate verification was DISABLED for this run. The transport was not " +
				"authenticated and the measurement cannot be attributed to a verified endpoint.",
		})
	}
	if c.Provider.AllowPlaintext && !isLoopbackHostFromEndpoint(c.Provider.Endpoint) {
		w = append(w, Warning{
			Field: "provider.allow_plaintext",
			Message: "The endpoint is plaintext http. Credentials cross the network in the " +
				"clear and responses can be rewritten in transit, so a timestamp from this " +
				"run is not evidence of anything an attacker on the path could not forge. " +
				"This is recorded in the report.",
			Limitation: "The endpoint was plaintext http. Credentials crossed the network in the clear " +
				"and responses could have been rewritten in transit, so the timestamps this run " +
				"collected carry no assurance against an attacker on the network path.",
		})
	}
	if c.Provider.Environment == EnvLive {
		w = append(w, Warning{
			Field: "provider.environment",
			Message: "Target is a LIVE production TSA. Quota consumed is real and " +
				"irreversible, and the service is shared with real customer traffic.",
		})
	}
	if c.TLS.TSACAFile == "" {
		w = append(w, Warning{
			Field: "tls.tsa_ca_file",
			Message: "No TSA CA bundle configured; the timestamp certificate chain will be " +
				"verified against the system root store, which may not contain the provider's CA.",
			Limitation: "No dedicated TSA CA bundle was configured; the timestamp certificate chain was " +
				"verified against the system root store.",
		})
	}
	return w
}

func requireEnv(add func(string, string), field, name string) {
	if name == "" {
		add(field, "must name an environment variable")
		return
	}
	if strings.ContainsAny(name, "${}/\\ ") {
		add(field, "must be a bare environment variable name, not a value or reference")
		return
	}
	if v, ok := os.LookupEnv(name); !ok || v == "" {
		add(field, fmt.Sprintf("environment variable %s is not set (value is never read into the config)", name))
	}
}

// isLoopbackHostFromEndpoint reports whether an endpoint points at this
// machine. A local mock needs no warning about plaintext.
func isLoopbackHostFromEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	return IsLoopbackHost(u.Hostname())
}

// IsLoopbackHost reports whether the host is a loopback address or the
// hostname "localhost". An empty host means "every interface" and is not
// loopback. It gates both the plaintext-endpoint warning and the mock's
// --bind-external check, which must agree on what counts as local.
func IsLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validOID(s string) bool {
	if s == "" {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return strings.Contains(s, ".")
}

// HashByName maps a configured hash name onto a constructor. Only algorithms
// that RFC 3161 responders are expected to support are accepted.
func HashByName(name string) (func() hash.Hash, error) {
	_, newHash, err := tsp.HashByName(name)
	return newHash, err
}
