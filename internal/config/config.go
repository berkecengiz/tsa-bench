// Package config loads, interpolates and validates the YAML configuration.
//
// Two rules drive the design:
//
//  1. Secrets never live in the file and never appear in a dump. The file names
//     *environment variables* that hold the secret; the value is read at use
//     time and is not retained in any printable structure.
//  2. Validation is total. `tsa-bench validate` must be able to reject a bad
//     configuration without opening a single socket, because a misconfigured
//     run against a live TSA burns irreplaceable quota.
package config

import (
	"crypto/tls"
	"fmt"
	"maps"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/berkecengiz/tsa-bench/internal/redact"
)

// Environment distinguishes a live production TSA from a vendor test bed.
// There is deliberately no default: the operator must state it.
type Environment string

const (
	EnvLive Environment = "live"
	EnvTest Environment = "test"
)

// AuthType enumerates supported authentication mechanisms.
type AuthType string

const (
	AuthNone   AuthType = "none"
	AuthBasic  AuthType = "basic"
	AuthBearer AuthType = "bearer"
	AuthHeader AuthType = "header"
	AuthMTLS   AuthType = "mtls"
	// AuthDigest is RFC 7616 digest access authentication. Unlike the others
	// it needs a challenge from the server before anything can be signed; see
	// internal/config/digest.go.
	AuthDigest AuthType = "digest"
)

// Config is the root document.
type Config struct {
	Provider Provider `yaml:"provider"`
	TLS      TLSConf  `yaml:"tls"`
	Request  Request  `yaml:"request"`
	Load     Load     `yaml:"load"`
	Limits   Limits   `yaml:"limits"`
	Output   Output   `yaml:"output"`
}

// Provider identifies the TSA under test.
type Provider struct {
	Name        string      `yaml:"name"`
	Endpoint    string      `yaml:"endpoint"`
	Environment Environment `yaml:"environment"`
	Auth        Auth        `yaml:"auth"`
	// AllowPlaintext permits an http:// endpoint on a routable host.
	//
	// It exists for a service that offers no TLS at all - one provider's
	// dedicated instance refuses 443 - reached over a private network where the operator
	// judges the path itself to be protected. It is never the right answer for
	// a service on the public internet: credentials cross the wire in the
	// clear, and a timestamp is evidence, so an attacker who can rewrite the
	// response can rewrite what the evidence says.
	//
	// Like tls.insecure_skip_verify it is warned about loudly and recorded in
	// the report, so a run made this way cannot be mistaken for an
	// authenticated one.
	AllowPlaintext bool `yaml:"allow_plaintext"`
}

// Auth describes how to authenticate. Only *_env names are accepted; a literal
// secret in the file or on the command line is rejected.
type Auth struct {
	Type        AuthType          `yaml:"type"`
	UsernameEnv string            `yaml:"username_env"`
	PasswordEnv string            `yaml:"password_env"`
	TokenEnv    string            `yaml:"token_env"`
	Headers     map[string]string `yaml:"headers"`
	// ChallengePerRequest draws a fresh digest challenge for every request
	// instead of reusing one nonce with an incrementing count.
	//
	// RFC 7616 qop="auth" exists precisely so a nonce can be reused, and the
	// default assumes the server means it. Some do not: one production TSA
	// advertises qop="auth" but invalidates the nonce after a single use, answering
	// everything afterwards with an HTTP 500 that names no authentication
	// problem at all. Set this for such a server. It costs one extra HTTP
	// request per timestamp, which issues nothing and consumes no quota.
	ChallengePerRequest bool `yaml:"challenge_per_request"`
}

// TLSConf controls the transport trust configuration.
type TLSConf struct {
	CAFile             string `yaml:"ca_file"`
	TSACAFile          string `yaml:"tsa_ca_file"`
	ClientCertFile     string `yaml:"client_cert_file"`
	ClientKeyFile      string `yaml:"client_key_file"`
	ServerName         string `yaml:"server_name"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	MinVersion         string `yaml:"min_version"`
}

// Request controls RFC 3161 request construction and acceptance.
type Request struct {
	HashAlgorithm string        `yaml:"hash_algorithm"`
	PayloadSize   int           `yaml:"payload_size"`
	Timeout       time.Duration `yaml:"timeout"`
	CertReq       *bool         `yaml:"cert_req"`
	MaxClockSkew  time.Duration `yaml:"max_clock_skew"`
	PolicyOID     string        `yaml:"policy_oid"`
	RequireESS    bool          `yaml:"require_ess"`
}

// Load controls the arrival-rate scheduler.
type Load struct {
	MaxConcurrency int           `yaml:"max_concurrency"`
	StagePause     time.Duration `yaml:"stage_pause"`
	LagThreshold   time.Duration `yaml:"lag_threshold"`
	GracePeriod    time.Duration `yaml:"grace_period"`
}

// Limits are the quota guards. These are the last line of defence against
// burning a provider's allowance.
type Limits struct {
	MaxRequests                int     `yaml:"max_requests"`
	HardCap                    int     `yaml:"hard_cap"`
	Retries                    int     `yaml:"retries"`
	AbortOnErrorRate           float64 `yaml:"abort_on_error_rate"`
	AbortWindow                int     `yaml:"abort_window"`
	AbortOnConsecutiveFailures int     `yaml:"abort_on_consecutive_failures"`
}

// Output controls where results land.
type Output struct {
	Directory string `yaml:"directory"`
}

// DefaultHardCap is the hard cap applied when a configuration does not set
// one. It is a conservative default, not a ceiling: the engagement quota
// differs per provider, so limits.hard_cap in the provider's own
// configuration is what actually bounds a run.
const DefaultHardCap = 50000

// MaxConfigurableHardCap is a backstop against a typo, nothing more. It is
// deliberately far above any real engagement so that it never has to be
// edited for a legitimate one, while still catching an extra digit.
const MaxConfigurableHardCap = 10_000_000

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Load reads, interpolates and validates a configuration file.
func LoadFile(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(raw)
}

// Parse interpolates ${VAR} references and unmarshals the document.
//
// Interpolation is intended for non-secret values such as an endpoint host.
// Secrets must use the *_env indirection instead, so that they are read at use
// time and never become part of a printable Config.
func Parse(raw []byte) (*Config, error) {
	var missing []string
	interpolated := envRef.ReplaceAllStringFunc(string(raw), func(m string) string {
		name := envRef.FindStringSubmatch(m)[1]
		v, ok := os.LookupEnv(name)
		if !ok {
			missing = append(missing, name)
			return ""
		}
		return v
	})
	if len(missing) > 0 {
		return nil, fmt.Errorf("config references unset environment variables: %s",
			strings.Join(missing, ", "))
	}

	cfg := Default()
	dec := yaml.NewDecoder(strings.NewReader(interpolated))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Default returns a Config with safe defaults applied. Note that
// insecure_skip_verify defaults to false and retries default to 0.
func Default() *Config {
	return &Config{
		Request: Request{
			HashAlgorithm: "sha256",
			PayloadSize:   64,
			Timeout:       10 * time.Second,
			MaxClockSkew:  60 * time.Second,
		},
		Load: Load{
			MaxConcurrency: 500,
			StagePause:     10 * time.Second,
			LagThreshold:   250 * time.Millisecond,
			GracePeriod:    30 * time.Second,
		},
		Limits: Limits{
			HardCap:                    DefaultHardCap,
			Retries:                    0,
			AbortOnErrorRate:           0.25,
			AbortWindow:                200,
			AbortOnConsecutiveFailures: 50,
		},
		Output: Output{Directory: "results"},
		TLS:    TLSConf{MinVersion: "1.2", InsecureSkipVerify: false},
	}
}

func (c *Config) applyDefaults() {
	if c.Request.CertReq == nil {
		t := true
		c.Request.CertReq = &t
	}
	if c.Limits.HardCap == 0 {
		c.Limits.HardCap = DefaultHardCap
	}
	if c.TLS.MinVersion == "" {
		c.TLS.MinVersion = "1.2"
	}
	if c.Output.Directory == "" {
		c.Output.Directory = "results"
	}
}

// MinTLSVersion maps the configured minimum version onto a crypto/tls constant.
func (c *Config) MinTLSVersion() (uint16, error) {
	switch c.TLS.MinVersion {
	case "1.2", "":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("tls.min_version %q is not supported (use 1.2 or 1.3)", c.TLS.MinVersion)
	}
}

// RedactedEndpoint returns the endpoint with userinfo and query stripped.
func (c *Config) RedactedEndpoint() string { return redact.URL(c.Provider.Endpoint) }

// String renders a dump that is safe to log. It never resolves *_env values.
func (c *Config) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "provider.name=%s\n", c.Provider.Name)
	fmt.Fprintf(&b, "provider.endpoint=%s\n", c.RedactedEndpoint())
	fmt.Fprintf(&b, "provider.allow_plaintext=%t\n", c.Provider.AllowPlaintext)
	fmt.Fprintf(&b, "provider.environment=%s\n", c.Provider.Environment)
	fmt.Fprintf(&b, "provider.auth.type=%s\n", c.Provider.Auth.Type)
	if c.Provider.Auth.UsernameEnv != "" {
		fmt.Fprintf(&b, "provider.auth.username_env=%s (value not shown)\n", c.Provider.Auth.UsernameEnv)
	}
	if c.Provider.Auth.PasswordEnv != "" {
		fmt.Fprintf(&b, "provider.auth.password_env=%s (value not shown)\n", c.Provider.Auth.PasswordEnv)
	}
	if c.Provider.Auth.TokenEnv != "" {
		fmt.Fprintf(&b, "provider.auth.token_env=%s (value not shown)\n", c.Provider.Auth.TokenEnv)
	}
	for _, name := range sortedKeys(c.Provider.Auth.Headers) {
		fmt.Fprintf(&b, "provider.auth.headers.%s=%s\n", name, redact.Mask)
	}
	fmt.Fprintf(&b, "tls.ca_file=%s\n", c.TLS.CAFile)
	fmt.Fprintf(&b, "tls.tsa_ca_file=%s\n", c.TLS.TSACAFile)
	fmt.Fprintf(&b, "tls.client_cert_file=%s\n", c.TLS.ClientCertFile)
	fmt.Fprintf(&b, "tls.server_name=%s\n", c.TLS.ServerName)
	fmt.Fprintf(&b, "tls.insecure_skip_verify=%t\n", c.TLS.InsecureSkipVerify)
	fmt.Fprintf(&b, "tls.min_version=%s\n", c.TLS.MinVersion)
	fmt.Fprintf(&b, "request.hash_algorithm=%s\n", c.Request.HashAlgorithm)
	fmt.Fprintf(&b, "request.payload_size=%d\n", c.Request.PayloadSize)
	fmt.Fprintf(&b, "request.timeout=%s\n", c.Request.Timeout)
	fmt.Fprintf(&b, "request.cert_req=%t\n", *c.Request.CertReq)
	fmt.Fprintf(&b, "request.max_clock_skew=%s\n", c.Request.MaxClockSkew)
	fmt.Fprintf(&b, "request.require_ess=%t\n", c.Request.RequireESS)
	fmt.Fprintf(&b, "load.max_concurrency=%d\n", c.Load.MaxConcurrency)
	fmt.Fprintf(&b, "load.stage_pause=%s\n", c.Load.StagePause)
	fmt.Fprintf(&b, "limits.max_requests=%d\n", c.Limits.MaxRequests)
	fmt.Fprintf(&b, "limits.hard_cap=%d\n", c.Limits.HardCap)
	fmt.Fprintf(&b, "limits.retries=%d\n", c.Limits.Retries)
	fmt.Fprintf(&b, "output.directory=%s\n", c.Output.Directory)
	return b.String()
}

func sortedKeys(m map[string]string) []string {
	return slices.Sorted(maps.Keys(m))
}

// Budget resolves how many timestamps a run may spend. requested is the
// operator's --max-requests; 0 means "whatever the configuration allows",
// which is the budget validate checks a profile against.
//
// This is the one place the precedence between --max-requests,
// limits.max_requests and limits.hard_cap is decided. run and validate both
// call it, so a profile validate accepts cannot be rejected by run - the
// arithmetic that bounds irreversible provider quota has a single definition
// rather than a comment asking two commands to agree.
func (c *Config) Budget(requested int64) (int64, error) {
	hardCap, maxRequests := int64(c.Limits.HardCap), int64(c.Limits.MaxRequests)

	if requested <= 0 {
		if maxRequests > 0 {
			return maxRequests, nil
		}
		return hardCap, nil
	}
	if hardCap > 0 && requested > hardCap {
		return 0, fmt.Errorf("--max-requests (%d) exceeds the configured hard cap of %d",
			requested, hardCap)
	}
	if maxRequests > 0 && requested > maxRequests {
		return 0, fmt.Errorf("--max-requests (%d) exceeds limits.max_requests (%d) from the config",
			requested, maxRequests)
	}
	return requested, nil
}

// EndpointURL parses the endpoint once, for reuse by doctor and run.
func (c *Config) EndpointURL() (*url.URL, error) {
	return url.Parse(c.Provider.Endpoint)
}
