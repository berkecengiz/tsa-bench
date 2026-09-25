package config

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// Credentials holds resolved secret material. It is created as late as possible,
// is never serialised, and has no String method that could leak it through %v.
type Credentials struct {
	username string
	password string
	token    string
	headers  map[string]string
	// digest carries the live challenge for AuthDigest. It is nil for every
	// other scheme.
	digest *digestState
}

// String deliberately hides the contents so an accidental %v or %s in a log
// statement cannot print a secret.
func (c *Credentials) String() string { return "config.Credentials{" + redactedCount(c) + "}" }

// GoString hides the contents from %#v as well.
func (c *Credentials) GoString() string { return c.String() }

func redactedCount(c *Credentials) string {
	n := 0
	if c == nil {
		return "nil"
	}
	if c.username != "" {
		n++
	}
	if c.password != "" {
		n++
	}
	if c.token != "" {
		n++
	}
	n += len(c.headers)
	return fmt.Sprintf("%d redacted value(s)", n)
}

// ResolveCredentials reads the referenced environment variables. It returns an
// error naming the variable, never its value.
func (c *Config) ResolveCredentials() (*Credentials, error) {
	cr := &Credentials{headers: map[string]string{}}
	get := func(name string) (string, error) {
		v, ok := os.LookupEnv(name)
		if !ok || v == "" {
			return "", fmt.Errorf("environment variable %s is not set or empty", name)
		}
		return v, nil
	}

	switch c.Provider.Auth.Type {
	case AuthBasic, AuthDigest:
		var err error
		if cr.username, err = get(c.Provider.Auth.UsernameEnv); err != nil {
			return nil, err
		}
		if cr.password, err = get(c.Provider.Auth.PasswordEnv); err != nil {
			return nil, err
		}
		if c.Provider.Auth.Type == AuthDigest {
			cr.digest = &digestState{}
		}
	case AuthBearer:
		var err error
		if cr.token, err = get(c.Provider.Auth.TokenEnv); err != nil {
			return nil, err
		}
	case AuthHeader:
		for name, ref := range c.Provider.Auth.Headers {
			if !strings.HasPrefix(ref, "env:") {
				return nil, fmt.Errorf("auth header %s must reference an environment variable as env:NAME", name)
			}
			v, err := get(strings.TrimPrefix(ref, "env:"))
			if err != nil {
				return nil, err
			}
			cr.headers[name] = v
		}
	}
	return cr, nil
}

// Apply sets authentication headers on an outgoing request.
func (cr *Credentials) Apply(req *http.Request, typ AuthType) {
	if cr == nil {
		return
	}
	switch typ {
	case AuthBasic:
		req.Header.Set("Authorization", "Basic "+
			base64.StdEncoding.EncodeToString([]byte(cr.username+":"+cr.password)))
	case AuthBearer:
		req.Header.Set("Authorization", "Bearer "+cr.token)
	case AuthDigest:
		cr.applyDigest(req)
	case AuthHeader:
		for name, value := range cr.headers {
			req.Header.Set(name, value)
		}
	}
}

// LoadCertPool reads a PEM bundle into a certificate pool. An empty path
// returns nil, which means "use the system roots".
func LoadCertPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA bundle %s contains no usable PEM certificates", path)
	}
	return pool, nil
}

// TSARoots returns the pool used to verify the TSA signing certificate chain.
// It prefers tsa_ca_file, falls back to ca_file, and finally to the system pool.
func (c *Config) TSARoots() (*x509.CertPool, string, error) {
	if c.TLS.TSACAFile != "" {
		p, err := LoadCertPool(c.TLS.TSACAFile)
		return p, c.TLS.TSACAFile, err
	}
	if c.TLS.CAFile != "" {
		p, err := LoadCertPool(c.TLS.CAFile)
		return p, c.TLS.CAFile, err
	}
	p, err := x509.SystemCertPool()
	if err != nil {
		return nil, "", fmt.Errorf("load system cert pool: %w", err)
	}
	return p, "system", nil
}
