package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/berkecengiz/tsa-bench/internal/config"
	"github.com/berkecengiz/tsa-bench/internal/redact"
	"github.com/berkecengiz/tsa-bench/internal/transport"
	"github.com/berkecengiz/tsa-bench/internal/tsp"
)

func runDoctor(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to the configuration file (required)")
	sendOne := fs.Bool("send-one", false,
		"send exactly one RFC 3161 request and verify it; consumes one unit of provider quota")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "tsa-bench doctor — check reachability of a configured endpoint.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Without --send-one this performs DNS, TCP and TLS checks only and")
		fmt.Fprintln(os.Stderr, "consumes no timestamp quota.")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		return fail(2, "--config is required")
	}

	cfg, err := config.LoadFile(*cfgPath)
	if err != nil {
		return fail(1, "%v", err)
	}
	for _, w := range cfg.Warnings() {
		fmt.Fprintf(os.Stderr, "WARNING [%s]: %s\n", w.Field, w.Message)
	}

	u, err := cfg.EndpointURL()
	if err != nil {
		return fail(1, "endpoint: %v", err)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	fmt.Printf("endpoint    %s\n", cfg.RedactedEndpoint())
	fmt.Printf("environment %s\n\n", cfg.Provider.Environment)

	// --- DNS ---
	start := time.Now()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		fmt.Printf("DNS         FAIL  %s\n", redact.Error(err))
		return fail(1, "DNS resolution failed")
	}
	ips := make([]string, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP.String())
	}
	fmt.Printf("DNS         ok    %s (%s)\n", strings.Join(ips, ", "), time.Since(start).Round(time.Millisecond))

	// --- TCP ---
	start = time.Now()
	dialer := &net.Dialer{Timeout: cfg.Request.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		fmt.Printf("TCP         FAIL  %s\n", redact.Error(err))
		return fail(1, "TCP connection failed")
	}
	tcpTime := time.Since(start)
	remote := conn.RemoteAddr().String()
	_ = conn.Close()
	fmt.Printf("TCP         ok    %s (%s)\n", remote, tcpTime.Round(time.Millisecond))

	// --- TLS ---
	if u.Scheme == "https" {
		if err := doctorTLS(ctx, cfg, host, port); err != nil {
			return err
		}
	} else {
		fmt.Println("TLS         skipped (endpoint is plaintext http)")
	}

	if !*sendOne {
		fmt.Println("\nNo timestamp request was sent. Pass --send-one to send exactly one " +
			"request, which consumes one unit of provider quota.")
		return nil
	}

	return doctorSendOne(ctx, cfg)
}

func doctorTLS(ctx context.Context, cfg *config.Config, host, port string) error {
	tlsCfg, err := transport.TLSConfig(cfg)
	if err != nil {
		return fail(1, "%v", err)
	}
	if tlsCfg.ServerName == "" {
		tlsCfg.ServerName = host
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: cfg.Request.Timeout},
		Config:    tlsCfg,
	}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		fmt.Printf("TLS         FAIL  %s\n", redact.Error(err))
		return fail(1, "TLS handshake failed")
	}
	defer conn.Close()

	state := conn.(*tls.Conn).ConnectionState()
	fmt.Printf("TLS         ok    %s / %s (%s)\n",
		tlsVersionName(state.Version), tls.CipherSuiteName(state.CipherSuite),
		time.Since(start).Round(time.Millisecond))
	if cfg.TLS.InsecureSkipVerify {
		fmt.Println("            NOTE  certificate verification was disabled for this check")
	}

	fmt.Println("\nServer certificate chain:")
	printChain(state.PeerCertificates)
	return nil
}

func printChain(chain []*x509.Certificate) {
	now := time.Now()
	for i, c := range chain {
		role := "intermediate"
		switch {
		case i == 0:
			role = "leaf"
		case c.IsCA && c.Subject.String() == c.Issuer.String():
			role = "root"
		}
		remaining := c.NotAfter.Sub(now)
		status := "valid"
		switch {
		case now.Before(c.NotBefore):
			status = "NOT YET VALID"
		case now.After(c.NotAfter):
			status = "EXPIRED"
		case remaining < 30*24*time.Hour:
			status = fmt.Sprintf("expires in %d days", int(remaining.Hours()/24))
		}
		fmt.Printf("  [%d] %-12s %s\n", i, role, c.Subject.String())
		fmt.Printf("       issuer   %s\n", c.Issuer.String())
		fmt.Printf("       validity %s .. %s (%s)\n",
			c.NotBefore.UTC().Format(time.RFC3339),
			c.NotAfter.UTC().Format(time.RFC3339), status)
		if len(c.DNSNames) > 0 {
			fmt.Printf("       names    %s\n", strings.Join(c.DNSNames, ", "))
		}
	}
}

// doctorSendOne performs a single full transaction, reporting each verification
// step. This is the check to run before a load test: it proves the trust
// configuration is right while spending only one unit of quota.
func doctorSendOne(ctx context.Context, cfg *config.Config) error {
	fmt.Println("\nSending one RFC 3161 request (consumes one unit of quota)...")

	roots, source, err := cfg.TSARoots()
	if err != nil {
		return fail(1, "%v", err)
	}
	verifier, err := tsp.NewVerifier(roots, cfg.Request.MaxClockSkew, cfg.Request.RequireESS)
	if err != nil {
		return fail(1, "%v", err)
	}
	builder, err := tsp.NewBuilder(tsp.BuilderOptions{
		HashName:    cfg.Request.HashAlgorithm,
		PayloadSize: cfg.Request.PayloadSize,
		CertReq:     *cfg.Request.CertReq,
		PolicyOID:   cfg.Request.PolicyOID,
	})
	if err != nil {
		return fail(1, "%v", err)
	}
	client, _, err := transport.New(cfg, nil)
	if err != nil {
		return fail(1, "%v", err)
	}
	creds, err := cfg.ResolveCredentials()
	if err != nil {
		return fail(1, "credentials: %v", err)
	}

	req, err := builder.Build()
	if err != nil {
		return fail(1, "%v", err)
	}

	var digestChallenge, digestCookie string
	reqCtx, cancel := context.WithTimeout(ctx, cfg.Request.Timeout)
	defer cancel()

	// Digest needs a nonce before anything can be signed. Drawing it here
	// costs one unauthenticated HTTP request that carries no timestamp
	// request, so the provider issues nothing and no quota is consumed.
	if cfg.Provider.Auth.Type == config.AuthDigest {
		challenge, cookie, err := transport.DrawDigestChallenge(
			reqCtx, client, cfg.Provider.Endpoint, tsp.ContentTypeRequest, nil)
		if err != nil {
			return fail(1, "%v", err)
		}
		digestCookie = cookie
		digestChallenge = challenge
		if cfg.Provider.Auth.ChallengePerRequest {
			fmt.Printf("  auth          digest challenge drawn for this request\n")
		} else {
			if err := creds.SetChallenge(challenge); err != nil {
				return fail(1, "prime digest authentication: %v", err)
			}
			fmt.Printf("  auth          digest challenge obtained\n")
		}
	}

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
		cfg.Provider.Endpoint, bytes.NewReader(req.DER))
	if err != nil {
		return fail(1, "%v", err)
	}
	httpReq.Header.Set("Content-Type", tsp.ContentTypeRequest)
	httpReq.Header.Set("Accept", tsp.ContentTypeResponse)
	if cfg.Provider.Auth.ChallengePerRequest && cfg.Provider.Auth.Type == config.AuthDigest {
		if digestCookie != "" {
			httpReq.Header.Set("Cookie", digestCookie)
		}
		if err := creds.AuthorizeOnce(httpReq, digestChallenge); err != nil {
			return fail(1, "answer digest challenge: %v", err)
		}
	} else {
		creds.Apply(httpReq, cfg.Provider.Auth.Type)
	}

	sentAt := time.Now()
	resp, err := client.Do(httpReq)
	if err != nil {
		return fail(1, "request failed: %s", redact.Error(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	receivedAt := time.Now()
	if err != nil {
		return fail(1, "read response: %s", redact.Error(err))
	}

	fmt.Printf("  HTTP status   %d\n", resp.StatusCode)
	fmt.Printf("  Content-Type  %s\n", resp.Header.Get("Content-Type"))
	fmt.Printf("  round trip    %s\n", receivedAt.Sub(sentAt).Round(time.Millisecond))
	fmt.Printf("  trust anchor  %s\n", source)

	res, verr := verifier.Verify(req, tsp.HTTPResponse{
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Body:        body,
		SentAt:      sentAt,
		ReceivedAt:  receivedAt,
	})
	if verr != nil {
		fmt.Printf("\n  VERIFICATION FAILED: %s\n", verr.Key())
		fmt.Printf("  %s\n", verr.Detail)
		return fail(1, "the response is not an acceptable RFC 3161 timestamp")
	}

	fmt.Println("\n  verification  PASSED")
	fmt.Printf("  genTime       %s (skew %s)\n",
		res.GenTime.UTC().Format(time.RFC3339Nano), res.ClockSkew.Round(time.Millisecond))
	fmt.Printf("  accuracy      %s\n", res.Accuracy)
	fmt.Printf("  serial        %s\n", res.SerialNumber)
	fmt.Printf("  policy        %s\n", res.Policy)
	fmt.Printf("  signer        %s\n", res.SignerSubject)
	fmt.Printf("  issuer        %s\n", res.SignerIssuer)
	fmt.Printf("  signer expiry %s\n", res.SignerExpiry.UTC().Format(time.RFC3339))
	if res.ESS.Present {
		fmt.Printf("  ESS binding   SigningCertificate%s matched\n", res.ESS.Version)
	} else {
		fmt.Println("  ESS binding   absent (signer binding could not be checked)")
	}
	for _, w := range res.Warnings {
		fmt.Printf("  warning       %s\n", w)
	}
	return nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
