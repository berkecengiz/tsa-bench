package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/berkecengiz/tsa-bench/internal/mock"
	"github.com/berkecengiz/tsa-bench/internal/testutil"
)

func runMock(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("mock", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8318", "address to bind")
	bindExternal := fs.Bool("bind-external", false,
		"allow binding to a non-loopback address; required to expose the mock beyond this host")
	caOut := fs.String("write-ca", "", "write the generated development CA certificate to this path")
	latency := fs.Duration("latency", 0, "artificial delay added to every response")
	useRSA := fs.Bool("rsa", false, "sign with RSA-2048 instead of ECDSA P-256")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "tsa-bench mock — run a local RFC 3161 responder.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "The mock exists to measure what this client can sustain and to exercise")
		fmt.Fprintln(os.Stderr, "the verification chain offline. Its latency is the latency of a local")
		fmt.Fprintln(os.Stderr, "signature: it does NOT represent any provider's performance.")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	keyType := testutil.ECDSAP256
	if *useRSA {
		keyType = testutil.RSA2048
	}

	srv, err := mock.New(mock.Options{KeyType: keyType, Latency: *latency})
	if err != nil {
		return fail(1, "%v", err)
	}

	if *caOut != "" {
		if err := os.MkdirAll(filepath.Dir(*caOut), 0o700); err != nil {
			return fail(1, "create CA directory: %v", err)
		}
		if err := os.WriteFile(*caOut, srv.CA().PEM, 0o600); err != nil {
			return fail(1, "write CA: %v", err)
		}
		fmt.Fprintf(os.Stderr, "development CA written to %s\n", *caOut)
	}

	ln, httpSrv, err := srv.ListenAndServe(*addr, *bindExternal)
	if err != nil {
		return fail(2, "%v", err)
	}

	fmt.Fprintln(os.Stderr, "mock RFC 3161 responder listening on http://"+ln.Addr().String())
	fmt.Fprintln(os.Stderr, "NOTE: development certificates are generated in memory and are not trusted")
	fmt.Fprintln(os.Stderr, "      by anything else. This mock does not represent provider performance.")
	if *bindExternal {
		fmt.Fprintln(os.Stderr, "WARNING: bound to a non-loopback address; anyone who can reach this port")
		fmt.Fprintln(os.Stderr, "         will receive timestamps signed by a throwaway key.")
	}

	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.Serve(ln) }()

	select {
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "\nshutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		fmt.Fprintf(os.Stderr, "served %d request(s)\n", srv.Requests())
		return nil
	case err := <-errCh:
		return fail(1, "mock server: %v", err)
	}
}
