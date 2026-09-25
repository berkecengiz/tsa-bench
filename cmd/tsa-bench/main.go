// Command tsa-bench measures the capacity of RFC 3161 timestamp services.
//
// Safety model, in short:
//
//   - No command contacts a network endpoint unless the operator configured one.
//     There is no built-in default endpoint.
//   - `run` refuses to start without both --max-requests and
//     --authorized-load-test, and additionally --acknowledge-live-environment
//     when the configuration declares a live production target.
//   - Secrets are never accepted as command line arguments, because the process
//     table is readable by other users on the host.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

// version is stamped at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

const usage = `tsa-bench %s — RFC 3161 timestamp service capacity testing

Usage:
  tsa-bench <command> [flags]

Commands:
  validate   Check a configuration file. Sends no network traffic.
  doctor     Check DNS, TCP and TLS reachability; optionally send one request.
  run        Execute a load profile against a configured provider.
  report     Build a comparative report from one or more result directories.
  mock       Run a local RFC 3161 responder for client capacity checks.
  version    Print version information.

Run "tsa-bench <command> -h" for the flags of a command.

Before testing a provider you must have written authorisation for load testing,
a confirmed endpoint, an agreed rate limit and quota, and an agreed test window.
See README.md for the full pre-flight checklist.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}

	// SIGINT/SIGTERM cancel the issuing context. Commands that have in-flight
	// work drain it within their configured grace period.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "validate":
		err = runValidate(os.Args[2:])
	case "doctor":
		err = runDoctor(ctx, os.Args[2:])
	case "run":
		err = runLoad(ctx, os.Args[2:])
	case "report":
		err = runReport(os.Args[2:])
	case "mock":
		err = runMock(ctx, os.Args[2:])
	case "version":
		fmt.Printf("tsa-bench %s (%s %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return
	case "-h", "--help", "help":
		fmt.Printf(usage, version)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}

	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "interrupted")
			os.Exit(130)
		}
		var ec *exitError
		if errors.As(err, &ec) {
			fmt.Fprintln(os.Stderr, "error: "+ec.msg)
			os.Exit(ec.code)
		}
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		os.Exit(1)
	}
}

// exitError carries a specific exit status.
type exitError struct {
	msg  string
	code int
}

func (e *exitError) Error() string { return e.msg }

func fail(code int, format string, args ...any) error {
	return &exitError{msg: fmt.Sprintf(format, args...), code: code}
}
