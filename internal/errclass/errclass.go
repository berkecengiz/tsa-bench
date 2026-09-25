// Package errclass defines the error taxonomy used across the benchmark.
//
// Every attempt ends in exactly one class. Classes are stable strings because
// they are written into CSV/JSON reports that outlive the binary.
package errclass

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/berkecengiz/tsa-bench/internal/redact"
)

// Class is a single error category.
type Class string

// The canonical error classes. Keep in sync with docs/runbook.md.
const (
	OK Class = "ok"

	DNSError        Class = "dns_error"
	ConnectError    Class = "connect_error"
	TLSError        Class = "tls_error"
	RequestTimeout  Class = "request_timeout"
	ResponseTimeout Class = "response_timeout"
	HTTP4xx         Class = "http_4xx"
	HTTP5xx         Class = "http_5xx"

	InvalidContentType Class = "invalid_content_type"
	TSPRejection       Class = "tsp_rejection"
	InvalidNonce       Class = "invalid_nonce"
	InvalidImprint     Class = "invalid_imprint"
	InvalidSignature   Class = "invalid_signature"
	UntrustedCert      Class = "untrusted_certificate"
	MalformedResponse  Class = "malformed_response"
	ClockSkewExceeded  Class = "clock_skew_exceeded"

	ClientSaturation Class = "client_saturation"
	ScheduleLag      Class = "schedule_lag"
	QuotaGuard       Class = "quota_guard"
	Cancelled        Class = "cancelled"
	UnknownError     Class = "unknown_error"
)

// All lists every class in report order.
func All() []Class {
	return []Class{
		OK,
		DNSError, ConnectError, TLSError, RequestTimeout, ResponseTimeout,
		HTTP4xx, HTTP5xx,
		InvalidContentType, TSPRejection, InvalidNonce, InvalidImprint,
		InvalidSignature, UntrustedCert, MalformedResponse, ClockSkewExceeded,
		ClientSaturation, ScheduleLag, QuotaGuard, Cancelled, UnknownError,
	}
}

func (c Class) String() string { return string(c) }

// IsFailure reports whether the class represents a failed timestamp attempt.
func (c Class) IsFailure() bool { return c != OK }

// Error carries a class plus a already-redacted human readable detail and an
// optional sub-category (used for TSP rejections).
type Error struct {
	Class  Class
	Detail string
	Sub    string
}

func (e *Error) Error() string {
	if e.Sub != "" {
		return string(e.Class) + "." + e.Sub + ": " + e.Detail
	}
	return string(e.Class) + ": " + e.Detail
}

// New builds a classified error. detail must already be safe to log.
func New(c Class, detail string) *Error { return &Error{Class: c, Detail: detail} }

// NewSub builds a classified error with a sub-category.
func NewSub(c Class, sub, detail string) *Error {
	return &Error{Class: c, Detail: detail, Sub: sub}
}

// Key returns "class" or "class.sub" for report grouping.
func (e *Error) Key() string {
	if e.Sub != "" {
		return string(e.Class) + "." + e.Sub
	}
	return string(e.Class)
}

// Classify maps a transport-level error onto the taxonomy. Verification errors
// are produced directly as *Error by the tsp package and pass through unchanged.
//
// requestWritten distinguishes a timeout that happened while sending the
// request from one that happened while waiting for the response.
func Classify(err error, requestWritten bool) *Error {
	if err == nil {
		return nil
	}

	var classified *Error
	if errors.As(err, &classified) {
		return classified
	}

	// Transport errors routinely quote the full request URL, userinfo
	// included, so nothing reaches a log or report unredacted.
	detail := redact.Error(err)

	if errors.Is(err, context.Canceled) {
		return New(Cancelled, detail)
	}

	// A DNS failure can hide behind url.Error -> net.OpError -> DNSError.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return New(DNSError, detail)
	}

	// TLS problems must be reported as TLS, not as a generic connect error.
	var certErr *tls.CertificateVerificationError
	var hostErr x509.HostnameError
	if errors.As(err, &certErr) || errors.As(err, &hostErr) || isTLSAlert(err) {
		return New(TLSError, detail)
	}

	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || isTimeout(err) {
		if requestWritten {
			return New(ResponseTimeout, detail)
		}
		return New(RequestTimeout, detail)
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return New(ConnectError, detail)
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return New(ConnectError, detail)
	}

	return New(UnknownError, detail)
}

// FromHTTPStatus classifies a non-2xx HTTP status code.
func FromHTTPStatus(code int) *Error {
	switch {
	case code >= 200 && code < 300:
		return nil
	case code >= 400 && code < 500:
		return NewSub(HTTP4xx, itoa(code), "unexpected HTTP status")
	case code >= 500:
		return NewSub(HTTP5xx, itoa(code), "unexpected HTTP status")
	default:
		return NewSub(UnknownError, itoa(code), "unexpected HTTP status")
	}
}

func isTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}

func isTLSAlert(err error) bool {
	s := err.Error()
	return strings.Contains(s, "tls:") || strings.Contains(s, "x509:") ||
		strings.Contains(s, "remote error:")
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [8]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
