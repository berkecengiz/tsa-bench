// Package redact masks credentials and other sensitive material before it can
// reach a log line, a report or an error message.
//
// The rule applied throughout tsa-bench is simple: a value that could
// authenticate a caller never leaves this package unmasked. That includes URL
// userinfo, query strings, Authorization/Cookie headers and anything the
// operator marked as an auth header in the configuration.
package redact

import (
	"net/url"
	"strings"
)

// Mask is the placeholder substituted for every redacted value.
const Mask = "[REDACTED]"

// sensitiveHeaders are always masked regardless of configuration.
var sensitiveHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"api-key":             true,
	"x-auth-token":        true,
}

// IsSensitiveHeader reports whether a header name must never be logged.
func IsSensitiveHeader(name string) bool {
	return sensitiveHeaders[strings.ToLower(strings.TrimSpace(name))]
}

// HeaderValue returns a loggable representation of a header value.
func HeaderValue(name, value string) string {
	if IsSensitiveHeader(name) {
		return Mask
	}
	return value
}

// Headers returns a copy of hdr safe for logging. Values of sensitive headers
// are replaced wholesale; no prefix or suffix of the secret survives.
func Headers(hdr map[string]string) map[string]string {
	out := make(map[string]string, len(hdr))
	for k, v := range hdr {
		out[k] = HeaderValue(k, v)
	}
	return out
}

// HeaderNames returns just the header names, sorted order not guaranteed.
// Useful when even the presence of a value should not be implied.
func HeaderNames(hdr map[string]string) []string {
	out := make([]string, 0, len(hdr))
	for k := range hdr {
		out = append(out, k)
	}
	return out
}

// URL strips userinfo and the entire query string from a URL so it can be
// logged or written into a report. Parse failures degrade to a fully masked
// value rather than leaking the original string.
func URL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return Mask
	}
	if u.User != nil {
		u.User = url.User(Mask)
	}
	if u.RawQuery != "" {
		u.RawQuery = Mask
	}
	u.Fragment = ""
	return u.String()
}

// Error redacts any URL that a wrapped error may have embedded. net/url and
// net/http errors routinely quote the full request URL, userinfo included.
func Error(err error) string {
	if err == nil {
		return ""
	}
	return Text(err.Error())
}

// Text scans free-form text for embedded URLs and redacts them in place.
func Text(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		start := indexScheme(s[i:])
		if start < 0 {
			b.WriteString(s[i:])
			break
		}
		b.WriteString(s[i : i+start])
		rest := s[i+start:]
		end := strings.IndexAny(rest, " \t\n\"'")
		if end < 0 {
			end = len(rest)
		}
		b.WriteString(URL(strings.TrimRight(rest[:end], ".,;:")))
		i += start + end
	}
	return b.String()
}

func indexScheme(s string) int {
	h := strings.Index(s, "http://")
	s2 := strings.Index(s, "https://")
	switch {
	case h < 0:
		return s2
	case s2 < 0:
		return h
	case h < s2:
		return h
	default:
		return s2
	}
}
