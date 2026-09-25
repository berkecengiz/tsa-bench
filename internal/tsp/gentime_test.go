package tsp

import (
	"encoding/asn1"
	"testing"
)

// TestParseGeneralizedTimeAcceptsNonMinimal covers the encoding that stopped a
// live run: a production TSA sent "20260924081902.10Z", which X.690 11.7
// forbids because of the trailing zero, and Go's strict parser rejected.
func TestParseGeneralizedTimeAcceptsNonMinimal(t *testing.T) {
	raw := asn1.RawValue{Tag: asn1.TagGeneralizedTime, Bytes: []byte("20260924081902.10Z")}

	got, warning, err := parseGeneralizedTime(raw)
	if err != nil {
		t.Fatalf("parseGeneralizedTime: %v", err)
	}
	if want := "2026-09-24T08:19:02.1Z"; got.UTC().Format("2006-01-02T15:04:05.9Z") != want {
		t.Errorf("time = %s, want %s", got.UTC().Format("2006-01-02T15:04:05.9Z"), want)
	}
	if warning == "" {
		t.Error("a non-DER encoding was accepted without a warning; the deviation must reach the report")
	}
	// The text must be constant so the report can count occurrences rather
	// than listing one entry per affected response.
	_, second, err := parseGeneralizedTime(
		asn1.RawValue{Tag: asn1.TagGeneralizedTime, Bytes: []byte("20260924084258.20Z")})
	if err != nil {
		t.Fatalf("parseGeneralizedTime: %v", err)
	}
	if warning != second {
		t.Errorf("two different values produced two different warnings:\n  %q\n  %q", warning, second)
	}
}

// TestParseGeneralizedTimeMinimalIsSilent: a conformant encoding must not
// produce a warning, or every row of every report would carry one.
func TestParseGeneralizedTimeMinimalIsSilent(t *testing.T) {
	for _, s := range []string{
		"20260924081902Z",
		"20260924081902.1Z",
		"20260924080943.369Z",
	} {
		t.Run(s, func(t *testing.T) {
			_, warning, err := parseGeneralizedTime(
				asn1.RawValue{Tag: asn1.TagGeneralizedTime, Bytes: []byte(s)})
			if err != nil {
				t.Fatalf("parseGeneralizedTime: %v", err)
			}
			if warning != "" {
				t.Errorf("conformant encoding produced a warning: %q", warning)
			}
		})
	}
}

func TestParseGeneralizedTimeRejectsRubbish(t *testing.T) {
	for name, raw := range map[string]asn1.RawValue{
		"wrong tag":  {Tag: asn1.TagUTCTime, Bytes: []byte("260924081902Z")},
		"not a time": {Tag: asn1.TagGeneralizedTime, Bytes: []byte("hello")},
		"truncated":  {Tag: asn1.TagGeneralizedTime, Bytes: []byte("2026")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseGeneralizedTime(raw); err == nil {
				t.Error("accepted an unusable genTime")
			}
		})
	}
}
