package tsp_test

import (
	"encoding/asn1"
	"testing"

	"github.com/berkecengiz/tsa-bench/internal/tsp"
)

// buildStatusResponse encodes a TimeStampResp carrying only a PKIStatusInfo.
func buildStatusResponse(t *testing.T, status int, statusStrings []string, failBits []int) []byte {
	t.Helper()

	var parts [][]byte

	statusDER, err := asn1.Marshal(status)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	parts = append(parts, statusDER)

	if len(statusStrings) > 0 {
		var inner []byte
		for _, s := range statusStrings {
			b, err := asn1.MarshalWithParams(s, "utf8")
			if err != nil {
				t.Fatalf("marshal statusString: %v", err)
			}
			inner = append(inner, b...)
		}
		parts = append(parts, wrapSequence(inner))
	}

	if len(failBits) > 0 {
		maxBit := 0
		for _, b := range failBits {
			if b > maxBit {
				maxBit = b
			}
		}
		bytesLen := maxBit/8 + 1
		bits := asn1.BitString{Bytes: make([]byte, bytesLen), BitLength: bytesLen * 8}
		for _, b := range failBits {
			bits.Bytes[b/8] |= 0x80 >> uint(b%8)
		}
		b, err := asn1.Marshal(bits)
		if err != nil {
			t.Fatalf("marshal failInfo: %v", err)
		}
		parts = append(parts, b)
	}

	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	return wrapSequence(wrapSequence(body))
}

// wrapSequence wraps DER content in a SEQUENCE.
func wrapSequence(content []byte) []byte {
	raw := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: content}
	out, err := asn1.Marshal(raw)
	if err != nil {
		panic(err)
	}
	return out
}

func TestParseStatusInfoGranted(t *testing.T) {
	der := buildStatusResponse(t, 0, nil, nil)
	si, err := tsp.ParseStatusInfo(der)
	if err != nil {
		t.Fatalf("ParseStatusInfo: %v", err)
	}
	if si.Status != tsp.StatusGranted || !si.Status.Granted() {
		t.Errorf("status = %v, want granted", si.Status)
	}
	if len(si.FailureInfo) != 0 {
		t.Errorf("failureInfo = %v, want none", si.FailureInfo)
	}
}

// TestParseStatusInfoFailureInfoSubcategories is what lets the report tell
// "our request is malformed" apart from "the TSA is overloaded".
func TestParseStatusInfoFailureInfoSubcategories(t *testing.T) {
	cases := []struct {
		bits []int
		want string
	}{
		{[]int{0}, "badAlg"},
		{[]int{2}, "badRequest"},
		{[]int{5}, "badDataFormat"},
		{[]int{14}, "timeNotAvailable"},
		{[]int{15}, "unacceptedPolicy"},
		{[]int{16}, "unacceptedExtension"},
		{[]int{17}, "addInfoNotAvailable"},
		{[]int{25}, "systemFailure"},
		{[]int{0, 2}, "badAlg+badRequest"},
	}

	for _, tc := range cases {
		der := buildStatusResponse(t, 2, nil, tc.bits)
		si, err := tsp.ParseStatusInfo(der)
		if err != nil {
			t.Fatalf("bits %v: %v", tc.bits, err)
		}
		if si.Status != tsp.StatusRejection {
			t.Errorf("bits %v: status = %v, want rejection", tc.bits, si.Status)
		}
		if got := si.SubCategory(); got != tc.want {
			t.Errorf("bits %v: subcategory = %q, want %q", tc.bits, got, tc.want)
		}
	}
}

func TestParseStatusInfoWithStatusStringAndFailInfo(t *testing.T) {
	der := buildStatusResponse(t, 2, []string{"quota exceeded"}, []int{25})
	si, err := tsp.ParseStatusInfo(der)
	if err != nil {
		t.Fatalf("ParseStatusInfo: %v", err)
	}
	if si.StatusString != "quota exceeded" {
		t.Errorf("statusString = %q", si.StatusString)
	}
	if si.SubCategory() != "systemFailure" {
		t.Errorf("subcategory = %q", si.SubCategory())
	}
}

// TestParseStatusInfoSkipsStatusStringToFindFailInfo guards the optional-field
// walk: a naive decoder lets an optional statusString swallow the failInfo.
func TestParseStatusInfoOptionalFieldOrdering(t *testing.T) {
	withText := buildStatusResponse(t, 2, []string{"nope"}, []int{2})
	si, err := tsp.ParseStatusInfo(withText)
	if err != nil {
		t.Fatalf("with statusString: %v", err)
	}
	if len(si.FailureInfo) != 1 || si.FailureInfo[0] != "badRequest" {
		t.Errorf("failInfo lost behind an optional statusString: %v", si.FailureInfo)
	}

	withoutText := buildStatusResponse(t, 2, nil, []int{2})
	si2, err := tsp.ParseStatusInfo(withoutText)
	if err != nil {
		t.Fatalf("without statusString: %v", err)
	}
	if len(si2.FailureInfo) != 1 || si2.FailureInfo[0] != "badRequest" {
		t.Errorf("failInfo misparsed when statusString is absent: %v", si2.FailureInfo)
	}
}

func TestParseStatusInfoUnknownBit(t *testing.T) {
	// An undefined bit must still be visible rather than silently dropped.
	der := buildStatusResponse(t, 2, nil, []int{9})
	si, err := tsp.ParseStatusInfo(der)
	if err != nil {
		t.Fatalf("ParseStatusInfo: %v", err)
	}
	if si.SubCategory() != "bit9" {
		t.Errorf("subcategory = %q, want bit9", si.SubCategory())
	}
}

func TestParseStatusInfoRejectsGarbage(t *testing.T) {
	for _, in := range [][]byte{
		{},
		{0x30, 0x03, 0x02, 0x01},
		{0x02, 0x01, 0x00},
	} {
		if _, err := tsp.ParseStatusInfo(in); err == nil {
			t.Errorf("garbage %x was accepted", in)
		}
	}
}

func TestParseStatusInfoRejectsTrailingData(t *testing.T) {
	der := buildStatusResponse(t, 0, nil, nil)
	if _, err := tsp.ParseStatusInfo(append(der, 0x00)); err == nil {
		t.Error("trailing data was accepted")
	}
}
