package tsp

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
)

// PKIStatus values from RFC 3161 section 2.4.2.
type PKIStatus int

const (
	StatusGranted                PKIStatus = 0
	StatusGrantedWithMods        PKIStatus = 1
	StatusRejection              PKIStatus = 2
	StatusWaiting                PKIStatus = 3
	StatusRevocationWarning      PKIStatus = 4
	StatusRevocationNotification PKIStatus = 5
)

func (s PKIStatus) String() string {
	switch s {
	case StatusGranted:
		return "granted"
	case StatusGrantedWithMods:
		return "grantedWithMods"
	case StatusRejection:
		return "rejection"
	case StatusWaiting:
		return "waiting"
	case StatusRevocationWarning:
		return "revocationWarning"
	case StatusRevocationNotification:
		return "revocationNotification"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// Granted reports whether a token is expected to be present.
func (s PKIStatus) Granted() bool {
	return s == StatusGranted || s == StatusGrantedWithMods
}

// failureInfoNames maps PKIFailureInfo bit positions to their ASN.1 names.
// Positions are taken verbatim from RFC 3161 section 2.4.2.
var failureInfoNames = map[int]string{
	0:  "badAlg",
	1:  "badMessageCheck",
	2:  "badRequest",
	3:  "badTime",
	5:  "badDataFormat",
	14: "timeNotAvailable",
	15: "unacceptedPolicy",
	16: "unacceptedExtension",
	17: "addInfoNotAvailable",
	25: "systemFailure",
}

// StatusInfo is the parsed PKIStatusInfo of a TimeStampResp.
//
// The timestamp library folds this into an opaque error string, which is not
// good enough for reporting: rejections must be broken down by failInfo so an
// operator can tell "the TSA is overloaded" (systemFailure) from "our request
// is wrong" (badAlg, badRequest).
type StatusInfo struct {
	Status       PKIStatus
	StatusString string
	FailureInfo  []string
	// HasToken reports whether a timeStampToken element was present.
	HasToken bool
}

// SubCategory returns the report key suffix for a rejection.
func (s StatusInfo) SubCategory() string {
	if len(s.FailureInfo) > 0 {
		return strings.Join(s.FailureInfo, "+")
	}
	return s.Status.String()
}

const maxStatusStringLen = 200

// ParseStatusInfo decodes just the PKIStatusInfo from a TimeStampResp, without
// touching the token. It tolerates responders that omit optional fields and
// that encode statusString with any of the usual string types.
func ParseStatusInfo(der []byte) (*StatusInfo, error) {
	var resp asn1.RawValue
	rest, err := asn1.Unmarshal(der, &resp)
	if err != nil {
		return nil, fmt.Errorf("decode TimeStampResp: %w", err)
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing data after TimeStampResp")
	}
	if resp.Class != asn1.ClassUniversal || resp.Tag != asn1.TagSequence || !resp.IsCompound {
		return nil, errors.New("TimeStampResp is not a SEQUENCE")
	}

	// TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken OPTIONAL }
	var statusInfo asn1.RawValue
	body, err := asn1.Unmarshal(resp.Bytes, &statusInfo)
	if err != nil {
		return nil, fmt.Errorf("decode PKIStatusInfo: %w", err)
	}
	if statusInfo.Tag != asn1.TagSequence || !statusInfo.IsCompound {
		return nil, errors.New("PKIStatusInfo is not a SEQUENCE")
	}

	out := &StatusInfo{HasToken: len(bytesTrimmed(body)) > 0}

	// PKIStatusInfo ::= SEQUENCE { status INTEGER,
	//                              statusString PKIFreeText OPTIONAL,
	//                              failInfo PKIFailureInfo OPTIONAL }
	inner := statusInfo.Bytes
	var status int
	inner, err = asn1.Unmarshal(inner, &status)
	if err != nil {
		return nil, fmt.Errorf("decode PKIStatus: %w", err)
	}
	out.Status = PKIStatus(status)

	for len(inner) > 0 {
		var field asn1.RawValue
		inner, err = asn1.Unmarshal(inner, &field)
		if err != nil {
			return nil, fmt.Errorf("decode PKIStatusInfo field: %w", err)
		}
		switch {
		case field.Tag == asn1.TagSequence && field.IsCompound:
			out.StatusString = decodeFreeText(field.Bytes)
		case field.Tag == asn1.TagBitString:
			var bs asn1.BitString
			if _, err := asn1.Unmarshal(field.FullBytes, &bs); err != nil {
				return nil, fmt.Errorf("decode PKIFailureInfo: %w", err)
			}
			out.FailureInfo = decodeFailureInfo(bs)
		}
	}

	return out, nil
}

// decodeFreeText concatenates a PKIFreeText. Unparsable elements are skipped
// rather than failing the whole response: the text is diagnostic only.
func decodeFreeText(der []byte) string {
	var parts []string
	for len(der) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(der, &v)
		if err != nil {
			break
		}
		der = rest
		parts = append(parts, sanitize(string(v.Bytes)))
	}
	s := strings.Join(parts, "; ")
	if len(s) > maxStatusStringLen {
		s = s[:maxStatusStringLen] + "..."
	}
	return s
}

// decodeFailureInfo lists the names of every set bit, including bits that are
// not defined by RFC 3161 so an unexpected responder behaviour is still visible.
func decodeFailureInfo(bs asn1.BitString) []string {
	var out []string
	for i := 0; i < bs.BitLength; i++ {
		if bs.At(i) != 1 {
			continue
		}
		if name, ok := failureInfoNames[i]; ok {
			out = append(out, name)
		} else {
			out = append(out, fmt.Sprintf("bit%d", i))
		}
	}
	return out
}

// sanitize strips control characters so a hostile status string cannot inject
// escape sequences into a terminal or break a CSV row.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == ',' || r == '"' {
			return ' '
		}
		return r
	}, s)
}

func bytesTrimmed(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}
