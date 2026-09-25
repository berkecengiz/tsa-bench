package tsp

import (
	"crypto"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"crypto/x509/pkix"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
)

// Tolerating a non-minimal DER GeneralizedTime.
//
// X.690 section 11.7 requires the fractional seconds of a DER GeneralizedTime
// to carry no trailing zeros, and Go's encoding/asn1 enforces it by checking
// that the value serialises back to the bytes it came from. At least one
// production TSA emits "20260924081902.10Z", which OpenSSL accepts
// and Go rejects. Roughly one timestamp in ten lands on a fractional value
// ending in zero, so a strict reading turns a conformance nit into thousands
// of failed requests in a single run and hides whatever the measurement was
// meant to show.
//
// The response is therefore parsed again, tolerantly, but only in how the time
// field is *read*: the signature is verified by pkcs7 over the original bytes,
// exactly as the strict path does, and nothing signed is rewritten. The
// timestamp's value is unchanged - ".10" and ".1" denote the same instant -
// so only the encoding is being forgiven. Every attempt parsed this way
// carries a warning into the report, because a provider shipping non-DER
// output is a finding in its own right.

// lenientMessageImprint mirrors the library's messageImprint.
type lenientMessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// lenientAccuracy mirrors the library's accuracy.
type lenientAccuracy struct {
	Seconds      int64 `asn1:"optional"`
	Milliseconds int64 `asn1:"tag:0,optional"`
	Microseconds int64 `asn1:"tag:1,optional"`
}

// lenientTSTInfo is the library's tstInfo with Time left raw, so the strict
// GeneralizedTime round-trip check never runs.
type lenientTSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint lenientMessageImprint
	SerialNumber   *big.Int
	Time           asn1.RawValue
	Accuracy       lenientAccuracy  `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"tag:0,optional"`
	Extensions     []pkix.Extension `asn1:"tag:1,optional"`
}

// rawResponse extracts the token without interpreting the status, which the
// strict parser has already accepted by the time this is reached.
type rawResponse struct {
	Status         asn1.RawValue
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// parseResponseTolerantly re-parses a response the library rejected. It
// returns the timestamp and a warning describing the deviation, or an error if
// the response is unusable for any reason beyond the time encoding.
func parseResponseTolerantly(body []byte) (*timestamp.Timestamp, string, error) {
	var resp rawResponse
	if _, err := asn1.Unmarshal(body, &resp); err != nil {
		return nil, "", err
	}
	if len(resp.TimeStampToken.FullBytes) == 0 {
		return nil, "", errors.New("no pkcs7 data in Time-Stamp response")
	}

	// The signature is not checked here. Verifier.Verify re-parses these same
	// bytes and runs VerifyWithOpts against the configured trust anchors,
	// which is strictly stronger; doing it twice would double the RSA work and
	// inflate the verification latency this tool exists to measure.
	p7, err := pkcs7.Parse(resp.TimeStampToken.FullBytes)
	if err != nil {
		return nil, "", err
	}

	var inf lenientTSTInfo
	if _, err := asn1.Unmarshal(p7.Content, &inf); err != nil {
		return nil, "", err
	}
	if len(inf.MessageImprint.HashedMessage) == 0 {
		return nil, "", errors.New("Time-Stamp response contains no hashed message")
	}

	genTime, warning, err := parseGeneralizedTime(inf.Time)
	if err != nil {
		return nil, "", err
	}

	hashAlg, ok := digestOIDs[inf.MessageImprint.HashAlgorithm.Algorithm.String()]
	if !ok || hashAlg == crypto.Hash(0) {
		return nil, "", errors.New("Time-Stamp response uses unknown hash function")
	}

	return &timestamp.Timestamp{
		RawToken:      resp.TimeStampToken.FullBytes,
		HashAlgorithm: hashAlg,
		HashedMessage: inf.MessageImprint.HashedMessage,
		Time:          genTime,
		Accuracy: (time.Second * time.Duration(inf.Accuracy.Seconds)) +
			(time.Millisecond * time.Duration(inf.Accuracy.Milliseconds)) +
			(time.Microsecond * time.Duration(inf.Accuracy.Microseconds)),
		SerialNumber:      inf.SerialNumber,
		Policy:            inf.Policy,
		Ordering:          inf.Ordering,
		Nonce:             inf.Nonce,
		Certificates:      p7.Certificates,
		AddTSACertificate: len(p7.Certificates) > 0,
		Extensions:        inf.Extensions,
	}, warning, nil
}

// warnNonMinimalGenTime is deliberately constant so that every affected
// response aggregates into a single reported count.
const warnNonMinimalGenTime = "genTime is not valid DER: X.690 11.7 forbids trailing zeros in " +
	"the fractional seconds. The instant is unambiguous and was accepted, but the encoding is " +
	"non-conformant and stricter verifiers will reject these tokens"

// parseGeneralizedTime reads a GeneralizedTime without requiring a minimal
// encoding. It returns a warning naming the deviation when the encoding is not
// the one DER demands, and an empty warning when it is.
func parseGeneralizedTime(raw asn1.RawValue) (time.Time, string, error) {
	if raw.Tag != asn1.TagGeneralizedTime {
		return time.Time{}, "", fmt.Errorf("genTime is ASN.1 tag %d, not a GeneralizedTime", raw.Tag)
	}
	s := string(raw.Bytes)

	// Go's time parser accepts a fractional second whether or not the layout
	// mentions one, so a single layout covers every precision.
	t, err := time.Parse("20060102150405Z0700", s)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("genTime %q is not a valid GeneralizedTime: %w", s, err)
	}

	if frac, ok := fractionalPart(s); ok && strings.HasSuffix(frac, "0") {
		// The message must not carry the offending value: warnings are counted
		// by text, and a per-token string would put one entry per affected
		// request in the report instead of one line with a count.
		return t, warnNonMinimalGenTime, nil
	}
	return t, "", nil
}

// fractionalPart returns the digits between the decimal point and the zone.
func fractionalPart(s string) (string, bool) {
	dot := strings.IndexByte(s, '.')
	if dot < 0 {
		return "", false
	}
	rest := s[dot+1:]
	end := strings.IndexAny(rest, "Z+-")
	if end < 0 {
		end = len(rest)
	}
	return rest[:end], true
}
