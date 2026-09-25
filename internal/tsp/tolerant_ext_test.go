package tsp_test

// The tolerant parser reimplements the library's TSTInfo decoding, so it must
// agree with it field for field on a response both can read. A drift here
// would silently change what the report says about a provider.
//
// Fixtures are generated rather than committed. Real provider responses were
// used originally, but a signed token carries the issuing TSA's certificate
// chain in its bytes, so committing one publishes which service was tested.
// The mock responder produces genuine RFC 3161 tokens over a throwaway PKI,
// which exercises the same decoding path and identifies nobody.
//
// This lives in package tsp_test because mock imports tsp; parseResponse-
// Tolerantly reaches it through export_test.go.

import (
	"bytes"
	"testing"

	"github.com/digitorus/timestamp"

	"github.com/berkecengiz/tsa-bench/internal/testutil"
	"github.com/berkecengiz/tsa-bench/internal/tsp"
)

func TestTolerantParseMatchesLibrary(t *testing.T) {
	// Both key types, because the signature algorithm changes the CMS
	// structure the two parsers walk.
	for name, kt := range map[string]testutil.KeyType{
		"ecdsa-p256": testutil.ECDSAP256,
		"rsa-2048":   testutil.RSA2048,
	} {
		t.Run(name, func(t *testing.T) {
			compareParsers(t, newHarness(t, kt).rawRoundTrip(t))
		})
	}
}

func compareParsers(t *testing.T, body []byte) {
	t.Helper()

	strict, err := timestamp.ParseResponse(body)
	if err != nil {
		t.Fatalf("the library rejected the response: %v", err)
	}
	lenient, _, warning, err := tsp.ParseResponseTolerantly(body)
	if err != nil {
		t.Fatalf("ParseResponseTolerantly: %v", err)
	}
	if warning != "" {
		t.Errorf("a conformant response produced a warning: %q", warning)
	}

	if !lenient.Time.Equal(strict.Time) {
		t.Errorf("time = %v, library says %v", lenient.Time, strict.Time)
	}
	if lenient.SerialNumber.Cmp(strict.SerialNumber) != 0 {
		t.Errorf("serial = %v, library says %v", lenient.SerialNumber, strict.SerialNumber)
	}
	if !lenient.Policy.Equal(strict.Policy) {
		t.Errorf("policy = %v, library says %v", lenient.Policy, strict.Policy)
	}
	if lenient.HashAlgorithm != strict.HashAlgorithm {
		t.Errorf("hash = %v, library says %v", lenient.HashAlgorithm, strict.HashAlgorithm)
	}
	if !bytes.Equal(lenient.HashedMessage, strict.HashedMessage) {
		t.Error("hashed message differs from the library's")
	}
	if lenient.Accuracy != strict.Accuracy {
		t.Errorf("accuracy = %v, library says %v", lenient.Accuracy, strict.Accuracy)
	}
	if lenient.Nonce.Cmp(strict.Nonce) != 0 {
		t.Errorf("nonce = %v, library says %v", lenient.Nonce, strict.Nonce)
	}
	if len(lenient.Certificates) != len(strict.Certificates) {
		t.Errorf("%d certificates, library says %d", len(lenient.Certificates), len(strict.Certificates))
	}
}
