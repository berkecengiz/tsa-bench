package tsp

import (
	"crypto"
	"crypto/sha1" //nolint:gosec // SHA-1 is mandated by ESSCertID (RFC 2634); used only to compare a hash the TSA chose
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/digitorus/pkcs7"
)

// ESS attribute OIDs.
var (
	oidSigningCertificate   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
)

var digestOIDs = map[string]crypto.Hash{
	"1.3.14.3.2.26":          crypto.SHA1,
	"2.16.840.1.101.3.4.2.1": crypto.SHA256,
	"2.16.840.1.101.3.4.2.2": crypto.SHA384,
	"2.16.840.1.101.3.4.2.3": crypto.SHA512,
	"2.16.840.1.101.3.4.2.4": crypto.SHA224,
}

// ESSResult describes the outcome of the signing-certificate binding check.
type ESSResult struct {
	// Present reports whether a SigningCertificate(V2) attribute was found.
	Present bool
	// Version is "V2", "V1" or "" when absent.
	Version string
	// Matched reports whether the attribute binds the actual signer certificate.
	Matched bool
	// Reason explains a non-match; empty when Matched or absent.
	Reason string
}

// CheckESSBinding verifies that the signed SigningCertificateV2 (or the legacy
// SigningCertificate) attribute really identifies the certificate that signed
// the token. Without this check, an attacker able to swap the certificate set
// could point verification at a different certificate than the signer intended.
//
// Policy: when the attribute is present, a mismatch is a hard failure. When it
// is absent, the caller decides — see Verifier.RequireESS. Absence is reported
// rather than silently treated as success.
func CheckESSBinding(p7 *pkcs7.PKCS7, signer *x509.Certificate) ESSResult {
	if signer == nil {
		return ESSResult{Reason: "no signer certificate"}
	}

	if raw, ok := signedAttr(p7, oidSigningCertificateV2); ok {
		return matchESS(raw, signer, "V2", true)
	}
	if raw, ok := signedAttr(p7, oidSigningCertificate); ok {
		return matchESS(raw, signer, "V1", false)
	}
	return ESSResult{Present: false}
}

func signedAttr(p7 *pkcs7.PKCS7, oid asn1.ObjectIdentifier) (asn1.RawValue, bool) {
	var raw asn1.RawValue
	if err := p7.UnmarshalSignedAttribute(oid, &raw); err != nil {
		return raw, false
	}
	return raw, true
}

// matchESS walks SigningCertificate[V2] and compares every ESSCertID against
// the signer certificate.
//
//	SigningCertificateV2 ::= SEQUENCE {
//	    certs    SEQUENCE OF ESSCertIDv2,
//	    policies SEQUENCE OF PolicyInformation OPTIONAL }
//	ESSCertIDv2 ::= SEQUENCE {
//	    hashAlgorithm AlgorithmIdentifier DEFAULT id-sha256,
//	    certHash      OCTET STRING,
//	    issuerSerial  IssuerSerial OPTIONAL }
func matchESS(raw asn1.RawValue, signer *x509.Certificate, version string, v2 bool) ESSResult {
	res := ESSResult{Present: true, Version: version}

	if raw.Tag != asn1.TagSequence || !raw.IsCompound {
		res.Reason = "SigningCertificate attribute is not a SEQUENCE"
		return res
	}
	var certsSeq asn1.RawValue
	if _, err := asn1.Unmarshal(raw.Bytes, &certsSeq); err != nil {
		res.Reason = "cannot decode ESSCertID sequence: " + err.Error()
		return res
	}
	if certsSeq.Tag != asn1.TagSequence || !certsSeq.IsCompound {
		res.Reason = "ESSCertID container is not a SEQUENCE"
		return res
	}

	rest := certsSeq.Bytes
	found := 0
	for len(rest) > 0 {
		var certID asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &certID)
		if err != nil {
			res.Reason = "cannot decode ESSCertID: " + err.Error()
			return res
		}
		found++
		ok, err := essCertIDMatches(certID.Bytes, signer, v2)
		if err != nil {
			res.Reason = err.Error()
			return res
		}
		if ok {
			res.Matched = true
			return res
		}
	}

	if found == 0 {
		res.Reason = "SigningCertificate attribute contains no ESSCertID"
		return res
	}
	res.Reason = fmt.Sprintf("none of the %d ESSCertID entries match the signer certificate", found)
	return res
}

func essCertIDMatches(der []byte, signer *x509.Certificate, v2 bool) (bool, error) {
	h := crypto.SHA1
	if v2 {
		h = crypto.SHA256 // the DEFAULT when hashAlgorithm is absent
	}

	var field asn1.RawValue
	rest, err := asn1.Unmarshal(der, &field)
	if err != nil {
		return false, errors.New("cannot decode ESSCertID body")
	}

	// A leading SEQUENCE is the optional AlgorithmIdentifier (v2 only).
	if v2 && field.Tag == asn1.TagSequence && field.IsCompound {
		var alg asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(field.Bytes, &alg); err != nil {
			return false, errors.New("cannot decode ESSCertID hash algorithm")
		}
		known, ok := digestOIDs[alg.String()]
		if !ok {
			return false, fmt.Errorf("ESSCertID uses unsupported hash algorithm %s", alg.String())
		}
		h = known
		if _, err := asn1.Unmarshal(rest, &field); err != nil {
			return false, errors.New("cannot decode ESSCertID certHash")
		}
	}

	if field.Tag != asn1.TagOctetString {
		return false, errors.New("ESSCertID certHash is not an OCTET STRING")
	}

	want := field.Bytes
	got, err := digestCert(h, signer.Raw)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(want, got) == 1, nil
}

func digestCert(h crypto.Hash, der []byte) ([]byte, error) {
	if h == crypto.SHA1 {
		sum := sha1.Sum(der) //nolint:gosec // comparing a TSA-chosen ESSCertID v1 hash
		return sum[:], nil
	}
	if !h.Available() {
		return nil, fmt.Errorf("hash %v is not available in this build", h)
	}
	hh := h.New()
	hh.Write(der)
	return hh.Sum(nil), nil
}
