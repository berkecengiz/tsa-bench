// Package tsp builds RFC 3161 timestamp requests and verifies the responses.
//
// Verification is deliberately strict: a transaction counts as successful only
// when every check in Verify passes. An HTTP 200 on its own proves nothing — a
// responder can return a well-formed HTTP response carrying a rejection, a
// replayed token, or a token signed by a certificate that chains nowhere.
package tsp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"hash"
	"math/big"
	"strconv"
	"strings"

	"github.com/digitorus/timestamp"
)

// ContentTypeRequest is the media type mandated for a timestamp query.
const ContentTypeRequest = "application/timestamp-query"

// ContentTypeResponse is the media type mandated for a timestamp reply.
const ContentTypeResponse = "application/timestamp-reply"

// nonceBits is the size of the generated nonce. RFC 3161 places no lower bound,
// but a 128-bit random nonce makes accidental or malicious replay detectable.
const nonceBits = 128

// Request is a prepared timestamp query together with everything needed to
// validate the matching response.
type Request struct {
	// DER is the encoded TimeStampReq, ready to POST.
	DER []byte
	// Nonce is the value the response must echo back.
	Nonce *big.Int
	// HashAlgorithm is the imprint algorithm.
	HashAlgorithm crypto.Hash
	// Imprint is the message imprint the response must echo back.
	Imprint []byte
	// Payload is the random data that was hashed. Retained only so that
	// --debug-artifacts can write it; it carries no secret.
	Payload []byte
}

// Builder produces unique requests at load-test rates.
type Builder struct {
	hashAlg     crypto.Hash
	newHash     func() hash.Hash
	payloadSize int
	certReq     bool
	policyOID   asn1.ObjectIdentifier
}

// BuilderOptions configures a Builder.
type BuilderOptions struct {
	HashName    string
	PayloadSize int
	CertReq     bool
	PolicyOID   string
}

// NewBuilder validates the options and returns a reusable Builder.
func NewBuilder(opts BuilderOptions) (*Builder, error) {
	alg, newHash, err := hashByName(opts.HashName)
	if err != nil {
		return nil, err
	}
	if opts.PayloadSize < 16 {
		return nil, fmt.Errorf("payload size %d is too small", opts.PayloadSize)
	}
	if !opts.CertReq {
		// Without the signing certificate the CMS signature cannot be checked
		// against a trust chain, so success could not be established.
		return nil, fmt.Errorf("cert_req must be true so the response carries the TSA certificate")
	}
	b := &Builder{
		hashAlg:     alg,
		newHash:     newHash,
		payloadSize: opts.PayloadSize,
		certReq:     opts.CertReq,
	}
	if opts.PolicyOID != "" {
		oid, err := parseOID(opts.PolicyOID)
		if err != nil {
			return nil, err
		}
		b.policyOID = oid
	}
	return b, nil
}

// HashAlgorithm reports the configured imprint algorithm.
func (b *Builder) HashAlgorithm() crypto.Hash { return b.hashAlg }

// Build creates a fresh request with a unique payload and nonce.
func (b *Builder) Build() (*Request, error) {
	payload := make([]byte, b.payloadSize)
	if _, err := rand.Read(payload); err != nil {
		return nil, fmt.Errorf("generate payload: %w", err)
	}

	h := b.newHash()
	h.Write(payload)
	imprint := h.Sum(nil)

	nonce, err := newNonce()
	if err != nil {
		return nil, err
	}

	der, err := timestamp.CreateRequest(bytes.NewReader(payload), &timestamp.RequestOptions{
		Hash:         b.hashAlg,
		Certificates: b.certReq,
		Nonce:        nonce,
		TSAPolicyOID: b.policyOID,
	})
	if err != nil {
		return nil, fmt.Errorf("create timestamp request: %w", err)
	}

	return &Request{
		DER:           der,
		Nonce:         nonce,
		HashAlgorithm: b.hashAlg,
		Imprint:       imprint,
		Payload:       payload,
	}, nil
}

// newNonce returns a cryptographically secure, positive, non-zero nonce.
func newNonce() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), nonceBits)
	for {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, fmt.Errorf("generate nonce: %w", err)
		}
		// Zero would be echoed indistinguishably by a responder that drops the
		// nonce entirely, so reject it.
		if n.Sign() != 0 {
			return n, nil
		}
	}
}

func hashByName(name string) (crypto.Hash, func() hash.Hash, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "sha256", "sha-256", "":
		return crypto.SHA256, crypto.SHA256.New, nil
	case "sha384", "sha-384":
		return crypto.SHA384, crypto.SHA384.New, nil
	case "sha512", "sha-512":
		return crypto.SHA512, crypto.SHA512.New, nil
	default:
		return 0, nil, fmt.Errorf("unsupported hash algorithm %q", name)
	}
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	oid := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 {
			return nil, fmt.Errorf("invalid OID %q", s)
		}
		oid = append(oid, v)
	}
	if len(oid) < 2 {
		return nil, fmt.Errorf("invalid OID %q", s)
	}
	return oid, nil
}
