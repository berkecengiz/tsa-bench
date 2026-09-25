// Package testutil builds throwaway PKI material for tests and for the local
// mock TSA. Nothing here is suitable for production use.
//
// Keys are generated in memory; the mock writes them to disk only when asked,
// and then with 0600 permissions.
package testutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// KeyType selects the algorithm used for generated keys.
type KeyType int

const (
	// ECDSAP256 is the default: fast enough to sign at load-test rates.
	ECDSAP256 KeyType = iota
	// RSA2048 mirrors what most public TSAs actually use.
	RSA2048
)

// CA is a self-signed issuer usable as a trust anchor.
type CA struct {
	Cert    *x509.Certificate
	Key     crypto.Signer
	DER     []byte
	PEM     []byte
	Pool    *x509.CertPool
	Subject string
}

// Leaf is an end-entity certificate issued by a CA.
type Leaf struct {
	Cert *x509.Certificate
	Key  crypto.Signer
	DER  []byte
	PEM  []byte
}

// TSAOptions tweaks the generated TSA certificate so tests can exercise the
// rejection paths of the verifier.
type TSAOptions struct {
	KeyType KeyType
	// NotBefore/NotAfter default to a wide window around now.
	NotBefore time.Time
	NotAfter  time.Time
	// OmitTimeStampingEKU issues a certificate without id-kp-timeStamping.
	OmitTimeStampingEKU bool
	// ExtraEKU adds a second extended key usage, which RFC 3161 forbids.
	ExtraEKU bool
	// NonCriticalEKU marks the EKU extension as non-critical.
	NonCriticalEKU bool
	// CommonName overrides the subject CN.
	CommonName string
}

func generateKey(kt KeyType) (crypto.Signer, error) {
	switch kt {
	case RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	default:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(fmt.Sprintf("testutil: serial: %v", err))
	}
	return n
}

// NewCA creates a self-signed certificate authority.
func NewCA(name string, kt KeyType) (*CA, error) {
	key, err := generateKey(kt)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: name, Organization: []string{"tsa-bench test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{
		Cert:    cert,
		Key:     key,
		DER:     der,
		PEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Pool:    pool,
		Subject: name,
	}, nil
}

// IssueTSA issues a timestamping certificate under the CA.
func (ca *CA) IssueTSA(opts TSAOptions) (*Leaf, error) {
	key, err := generateKey(opts.KeyType)
	if err != nil {
		return nil, err
	}

	notBefore := opts.NotBefore
	if notBefore.IsZero() {
		notBefore = time.Now().Add(-time.Hour)
	}
	notAfter := opts.NotAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(24 * time.Hour)
	}
	cn := opts.CommonName
	if cn == "" {
		cn = "tsa-bench mock TSA"
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"tsa-bench test"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		BasicConstraintsValid: true,
	}

	if !opts.OmitTimeStampingEKU {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
		if opts.ExtraEKU {
			tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, key.Public(), ca.Key)
	if err != nil {
		return nil, err
	}
	if !opts.OmitTimeStampingEKU && !opts.NonCriticalEKU {
		// Go's x509 marshals the EKU extension as non-critical. RFC 3161
		// requires it to be critical, so re-issue with an explicit extension.
		der, err = ca.reissueWithCriticalEKU(tmpl, key)
		if err != nil {
			return nil, err
		}
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Leaf{
		Cert: cert,
		Key:  key,
		DER:  der,
		PEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}, nil
}

// reissueWithCriticalEKU re-creates the certificate with the extended key usage
// supplied as a raw critical extension.
func (ca *CA) reissueWithCriticalEKU(tmpl *x509.Certificate, key crypto.Signer) ([]byte, error) {
	ekuDER, err := marshalEKU(tmpl.ExtKeyUsage)
	if err != nil {
		return nil, err
	}
	clone := *tmpl
	clone.ExtKeyUsage = nil
	clone.ExtraExtensions = append(clone.ExtraExtensions, pkix.Extension{
		Id:       oidExtKeyUsage,
		Critical: true,
		Value:    ekuDER,
	})
	return x509.CreateCertificate(rand.Reader, &clone, ca.Cert, key.Public(), ca.Key)
}

// ServerCert issues a TLS server certificate for the given hosts.
func (ca *CA) ServerCert(hosts []string, kt KeyType) (*Leaf, error) {
	key, err := generateKey(kt)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: hosts[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, key.Public(), ca.Key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Leaf{
		Cert: cert, Key: key, DER: der,
		PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}, nil
}

// KeyPEM encodes the private key in PKCS#8 PEM form.
func (l *Leaf) KeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(l.Key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
