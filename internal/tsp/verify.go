package tsp

import (
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"mime"
	"strings"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"

	"github.com/berkecengiz/tsa-bench/internal/errclass"
)

// oidExtKeyUsage is the id-ce-extKeyUsage extension, needed to inspect the
// criticality flag that RFC 3161 section 2.3 requires.
var oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

// Verifier applies the full RFC 3161 acceptance chain. It is safe for
// concurrent use.
type Verifier struct {
	// Roots is the trust anchor set for the TSA signing certificate. It must
	// not be nil: without it no chain can be established and no transaction
	// could honestly be called successful.
	Roots *x509.CertPool
	// MaxClockSkew is the tolerated difference between genTime and local time.
	MaxClockSkew time.Duration
	// RequireESS turns a missing SigningCertificate(V2) attribute into a
	// failure. When false, absence is reported as a warning instead.
	RequireESS bool
	// AllowGrantedWithMods accepts PKIStatus grantedWithMods (1) in addition to
	// granted (0). RFC 3161 permits it; it is on by default.
	AllowGrantedWithMods bool
}

// Result is the verified content of a successful response, plus diagnostics
// that are useful even when verification fails part-way.
type Result struct {
	Status        *StatusInfo
	GenTime       time.Time
	Accuracy      time.Duration
	SerialNumber  *big.Int
	Policy        string
	SignerSubject string
	SignerIssuer  string
	SignerExpiry  time.Time
	ChainLength   int
	ESS           ESSResult
	ClockSkew     time.Duration
	// Warnings are non-fatal observations recorded in the report.
	Warnings []string
}

// NewVerifier validates the verifier configuration up front, so a missing trust
// anchor is caught before the load test starts rather than per request.
func NewVerifier(roots *x509.CertPool, maxSkew time.Duration, requireESS bool) (*Verifier, error) {
	if roots == nil {
		return nil, errors.New("no trust anchors configured; the TSA certificate chain could not be verified")
	}
	if maxSkew <= 0 {
		return nil, errors.New("max clock skew must be greater than zero")
	}
	return &Verifier{
		Roots:                roots,
		MaxClockSkew:         maxSkew,
		RequireESS:           requireESS,
		AllowGrantedWithMods: true,
	}, nil
}

// HTTPResponse carries everything the verifier needs about the HTTP layer.
type HTTPResponse struct {
	StatusCode  int
	ContentType string
	Body        []byte
	SentAt      time.Time
	ReceivedAt  time.Time
}

// Verify runs the acceptance chain. It returns a Result on success, or a
// classified error naming the first check that failed.
//
// Every step is mandatory. There is no mode in which a check is skipped and the
// transaction still counts as successful.
func (v *Verifier) Verify(req *Request, resp HTTPResponse) (*Result, *errclass.Error) {
	// 1. HTTP status.
	if e := errclass.FromHTTPStatus(resp.StatusCode); e != nil {
		return nil, e
	}

	// 2. Content type. RFC 3161 mandates application/timestamp-reply.
	if e := checkContentType(resp.ContentType); e != nil {
		return nil, e
	}

	// 3. PKIStatusInfo, parsed independently so rejections can be broken down
	//    by failInfo instead of being flattened into an opaque string.
	status, err := ParseStatusInfo(resp.Body)
	if err != nil {
		return nil, errclass.New(errclass.MalformedResponse, err.Error())
	}
	res := &Result{Status: status}
	if !v.statusAccepted(status.Status) {
		return nil, errclass.NewSub(errclass.TSPRejection, status.SubCategory(),
			fmt.Sprintf("PKIStatus=%s statusString=%q", status.Status, status.StatusString))
	}
	if !status.HasToken {
		return nil, errclass.New(errclass.MalformedResponse,
			"PKIStatus is granted but the response carries no timeStampToken")
	}
	if status.Status == StatusGrantedWithMods {
		res.Warnings = append(res.Warnings, "PKIStatus is grantedWithMods: the TSA modified the request")
	}

	// 4. Parse the token. The library verifies the CMS signature against the
	//    embedded certificates here, but only when certificates are present —
	//    see step 7 for why that is not sufficient on its own.
	ts, err := timestamp.ParseResponse(resp.Body)
	if err != nil {
		// The strict parser rejects a GeneralizedTime that is not minimally
		// encoded, which at least one production TSA emits. Retry tolerantly,
		// but accept the result only when that is what actually differed: the
		// tolerant path is a second, hand-written decoder, and a genuinely
		// malformed response should be reported as the strict parser saw it
		// rather than pushed through it.
		lenient, warning, lerr := parseResponseTolerantly(resp.Body)
		if lerr != nil || warning == "" {
			return nil, classifyParseError(err)
		}
		ts = lenient
		res.Warnings = append(res.Warnings, warning)
	}
	res.GenTime = ts.Time
	res.Accuracy = ts.Accuracy
	res.SerialNumber = ts.SerialNumber
	if ts.Policy != nil {
		res.Policy = ts.Policy.String()
	}

	// 5. Nonce echo. A responder that drops the nonce cannot prove freshness.
	if ts.Nonce == nil {
		return nil, errclass.New(errclass.InvalidNonce, "response contains no nonce")
	}
	if ts.Nonce.Cmp(req.Nonce) != 0 {
		return nil, errclass.New(errclass.InvalidNonce, "response nonce does not match the request nonce")
	}

	// 6. Message imprint echo, algorithm and value.
	if ts.HashAlgorithm != req.HashAlgorithm {
		return nil, errclass.New(errclass.InvalidImprint,
			fmt.Sprintf("response hash algorithm %v does not match request %v", ts.HashAlgorithm, req.HashAlgorithm))
	}
	if subtle.ConstantTimeCompare(ts.HashedMessage, req.Imprint) != 1 {
		return nil, errclass.New(errclass.InvalidImprint, "response message imprint does not match the request")
	}

	// 7. Signature. The token must carry the signing certificate: without it
	//    the timestamp library skips signature verification entirely, so an
	//    unverified token must never be reported as a success.
	if len(ts.Certificates) == 0 {
		return nil, errclass.New(errclass.UntrustedCert,
			"response carries no TSA certificate although certReq was true; the signature cannot be verified")
	}
	p7, err := pkcs7.Parse(ts.RawToken)
	if err != nil {
		return nil, errclass.New(errclass.MalformedResponse, "cannot parse CMS token: "+err.Error())
	}
	signer := p7.GetOnlySigner()
	if signer == nil {
		return nil, errclass.New(errclass.InvalidSignature,
			"token does not have exactly one signer")
	}
	res.SignerSubject = signer.Subject.String()
	res.SignerIssuer = signer.Issuer.String()
	res.SignerExpiry = signer.NotAfter
	res.ChainLength = len(ts.Certificates)

	// 7b. ESS signing-certificate binding.
	res.ESS = CheckESSBinding(p7, signer)
	switch {
	case res.ESS.Present && !res.ESS.Matched:
		return nil, errclass.New(errclass.InvalidSignature,
			"SigningCertificate"+res.ESS.Version+" attribute does not bind the signer certificate: "+res.ESS.Reason)
	case !res.ESS.Present && v.RequireESS:
		return nil, errclass.New(errclass.InvalidSignature,
			"token has no SigningCertificate(V2) attribute and require_ess is set")
	case !res.ESS.Present:
		res.Warnings = append(res.Warnings,
			"token has no SigningCertificate(V2) attribute; signer binding could not be checked")
	}

	// 8. Chain of trust, validity at genTime, and the timeStamping EKU.
	//    VerifyWithOpts re-checks the signature *and* builds the chain against
	//    our trust anchors; Verify() alone uses an empty trust store.
	opts := x509.VerifyOptions{
		Roots:         v.Roots,
		Intermediates: intermediatePool(ts.Certificates),
		CurrentTime:   ts.Time,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	if err := p7.VerifyWithOpts(opts); err != nil {
		return nil, classifyVerifyError(err)
	}
	if e := checkTimeStampingEKU(signer); e != nil {
		return nil, e
	}

	// 9. Clock skew. genTime must sit inside the request window widened by the
	//    tolerated skew; a TSA whose clock drifts produces timestamps that are
	//    worthless as evidence.
	skew, e := v.checkSkew(ts.Time, resp.SentAt, resp.ReceivedAt)
	res.ClockSkew = skew
	if e != nil {
		// Return the result as well: the magnitude of the skew is exactly what
		// the operator needs from a clock_skew_exceeded row, and discarding it
		// here would also drop any warnings gathered above.
		return res, e
	}

	return res, nil
}

func (v *Verifier) statusAccepted(s PKIStatus) bool {
	if s == StatusGranted {
		return true
	}
	return s == StatusGrantedWithMods && v.AllowGrantedWithMods
}

// checkSkew measures how far genTime falls outside the request window.
func (v *Verifier) checkSkew(genTime, sentAt, receivedAt time.Time) (time.Duration, *errclass.Error) {
	var skew time.Duration
	switch {
	case genTime.Before(sentAt):
		skew = sentAt.Sub(genTime)
	case genTime.After(receivedAt):
		skew = genTime.Sub(receivedAt)
	default:
		return 0, nil
	}
	if skew > v.MaxClockSkew {
		return skew, errclass.New(errclass.ClockSkewExceeded,
			fmt.Sprintf("genTime is %s outside the request window (limit %s); check NTP on both ends",
				skew.Round(time.Millisecond), v.MaxClockSkew))
	}
	return skew, nil
}

// checkTimeStampingEKU enforces RFC 3161 section 2.3: the TSA certificate must
// carry the timeStamping extended key usage, it must be the only one, and the
// extension must be marked critical. x509 chain building checks that the EKU is
// present but not that it is exclusive or critical.
func checkTimeStampingEKU(cert *x509.Certificate) *errclass.Error {
	hasTS := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageTimeStamping {
			hasTS = true
		}
	}
	if !hasTS {
		return errclass.New(errclass.UntrustedCert,
			"TSA certificate does not carry the timeStamping extended key usage")
	}
	if len(cert.ExtKeyUsage) != 1 || len(cert.UnknownExtKeyUsage) > 0 {
		return errclass.New(errclass.UntrustedCert,
			"TSA certificate carries extended key usages besides timeStamping, which RFC 3161 forbids")
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidExtKeyUsage) {
			if !ext.Critical {
				return errclass.New(errclass.UntrustedCert,
					"the extended key usage extension of the TSA certificate is not marked critical")
			}
			return nil
		}
	}
	return errclass.New(errclass.UntrustedCert,
		"TSA certificate has no extended key usage extension")
}

func intermediatePool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}

func checkContentType(raw string) *errclass.Error {
	if raw == "" {
		return errclass.New(errclass.InvalidContentType, "response has no Content-Type header")
	}
	mt, _, err := mime.ParseMediaType(raw)
	if err != nil {
		return errclass.New(errclass.InvalidContentType,
			fmt.Sprintf("unparsable Content-Type %q", sanitize(raw)))
	}
	if !strings.EqualFold(mt, ContentTypeResponse) {
		return errclass.New(errclass.InvalidContentType,
			fmt.Sprintf("Content-Type %q is not %s", sanitize(mt), ContentTypeResponse))
	}
	return nil
}

// classifyParseError separates a signature failure reported by the timestamp
// library from a structural decoding failure.
func classifyParseError(err error) *errclass.Error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "digest") || strings.Contains(msg, "signature") ||
		strings.Contains(msg, "verification") || strings.Contains(msg, "crypto/rsa"):
		return errclass.New(errclass.InvalidSignature, msg)
	case strings.Contains(msg, "x509:"):
		return errclass.New(errclass.UntrustedCert, msg)
	default:
		return errclass.New(errclass.MalformedResponse, msg)
	}
}

// classifyVerifyError distinguishes a broken signature from an untrusted chain.
func classifyVerifyError(err error) *errclass.Error {
	var unknownAuthority x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	switch {
	case errors.As(err, &unknownAuthority), errors.As(err, &invalid), errors.As(err, &hostname):
		return errclass.New(errclass.UntrustedCert, err.Error())
	case strings.Contains(err.Error(), "x509:"):
		return errclass.New(errclass.UntrustedCert, err.Error())
	default:
		return errclass.New(errclass.InvalidSignature, err.Error())
	}
}
