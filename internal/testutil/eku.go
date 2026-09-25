package testutil

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

var ekuOIDs = map[x509.ExtKeyUsage]asn1.ObjectIdentifier{
	x509.ExtKeyUsageTimeStamping: {1, 3, 6, 1, 5, 5, 7, 3, 8},
	x509.ExtKeyUsageClientAuth:   {1, 3, 6, 1, 5, 5, 7, 3, 2},
	x509.ExtKeyUsageServerAuth:   {1, 3, 6, 1, 5, 5, 7, 3, 1},
}

// marshalEKU encodes an ExtKeyUsageSyntax so it can be attached as a critical
// extension; Go's certificate builder always marks its own EKU non-critical.
func marshalEKU(usages []x509.ExtKeyUsage) ([]byte, error) {
	oids := make([]asn1.ObjectIdentifier, 0, len(usages))
	for _, u := range usages {
		oid, ok := ekuOIDs[u]
		if !ok {
			return nil, fmt.Errorf("testutil: unsupported extended key usage %v", u)
		}
		oids = append(oids, oid)
	}
	return asn1.Marshal(oids)
}
