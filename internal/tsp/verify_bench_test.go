package tsp_test

import (
	"testing"
	"time"

	"github.com/berkecengiz/tsa-bench/internal/testutil"
	"github.com/berkecengiz/tsa-bench/internal/tsp"
)

// BenchmarkVerify measures the verification half of a transaction with the
// network taken out: one response, captured once, then verified repeatedly.
//
// It exists because Verify's cost is charged to the latency this tool reports.
// Work duplicated inside it does not merely waste CPU, it makes the provider
// look slower than it is - so a redundant parse or signature check here is a
// measurement-accuracy problem, not only a performance one.
func BenchmarkVerify(b *testing.B) {
	for _, tc := range []struct {
		name string
		kt   testutil.KeyType
	}{
		{"ecdsa-p256", testutil.ECDSAP256},
		{"rsa-2048", testutil.RSA2048},
	} {
		b.Run(tc.name, func(b *testing.B) {
			h := newHarness(b, tc.kt)

			req, err := h.builder.Build()
			if err != nil {
				b.Fatalf("Build: %v", err)
			}
			sentAt := time.Now()
			body := h.rawRoundTripFor(b, req)
			raw := tsp.HTTPResponse{
				StatusCode:  200,
				ContentType: tsp.ContentTypeResponse,
				Body:        body,
				SentAt:      sentAt,
				ReceivedAt:  time.Now(),
			}

			// Fail before timing rather than benchmark an error path.
			if _, cerr := h.verifier.Verify(req, raw); cerr != nil {
				b.Fatalf("Verify: %v", cerr)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, cerr := h.verifier.Verify(req, raw); cerr != nil {
					b.Fatalf("Verify: %v", cerr)
				}
			}
		})
	}
}
