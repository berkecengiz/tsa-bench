package report

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
)

// ArtifactStore writes raw protocol bytes when --debug-artifacts is set.
//
// This is off by default and deliberately noisy when enabled: a raw timestamp
// response contains the TSA's signature over data the operator supplied, and a
// raw request could be correlated with a customer workload. Files are 0600 and
// the operator is warned on stderr.
type ArtifactStore struct {
	dir     string
	limit   int64
	written atomic.Int64
}

// NewArtifactStore creates the artifact directory with restrictive permissions.
func NewArtifactStore(runDir string, limit int64) (*ArtifactStore, error) {
	dir := filepath.Join(runDir, "artifacts")
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, fmt.Errorf("create artifact directory: %w", err)
	}
	if limit <= 0 {
		limit = 100
	}
	return &ArtifactStore{dir: dir, limit: limit}, nil
}

// Dir returns the artifact directory.
func (s *ArtifactStore) Dir() string { return s.dir }

// WriteAttempt stores the request and response of one attempt.
func (s *ArtifactStore) WriteAttempt(seq int64, requestDER, responseBody []byte) error {
	// Claim the slot and test in one step: with 150 workers a check-then-act
	// would let many goroutines past the limit at once.
	if s.written.Add(1) > s.limit {
		return nil
	}

	base := filepath.Join(s.dir, fmt.Sprintf("%08d", seq))
	if err := os.WriteFile(base+".req.der", requestDER, sensitiveFilePerm); err != nil {
		return err
	}
	if len(responseBody) == 0 {
		return nil
	}
	return os.WriteFile(base+".resp.der", responseBody, sensitiveFilePerm)
}

// Warning is the text shown to the operator when artifacts are enabled.
const ArtifactWarning = "WARNING: --debug-artifacts is enabled. Raw RFC 3161 requests and responses " +
	"will be written to disk with 0600 permissions. They contain the data you submitted for " +
	"timestamping and the TSA's signatures over it. Do not share the results directory."
