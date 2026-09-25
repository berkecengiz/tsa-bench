package load

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// StageMode selects how a stage generates requests.
type StageMode string

const (
	// ModeSequential issues count requests one at a time. Used for the
	// functional validation stage, where the point is to prove the chain works
	// before any load is applied.
	ModeSequential StageMode = "sequential"
	// ModeRate issues requests at a constant arrival rate for a duration.
	ModeRate StageMode = "rate"
)

// Stage is one phase of a load profile.
type Stage struct {
	Name     string        `yaml:"name"`
	Mode     StageMode     `yaml:"mode"`
	Count    int64         `yaml:"count"`
	TPS      float64       `yaml:"tps"`
	Duration time.Duration `yaml:"duration"`
	// PauseAfter overrides load.stage_pause for this stage.
	PauseAfter *time.Duration `yaml:"pause_after"`
}

// Planned returns how many requests the stage intends to send.
func (s Stage) Planned() int64 {
	if s.Mode == ModeSequential {
		return s.Count
	}
	return int64(s.TPS * s.Duration.Seconds())
}

// Profile is an ordered set of stages plus an operational reserve.
type Profile struct {
	Name   string  `yaml:"name"`
	Note   string  `yaml:"note"`
	Stages []Stage `yaml:"stages"`
	// Reserve is quota deliberately left unsent, for error repetition and
	// operational headroom. It is documentation for the operator and is
	// cross-checked against the hard cap.
	Reserve int64 `yaml:"reserve"`
}

// TotalPlanned sums the planned requests across all stages.
func (p *Profile) TotalPlanned() int64 {
	var total int64
	for _, s := range p.Stages {
		total += s.Planned()
	}
	return total
}

// LoadProfile reads and validates a profile file.
func LoadProfile(path string) (*Profile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}
	var p Profile
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse profile: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks stage definitions and the quota arithmetic.
func (p *Profile) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("profile name must not be empty")
	}
	if len(p.Stages) == 0 {
		return fmt.Errorf("profile %s defines no stages", p.Name)
	}

	seen := map[string]bool{}
	for i, s := range p.Stages {
		if strings.TrimSpace(s.Name) == "" {
			return fmt.Errorf("stage %d has no name", i)
		}
		if seen[s.Name] {
			return fmt.Errorf("duplicate stage name %q", s.Name)
		}
		seen[s.Name] = true

		switch s.Mode {
		case ModeSequential:
			if s.Count < 1 {
				return fmt.Errorf("stage %s: sequential mode requires count >= 1", s.Name)
			}
			if s.TPS != 0 || s.Duration != 0 {
				return fmt.Errorf("stage %s: sequential mode must not set tps or duration", s.Name)
			}
		case ModeRate:
			if s.TPS <= 0 {
				return fmt.Errorf("stage %s: rate mode requires tps > 0", s.Name)
			}
			if s.Duration <= 0 {
				return fmt.Errorf("stage %s: rate mode requires a positive duration", s.Name)
			}
			if s.Count != 0 {
				return fmt.Errorf("stage %s: rate mode must not set count", s.Name)
			}
			// Planned() truncates, so a stage can pass the checks above and
			// still send nothing; it would appear in the report as a stage
			// that ran with planned_requests: 0.
			if s.Planned() < 1 {
				return fmt.Errorf("stage %s: tps %g over %s plans 0 requests; raise tps or duration",
					s.Name, s.TPS, s.Duration)
			}
		default:
			return fmt.Errorf("stage %s: mode must be %q or %q", s.Name, ModeSequential, ModeRate)
		}
	}
	if p.Reserve < 0 {
		return fmt.Errorf("reserve must not be negative")
	}
	return nil
}

// CheckAgainstQuota verifies the profile fits inside the run budget and the
// absolute hard cap. This runs before a single request is sent.
func (p *Profile) CheckAgainstQuota(maxRequests, hardCap int64) error {
	planned := p.TotalPlanned()
	if planned > maxRequests {
		return fmt.Errorf("profile %s plans %d requests but --max-requests is %d",
			p.Name, planned, maxRequests)
	}
	if planned > hardCap {
		return fmt.Errorf("profile %s plans %d requests but the hard cap is %d",
			p.Name, planned, hardCap)
	}
	if p.Reserve > 0 && planned+p.Reserve > hardCap {
		return fmt.Errorf("profile %s plans %d requests plus a reserve of %d, which exceeds the hard cap of %d",
			p.Name, planned, p.Reserve, hardCap)
	}
	return nil
}
