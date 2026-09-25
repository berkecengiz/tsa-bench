//go:build !darwin && !linux

package metrics

import "time"

// processCPUTime is unavailable on this platform; resource metrics are reported
// as zero rather than guessed. This covers Windows, Plan 9, wasm and the
// unixes other than darwin and linux, where ru_maxrss has no portable unit.
func processCPUTime() time.Duration { return 0 }

func peakResidentMemoryMB() float64 { return 0 }
