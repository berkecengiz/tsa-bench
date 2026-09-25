// maxRSSUnitBytes is defined only for darwin and linux, so this file is
// constrained to the same pair; other unixes fall back to rusage_other.go.
//go:build darwin || linux

package metrics

import (
	"syscall"
	"time"
)

// processCPUTime returns total CPU time consumed by this process.
func processCPUTime() time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	return timevalToDuration(ru.Utime) + timevalToDuration(ru.Stime)
}

func timevalToDuration(tv syscall.Timeval) time.Duration {
	return time.Duration(tv.Sec)*time.Second + time.Duration(tv.Usec)*time.Microsecond
}

// peakResidentMemoryMB returns the process peak resident set size in MiB.
//
// This is ru_maxrss, a high-water mark: the value never decreases, so it shows
// how much memory the client has needed but not how much it holds right now.
// There is no portable point-in-time RSS across the supported platforms, and a
// series that meant different things per OS would be worse than one that is
// consistently a peak.
//
// ru_maxrss is bytes on Darwin and kilobytes on Linux; the conversion is
// selected at build time.
func peakResidentMemoryMB() float64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	return float64(ru.Maxrss) * maxRSSUnitBytes / (1 << 20)
}
