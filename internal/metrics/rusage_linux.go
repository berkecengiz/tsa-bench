//go:build linux

package metrics

// On Linux ru_maxrss is reported in kilobytes.
const maxRSSUnitBytes = 1024
