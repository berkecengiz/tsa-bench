//go:build darwin

package metrics

// On Darwin ru_maxrss is reported in bytes.
const maxRSSUnitBytes = 1
