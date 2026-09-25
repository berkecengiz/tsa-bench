//go:build !race

package load_test

// raceEnabled reports whether the race detector is active. The detector adds
// substantial synchronisation overhead, so a capacity threshold that is
// meaningful in a normal build would be measuring the detector instead.
const raceEnabled = false
