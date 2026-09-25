// Package metrics collects latency and throughput statistics.
//
// Latencies are recorded into a fixed-size HDR-style histogram rather than a
// slice of samples. A 5-minute run at 150 TPS produces 45,000 samples, and
// keeping every one would still be feasible — but the tool must stay honest at
// higher rates and longer runs, so memory is bounded by construction.
package metrics

import (
	"math"
	"math/bits"
	"sync/atomic"
	"time"
)

// significantFigures fixes the histogram's relative precision. Three
// significant figures means every recorded value is stored in a bucket whose
// width is at most 1/2048 of the value, i.e. a worst-case relative error of
// about 0.05% — well inside the 1% documented in the report.
const significantFigures = 3

// maxTrackable is one hour. Anything slower is clamped and counted, so a
// pathological outlier cannot silently vanish from the maximum.
const maxTrackable = int64(time.Hour)

// Histogram is a lock-free HDR-style histogram of int64 values (nanoseconds).
//
// Recording uses atomic adds, so many workers can record concurrently without
// serialising on a mutex. Snapshots are taken without stopping recording; a
// snapshot is therefore a consistent-enough view rather than a strict
// point-in-time one, which is the right trade-off for a load generator.
type Histogram struct {
	counts []int64

	subBucketCount          int32
	subBucketHalfCount      int32
	subBucketHalfCountMagni uint32
	subBucketMask           int64
	leadingZeroCountBase    uint32

	total    atomic.Int64
	sum      atomic.Int64
	min      atomic.Int64
	max      atomic.Int64
	overflow atomic.Int64
}

// NewHistogram returns a histogram covering [1, one hour] in nanoseconds.
func NewHistogram() *Histogram {
	subBucketCountMagnitude := uint32(math.Ceil(math.Log2(2 * math.Pow10(significantFigures))))
	subBucketCount := int32(1) << subBucketCountMagnitude
	subBucketHalfCount := subBucketCount / 2

	// Number of buckets needed to reach maxTrackable, each covering twice the
	// range of the previous one.
	bucketCount := int32(1)
	smallestUntrackable := int64(subBucketCount)
	for smallestUntrackable < maxTrackable {
		smallestUntrackable <<= 1
		bucketCount++
	}

	h := &Histogram{
		counts:                  make([]int64, (bucketCount+1)*subBucketHalfCount),
		subBucketCount:          subBucketCount,
		subBucketHalfCount:      subBucketHalfCount,
		subBucketHalfCountMagni: subBucketCountMagnitude - 1,
		subBucketMask:           int64(subBucketCount) - 1,
		leadingZeroCountBase:    64 - subBucketCountMagnitude,
	}
	h.min.Store(math.MaxInt64)
	return h
}

// RecordDuration records a latency sample.
func (h *Histogram) RecordDuration(d time.Duration) { h.Record(int64(d)) }

// Record adds a single value. Negative values are treated as zero; values above
// the trackable range are clamped and counted separately.
func (h *Histogram) Record(v int64) {
	if v < 0 {
		v = 0
	}
	if v > maxTrackable {
		h.overflow.Add(1)
		v = maxTrackable
	}

	idx := h.countsIndex(v)
	atomic.AddInt64(&h.counts[idx], 1)
	h.total.Add(1)
	h.sum.Add(v)

	for {
		cur := h.min.Load()
		if v >= cur || h.min.CompareAndSwap(cur, v) {
			break
		}
	}
	for {
		cur := h.max.Load()
		if v <= cur || h.max.CompareAndSwap(cur, v) {
			break
		}
	}
}

// Count returns the number of recorded samples.
func (h *Histogram) Count() int64 { return h.total.Load() }

// Overflows returns how many samples exceeded the trackable range.
func (h *Histogram) Overflows() int64 { return h.overflow.Load() }

func (h *Histogram) countsIndex(v int64) int32 {
	bucketIdx := h.bucketIndex(v)
	subBucketIdx := int32(v >> uint32(bucketIdx))
	// The first half of bucket 0 is addressed directly; every later bucket
	// contributes only its upper half, which is what makes the layout compact.
	return ((bucketIdx + 1) << h.subBucketHalfCountMagni) + subBucketIdx - h.subBucketHalfCount
}

func (h *Histogram) bucketIndex(v int64) int32 {
	return int32(h.leadingZeroCountBase) - int32(bits.LeadingZeros64(uint64(v|h.subBucketMask)))
}

// valueAt returns the lowest value stored at a counts index.
func (h *Histogram) valueAt(idx int32) int64 {
	bucketIdx := (idx >> h.subBucketHalfCountMagni) - 1
	subBucketIdx := (idx & (h.subBucketHalfCount - 1)) + h.subBucketHalfCount
	if bucketIdx < 0 {
		subBucketIdx -= h.subBucketHalfCount
		bucketIdx = 0
	}
	return int64(subBucketIdx) << uint32(bucketIdx)
}

// highestEquivalent returns the largest value that shares a bucket with idx, so
// a reported percentile is never lower than a value that was actually observed.
func (h *Histogram) highestEquivalent(idx int32) int64 {
	bucketIdx := (idx >> h.subBucketHalfCountMagni) - 1
	if bucketIdx < 0 {
		bucketIdx = 0
	}
	return h.valueAt(idx) + (int64(1) << uint32(bucketIdx)) - 1
}

// Snapshot is an immutable summary of a histogram.
type Snapshot struct {
	Count     int64         `json:"count"`
	Min       time.Duration `json:"min_ns"`
	Mean      time.Duration `json:"mean_ns"`
	P50       time.Duration `json:"p50_ns"`
	P90       time.Duration `json:"p90_ns"`
	P95       time.Duration `json:"p95_ns"`
	P99       time.Duration `json:"p99_ns"`
	Max       time.Duration `json:"max_ns"`
	Overflows int64         `json:"overflows"`
}

// Snapshot computes the summary statistics in a single pass over the buckets.
func (h *Histogram) Snapshot() Snapshot {
	total := h.total.Load()
	s := Snapshot{Count: total, Overflows: h.overflow.Load()}
	if total == 0 {
		return s
	}

	s.Min = time.Duration(h.min.Load())
	s.Max = time.Duration(h.max.Load())
	s.Mean = time.Duration(h.sum.Load() / total)

	targets := []struct {
		q   float64
		out *time.Duration
	}{
		{0.50, &s.P50},
		{0.90, &s.P90},
		{0.95, &s.P95},
		{0.99, &s.P99},
	}

	next := 0
	var cumulative int64
	for idx := range h.counts {
		c := atomic.LoadInt64(&h.counts[idx])
		if c == 0 {
			continue
		}
		cumulative += c
		for next < len(targets) &&
			float64(cumulative) >= targets[next].q*float64(total) {
			*targets[next].out = time.Duration(h.highestEquivalent(int32(idx)))
			next++
		}
		if next == len(targets) {
			break
		}
	}
	// Guard against rounding leaving a tail percentile unset.
	for ; next < len(targets); next++ {
		*targets[next].out = s.Max
	}
	return s
}
