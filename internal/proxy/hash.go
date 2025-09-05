package proxy

// jumpHash implements Jump Consistent Hash as described by Lamping and Veach.
// Input: 64-bit key hash and number of buckets. Output: bucket index in [0, numBuckets).
func jumpHash(key uint64, numBuckets int) int {
	if numBuckets <= 0 {
		return 0
	}
	var b int64 = -1
	var j int64 = 0
	for j < int64(numBuckets) {
		b = j
		key = key*2862933555777941757 + 1
		j = int64(float64(b+1) * (float64(1<<31) / float64((key>>33)+1)))
	}
	return int(b)
}
