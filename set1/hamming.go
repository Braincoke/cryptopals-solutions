package set1

import "math/bits"

// HammingDistance measures the minimum number of substitutions required to change one string into the other
func HammingDistance(a []byte, b []byte) (int, error) {
	dist := 0
	xorResult, err := XOR(a, b)
	if err != nil {
		return 0, err
	}
	for _, b := range xorResult {
		dist += bits.OnesCount8(b)
	}
	return dist, nil
}
