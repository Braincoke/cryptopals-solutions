package set1

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func mapToString(a map[byte]float32) string {
	var result strings.Builder
	result.WriteRune('[')
	for k, v := range a {
		result.WriteString(fmt.Sprintf("(%x : %f), ", k, v))
	}
	result.WriteRune(']')
	return result.String()
}

func mapsEqual(a map[byte]float32, b map[byte]float32) bool {
	if len(a) != len(b) {
		return false
	}
	// Get keys
	j := 0
	keys := make([]byte, len(a))
	for k := range a {
		keys[j] = k
		j++
	}
	// Test the equality
	equal := true
	for i := 0; i < len(keys); i++ {
		if a[keys[i]] != b[keys[i]] {
			equal = false
		}
	}
	return equal
}

// TestFrequencyAnalysis "aavveeee"
func TestFrequencyAnalysis(t *testing.T) {
	hexString := "6161767665656565"
	bytes, _ := hex.DecodeString(hexString)
	var expected = map[byte]float32{
		97:  0.25, //a
		118: 0.25, //v
		101: 0.5,  //e
	}
	freq, keys := FrequencyAnalysis(bytes)

	// Test the equality
	if !mapsEqual(freq, expected) {
		t.Errorf("Frequency analysis of %s - received %s ; Expected %s", hexString, mapToString(freq), mapToString(expected))
	}
	expectedKeys := []byte{101, 97, 118}
	for i := 0; i < len(keys); i++ {
		if keys[i] != expectedKeys[i] {
			t.Errorf("Expected keys to be %s but found %s", expectedKeys, keys)
		}
	}
}
