package set1

import (
	. "cryptopals/utils"
	"encoding/hex"
	"testing"
)

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
	if !MapsEqual(freq, expected) {
		t.Errorf("Frequency analysis of %s - received %s ; Expected %s", hexString, MapToString(freq), MapToString(expected))
	}
	expectedKeys := []byte{101, 97, 118}
	for i := 0; i < len(keys); i++ {
		if keys[i] != expectedKeys[i] {
			t.Errorf("Expected keys to be %s but found %s", expectedKeys, keys)
		}
	}
}
