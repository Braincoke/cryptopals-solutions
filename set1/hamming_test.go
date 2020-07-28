package set1

import "testing"

// TestHammingDistance test the function HammingDistance against the cryptopals challenge #6
func TestHammingDistance(t *testing.T) {
	a := "this is a test"
	b := "wokka wokka!!!"
	distance, err := HammingDistance([]byte(a), []byte(b))
	if err != nil {
		t.Errorf(err.Error())
	}
	expected := 37
	if distance != expected {
		t.Errorf("Received %d\nExpected %d", distance, expected)
	}
}
