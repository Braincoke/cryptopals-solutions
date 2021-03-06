package set1

import (
	. "cryptopals/utils"
	"strings"
	"testing"
)

// TestReadB64File reads a base64 file and decodes it
func TestReadB64File(t *testing.T) {
	filename := "challenge6-data.txt"
	data, _ := ReadBase64File(filename)
	if data[0] != 29 && len(data) != 2924 {
		t.Error("Error reading base64 file")
	}
}

func TestSplitBytesSimple(t *testing.T) {
	inputBytes := []byte{10, 20, 30, 11, 21, 31, 12, 22, 32, 13, 23, 33}
	split := SplitBytesByMod(inputBytes, 3)
	expected := [][]byte{
		{10, 11, 12, 13},
		{20, 21, 22, 23},
		{30, 31, 32, 33},
	}
	if !ByteMatrixEqual(split, expected) {
		t.Errorf("Expected array \n%s but got \n%s", ByteMatrixToString(expected), ByteMatrixToString(split))
	}
}

func TestSplitBytesUnbanlaced(t *testing.T) {
	inputBytes := []byte{10, 20, 30, 11, 21, 31, 12, 22, 32, 13}
	split := SplitBytesByMod(inputBytes, 3)
	expected := [][]byte{
		{10, 11, 12, 13},
		{20, 21, 22},
		{30, 31, 32},
	}
	if !ByteMatrixEqual(split, expected) {
		t.Errorf("Expected array \n%s but got \n%s", ByteMatrixToString(expected), ByteMatrixToString(split))
	}
}

// TestBreakRepeatingKeyXOR solves the cryptopal challenge #6
func TestBreakRepeatingKeyXOR(t *testing.T) {
	filename := "challenge6-data.txt"
	data, _ := ReadBase64File(filename)
	_, plaintext := BreakRepeatingKeyXOR(data)
	if !strings.Contains(string(plaintext), "funky") {
		t.Error("Decryption failed")
	}
}
