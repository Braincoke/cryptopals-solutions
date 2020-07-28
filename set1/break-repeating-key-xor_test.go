package set1

import (
	"fmt"
	"strings"
	"testing"
)

func Slices2DToString(a [][]byte) string {
	var result strings.Builder
	result.WriteRune('[')
	for _, subA := range a {
		result.WriteString(fmt.Sprintf(" {"))
		for _, e := range subA {
			result.WriteString(fmt.Sprintf("%d,", e))
		}
		result.WriteString(fmt.Sprintf("},"))
	}
	result.WriteRune(']')
	return result.String()
}

func Slices2DEqual(a [][]byte, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, subA := range a {
		if len(b[i]) != len(subA) {
			return false
		}
		for index, elementA := range subA {
			if b[i][index] != elementA {
				return false
			}
		}
	}
	return true
}

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
	if !Slices2DEqual(split, expected) {
		t.Errorf("Expected array \n%s but got \n%s", Slices2DToString(expected), Slices2DToString(split))
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
	if !Slices2DEqual(split, expected) {
		t.Errorf("Expected array \n%s but got \n%s", Slices2DToString(expected), Slices2DToString(split))
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
