package set1

import (
	. "cryptopals/utils"
	"testing"
)

// TestRepeatingXOROneByte 00001111 xor 00111100 == 00110011
func TestRepeatingXOROneByte(t *testing.T) {
	plaintext := []byte{15, 15, 15}
	key := []byte{60}
	expected := []byte{51, 51, 51}
	ans := RepeatingXOR(key, plaintext)

	// Test the equality
	if !ByteArraysEqual(ans, expected) {
		t.Errorf("Key: %x xor Data: %x = %x ; Expected %x", key, plaintext, ans, expected)
	}
}

// TestRepeatingXORTwoBytes [00001111, 11110000] (key)
//          xor [00111100, 00111100, 00111100, 00111100]
//           == [00110011, 11001100, 00110011, 11001100]
func TestRepeatingXORTwoBytes(t *testing.T) {
	key := []byte{15, 240}
	plaintext := []byte{60, 60, 60, 60}
	expected := []byte{51, 204, 51, 204}
	ans := RepeatingXOR(key, plaintext)

	// Test the equality
	if !ByteArraysEqual(ans, expected) {
		t.Errorf("Key: %x xor Data: %x = %x ; Expected %x", key, plaintext, ans, expected)
	}
}

// TestRepeatingXORCryptopals test the function RepeatingXOR against the cryptopals challenge #5
func TestRepeatingXORCryptopals(t *testing.T) {
	key := "ICE"
	plaintext := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	ans := RepeatingXORString(key, plaintext)
	if ans != expected {
		t.Errorf("Received %s\nExpected %s", ans, expected)
	}
}
