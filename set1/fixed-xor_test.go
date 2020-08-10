package set1

import (
	. "cryptopals/utils"
	"testing"
)

// TestXOROneByte 00001111 xor 00111100 == 00110011
func TestXOROneByte(t *testing.T) {
	var a = []byte{15}
	var b = []byte{60}
	var expected = []byte{51}
	ans, _ := XOR(a, b)

	// Test the equality
	if !ByteSlicesEqual(ans, expected) {
		t.Errorf("%x xor %x = %x ; Expected %x", a, b, ans, expected)
	}
}

// TestXORTwoBytes 11111111 00001111 xor 11111110 00111100 == 00000000 00110011
func TestXORTwoBytes(t *testing.T) {
	var a = []byte{255, 15}
	var b = []byte{254, 60}
	var expected = []byte{1, 51}
	ans, _ := XOR(a, b)

	// Test the equality
	if !ByteSlicesEqual(ans, expected) {
		t.Errorf("%x xor %x = %x ; Expected %x", a, b, ans, expected)
	}
}

// TestXORHexCryptopal 1c0111001f010100061a024b53535009181c xor 686974207468652062756c6c277320657965 == 746865206b696420646f6e277420706c6179
func TestXORHexCryptopal(t *testing.T) {
	var a = "1c0111001f010100061a024b53535009181c"
	var b = "686974207468652062756c6c277320657965"
	var expected = "746865206b696420646f6e277420706c6179"
	ans, _ := XORHex(a, b)

	// Test the equality
	if ans != expected {
		t.Errorf("%s xor %s = %s ; Expected %s", a, b, ans, expected)
	}
}
