package set1

import (
	"encoding/hex"
	"errors"
)

/**
 * Cryptopal Set 1
 * Challenge 2 - Fixed XOR
 * https://cryptopals.com/sets/1/challenges/2
 */

// XOR returns the xor of two equal lengths buffers a and b
func XOR(a []byte, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return []byte{}, errors.New("Buffers are not equal length")
	}
	xor := make([]byte, len(a))

	for i := 0; i < len(a); i++ {
		xor[i] = a[i] ^ b[i]
	}
	return xor, nil
}

// XORHex returns the xor of two hex strings
func XORHex(a string, b string) (string, error) {
	bytesA, _ := hex.DecodeString(a)
	bytesB, _ := hex.DecodeString(b)
	bytesXor, error := XOR(bytesA, bytesB)
	if error != nil {
		return "", error
	}
	return hex.EncodeToString(bytesXor), error
}
