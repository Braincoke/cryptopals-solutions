package set1

import "encoding/hex"

/**
 * Cryptopal Set 1
 * Challenge 5 - Repeating key XOR
 * https://cryptopals.com/sets/1/challenges/5
 */

// RepeatingXOR encrypts a plaintext by xoring it to a key repeated as much as necessary
func RepeatingXOR(key []byte, plaintext []byte) []byte {
	keyLength := len(key)
	repeatedKey := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		repeatedKey[i] = key[i%keyLength]
	}
	cipher, _ := XOR(plaintext, repeatedKey)
	return cipher
}

// RepeatingXORString encrypts a plaintext by xoring it to a key repeated as much as necessary
func RepeatingXORString(key string, plaintext string) string {
	return hex.EncodeToString(RepeatingXOR([]byte(key), []byte(plaintext)))
}
