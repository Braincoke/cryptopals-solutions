package set2

import (
	"crypto/sha512"
	"strings"
)

// Challenge16EncryptionOracle implements the oracle in challenge 16
func Challenge16EncryptionOracle(input []byte) (ciphertext []byte, iv []byte) {
	prefix := "comment1=cooking%20MCs;userdata="
	suffix := ";comment2=%20like%20a%20pound%20of%20bacon"
	// Sanitize input
	sanitizedInput := strings.ReplaceAll(string(input), ";", "_")
	sanitizedInput = strings.ReplaceAll(string(input), "=", "_")
	plaintext := []byte(prefix + sanitizedInput + suffix)

	// Hash a value and keep the first 16 bytes to create the key
	hash := sha512.Sum512([]byte("This string is hashed to a key"))
	key := hash[:16]

	// Generate a random iv
	iv = GenerateRandomBytes(16)
	ciphertext = EncryptCBC(plaintext, iv, key, 4, 10)
	return ciphertext, iv
}

// Challenge16IsAdmin implements the decryption oracle in challenge 16
func Challenge16IsAdmin(ciphertext []byte, iv []byte) bool {
	// Decryption
	hash := sha512.Sum512([]byte("This string is hashed to a key"))
	key := hash[:16]
	plaintext := DecryptCBC(ciphertext, iv, key, 4, 10)
	// Look for the admin configuration string
	return strings.Contains(string(plaintext), ";admin=true;")
}
