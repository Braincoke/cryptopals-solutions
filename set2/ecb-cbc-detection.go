package set2

import (
	"crypto/rand"
	"math/big"
)

// GenerateRandomKey generates a new random key of 16 bytes
func GenerateRandomKey() []byte {
	return GenerateRandomBytes(16)
}

// GenerateRandomBytes generates new random bytes
func GenerateRandomBytes(byteCount int) []byte {
	bytes := make([]byte, byteCount)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}
	return bytes
}

// EncryptData generates a random key and encrypts the data with it
func EncryptData(plaintext []byte) ([]byte, string) {
	Nk := 4
	Nr := 10
	key := GenerateRandomKey()
	prefixCount, _ := rand.Int(rand.Reader, big.NewInt(6))
	suffixCount, _ := rand.Int(rand.Reader, big.NewInt(6))
	prefix := GenerateRandomBytes(int(prefixCount.Uint64()) + 5)
	suffix := GenerateRandomBytes(int(suffixCount.Uint64()) + 5)
	data := append(prefix, plaintext...)
	data = append(data, suffix...)

	randBit, _ := rand.Int(rand.Reader, big.NewInt(2))
	ecbEncryption := randBit.Uint64() == 0
	if ecbEncryption {
		return EncryptECB(data, key, Nk, Nr), "ECB"
	}
	// Else CBC encryption
	iv := GenerateRandomBytes(16)
	return EncryptCBC(data, iv, key, Nk, Nr), "CBC"
}
