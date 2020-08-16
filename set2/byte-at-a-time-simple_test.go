package set2

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestDecryptByte(t *testing.T) {
	decrypted, _ := DecryptByte(4, []byte{'R', 'o', 'l', 'l'}, 16)
	fmt.Printf("Decrypted byte %q", decrypted)
}

func TestDetectBlockSize(t *testing.T) {
	fmt.Printf("Block size %d\n", DetectBlockSize())
}

func TestDecryptUnknownStringSimple(t *testing.T) {
	unknownStringB64 := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	unknownString, _ := base64.StdEncoding.DecodeString(unknownStringB64)

	// Detect block size
	blockSize := DetectBlockSize()

	decryptedBytes := make([]byte, 0)
	for i := 0; i < len(unknownString); i++ {
		decryptedByte, err := DecryptByte(i, decryptedBytes, blockSize)
		if err != nil {
			t.Errorf(err.Error())
		}
		if decryptedByte != unknownString[i] {
			t.Errorf("Expected to decrypt byte %q but decrypted %q\n", unknownString[i], decryptedByte)
		}
		decryptedBytes = append(decryptedBytes, decryptedByte)
	}
	fmt.Print(string(decryptedBytes))
}
