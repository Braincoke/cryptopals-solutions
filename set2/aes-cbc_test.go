package set2

import (
	"cryptopals/aes"
	"cryptopals/set1"
	. "cryptopals/utils"
	"fmt"
	"testing"
)

func TestCBCEncryptionOneBlock(t *testing.T) {
	// We craft a plaintext so that after the padding
	// it is equal to sixteen 0x01 bytes
	plaintext := []byte{
		0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01}

	// We craft the IV so that iv^plaintext = 0x00
	// This is just to facilitate the mental verifications
	iv := []byte{
		0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01}

	// The key is 0x00
	Nk := 4
	Nr := 10
	key := make([]byte, 16)
	fmt.Printf("Key = %x\n", key)

	// Since there is only one block p1, the ciphertext c1 is easy to compute
	// c1 = AES(iv^p1)
	xor, _ := set1.XOR(PadPCKS7(plaintext, 16), iv)
	c1 := aes.EncryptBlock(ByteToUintSlice(xor), ByteToUintSlice(key), Nk, Nr)
	expectedCiphertext := UintToByteSlice(c1)
	fmt.Printf("Ciphertext = %x\n", expectedCiphertext)
	// Test encryption
	ciphertext := EncryptCBC(plaintext, iv, key, Nk, Nr)
	if !ByteSlicesEqual(ciphertext, expectedCiphertext) {
		t.Errorf("Expected \n%q\n but got\n%q\n", expectedCiphertext, ciphertext)
	}
}

func TestCBCModeDecryptionOneBlock(t *testing.T) {
	// Plaintext was crafted so that after the padding
	// it is equal to sixteen 0x01 bytes
	expectedPlaintext := []byte{
		0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01}

	// We craft the IV so that iv^plaintext = 0x00
	// This is just to facilitate the mental verifications
	iv := []byte{
		0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01}

	// The key is 0x00
	Nk := 4
	Nr := 10
	key := make([]byte, 16)
	fmt.Printf("Key = %x\n", key)

	// AES(iv^plaintext)
	ciphertext := []byte{
		0x66, 0xe9, 0x4b, 0xd4,
		0xef, 0x8a, 0x2c, 0x3b,
		0x88, 0x4c, 0xfa, 0x59,
		0xca, 0x34, 0x2b, 0x2e,
	}

	// Manual decryption
	c := ByteToUintSlice(ciphertext)
	k := ByteToUintSlice(key)
	d1 := aes.DecryptBlock(c, k, Nk, Nr)
	p1, _ := set1.XOR(UintToByteSlice(d1), iv)
	// Test
	plaintext := DecryptCBC(ciphertext, iv, key, Nk, Nr)

	if !ByteSlicesEqual(p1, plaintext) {
		t.Errorf("From manual decryption, expected \n%q\n but got\n%q\n", p1, plaintext)
	}
	if !ByteSlicesEqual(expectedPlaintext, plaintext) {
		t.Errorf("Expected \n%x\n but got\n%x\n", expectedPlaintext, plaintext)
	}
}

func TestCBCMode(t *testing.T) {
	// Ciphertext 66e94bd4ef8a2c3b884cfa59ca342b2e
	Nk := 4
	Nr := 10
	key := make([]byte, 16)

	plaintext := []byte{
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C,
		0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14,
		0x15, 0x16, 0x17, 0x18,
		0x19, 0x1A, 0x1B, 0x1C,
		0x1D}
	iv := []byte{
		0xA5, 0xB6, 0xC7, 0xD8,
		0xA5, 0xA6, 0xA7, 0xA8,
		0xA9, 0xBA, 0xCB, 0xDC,
		0xAB, 0xAC, 0xAC, 0xBB}
	expected := []byte{
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C,
		0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14,
		0x15, 0x16, 0x17, 0x18,
		0x19, 0x1A, 0x1B, 0x1C,
		0x1D, 0x03, 0x03, 0x03}

	// Encrypt
	ciphertext := EncryptCBC(plaintext, iv, key, Nk, Nr)

	// Decrypt
	decrypted := DecryptCBC(ciphertext, iv, key, Nk, Nr)

	if !ByteSlicesEqual(expected, decrypted) {
		t.Errorf("Expected %q but got %q", expected, decrypted)
	}
}

func TestCBCCryptopals(t *testing.T) {
	Nk := 4
	Nr := 10
	iv := make([]byte, 16)
	key := []byte("YELLOW SUBMARINE")

	ciphertext, _ := set1.ReadBase64File("./challenge10-data.txt")
	plaintext := DecryptCBC(ciphertext, iv, key, Nk, Nr)
	fmt.Print(string(plaintext))
}
