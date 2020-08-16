package set2

import (
	"cryptopals/aes"
	"cryptopals/utils"
)

// EncryptCBC takes a plaintext and encrypts it with AES-128 in CBC mode
func EncryptCBC(plaintext []byte, iv []byte, key []byte, Nk int, Nr int) []byte {
	blockSize := 16
	// Pad the plaintext PKCS#7
	paddedPlaintext := PadPCKS7(plaintext, byte(blockSize))

	pBlocks := utils.ByteToUintSlice(paddedPlaintext)
	keyInts := utils.ByteToUintSlice(key)
	previousCipher := utils.ByteToUintSlice(iv)

	// Encrypt each plaintext block
	cBlocks := make([]uint32, 0)
	for i := 0; i < len(pBlocks); i += 4 {
		xor := utils.XORUint32(pBlocks[i:i+4], previousCipher)
		previousCipher = aes.EncryptBlock(xor, keyInts, Nk, Nr)
		cBlocks = append(cBlocks, previousCipher...)
	}

	return utils.UintToByteSlice(cBlocks)
}

// DecryptCBC takes a ciphertext and decrypts it with AES-128 in CBC mode
func DecryptCBC(ciphertext []byte, iv []byte, key []byte, Nk int, Nr int) []byte {
	previousCipher := utils.ByteToUintSlice(iv)
	keyInts := utils.ByteToUintSlice(key)
	cBlocks := utils.ByteToUintSlice(ciphertext)
	pBlocks := make([]uint32, 0)
	// Decrypt each ciphertext block
	for i := 0; i < len(cBlocks); i += 4 {
		decryptedBlock := aes.DecryptBlock(cBlocks[i:i+4], keyInts, Nk, Nr)
		plaintext := utils.XORUint32(previousCipher, decryptedBlock)
		pBlocks = append(pBlocks, plaintext...)
		previousCipher = cBlocks[i : i+4]
	}

	return utils.UintToByteSlice(pBlocks)
}
