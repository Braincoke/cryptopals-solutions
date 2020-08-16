package set2

import (
	aes "cryptopals/aes"
	"cryptopals/utils"
)

// DecryptECB will decrypt a ciphertext encrypted with AES in ECB mode
func DecryptECB(ciphertext []byte, key []byte, Nk int, Nr int) []byte {
	Nb := 4
	cBlocks := utils.ByteToUintSlice(ciphertext)
	keyBlock := utils.ByteToUintSlice(key)
	pBlocks := make([]uint32, len(cBlocks))
	for i := 0; i < len(cBlocks); {
		cBlock := cBlocks[i:(i + Nb)]
		pBlock := aes.DecryptBlock(cBlock, keyBlock, Nk, Nr)
		for j := 0; j < Nb; j++ {
			pBlocks[i+j] = pBlock[j]
		}
		i += Nb
	}
	return UnpadPKCS7(utils.UintToByteSlice(pBlocks))
}

// EncryptECB will encrypt a plaintext with AES in ECB mode
func EncryptECB(plaintext []byte, key []byte, Nk int, Nr int) []byte {
	Nb := 4
	blockSize := 16
	paddedPlaintext := PadPCKS7(plaintext, byte(blockSize))
	pBlocks := utils.ByteToUintSlice(paddedPlaintext)
	keyBlock := utils.ByteToUintSlice(key)
	cBlocks := make([]uint32, len(pBlocks))
	for i := 0; i < len(pBlocks); {
		pBlock := pBlocks[i:(i + Nb)]
		cBlock := aes.EncryptBlock(pBlock, keyBlock, Nk, Nr)
		for j := 0; j < Nb; j++ {
			cBlocks[i+j] = cBlock[j]
		}
		i += Nb
	}
	return utils.UintToByteSlice(cBlocks)
}
