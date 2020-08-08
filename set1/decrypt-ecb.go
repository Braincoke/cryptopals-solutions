package set1

import aes "cryptopals/aes"

// ECBDecrypt will decrypt a ciphertext encrypted with AES in ECB mode
func ECBDecrypt(ciphertext []uint32, key []uint32, Nk int, Nr int) []uint32 {
	Nb := 4
	nbBlocks := len(ciphertext) / Nb
	plaintext := make([]uint32, len(ciphertext))
	for i := 0; i < nbBlocks; {
		cipherBlock := ciphertext[i:(i + Nb)]
		i += 4
		plaintextBlock := aes.DecryptBlock(cipherBlock, key, Nk, Nr)
		for j := 0; j < Nb; j++ {
			plaintext[i+j] = plaintextBlock[j]
		}
	}
	return plaintext
}
