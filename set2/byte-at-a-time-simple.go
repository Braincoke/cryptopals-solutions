package set2

import (
	"crypto/sha512"
	"cryptopals/utils"
	"encoding/base64"
	"errors"
	"strings"
)

type oracleFunction func([]byte) []byte

// Challenge12Oracle implements the Oracle defined in Challenge 12
func Challenge12Oracle(chosenString []byte) []byte {
	unknownStringB64 := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	unknownString, _ := base64.StdEncoding.DecodeString(unknownStringB64)
	plaintext := []byte(string(chosenString) + string(unknownString))

	// Hash a value and keep the first 16 bytes to create the key
	hash := sha512.Sum512([]byte("This string is hashed to a key"))
	key := hash[:16]

	ciphertext := EncryptECB(plaintext, key, 4, 10)
	return ciphertext
}

// DetectBlockSize finds the block size of the cipher used in the Oracle
func DetectBlockSize(oracle oracleFunction) int {
	initialCiphertext := oracle([]byte("A"))
	initialLenght := len(initialCiphertext)
	blockLength := 0
	for i := 2; i < 6000 && blockLength == 0; i++ {
		chosenString := []byte(strings.Repeat("A", i))
		ciphertext := oracle(chosenString)
		if len(ciphertext) > initialLenght {
			blockLength = len(ciphertext) - initialLenght
		}
	}
	return blockLength
}

// DecryptByte decrypts one byte of the unknown plaintext in the oracle
func DecryptByte(position int, knownBytes []byte, blockSize int) (decryptedByte byte, err error) {
	targetedBlock := position / blockSize

	// For the attack to work, every preceding byte should be known
	if len(knownBytes) != position {
		return 0, errors.New("Not enough known bytes to decrypt the current byte")
	}

	// Number of bytes used as a filler
	// = Blocksize - number of known byte on the first row of the plaintext
	fillerLength := blockSize - (position + 1 - blockSize*targetedBlock)
	// Choose a string that will generate a ciphertext block with only one unknown byte
	// Example : if position = 35 (looking for s35) then the plaintext should be
	// BLOCK 0 => A   A   A   ... s0  s1  s2   s3
	// BLOCK 1 => s4  s5  s6  ... s16 s17 s18  s19
	// BLOCK 2 => s20 s21 s22 ... s32 s33 s34 [s35]
	chosenString := []byte(strings.Repeat("A", fillerLength))
	ciphertext := Challenge12Oracle(chosenString)

	// Block that will be brute forced
	cipherBlock := ciphertext[targetedBlock*blockSize : (targetedBlock+1)*blockSize]

	// Craft our guess plaintext
	// Example if position = 35
	// GUESS => s20 s21 s22 ... s32 s33 s34 [s35]
	guess := make([]byte, blockSize)
	k := blockSize - 2
	for i := position - 1; i >= 0 && k >= 0; i-- {
		guess[k] = knownBytes[i]
		k--
	}
	for k >= 0 {
		guess[k] = 'A'
		k--
	}

	// Brute force the byte
	found := false
	for i := 0; i < 255 && !found; i++ {
		guess[blockSize-1] = byte(i)
		c := Challenge12Oracle(guess)
		guessCipherBlock := c[:blockSize]
		if utils.ByteSlicesEqual(guessCipherBlock, cipherBlock) {
			found = true
			decryptedByte = byte(i)
		}
	}
	return decryptedByte, nil
}
