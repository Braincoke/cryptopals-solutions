package set2

import (
	"crypto/sha512"
	"cryptopals/utils"
	"encoding/base64"
	"errors"
	"strings"
)

// Challenge14Oracle implements the Oracle defined in Challenge 14
func Challenge14Oracle(chosenString []byte) []byte {
	randomPrefix := "0f6WF0BdpEAAm8Y1U"
	unknownStringB64 := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	unknownString, _ := base64.StdEncoding.DecodeString(unknownStringB64)
	plaintext := []byte(randomPrefix + string(chosenString) + string(unknownString))

	// Hash a value and keep the first 16 bytes to create the key
	hash := sha512.Sum512([]byte("This string is hashed to a key"))
	key := hash[:16]

	ciphertext := EncryptECB(plaintext, key, 4, 10)
	return ciphertext
}

// CountCommonBlockSequence finds the number of sequential blocks two cipher have in common
// It only counts blocks in common from the beginning of the cipher and stops
// counting as soon as a difference is found
func CountCommonBlockSequence(cipher1 []byte, cipher2 []byte, blockSize int) int {
	i := 0 // number of sequential bytes in common
	minSize := utils.MinInt(len(cipher1), len(cipher2))
	for cipher1[i] == cipher2[i] && i < minSize {
		i++
	}
	return i / blockSize
}

// DetectPrefixLength14 finds the length of the prefix in the Challenge 14 Oracle
// This function is based on DetectPrefixLength14Iteration but is more robust to
// limit cases
func DetectPrefixLength14(blockSize int, oracle oracleFunction) int {
	l1 := DetectPrefixLength14Iteration(blockSize, oracle, 'A')
	l2 := DetectPrefixLength14Iteration(blockSize, oracle, 'B')
	return utils.MinInt(l1, l2)
}

// DetectPrefixLength14Iteration finds the length of the prefix in the Challenge 14 Oracle
func DetectPrefixLength14Iteration(blockSize int, oracle oracleFunction, testRune rune) int {
	/* We vary the input we control to generate multiple ciphers
	 * o = prefix byte
	 * x = input byte
	 * t = target byte
	 * P = padding byte
	 *
	 *        One block
	 *        --^--
	 * i = 4  |ooox|xxxt|tttt|PPPP|  <-- cipher
	 * i = 3  |ooox|xxtt|tttP|
	 * i = 2  |ooox|xttt|ttPP|
	 * i = 1  |ooox|tttt|tPPP|
	 * i = 0  |ooot|tttt|PPPP|
	 *
	 * We count how many blocks the new cipher has in common
	 * with the previous one to find and keep the max value found
	 */

	i := blockSize // iteration counter starting at the block size
	common := 0    // number of sequential blocks in common
	ncommon := 0   // newly computed number of sequential blocks in common
	payload := strings.Repeat(string(testRune), i)
	pc := oracle([]byte(payload)) // previous cipher
	var nc []byte                 // new cipher
	for i > 0 && ncommon >= common {
		i--
		payload = strings.Repeat(string(testRune), i)
		nc = oracle([]byte(payload))
		ncommon = CountCommonBlockSequence(pc, nc, blockSize)
		if common == 0 {
			common = ncommon
		}
		pc = nc
	}
	// Usually the index is decreased one step further than necessary
	offset := i + 1
	// When the prefix length is a multiple of the block size
	// we will stop at i = 0 and not because ncommon < common
	// in that cas we stopped on the right index
	if ncommon == common {
		offset = i
	}
	return blockSize*common - offset
}

// DecryptByte14 decrypts one byte of the unknown plaintext in the oracle of challenge 14
func DecryptByte14(prefixLength int, position int, knownBytes []byte, blockSize int, oracle oracleFunction) (decryptedByte byte, err error) {
	/* Number of payload bytes to add to isolate the prefix in its own blocks
	 * (P = prefix byte; A = payload byte; sXX = target byte XX)
	 * Initially we may have
	 * BLOCK 0 => P   P   P   ...   P   P   P
	 * BLOCK 1 => P   P   s0  ...   s11 s12 s13
	 *
	 * We want to insert payload bytes to get something like
	 * BLOCK 0 => P   P   P   ...   P   P   P
	 * BLOCK 1 => P   P   A   ...   A   A   A  <= number of A == prefixFillerLength
	 * BLOCK 2 => s0  s1  s2  ...   s13 s14 s15
	 *
	 */
	prefixFillerLength := blockSize - (prefixLength % blockSize)
	// Number of blocks rendered "useless" because of the prefix
	blockOffset := (prefixLength + prefixFillerLength) / blockSize

	/* Considering the prefix isolated, which block are we targeting ?
	 * Example if position == 18
	 * BLOCK 0 => P   P   P   ...   P   P   P
	 * BLOCK 1 => P   P   A   ...   A   A   A
	 * BLOCK 2 => s0  s1  s2  ...   s13 s14 s15
	 * BLOCK 3 => s16 s17 s18  ...  s29 s30 s31
	 * We are targeting block 3
	 */
	targetedBlock := (position + prefixLength + prefixFillerLength) / blockSize

	// For the attack to work, every preceding byte should be known
	if len(knownBytes) != position {
		return 0, errors.New("Not enough known bytes to decrypt the current byte")
	}
	/* Choose a string that will generate a ciphertext block with only one unknown byte
	 * Example : if position = 0 (looking for s0) then the plaintext should be
	 * BLOCK 0 => P   P   P   ... P   P   P   P
	 * BLOCK 1 => P   P   A   ... A   A   A   A
	 * BLOCK 2 => A   A   A   ... A   A   A  [s0]
	 * Example : if position = 35 (looking for s35) then the plaintext should be
	 * BLOCK 0 => P   P   P   ... P   P   P   P
	 * BLOCK 1 => P   P   A   ... A   A   A   A
	 * BLOCK 2 => A   A   A   ... s0  s1  s2   s3
	 * BLOCK 3 => s4  s5  s6  ... s16 s17 s18  s19
	 * BLOCK 4 => s20 s21 s22 ... s32 s33 s34 [s35]
	 *
	 * This gives us the size of the payload
	 * in other words : number of bytes used as a filler
	 * = fill the prefix + (Blocksize - number of known byte on the first row of the plaintext)
	 */
	fillerLength := prefixFillerLength + blockSize - (position + 1 - blockSize*(targetedBlock-blockOffset))
	chosenString := strings.Repeat("A", fillerLength)
	ciphertext := oracle([]byte(chosenString))

	// Block that will be brute forced
	cipherBlock := ciphertext[targetedBlock*blockSize : (targetedBlock+1)*blockSize]

	/* Remember that this oracle adds a prefix
	* so we need to craft a payload to retrieve
	* the proper ciphertext corresponding to our
	* current guess.
	*
	* Example if position = 35
	* GUESS   => s20 s21 s22 ... s32 s33 s34 [s35]
	* PAYLOAD => A   A   A   ... s20 s21 s22 s24
	*         =>             ... s34
	*
	 */
	payload := make([]byte, blockSize+prefixFillerLength)
	// Fill the payload to isolate the prefix in the oracle
	// Payload => A A A ... <to be defined>
	for i := 0; i < prefixFillerLength; i++ {
		payload[i] = 'A'
	}
	// Then fill the payload with the known bytes
	// Example if position = 35
	// Payload => A A ... A A <to be defined> s0 s1 ... s33 s34
	//           |-----v-----|
	//           Filler len
	// Example if position = 0
	// Payload => A A ... A A <to be defined>
	k := len(payload) - 2 // we start by filling the penultimate byte and work our way down
	for i := position - 1; i >= 0 && k >= 0; i-- {
		payload[k] = knownBytes[i]
		k--
	}
	// Now we fill the rest of the payload with other filler runes
	for k >= 0 {
		payload[k] = 'A'
		k--
	}

	// Brute force the last byte
	found := false
	blockStart := prefixLength + prefixFillerLength
	blockEnd := blockStart + blockSize
	for i := 0; i < 255 && !found; i++ {
		payload[len(payload)-1] = byte(i)
		c := oracle(payload)
		guessCipherBlock := c[blockStart:blockEnd]
		if utils.ByteSlicesEqual(guessCipherBlock, cipherBlock) {
			found = true
			decryptedByte = byte(i)
		}
	}
	return decryptedByte, nil
}
