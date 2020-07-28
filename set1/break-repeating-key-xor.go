package set1

import (
	b64 "encoding/base64"
	"io/ioutil"
	"strings"
)

// BreakRepeatingKeyXOR finds the most probable key for a repeating XOR encryption
func BreakRepeatingKeyXOR(cipher []byte) (mostProbableKey []byte, plaintext []byte) {
	// You have to play with the max keysize, it might be bigger than you thought
	maxKeysize := 200
	keyAnalysis := make(map[int]float32, maxKeysize-2)
	keySizes := make([]int, maxKeysize-2)
	for keysize := 2; keysize < maxKeysize; keysize++ {
		dist, _ := HammingDistance(cipher[:keysize], cipher[keysize:keysize*2])
		keyAnalysis[keysize] = float32(dist) / float32(keysize)
		keySizes[keysize-2] = keysize
	}

	// Sort key sizes according to normalized hamming distance in ascending order (insertion sort)
	for i := 0; i < (maxKeysize - 2); i++ {
		j := i
		for j > 0 && keyAnalysis[keySizes[j-1]] > keyAnalysis[keySizes[j]] {
			keySizes[j-1], keySizes[j] = keySizes[j], keySizes[j-1]
			j--
		}
	}

	// Keep only the 5 most probable key sizes (i.e. with the smallest normalized hamming distance)
	// You might need to play with this parameter as well
	probableKeySizes := keySizes[:5]

	// Cut the ciphertext to solve as many 'single-byte XOR' encryption
	// as there are bytes in the key
	var bestNormalizedScore float64 = 0
	for _, probableKeySize := range probableKeySizes {
		cipherBlocks := SplitBytesByMod(cipher, probableKeySize)
		// Solve each block as if it was a single-character XOR
		localScore := 0
		probableKey := make([]byte, probableKeySize)
		for i := 0; i < probableKeySize; i++ {
			score, repeatingKey, _ := SingleByteXorCrackFromByte(cipherBlocks[i])
			probableKey[i] = repeatingKey
			localScore += score
		}
		normalizedScore := float64(localScore) / float64(probableKeySize)
		if normalizedScore > bestNormalizedScore {
			mostProbableKey = probableKey
		}
	}

	// Decrypt the cipher with the most probable key
	plaintext = RepeatingXOR(mostProbableKey, cipher)

	return mostProbableKey, plaintext
}

// SplitBytesByMod takes an array of bytes and splits it in N arrays
// where the first array contains every byte at position i = 0 mod N,
// the second array contains every byte at position i = 1 mod N, and so on.
func SplitBytesByMod(inputBytes []byte, modulus int) (splitBytes [][]byte) {
	// Break the input bytes into N arrays
	splitBytes = make([][]byte, modulus)
	for i := 0; i < len(inputBytes); i++ {
		splitBytes[i%modulus] = append(splitBytes[i%modulus], inputBytes[i])
	}
	return splitBytes
}

// ReadBase64File reads a file containing a base64 text and returns the decoded text
func ReadBase64File(filename string) (decoded []byte, err error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return []byte{}, err
	}
	b64Text := strings.Replace(string(data), "\n", "", -1)
	decoded, err = b64.StdEncoding.DecodeString(b64Text)
	if err != nil {
		return []byte{}, err
	}
	return decoded, nil
}
