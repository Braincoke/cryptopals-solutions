package set1

import (
	"encoding/hex"
)

/**
 * Cryptopal Set 1
 * Challenge 3 - Single Byte Xor Cipher
 * https://cryptopals.com/sets/1/challenges/3
 */

// SingleByteXorCrack tries to decrypt a cipher xor'd against a single character
func SingleByteXorCrack(s string) (int, string) {

	cipher, _ := hex.DecodeString(s)
	bestScore := -1
	var probablePlaintext []byte

	// Brute force the key
	var i byte
	for i = 0; i < 255; i++ {
		// Create the key [k, k, k, ..., k]
		key := make([]byte, len(cipher))
		for j := 0; j < len(cipher); j++ {
			key[j] = i
		}
		// cipher XOR key = plaintext
		plaintext, _ := XOR(key, cipher)
		frequencyAnalysis, _ := FrequencyAnalysis(plaintext)
		score := scoreFrequencyAnalysis(frequencyAnalysis)
		if score > bestScore {
			bestScore = score
			probablePlaintext = plaintext
		}

	}
	return bestScore, string(probablePlaintext)
}

// IndexOf find the index of a byte in a byte array
func IndexOf(arr []byte, candidate byte) int {
	for index, c := range arr {
		if c == candidate {
			return index
		}
	}
	return -1
}

func scoreFrequencyAnalysis(frequencies map[byte]float32) int {
	// https://en.wikipedia.org/wiki/Letter_frequency
	// englishFrequency := map[byte]float32{
	// 	' ': 0.13,
	// 	'e': 0.12702, 't': 0.9056, 'a': 0.8167, 'o': 0.7507,
	// 	'i': 0.6966, 'n': 0.6749, 's': 0.6327, 'h': 0.6094,
	// 	'r': 0.5987, 'd': 0.4253, 'l': 0.4025, 'c': 0.2782,
	// 	'u': 0.2758, 'm': 0.2406, 'w': 0.2360, 'f': 0.2228,
	// 	'g': 0.2015, 'y': 0.1974, 'p': 0.1929, 'b': 0.1492,
	// 	'v': 0.0978, 'k': 0.0772, 'j': 0.0153, 'x': 0.0150,
	// 	'q': 0.0095, 'z': 0.0074,
	// }
	// https://www.mdickens.me/typing/letter_frequency.html
	characterOrder := []byte{
		' ', 'e', 't', 'a', 'o', 'i', 'n', 's', 'h', 'r', 'd', 'l',
		'c', 'u', 'm', 'w', 'f', 'g', 'y', 'p', 'b', 'v', 'k', 'j',
		'x', 'q', 'z',
	}

	// To score the frequency analysis against the english frequency
	// we determine how close we are to the expected order of characters
	score := 0
	for char, freq := range frequencies {
		index := IndexOf(characterOrder, char)
		if index != -1 {
			// Check the expected relative frequency to other characters
			for j := 0; j < index; j++ {
				otherChar := characterOrder[j]
				if freq < frequencies[otherChar] {
					score++
				}
			}
			for j := index; j < len(characterOrder); j++ {
				otherChar := characterOrder[j]
				if freq > frequencies[otherChar] {
					score++
				}
			}
		}
	}

	return score
}

// FrequencyAnalysis performs a frequency analysis of each byte in an array
func FrequencyAnalysis(bytes []byte) (map[byte]float32, []byte) {
	length := len(bytes)

	// Count the occurence of each byte
	counter := make(map[byte]int)
	for i := 0; i < len(bytes); i++ {
		counter[bytes[i]]++
	}

	// Get bytes used in the array
	j := 0
	keys := make([]byte, len(counter))
	for k := range counter {
		keys[j] = k
		j++
	}

	// Compute frequency
	freq := make(map[byte]float32, len(keys))
	for i := 0; i < len(keys); i++ {
		freq[keys[i]] = float32(counter[keys[i]]) / float32(length)
	}

	// Sort keys according to frequencies in descending order (insertion sort)
	for i := 0; i < len(keys); i++ {
		j := i
		for j > 0 && freq[keys[j-1]] < freq[keys[j]] {
			keys[j-1], keys[j] = keys[j], keys[j-1]
			j--
		}
	}

	return freq, keys
}
