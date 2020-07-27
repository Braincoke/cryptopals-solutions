package set1

import (
	"bufio"
	"log"
	"os"
)

/**
 * Cryptopal Set 1
 * Challenge 4 - Detect single-character XOR
 * https://cryptopals.com/sets/1/challenges/4
 */

// DetectSingleCharXOR detects which line was encrypted by a single byte XOR in a file
// It returns the line (the cipher) and the plaintext, as well as the score used to find the key
func DetectSingleCharXOR(filename string) (int, string, string) {
	// Read the file to retrieve each line
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	file.Close()

	// Crack each line as if it was XOR'd with a single character
	// and keep the best score
	var bestScore int = -1
	var probablePlaintext string
	var probableCipher string
	for _, line := range lines {
		score, plaintext := SingleByteXorCrack(line)
		if score > bestScore {
			bestScore = score
			probablePlaintext = plaintext
			probableCipher = line
		}
	}
	return bestScore, probableCipher, probablePlaintext
}
