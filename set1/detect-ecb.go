package set1

import (
	"bufio"
	"encoding/hex"
	"os"
)

// DetectECB detects ECB
// the ciphertext should be a hex string
func DetectECB(ciphertext []byte) (detected bool, count map[string]int) {
	// Split the ciphertext in blocks of 128 bits
	blockSize := 16
	blocks := make([]string, len(ciphertext)/blockSize)
	j := 0
	for i := 0; i < len(ciphertext); {
		block := hex.EncodeToString(ciphertext[i : i+blockSize])
		blocks[j] = block
		j++
		i += blockSize
	}
	duplicates := 0
	count = make(map[string]int)
	for _, b := range blocks {
		if count[b] > 0 {
			duplicates++
		}
		count[b]++
	}
	return (duplicates >= 1), count
}

// ReadFileLines reads each line of a file
func ReadFileLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, nil
}
