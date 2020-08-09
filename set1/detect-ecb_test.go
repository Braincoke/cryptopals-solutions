package set1

import (
	"fmt"
	"testing"
)

func TestDetectECB(t *testing.T) {
	lines, _ := ReadFileLines("./challenge8-data.txt")
	detected := 0
	cipherlines := make([]string, 1)
	for _, line := range lines {
		isECB, _ := DetectECB([]byte(line))
		if isECB {
			detected++
			cipherlines = append(cipherlines, line)
		}
	}
	fmt.Printf("Detected %d lines using ECB\n", detected)
	for _, cipher := range cipherlines {
		fmt.Println(cipher)
	}
}
