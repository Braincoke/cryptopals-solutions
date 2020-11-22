package set2

import (
	"fmt"
	"strings"
	"testing"
)

func TestDetectBlockSize14(t *testing.T) {
	fmt.Printf("Block size %d\n", DetectBlockSize(Challenge14Oracle))
}

func TestCommonBlockSequence(t *testing.T) {
	key := "This is the key!"
	blockSize := 16
	p1 := []string{
		"YELLOWSUBMARINE_OKLAHOMA SMASH!_ASTONISHING LIFE",
		"YELLOWSUBMARINE_BLABLABLA",
		"YELLOWSUBMARINE_OKLAHOMA SMASH!_ASTONISHING LIFE_AND GREAT VALUE",
	}
	p2 := []string{
		"YELLOWSUBMARINE_OKLAHOMA SMASH!_ASTONISHING GIRL",
		"YELLOWSUBMARINE_NOTHING MORE",
		"YELLOWSUBMARINE_OKLAHOMA SMASH!_ASTONISHING LIFE_AND GREAT VALUE_ISNT IT ?",
	}
	expectedCommon := []int{2, 1, 4}

	for i := 0; i < len(p1); i++ {
		c1 := EncryptECB([]byte(p1[i]), []byte(key), 4, 10)
		c2 := EncryptECB([]byte(p2[i]), []byte(key), 4, 10)
		common := CountCommonBlockSequence(c1, c2, blockSize)
		if common != expectedCommon[i] {
			t.Errorf("Expected to %d blocks in common but found %d\n", expectedCommon, common)
		}
	}
}

func GenerateDummyOracle14(prefix string, target string) func([]byte) []byte {
	return func(chosenString []byte) []byte {
		plaintext := []byte(prefix + string(chosenString) + target)
		key := []byte("YELLOW SUBMARINE")
		ciphertext := EncryptECB(plaintext, key, 4, 10)
		return ciphertext
	}
}

func TestDetectPrefixLength14(t *testing.T) {
	blockSize := 16
	for expectedLength := 100; expectedLength > 0; expectedLength-- {
		prefix := strings.Repeat("B", expectedLength)
		prefixLength := DetectPrefixLength14(blockSize, GenerateDummyOracle14(prefix, "whatever"))
		if prefixLength != expectedLength {
			t.Errorf("Expected to detect prefix length of %d but found %d\n", expectedLength, prefixLength)
		}
	}
}

func TestDecryptUnknownString14(t *testing.T) {
	unknownString := []string{
		"AAAAAAAAAAA",
		"CDEFGHIJKLMNOPQRSTUVWXYZAB",
	}
	prefix := []string{
		strings.Repeat("B", 15),
		strings.Repeat("X", 55),
	}
	for k := 0; k < len(prefix); k++ {
		oracle := GenerateDummyOracle14(prefix[k], unknownString[k])
		// Detect block size
		blockSize := DetectBlockSize(oracle)
		// Detect prefix length
		prefixLength := DetectPrefixLength14(blockSize, oracle)

		decryptedBytes := make([]byte, 0)
		for i := 0; i < len(unknownString[k]); i++ {
			decryptedByte, err := DecryptByte14(prefixLength, i, decryptedBytes, blockSize, oracle)
			if err != nil {
				t.Errorf(err.Error())
			}
			if decryptedByte != unknownString[k][i] {
				t.Errorf("Expected to decrypt byte %q but decrypted %q\n", unknownString[k][i], decryptedByte)
			}
			decryptedBytes = append(decryptedBytes, decryptedByte)
		}
		fmt.Println(string(decryptedBytes))
	}
}
