package set1

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func TestDecryptEcbChallenge7(t *testing.T) {
	Nb := 4
	// Format the ciphertext as []uint32
	filename := "challenge7-data.txt"
	data, _ := ReadBase64File(filename)
	// We are in a very special case where len(data) is divisible by 4
	ciphertext := make([]uint32, len(data)/Nb)
	for i := 0; i < len(ciphertext); i++ {
		ciphertext[i] = binary.BigEndian.Uint32([]byte{data[i*Nb], data[i*Nb+1], data[i*Nb+2], data[i*Nb+3]})
	}

	keyBytes := []byte("YELLOW SUBMARINE")
	key := make([]uint32, Nb)
	for i := 0; i < Nb; i++ {
		key[i] = binary.BigEndian.Uint32([]byte{keyBytes[i*Nb], keyBytes[i*Nb+1], keyBytes[i*Nb+2], keyBytes[i*Nb+3]})
	}

	plaintext := ECBDecrypt(ciphertext, key, 4, 10)
	plaintextBytes := make([]byte, len(plaintext)*Nb)
	for i := 0; i < len(plaintext); i++ {
		bytes := make([]byte, Nb)
		binary.BigEndian.PutUint32(bytes, plaintext[i])
		for j := 0; j < Nb; j++ {
			plaintextBytes[i*Nb+j] = bytes[j]
		}
	}
	fmt.Print(string(plaintextBytes))
}
