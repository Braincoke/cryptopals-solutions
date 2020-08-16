package set2

import (
	. "cryptopals/utils"
	"fmt"
	"testing"
)

func TestPadBlockPKCS7(t *testing.T) {
	input := []byte("YELLOW SUBMARINE")
	var blockSize byte = 20
	paddedBlock, _ := PadBlockPKCS7(input, blockSize)
	expected := append(input, []byte{0x04, 0x04, 0x04, 0x04}...)
	if !ByteSlicesEqual(expected, paddedBlock) {
		t.Errorf("Expected %x but got %x", expected, paddedBlock)
	}

	fmt.Printf("%q\n", paddedBlock)
}

func TestPadBlockPKCS7Equality(t *testing.T) {
	input := []byte("YELLOW SUBMARINE")
	var blockSize byte = 16
	paddedBlock, _ := PadBlockPKCS7(input, blockSize)
	padding := make([]byte, 16)
	for i := 0; i < len(padding); i++ {
		padding[i] = 16
	}
	expected := append(input, padding...)
	if !ByteSlicesEqual(expected, paddedBlock) {
		t.Errorf("Expected %x but got %x", expected, paddedBlock)
	}

	fmt.Printf("%q\n", paddedBlock)
}

func TestPKCS7OneBlockEquality(t *testing.T) {
	input := []byte("YELLOW SUBMARINE")
	var blockSize byte = 16
	paddedArray := PadPCKS7(input, blockSize)
	padding := make([]byte, 16)
	for i := 0; i < len(padding); i++ {
		padding[i] = 16
	}
	expected := append(input, padding...)
	if !ByteSlicesEqual(expected, paddedArray) {
		t.Errorf("Expected %x but got %x", expected, paddedArray)
	}

	fmt.Printf("%q\n", paddedArray)
}

func TestPKCS7OneBlock(t *testing.T) {
	input := []byte("YELLOW SUBMARINE")
	var blockSize byte = 20
	paddedArray := PadPCKS7(input, blockSize)
	padding := make([]byte, 4)
	for i := 0; i < len(padding); i++ {
		padding[i] = 4
	}
	expected := append(input, padding...)
	if !ByteSlicesEqual(expected, paddedArray) {
		t.Errorf("Expected %x but got %x", expected, paddedArray)
	}

	fmt.Printf("%q\n", paddedArray)
}

func TestPKCS7NonMultiple(t *testing.T) {
	input := []byte("YELLOW SUBMARINE")
	var blockSize byte = 3
	paddedArray := PadPCKS7(input, blockSize)
	padding := make([]byte, 2)
	for i := 0; i < len(padding); i++ {
		padding[i] = 2
	}
	expected := append(input, padding...)
	if !ByteSlicesEqual(expected, paddedArray) {
		t.Errorf("Expected %x but got %x", expected, paddedArray)
	}

	fmt.Printf("%q\n", paddedArray)
}

func TestPKCS7Multiple(t *testing.T) {
	input := []byte("YELLOW SUBMARINE")
	var blockSize byte = 4
	paddedArray := PadPCKS7(input, blockSize)
	padding := make([]byte, 4)
	for i := 0; i < len(padding); i++ {
		padding[i] = 4
	}
	expected := append(input, padding...)
	if !ByteSlicesEqual(expected, paddedArray) {
		t.Errorf("Expected %x but got %x", expected, paddedArray)
	}

	fmt.Printf("%q\n", paddedArray)
}

func TestPKCS7Unpad(t *testing.T) {
	input := []byte("YELLOW SUBMARINE")
	var blockSize byte = 4
	paddedArray := PadPCKS7(input, blockSize)
	unpaddedArray := UnpadPKCS7(paddedArray)
	if !ByteSlicesEqual(input, unpaddedArray) {
		t.Errorf("Expected %q but got %q", input, unpaddedArray)
	}
}
