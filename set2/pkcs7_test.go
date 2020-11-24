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
	expectedString := [][]byte{
		[]byte("ICE ICE BABY"),
	}
	validPadding := [][]byte{
		[]byte("ICE ICE BABY\x04\x04\x04\x04"),
	}
	invalidPadding := [][]byte{
		[]byte("ICE ICE BABY\x05\x05\x05\x05"),
		[]byte("ICE ICE BABY\x01\x02\x03\x04"),
	}
	for i := 0; i < len(validPadding); i++ {
		unpaddedArray, err := UnpadPKCS7(validPadding[i])
		if err != nil {
			t.Errorf("Padded string %q should have been found as valid PKCS#7 but did not", validPadding[i])
		}
		if !ByteSlicesEqual(unpaddedArray, expectedString[i]) {
			t.Errorf("Expected %q but got %q", expectedString[i], unpaddedArray)
		}
	}
	for i := 0; i < len(invalidPadding); i++ {
		_, err := UnpadPKCS7(invalidPadding[i])
		if err == nil {
			t.Errorf("Padded string %q should have been found as invalid PKCS#7 but did not", invalidPadding[i])
		}
	}
}

func TestPKCS7Validation(t *testing.T) {
	validPadding := [][]byte{
		[]byte("ICE ICE BABY\x04\x04\x04\x04"),
	}
	invalidPadding := [][]byte{
		[]byte("ICE ICE BABY\x05\x05\x05\x05"),
		[]byte("ICE ICE BABY\x01\x02\x03\x04"),
	}
	for i := 0; i < len(validPadding); i++ {
		if !ValidatePKCS7(validPadding[i]) {
			t.Errorf("Padded string %q should have been found as valid PKCS#7 but did not", validPadding[i])
		}
	}
	for i := 0; i < len(invalidPadding); i++ {
		if ValidatePKCS7(invalidPadding[i]) {
			t.Errorf("Padded string %q should have been found as invalid PKCS#7 but did not", invalidPadding[i])
		}
	}
}
