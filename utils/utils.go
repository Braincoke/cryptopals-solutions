package utils

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// ByteSlicesEqual tests if two byte arrays are equal
func ByteSlicesEqual(a []byte, b []byte) bool {
	// Test the equality
	if len(a) != len(b) {
		return false
	}
	equal := true
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			equal = false
		}
	}
	return equal
}

// Uint32SlicesEqual tests if two slices of uint32 are equal
func Uint32SlicesEqual(a []uint32, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Uint32MatrixEqual tests if two double slices of uint32 are equal
func Uint32MatrixEqual(a [][]uint32, b [][]uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if !Uint32SlicesEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

// Uint32SliceToString prints a uint32 slice
func Uint32SliceToString(a []uint32) string {
	var result strings.Builder
	result.WriteRune('{')
	for i := 0; i < len(a); i++ {
		result.WriteString(fmt.Sprintf(" %08x,", a[i]))
	}
	result.WriteRune('}')
	return result.String()
}

// Uint32MatrixToString prints a double slice of uint32
func Uint32MatrixToString(a [][]uint32) string {
	var result strings.Builder
	for i := 0; i < len(a); i++ {
		result.WriteString(Uint32SliceToString(a[i]))
		result.WriteRune('\n')
	}
	return result.String()
}

// ByteMatrixToString prints a double slice of byte
func ByteMatrixToString(a [][]byte) string {
	var result strings.Builder
	result.WriteRune('[')
	for _, subA := range a {
		result.WriteString(fmt.Sprintf(" {"))
		for _, e := range subA {
			result.WriteString(fmt.Sprintf("%d,", e))
		}
		result.WriteString(fmt.Sprintf("},"))
	}
	result.WriteRune(']')
	return result.String()
}

// ByteMatrixEqual tests if two double slice of byte are equal
func ByteMatrixEqual(a [][]byte, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, subA := range a {
		if len(b[i]) != len(subA) {
			return false
		}
		for index, elementA := range subA {
			if b[i][index] != elementA {
				return false
			}
		}
	}
	return true
}

// MapToString prints a map[byte]float32
func MapToString(a map[byte]float32) string {
	var result strings.Builder
	result.WriteRune('[')
	for k, v := range a {
		result.WriteString(fmt.Sprintf("(%x : %f), ", k, v))
	}
	result.WriteRune(']')
	return result.String()
}

// MapsEqual tests the equality of two map[byte]float32
func MapsEqual(a map[byte]float32, b map[byte]float32) bool {
	if len(a) != len(b) {
		return false
	}
	// Get keys
	j := 0
	keys := make([]byte, len(a))
	for k := range a {
		keys[j] = k
		j++
	}
	// Test the equality
	equal := true
	for i := 0; i < len(keys); i++ {
		if a[keys[i]] != b[keys[i]] {
			equal = false
		}
	}
	return equal
}

// XORUint32 computes the exclusive or of two arrays of uint32
func XORUint32(a []uint32, b []uint32) []uint32 {
	result := make([]uint32, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// ByteToUintSlice converts a byte array to a uint32 array
func ByteToUintSlice(byteArray []byte) []uint32 {
	uintArray := make([]uint32, len(byteArray)/4)
	for i := 0; i < len(uintArray); i++ {
		uintArray[i] = binary.BigEndian.Uint32(byteArray[i*4 : i*4+4])
	}
	return uintArray
}

// UintToByteSlice converts a uint32 array to a byte array
func UintToByteSlice(uintArray []uint32) []byte {
	byteArray := make([]byte, 0)
	for i := 0; i < len(uintArray); i++ {
		uintBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(uintBytes, uintArray[i])
		byteArray = append(byteArray, uintBytes...)
	}
	return byteArray
}
