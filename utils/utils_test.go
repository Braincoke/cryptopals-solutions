package utils

import "testing"

func TestBtoU(t *testing.T) {
	bArray := []byte{
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17,
	}
	expected := []uint32{
		0x00010203,
		0x04050607,
		0x10111213,
		0x14151617,
	}
	uArray := ByteToUintSlice(bArray)
	if !Uint32SlicesEqual(uArray, expected) {
		t.Errorf("Expected \n%s but got \n%s", Uint32SliceToString(expected), Uint32SliceToString(uArray))
	}

}

func TestUtoB(t *testing.T) {
	expected := []byte{
		0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07,
		0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17,
	}
	uArray := []uint32{
		0x00010203,
		0x04050607,
		0x10111213,
		0x14151617,
	}
	bArray := UintToByteSlice(uArray)
	if !ByteSlicesEqual(bArray, expected) {
		t.Errorf("Expected \n%q but got \n%q", expected, bArray)
	}
}
