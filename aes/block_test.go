package set1

import (
	"fmt"
	"strings"
	"testing"
)

func uint32SlicesEqual(a []uint32, b []uint32) bool {
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

func Uint32SliceToString(a []uint32) string {
	var result strings.Builder
	result.WriteRune('[')
	for i := 0; i < len(a); i++ {
		if i%4 == 0 {
			result.WriteRune('\n')
		}
		result.WriteString(fmt.Sprintf(" %08x,", a[i]))
	}
	result.WriteRune('\n')
	result.WriteRune(']')
	return result.String()
}

func TestSubword(t *testing.T) {
	var word uint32 = 0xcf4f3c09
	var result uint32 = subword(word)
	var expected uint32 = 0x8a84eb01
	if expected != result {
		t.Errorf("Expected subword(%x) = %x but got %x", word, expected, result)
	}
}

func TestRotword(t *testing.T) {
	var word uint32 = 0x09cf4f3c
	var result uint32 = rotword(word)
	var expected uint32 = 0xcf4f3c09
	if expected != result {
		t.Errorf("Expected subword(%x) = %x but got %x", word, expected, result)
	}
}

func TestKeyExpansionAES128(t *testing.T) {
	Nk := 4
	Nr := 10
	key := []uint32{0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c}
	subkeys := keyExpansion(Nk, Nr, key)
	expected := []uint32{
		0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c,
		0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605,
		0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f,
		0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b,
		0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00,
		0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc,
		0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
		0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f,
		0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f,
		0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e,
		0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6,
	}
	if !uint32SlicesEqual(expected, subkeys) {
		t.Error("Key expansion algorithm failed")
	}
}

func TestKeyExpansionAES192(t *testing.T) {
	Nk := 6
	Nr := 12
	key := []uint32{0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, 0x522c6b7b}
	subkeys := keyExpansion(Nk, Nr, key)
	expected := []uint32{
		0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, 0x522c6b7b,
		0xfe0c91f7, 0x2402f5a5, 0xec12068e, 0x6c827f6b, 0x0e7a95b9, 0x5c56fec2,
		0x4db7b4bd, 0x69b54118, 0x85a74796, 0xe92538fd, 0xe75fad44, 0xbb095386,
		0x485af057, 0x21efb14f, 0xa448f6d9, 0x4d6dce24, 0xaa326360, 0x113b30e6,
		0xa25e7ed5, 0x83b1cf9a, 0x27f93943, 0x6a94f767, 0xc0a69407, 0xd19da4e1,
		0xec1786eb, 0x6fa64971, 0x485f7032, 0x22cb8755, 0xe26d1352, 0x33f0b7b3,
		0x40beeb28, 0x2f18a259, 0x6747d26b, 0x458c553e, 0xa7e1466c, 0x9411f1df,
		0x821f750a, 0xad07d753, 0xca400538, 0x8fcc5006, 0x282d166a, 0xbc3ce7b5,
		0xe98ba06f, 0x448c773c, 0x8ecc7204, 0x01002202,
	}
	if !uint32SlicesEqual(expected, subkeys) {
		t.Error("Key expansion algorithm failed")
	}
}

func TestKeyExpansionAES256(t *testing.T) {
	Nk := 8
	Nr := 14
	key := []uint32{
		0x603deb10,
		0x15ca71be,
		0x2b73aef0,
		0x857d7781,
		0x1f352c07,
		0x3b6108d7,
		0x2d9810a3,
		0x0914dff4,
	}
	subkeys := keyExpansion(Nk, Nr, key)
	expected := []uint32{
		0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781,
		0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4,
		0x9ba35411, 0x8e6925af, 0xa51a8b5f, 0x2067fcde,
		0xa8b09c1a, 0x93d194cd, 0xbe49846e, 0xb75d5b9a,
		0xd59aecb8, 0x5bf3c917, 0xfee94248, 0xde8ebe96,
		0xb5a9328a, 0x2678a647, 0x98312229, 0x2f6c79b3,
		0x812c81ad, 0xdadf48ba, 0x24360af2, 0xfab8b464,
		0x98c5bfc9, 0xbebd198e, 0x268c3ba7, 0x09e04214,
		0x68007bac, 0xb2df3316, 0x96e939e4, 0x6c518d80,
		0xc814e204, 0x76a9fb8a, 0x5025c02d, 0x59c58239,
		0xde136967, 0x6ccc5a71, 0xfa256395, 0x9674ee15,
		0x5886ca5d, 0x2e2f31d7, 0x7e0af1fa, 0x27cf73c3,
		0x749c47ab, 0x18501dda, 0xe2757e4f, 0x7401905a,
		0xcafaaae3, 0xe4d59b34, 0x9adf6ace, 0xbd10190d,
		0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e,
	}
	if !uint32SlicesEqual(expected, subkeys) {
		t.Errorf("Expected \n%s \nbut got \n%s", Uint32SliceToString(expected), Uint32SliceToString(subkeys))
	}
}

func TestSubBytes(t *testing.T) {
	state := []uint32{
		0x193de3be,
		0xa0f4e22b,
		0x9ac68d2a,
		0xe9f84808,
	}
	result := subBytes(state)
	expected := []uint32{
		0xd42711ae,
		0xe0bf98f1,
		0xb8b45de5,
		0x1e415230,
	}
	if !uint32SlicesEqual(expected, result) {
		t.Errorf("Expected \n%s \nbut got \n%s", Uint32SliceToString(expected), Uint32SliceToString(result))
	}
}

func TestColumnToRows(t *testing.T) {
	/* State
	 *    | c0 | c1 | c2 | c3
	 *    |------------------
	 * r0 | 00 | 01 | 02 | 03
	 * r1 | 10 | 11 | 12 | 13
	 * r2 | 20 | 21 | 22 | 23
	 * r3 | 30 | 31 | 32 | 33
	 */
	state := []uint32{
		0x00102030,
		0x01112131,
		0x02122232,
		0x03132333,
	}
	expected := []uint32{
		0x00010203,
		0x10111213,
		0x20212223,
		0x30313233,
	}
	result := columnsToRows(state)
	if !uint32SlicesEqual(expected, result) {
		t.Errorf("Expected \n%s \nbut got \n%s", Uint32SliceToString(expected), Uint32SliceToString(result))
	}
}

func TestRowsToColumns(t *testing.T) {
	/* State
	 *    | c0 | c1 | c2 | c3
	 *    |------------------
	 * r0 | 00 | 01 | 02 | 03
	 * r1 | 10 | 11 | 12 | 13
	 * r2 | 20 | 21 | 22 | 23
	 * r3 | 30 | 31 | 32 | 33
	 */
	stateAsRows := []uint32{
		0x00010203,
		0x10111213,
		0x20212223,
		0x30313233,
	}
	expected := []uint32{
		0x00102030,
		0x01112131,
		0x02122232,
		0x03132333,
	}
	result := rowsToColumns(stateAsRows)
	if !uint32SlicesEqual(expected, result) {
		t.Errorf("Expected \n%s \nbut got \n%s", Uint32SliceToString(expected), Uint32SliceToString(result))
	}
}

func TestShiftRows(t *testing.T) {
	/* State
	 *    | c0 | c1 | c2 | c3
	 *    |------------------
	 * r0 | 00 | 01 | 02 | 03
	 * r1 | 10 | 11 | 12 | 13
	 * r2 | 20 | 21 | 22 | 23
	 * r3 | 30 | 31 | 32 | 33
	 */
	state := []uint32{
		0x00102030,
		0x01112131,
		0x02122232,
		0x03132333,
	}

	/* ShiftRows(State)
	 *    | c0 | c1 | c2 | c3
	 *    |------------------
	 * r0 | 00 | 01 | 02 | 03
	 * r1 | 11 | 12 | 13 | 10
	 * r2 | 22 | 23 | 20 | 21
	 * r3 | 33 | 30 | 31 | 32
	 */
	expected := []uint32{
		0x00112233,
		0x01122330,
		0x02132031,
		0x03102132,
	}
	result := shiftRows(state)
	if !uint32SlicesEqual(expected, result) {
		t.Errorf("Expected \n%s \nbut got \n%s", Uint32SliceToString(expected), Uint32SliceToString(result))
	}
}

func TestShiftRowsAES(t *testing.T) {
	/* State
	 *    | c0 | c1 | c2 | c3
	 *    |------------------
	 * r0 | d4 | e0 | b8 | 1e
	 * r1 | 27 | bf | b4 | 41
	 * r2 | 11 | 98 | 5d | 52
	 * r3 | ae | f1 | e5 | 30
	 */
	state := []uint32{
		0xd42711ae,
		0xe0bf98f1,
		0xb8b45de5,
		0x1e415230,
	}

	/* ShiftRows(State)
	 *    | c0 | c1 | c2 | c3
	 *    |------------------
	 * r0 | d4 | e0 | b8 | 1e
	 * r1 | bf | b4 | 41 | 27
	 * r2 | 5d | 52 | 11 | 98
	 * r3 | 30 | ae | f1 | e5
	 */
	expected := []uint32{
		0xd4bf5d30,
		0xe0b452ae,
		0xb84111f1,
		0x1e2798e5,
	}
	result := shiftRows(state)
	if !uint32SlicesEqual(expected, result) {
		t.Errorf("Expected \n%s \nbut got \n%s", Uint32SliceToString(expected), Uint32SliceToString(result))
	}
}

func TestXTime(t *testing.T) {
	var in, expected []byte
	in = []byte{0x57, 0xae, 0x47, 0x8e}
	expected = []byte{0xae, 0x47, 0x8e, 0x07}
	for i := 0; i < len(in); i++ {
		out := xtime(in[i])
		if expected[i] != out {
			t.Errorf("xtime(0x%02x) = 0x%02x but got 0x%02x", in[i], expected[i], out)
		}
	}
}

func TestMul(t *testing.T) {
	a := []byte{0x57, 0x57, 0x57, 0x57, 0x57}
	b := []byte{0x02, 0x04, 0x08, 0x10, 0x13}
	expected := []byte{0xae, 0x47, 0x8e, 0x07, 0xfe}
	for i := 0; i < len(a); i++ {
		out := mul(a[i], b[i])
		if expected[i] != out {
			t.Errorf("mul(0x%02x, 0x%02x) = 0x%02x but got 0x%02x", a[i], b[i], expected[i], out)
		}
	}
}

func TestAddRoundKey(t *testing.T) {
	states := [][]uint32{
		/* State
		 * 32 | 88 | 31 | e0
		 * 43 | 5a | 31 | 37
		 * f6 | 30 | 98 | 07
		 * a8 | 8d | a2 | 34
		 */
		{
			0x3243f6a8,
			0x885a308d,
			0x313198a2,
			0xe0370734,
		},
		{
			0x046681e5,
			0xe0cb199a,
			0x48f8d37a,
			0x2806264c,
		},
	}
	keys := [][]uint32{
		/* Key
		 * 2b | 28 | ab | 09
		 * 7e | ae | f7 | cf
		 * 15 | d2 | 15 | 4f
		 * 16 | a6 | 88 | 3c
		 */
		{
			0x2b7e1516,
			0x28aed2a6,
			0xabf71588,
			0x09cf4f3c,
		},
		{
			0xa0fafe17,
			0x88542cb1,
			0x23a33939,
			0x2a6c7605,
		},
	}
	expected := [][]uint32{
		{
			0x193de3be,
			0xa0f4e22b,
			0x9ac68d2a,
			0xe9f84808,
		},
		{
			0xa49c7ff2,
			0x689f352b,
			0x6b5bea43,
			0x026a5049,
		},
	}
	for i := 0; i < len(states); i++ {
		out := addRoundKey(states[i], keys[i])
		if !uint32SlicesEqual(out, expected[i]) {
			t.Errorf("AddRoundKey expected \n%s but got \n%s", Uint32SliceToString(expected[i]), Uint32SliceToString(out))
		}
	}
}

func TestMixColumns(t *testing.T) {
	states := [][]uint32{
		/* State
		 * d4 | e0 | b8 | 1e
		 * bf | bf | b4 | 41
		 * 5d | 98 | 5d | 52
		 * 30 | f1 | e5 | 30
		 */
		{
			0xd4bf5d30,
			0xe0b452ae,
			0xb84111f1,
			0x1e2798e5,
		},
		{
			0xe1fb967c,
			0xe8c8ae9b,
			0x356cd2ba,
			0x974ffb53,
		},
	}
	expected := [][]uint32{
		{
			0x046681e5,
			0xe0cb199a,
			0x48f8d37a,
			0x2806264c,
		},
		{
			0x25d1a9ad,
			0xbd11d168,
			0xb63a338e,
			0x4c4cc0b0,
		},
	}
	for i := 0; i < len(states); i++ {
		out := mixColumns(states[i])
		if !uint32SlicesEqual(out, expected[i]) {
			t.Errorf("MixColumns expected \n%s but got \n%s", Uint32SliceToString(expected[i]), Uint32SliceToString(out))
		}
	}
}

// Test an encryption round
func TestEncryptRound(t *testing.T) {
	/* State
	 * 19 | a0 | 9a | e9
	 * 3d | f4 | c6 | f8
	 * e3 | e2 | 8d | 48
	 * be | 2b | 2a | 08
	 */
	state := []uint32{
		0x193de3be,
		0xa0f4e22b,
		0x9ac68d2a,
		0xe9f84808,
	}
	expectedAfterSubBytes := []uint32{
		0xd42711ae,
		0xe0bf98f1,
		0xb8b45de5,
		0x1e415230,
	}
	afterSubBytes := subBytes(state)
	if !uint32SlicesEqual(expectedAfterSubBytes, afterSubBytes) {
		t.Errorf("After SubBytes expected \n%s but got \n%s", Uint32SliceToString(expectedAfterSubBytes), Uint32SliceToString(afterSubBytes))
	}

	/* State
	 * d4 | e0 | b8 | 1e
	 * bf | bf | b4 | 41
	 * 5d | 98 | 5d | 52
	 * 30 | f1 | e5 | 30
	 */
	expectedAfterShiftRows := []uint32{
		0xd4bf5d30,
		0xe0b452ae,
		0xb84111f1,
		0x1e2798e5,
	}
	afterShiftRows := shiftRows(afterSubBytes)
	if !uint32SlicesEqual(expectedAfterShiftRows, afterShiftRows) {
		t.Errorf("After ShiftRows expected \n%s but got \n%s", Uint32SliceToString(expectedAfterShiftRows), Uint32SliceToString(afterShiftRows))
	}

	expectedAfterMixColumns := []uint32{
		0x046681e5,
		0xe0cb199a,
		0x48f8d37a,
		0x2806264c,
	}
	afterMixColumns := mixColumns(afterShiftRows)
	if !uint32SlicesEqual(expectedAfterMixColumns, afterMixColumns) {
		t.Errorf("After MixColumns expected \n%s but got \n%s", Uint32SliceToString(expectedAfterMixColumns), Uint32SliceToString(afterMixColumns))
	}

	/* Key
	 * a0 | 88 | 23 | 2a
	 * fa | 54 | a3 | 6c
	 * fe | 2c | 39 | 76
	 * 17 | b1 | 39 | 05
	 */
	key := []uint32{
		0xa0fafe17,
		0x88542cb1,
		0x23a33939,
		0x2a6c7605,
	}

	/* Expected
	 * a4 | 68 | 6b | 02
	 * 9c | 9f | 5b | 6a
	 * 7f | 35 | ea | 50
	 * f2 | 2c | 43 | 49
	 */
	expectedAfterRoundKey := []uint32{
		0xa49c7ff2,
		0x689f352b,
		0x6b5bea43,
		0x026a5049,
	}
	afterRoundKey := addRoundKey(afterMixColumns, key)
	if !uint32SlicesEqual(afterRoundKey, expectedAfterRoundKey) {
		t.Errorf("After AddRoundKey expected \n%s but got \n%s", Uint32SliceToString(expectedAfterRoundKey), Uint32SliceToString(afterRoundKey))
	}
}

func TestEncryptBlock(t *testing.T) {
	plaintext := [][]uint32{
		{
			0x3243f6a8,
			0x885a308d,
			0x313198a2,
			0xe0370734,
		},
	}
	keys := [][]uint32{
		{
			0x2b7e1516,
			0x28aed2a6,
			0xabf71588,
			0x09cf4f3c,
		},
	}
	expected := [][]uint32{
		{
			0x3925841d,
			0x02dc09fb,
			0xdc118597,
			0x196a0b32,
		},
	}
	for i := 0; i < len(plaintext); i++ {
		out := encryptBlock(plaintext[i], keys[i], 4, 10)
		if !uint32SlicesEqual(out, expected[i]) {
			t.Errorf("EncryptBlock expected \n%s but got \n%s", Uint32SliceToString(expected[i]), Uint32SliceToString(out))
		}
	}
}
