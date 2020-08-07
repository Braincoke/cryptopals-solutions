package set1

import "encoding/binary"

// rotword perform a left rotation on the s of a word
func rotword(word uint32) uint32 {
	return word<<8 | word>>24
}

// subword applies the AES S-box to a 4-byte word
func subword(word uint32) (output uint32) {
	s := make([]byte, 4)
	wb := make([]byte, 4)
	binary.BigEndian.PutUint32(wb, word)
	for i := 0; i < 4; i++ {
		s[i] = sboxForward[wb[i]]
	}
	return binary.BigEndian.Uint32(s)
}

// keyExpansion implements the AES key schedule
func keyExpansion(Nk int, Nr int, key []uint32) (subkeys []uint32) {
	w := make([]uint32, 4*(Nr+1))
	i := 0
	for i < Nk {
		w[i] = key[i]
		i++
	}

	var temp uint32
	for i < (4 * (Nr + 1)) {
		temp = w[i-1]
		if i%Nk == 0 {
			temp = subword(rotword(temp)) ^ rcon[i/Nk-1]
		} else if Nk > 6 && i%Nk == 4 {
			temp = subword(temp)
		}
		w[i] = w[i-Nk] ^ temp
		i++
	}
	return w
}

// subBytes applies the S-box on each byte of the state
// Here the state is represented as an array of columns
func subBytes(state []uint32) []uint32 {
	output := make([]uint32, len(state))
	for i := 0; i < len(state); i++ {
		output[i] = subword(state[i])
	}
	return output
}

// shiftRows applies a rotation each row of the state
// Here the state is represented as an array of columns
func shiftRows(state []uint32) []uint32 {
	stateRows := columnsToRows(state)
	for i := 0; i < len(state); i++ {
		highBits := stateRows[i] << (i * 8)
		lowBits := stateRows[i] >> ((len(state) - i) * 8)
		stateRows[i] = highBits | lowBits
	}
	return rowsToColumns(stateRows)
}

// columnsToRows converts the representation of the state from columns to rows
func columnsToRows(state []uint32) []uint32 {
	output := make([]uint32, len(state))
	// Iterate through each column
	for c := 0; c < len(state); c++ {
		// Iterate through each row
		for r := 0; r < len(state); r++ {
			shift := len(state) - 1 - r
			// (0xff << 8*shift) selects the byte in the column
			// (>> 8*shift) puts back the byte in the least significant position
			// << (len(state)-c-1) * 8 places the byte in the correct position in the row
			output[r] = (((state[c] & (0xff << (shift * 8))) >> (shift * 8)) << ((len(state) - 1 - c) * 8)) | output[r]
		}
	}
	return output
}

// rowsToColumns converts the representation of the state from rows to columns
func rowsToColumns(state []uint32) []uint32 {
	output := make([]uint32, len(state))
	// Iterate through each row
	for r := 0; r < len(state); r++ {
		// Iterate through each column
		for c := 0; c < len(state); c++ {
			shift := len(state) - 1 - c
			// select the row byte with (0xff << shift)
			// place back the byte in least significant position with >> shift*8
			// place the byte in the correct position in the column with << r*8
			output[c] = (((state[r] & (0x000000ff << (shift * 8))) >> (shift * 8)) << ((len(state) - 1 - r) * 8)) | output[c]
		}
	}
	return output
}

// mul computes the multiplication of two s as defined in FIPS-197
func mul(a byte, b byte) byte {
	// We are basically doing a long multiplication except that additions
	// are replaced by XOR : https://en.wikipedia.org/wiki/Multiplication_algorithm#Long_multiplication
	var output byte
	for i := 0; i < 8; i++ {
		// add
		if (b & 1) != 0 {
			output = output ^ a
		}
		// shift
		a = xtime(a)
		b = b >> 1
	}
	return output
}

// xtime as defined in FIPS-197
func xtime(x byte) byte {
	var b7 byte = 0x80 /* to test if the high bit is set */
	var temp byte = x << 1
	if (b7 & x) == b7 {
		temp ^= 0x1b /* x^8 + x^4 + x^3 + x + 1*/
	}
	return temp
}

// mixColumns as defined in FIPS-197
func mixColumns(state []uint32) []uint32 {
	var two byte = 0x02
	var three byte = 0x03
	newState := make([]uint32, len(state))
	for c := 0; c < len(state); c++ {
		s := make([]byte, 4)
		binary.BigEndian.PutUint32(s, state[c])
		b0 := mul(two, s[0]) ^ mul(three, s[1]) ^ s[2] ^ s[3]
		b1 := s[0] ^ mul(two, s[1]) ^ mul(three, s[2]) ^ s[3]
		b2 := s[0] ^ s[1] ^ mul(two, s[2]) ^ mul(three, s[3])
		b3 := mul(three, s[0]) ^ s[1] ^ s[2] ^ mul(two, s[3])
		newState[c] = binary.BigEndian.Uint32([]byte{b0, b1, b2, b3})
	}
	return newState
}

// addRoundKey XOR the state with the round key
func addRoundKey(state []uint32, key []uint32) []uint32 {
	out := make([]uint32, len(state))
	for i := 0; i < len(state); i++ {
		out[i] = state[i] ^ key[i]
	}
	return out
}

// encryptBlock encrypts a 128-bit block with the AES algorithm
// This implementation is as close to the specification as possible but
// there are better implementations in terms of speed and readability
// Check out https://golang.org/src/crypto/aes/block.go
func encryptBlock(plaintext []uint32, key []uint32, Nk int, Nr int) []uint32 {
	Nb := 4
	roundKeys := make([][]uint32, (Nr + 1))
	for i := 0; i <= Nr; i++ {
		roundKeys[i] = make([]uint32, Nb)
	}
	round := 0
	subkeys := keyExpansion(Nk, Nr, key)
	for index, keyByte := range subkeys {
		roundKeys[round][index%Nb] = keyByte
		if (index+1)%Nb == 0 {
			round++
		}
	}

	// Init
	state := plaintext
	// Round 0
	state = addRoundKey(roundKeys[0], state)
	// Round 1 to (Nr-1)
	for round = 1; round < Nr; round++ {
		state = addRoundKey(mixColumns(shiftRows(subBytes(state))), roundKeys[round])
	}
	// Round Nr
	state = addRoundKey(shiftRows(subBytes(state)), roundKeys[round])
	return state
}
