package set2

import (
	"cryptopals/set1"
	"fmt"
	"testing"
)

func TestChallenge16IsAdmin(t *testing.T) {
	input := []byte("blablabl")
	ciphertext, iv := Challenge16EncryptionOracle(input)
	if Challenge16IsAdmin(ciphertext, iv) {
		t.Error("Detected admin when it was not the case")
	}
}

func TestChallenge16CipherBreaking(t *testing.T) {
	// p = p1 || p2 || p3
	input := []byte("YELLOW_SUBMARINE_DETROIT_TORINO_etcetera")
	// c = c1 || c2 || ... || cN
	// iv = c0
	c, iv := Challenge16EncryptionOracle(input)
	// First plaintext block
	p1 := []byte("comment1=cooking")
	// i1 = p1 ^ c0
	i1, _ := set1.XOR([]byte(p1), iv)
	// What we whish p1 to be equal to
	targetp1 := []byte(";admin=true;1234")

	// What the iv should be to have this plaintext
	craftedIV, _ := set1.XOR(targetp1, i1)
	fmt.Printf("Crafted IV = %x\n", craftedIV)
	// craftedIV := iv
	fmt.Printf("Admin = %t\n", Challenge16IsAdmin(c, craftedIV))

}
