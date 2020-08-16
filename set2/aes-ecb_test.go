package set2

import (
	"fmt"
	"strings"
	"testing"
)

func TestECBMode(t *testing.T) {
	pString := "braincoke.fr"
	plaintext := []byte(pString)
	key := []byte("YELLOW SUBMARINE")

	ciphertext := EncryptECB(plaintext, key, 4, 10) // AES-128
	decrypted := DecryptECB(ciphertext, key, 4, 10)
	if !strings.Contains(string(decrypted), pString) {
		t.Errorf("AES ECB error, decrypted plaintext = %q\n", decrypted)
	}
	fmt.Printf("%q\n", decrypted)

}
