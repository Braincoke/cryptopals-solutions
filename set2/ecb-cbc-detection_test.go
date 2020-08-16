package set2

import (
	"cryptopals/set1"
	"fmt"
	"testing"
)

func TestRandomEncryption(t *testing.T) {
	plaintext := []byte("braincoke.fr")
	ciphertext, _ := EncryptData(plaintext)
	fmt.Printf("%x\n", ciphertext)
}

func TestModeDetection(t *testing.T) {

	plaintext := []byte(`
	Blackbird singing in the dead of night
	Take these broken wings and learn to fly
	All your life
	You were only waiting for this moment to arise

	Blackbird singing in the dead of night
	Take these sunken eyes and learn to see
	All your life
	You were only waiting for this moment to be free

	Black bird fly, black bird fly
	Into the light of the dark black night

	Black bird fly, black bird fly
	Into the light of the dark black night

	Blackbird singing in the dead of night
	Take these broken wings and learn to fly
	All your life
	You were only waiting for this moment to arise
	You were only waiting for this moment to arise
	You were only waiting for this moment to arise`)

	for i := 0; i < 200; i++ {
		ciphertext, mode := EncryptData(plaintext)
		fmt.Printf("Mode used was %s\n", mode)

		isECB, _ := set1.DetectECB(ciphertext)
		var detectedMode string
		if isECB {
			detectedMode = "ECB"
		} else {
			detectedMode = "CBC"
		}
		if detectedMode != mode {
			t.Errorf("Mode used was %s but detected %s\n", mode, detectedMode)
		}
	}
}
