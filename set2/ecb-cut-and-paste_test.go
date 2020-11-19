package set2

import (
	"testing"
)

func TestDecodeProfile(t *testing.T) {
	p := decodeProfile("email=foo@bar.com&uid=10&role=user")
	if p.Email != "foo@bar.com" || p.UID != 10 || p.Role != "user" {
		t.Error("Error when decoding profile")
	}
}

func TestProfileFor(t *testing.T) {
	p := profileFor("foo@bar.com")
	if p != "email=foo@bar.com&uid=10&role=user" {
		t.Errorf("Incorrect encoded profile :\n%s", p)
	}
}

func TestEncryptDecryptProfile(t *testing.T) {
	ciphertext := EncryptProfile("foo@bar.com")
	p := DecryptProfile(ciphertext)
	if p.Email != "foo@bar.com" || p.UID != 10 || p.Role != "user" {
		t.Errorf("Error when decoding profile. \nemail=%s\nuid=%d\nrole=%s", p.Email, p.UID, p.Role)
	}
}

func TestPayload(t *testing.T) {
	payload := "what@ever.admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
	profile := profileFor(payload)
	blocks := []string{"email=what@ever.", "admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", "&uid=10&role=use"}
	if profile[:16] != blocks[0] {
		t.Errorf("Error on first block \n%s", profile[:16])
	}
	if profile[16:32] != blocks[1] {
		t.Errorf("Error on first block \n%s", profile[16:32])
	}
}

func TestCutAndPaste(t *testing.T) {
	ci := EncryptProfile("what@ever.com")
	payload := "what@ever.admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
	ct := EncryptProfile(payload)
	c := make([]byte, 16*3)
	for i := 0; i < 16*2; i++ {
		c[i] = ci[i]
	}
	for i := 16; i < 16*2; i++ {
		c[i+16] = ct[i]
	}
	p := DecryptProfile(c)
	if p.Email != "what@ever" && p.UID != 10 {
		t.Error("Error on email or UID")
	}
	if p.Role != "admin" {
		t.Errorf("Role is not admin but %s", p.Role)
	}
}
