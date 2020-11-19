package set2

import (
	"crypto/sha512"
	"strconv"
	"strings"
)

// Profile of a user
type Profile struct {
	Email string
	UID   int
	Role  string
}

// decodeProfile returns a profile struct from an encoded string
func decodeProfile(encoded string) Profile {
	p := Profile{}
	pairs := strings.Split(encoded, "&")
	for _, pair := range pairs {
		split := strings.Split(pair, "=")
		key := split[0]
		value := split[1]
		switch key {
		case "email":
			p.Email = value
		case "uid":
			p.UID, _ = strconv.Atoi(value)
		case "role":
			p.Role = value
		}
	}
	return p
}

func encodeProfile(p Profile) string {
	return "email=" + p.Email + "&uid=" + strconv.Itoa(p.UID) + "&role=" + p.Role
}

func profileFor(email string) string {
	sanitizedEmail := strings.ReplaceAll(email, "&", "-")
	sanitizedEmail = strings.ReplaceAll(sanitizedEmail, "=", "-")
	p := Profile{Email: sanitizedEmail, UID: 10, Role: "user"}
	return encodeProfile(p)
}

// EncryptProfile creates a new profile from an email and return its encryption
func EncryptProfile(email string) []byte {
	// Hash a value and keep the first 16 bytes to create the key
	hash := sha512.Sum512([]byte("This string is hashed to a key"))
	key := hash[:16]

	encodedProfile := profileFor(email)
	return EncryptECB([]byte(encodedProfile), key, 4, 10)
}

// DecryptProfile decrypts and decodes a profile
func DecryptProfile(ciphertext []byte) Profile {
	// Hash a value and keep the first 16 bytes to create the key
	hash := sha512.Sum512([]byte("This string is hashed to a key"))
	key := hash[:16]

	decryptedProfile := DecryptECB(ciphertext, key, 4, 10)
	stringProfile := string(decryptedProfile)
	return decodeProfile(stringProfile)
}
