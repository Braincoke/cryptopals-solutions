package set1

import "testing"

// TestByteToBase64Simple1 "abc" => "YWJj"
func TestByteToBase64Simple1(t *testing.T) {
	testString := "abc"
	expected := "YWJj"
	ans := BytesToBase64([]byte(testString))
	if string(ans) != expected {
		t.Errorf("base64(\"%s\") = %s ; Expected %s", testString, string(ans), expected)
	}
}

// TestByteToBase64Simple2 "Hello World 123456" => "SGVsbG8gV29ybGQgMTIzNDU2"
func TestByteToBase64Simple2(t *testing.T) {
	testString := "Hello World 123456"
	expected := "SGVsbG8gV29ybGQgMTIzNDU2"
	ans := BytesToBase64([]byte(testString))
	if string(ans) != expected {
		t.Errorf("base64(\"%s\") = %s ; Expected %s", testString, string(ans), expected)
	}
}

// TestByteToBase64Special1 "abc$ +:/_{" => "YWJjJCArOi9few=="
func TestByteToBase64Special1(t *testing.T) {
	testString := "abc$ +:/_{"
	expected := "YWJjJCArOi9few=="
	ans := BytesToBase64([]byte(testString))
	if string(ans) != expected {
		t.Errorf("base64(\"%s\") = %s ; Expected %s", testString, string(ans), expected)
	}
}

// TestHexToBase64Simple1 "616263" => "YWJj"
func TestHexToBase64Simple1(t *testing.T) {
	testString := "616263"
	expected := "YWJj"
	ans := HexToBase64(testString)
	if string(ans) != expected {
		t.Errorf("HexToBase64(\"%s\") = %s ; Expected %s", testString, string(ans), expected)
	}
}

// TestHexToBase64Simple2 "48656c6c6f20576f726c6420313233343536" => "SGVsbG8gV29ybGQgMTIzNDU2"
func TestHexToBase64Simple2(t *testing.T) {
	testString := "48656c6c6f20576f726c6420313233343536"
	expected := "SGVsbG8gV29ybGQgMTIzNDU2"
	ans := HexToBase64(testString)
	if string(ans) != expected {
		t.Errorf("HexToBase64(\"%s\") = %s ; Expected %s", testString, string(ans), expected)
	}
}

// TestHexToBase64Special "61626324202b3a2f5f7b" => "YWJjJCArOi9few=="
func TestHexToBase64Special(t *testing.T) {
	testString := "61626324202b3a2f5f7b"
	expected := "YWJjJCArOi9few=="
	ans := HexToBase64(testString)
	if string(ans) != expected {
		t.Errorf("HexToBase64(\"%s\") = %s ; Expected %s", testString, string(ans), expected)
	}
}

// TestHexToBase64Cryptopal "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d" => "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
func TestHexToBase64Cryptopal(t *testing.T) {
	testString := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	ans := HexToBase64(testString)
	if string(ans) != expected {
		t.Errorf("HexToBase64(\"%s\") = %s ; Expected %s", testString, string(ans), expected)
	}
}
