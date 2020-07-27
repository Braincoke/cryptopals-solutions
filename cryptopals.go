package main

import (
	"cryptopals/set1"
	"fmt"
	"os"
	"strconv"
)

/**
 * Cryptopal challenges
 * https://cryptopals.com/sets/1/
 */

func main() {
	// Verify that the user gave a set and a challenge number
	args := os.Args[1:]
	if len(args) != 2 {
		fmt.Println("Please specify the set and the challenge to run: ./cryptopals 1 3 to run the third challenge of the first set")
		os.Exit(2)
	}
	// Verify that they are integers
	setToRun, errSet := strconv.ParseInt(args[0], 0, 64)
	challengeToRun, errChallenge := strconv.ParseInt(args[1], 0, 64)
	if errSet != nil || errChallenge != nil {
		fmt.Println("The set and challenge to run must be numbers: ./cryptopals 1 3 to run the third challenge of the first set")
		os.Exit(3)
	}

	// Run the challenge
	switch setToRun {
	/**
	 * Cryptopals set 1
	 * https://cryptopals.com/sets/1/
	 */
	case 1:
		fmt.Print("### Set 1")
		switch challengeToRun {
		case 1:
			fmt.Println(" - Challenge 1 ###")
			testString := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
			expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
			base64 := set1.HexToBase64(testString)
			fmt.Printf("Test string:\t\t%s\n", testString)
			fmt.Printf("Base64 conversion:\t%s\n", string(base64))
			fmt.Printf("Expected base64:\t%s\n", expected)
			fmt.Printf("Result == Expected:\t%t	\n", expected == string(base64))
		case 2:
			fmt.Println(" - Challenge 2 ###")
			var a = "1c0111001f010100061a024b53535009181c"
			var b = "686974207468652062756c6c277320657965"
			var expected = "746865206b696420646f6e277420706c6179"
			ans, _ := set1.XORHex(a, b)
			fmt.Printf("a:\t\t%s\n", a)
			fmt.Printf("b:\t\t%s\n", b)
			fmt.Printf("a ^ b:\t\t%s\n", ans)
			fmt.Printf("expected:\t%s\n", expected)
			fmt.Printf("Result == Expected:\t%t\n", expected == ans)
		case 3:
			fmt.Println(" - Challenge 3 ###")
			cipher := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
			score, plaintext := set1.SingleByteXorCrack(cipher)
			fmt.Printf("Cipher:\t\t%s\n", cipher)
			fmt.Printf("Plaintext:\t%s\n", plaintext)
			fmt.Printf("Score:\t\t%d\n", score)
		case 4:
			fmt.Println(" - Challenge 4 ###")
			score, cipher, plaintext := set1.DetectSingleCharXOR("set1/challenge4-data.txt")
			fmt.Printf("Cipher:\t\t%s\n", cipher)
			fmt.Printf("Plaintext:\t%s", plaintext)
			fmt.Printf("Score:\t\t%d\n", score)
		case 5:
			fmt.Println(" - Challenge 5 ###")
			key := "ICE"
			plaintext := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
			expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
			cipher := set1.RepeatingXORString(key, plaintext)
			fmt.Printf("Plaintext:\t\n----------\n%s\n-----------\n", plaintext)
			fmt.Printf("Key:\t\t%s\n", key)
			fmt.Printf("Cipher:\t\t%s\n", cipher)
			fmt.Printf("Expected:\t%s\n", expected)
			fmt.Printf("Cipher == Expected:\t%t	\n", expected == cipher)
		default:
			fmt.Println(" - Unknown challenge number !!!")
			os.Exit(5)
		}
	default:
		fmt.Println("!!! Unknown Set number !!!")
		os.Exit(4)
	}
	os.Exit(0)
}
