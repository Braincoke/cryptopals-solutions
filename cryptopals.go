package main

import (
	"cryptopals/set1"
	"cryptopals/set2"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
)

/**
 * Cryptopal challenges
 * https://cryptopals.com/sets/
 */

func main() {
	// Verify that the user gave a set and a challenge number
	args := os.Args[1:]
	if len(args) != 1 {
		fmt.Println("Please specify the challenge to run: ./cryptopals 3 to run the third challenge")
		os.Exit(2)
	}
	// Verify that they are integers
	challengeToRun, errChallenge := strconv.ParseInt(args[0], 0, 64)
	if errChallenge != nil {
		fmt.Println("The set and challenge to run must be numbers: ./cryptopals 3 to run the third challenge")
		os.Exit(3)
	}

	// Run the challenge
	/**
	 * Cryptopals set 1
	 * https://cryptopals.com/sets/1/
	 */
	switch challengeToRun {
	case 1:
		fmt.Println("### Set 1 - Challenge 1 ###")
		testString := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
		expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
		base64 := set1.HexToBase64(testString)
		fmt.Printf("Test string:\t\t%s\n", testString)
		fmt.Printf("Base64 conversion:\t%s\n", string(base64))
		fmt.Printf("Expected base64:\t%s\n", expected)
		fmt.Printf("Result == Expected:\t%t	\n", expected == string(base64))
	case 2:
		fmt.Println("### Set 1 - Challenge 2 ###")
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
		fmt.Println("### Set 1 - Challenge 3 ###")
		cipher := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
		score, plaintext := set1.SingleByteXorCrack(cipher)
		fmt.Printf("Cipher:\t\t%s\n", cipher)
		fmt.Printf("Plaintext:\t%s\n", plaintext)
		fmt.Printf("Score:\t\t%d\n", score)
	case 4:
		fmt.Println("### Set 1 - Challenge 4 ###")
		score, cipher, plaintext := set1.DetectSingleCharXOR("set1/challenge4-data.txt")
		fmt.Printf("Cipher:\t\t%s\n", cipher)
		fmt.Printf("Plaintext:\t%s", plaintext)
		fmt.Printf("Score:\t\t%d\n", score)
	case 5:
		fmt.Println("### Set 1 - Challenge 5 ###")
		key := "ICE"
		plaintext := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
		expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
		cipher := set1.RepeatingXORString(key, plaintext)
		fmt.Printf("Plaintext:\t\n----------\n%s\n-----------\n", plaintext)
		fmt.Printf("Key:\t\t%s\n", key)
		fmt.Printf("Cipher:\t\t%s\n", cipher)
		fmt.Printf("Expected:\t%s\n", expected)
		fmt.Printf("Cipher == Expected:\t%t	\n", expected == cipher)
	case 6:
		fmt.Println("### Set 1 - Challenge 6 ###")
		filename := "set1/challenge6-data.txt"
		data, _ := set1.ReadBase64File(filename)
		key, plaintext := set1.BreakRepeatingKeyXOR(data)
		fmt.Printf("Key:\t%s\n", string(key))
		fmt.Println("--------------------------------------------")
		fmt.Print(string(plaintext))
	case 7:
		fmt.Println("### Set 1 - Challenge 7 ###")
		Nb := 4
		// Format the ciphertext as []uint32
		filename := "set1/challenge7-data.txt"
		data, _ := set1.ReadBase64File(filename)
		ciphertext := make([]uint32, len(data)/Nb) // Special case where len(data) divisible by 4
		for i := 0; i < len(ciphertext); i++ {
			ciphertext[i] = binary.BigEndian.Uint32(data[i*Nb : i*Nb+4])
		}
		// Set up the key
		keyBytes := []byte("YELLOW SUBMARINE")
		key := make([]uint32, Nb)
		for i := 0; i < Nb; i++ {
			key[i] = binary.BigEndian.Uint32(keyBytes[i*Nb : i*Nb+4])
		}
		// Decrypt
		plaintext := set1.ECBDecrypt(ciphertext, key, 4, 10)
		plaintextBytes := make([]byte, len(plaintext)*Nb)
		for i := 0; i < len(plaintext); i++ {
			bytes := make([]byte, Nb)
			binary.BigEndian.PutUint32(bytes, plaintext[i])
			for j := 0; j < Nb; j++ {
				plaintextBytes[i*Nb+j] = bytes[j]
			}
		}
		fmt.Print(string(plaintextBytes))
	case 8:
		fmt.Println("### Set 1 - Challenge 8 ###")
		lines, _ := set1.ReadFileLines("set1/challenge8-data.txt")
		detected := 0
		cipherlines := make([]string, 1)
		for _, line := range lines {
			isECB, _ := set1.DetectECB([]byte(line))
			if isECB {
				detected++
				cipherlines = append(cipherlines, line)
			}
		}
		fmt.Printf("Detected %d lines using ECB\n", detected)
		for _, cipher := range cipherlines {
			fmt.Println(cipher)
		}
	/**
	 * Cryptopals set 2
	 * https://cryptopals.com/sets/2/
	 */
	case 9:
		fmt.Println("### Set 2 - Challenge 9 ###")
		input := []byte("YELLOW SUBMARINE")
		var blockSize byte = 20
		paddedBlock, _ := set2.PadBlockPKCS7(input, blockSize)
		fmt.Printf("%q\n", paddedBlock)
	case 10:
		fmt.Println("### Set 2 - Challenge 10 ###")
		Nk := 4
		Nr := 10
		iv := make([]byte, 16)
		key := []byte("YELLOW SUBMARINE")
		ciphertext, _ := set1.ReadBase64File("./set2/challenge10-data.txt")
		plaintext := set2.DecryptCBC(ciphertext, iv, key, Nk, Nr)
		fmt.Print(string(plaintext))
	case 11:
		fmt.Println("### Set 2 - Challenge 11 ###")
		// Note that this plaintext helps a lot in the detection
		// since are almost guaranteed to have repeating blocks
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
		totalGuess := 200
		correctGuess := 0
		for i := 0; i < totalGuess; i++ {
			ciphertext, mode := set2.EncryptData(plaintext)
			isECB, _ := set1.DetectECB(ciphertext)
			var detectedMode string
			if isECB {
				detectedMode = "ECB"
			} else {
				detectedMode = "CBC"
			}
			if detectedMode == mode {
				correctGuess++
			}
		}
		fmt.Printf("Out of %d guesses, %d were correct\n", totalGuess, correctGuess)
	case 12:
		fmt.Println("### Set 2 - Challenge 12 ###")
		unknownStringB64 := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
		unknownString, _ := base64.StdEncoding.DecodeString(unknownStringB64)

		// Detect block size
		blockSize := set2.DetectBlockSize(set2.Challenge12Oracle)
		fmt.Printf("Detected a block size of %d bytes\n", blockSize)

		fmt.Println("Decrypting the unknown string...")
		decryptedBytes := make([]byte, 0)
		for i := 0; i < len(unknownString); i++ {
			decryptedByte, err := set2.DecryptByte(i, decryptedBytes, blockSize)
			if err != nil {
				fmt.Println("Error when cracking the byte")
			}
			if decryptedByte != unknownString[i] {
				fmt.Printf("Expected to decrypt byte %q but decrypted %q\n", unknownString[i], decryptedByte)
			}
			decryptedBytes = append(decryptedBytes, decryptedByte)
		}
		fmt.Println("------------------------------------------------------------------")
		fmt.Print(string(decryptedBytes))
	case 13:
		fmt.Println("### Set 2 - Challenge 13 ###")
		fmt.Println("Check out the full explanation at https://braincoke.fr/write-up/cryptopals/cryptopals-ecb-cut-and-paste/")
		fmt.Println("Getting ciphertext ci for profile 'what@ever.com'...")
		ci := set2.EncryptProfile("what@ever.com")
		payload := "what@ever.admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
		fmt.Printf("Getting the ciphertext ct for the payload = '%q'\n", payload)
		ct := set2.EncryptProfile(payload)
		fmt.Println("Crafting the final ciphertext c = [ci[0], ci[1], ct[2]]")
		c := make([]byte, 16*3)
		for i := 0; i < 16*2; i++ {
			c[i] = ci[i]
		}
		for i := 16; i < 16*2; i++ {
			c[i+16] = ct[i]
		}
		fmt.Println("Decrypting c for verification:")
		p := set2.DecryptProfile(c)
		fmt.Printf("Role = %s\n", p.Role)
	case 14:
		fmt.Println("### Set 2 - Challenge 14 ###")
		unknownStringB64 := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
		unknownString, _ := base64.StdEncoding.DecodeString(unknownStringB64)

		oracle := set2.Challenge14Oracle
		// Detect block size
		blockSize := set2.DetectBlockSize(oracle)
		fmt.Printf("Detected a block size of %d bytes\n", blockSize)
		// Detect prefix length
		prefixLength := set2.DetectPrefixLength14(blockSize, oracle)
		fmt.Printf("Detected a prefix size of %d bytes\n", prefixLength)

		fmt.Println("Decrypting the unknown string...")
		decryptedBytes := make([]byte, 0)
		for i := 0; i < len(unknownString); i++ {
			decryptedByte, err := set2.DecryptByte14(prefixLength, i, decryptedBytes, blockSize, oracle)
			if err != nil {
				fmt.Println("Error when cracking the byte")
			}
			if decryptedByte != unknownString[i] {
				fmt.Printf("Expected to decrypt byte %q but decrypted %q\n", unknownString[i], decryptedByte)
			}
			decryptedBytes = append(decryptedBytes, decryptedByte)
		}
		fmt.Println("------------------------------------------------------------------")
		fmt.Print(string(decryptedBytes))
	case 15:
		fmt.Println("### Set 2 - Challenge 15 ###")
		fmt.Println("See the implementation directly for this challenge")
	case 16:
		fmt.Println("### Set 2 - Challenge 16 ###")
		input := []byte("YELLOW_SUBMARINE_DETROIT_TORINO_etcetera")
		c, iv := set2.Challenge16EncryptionOracle(input)
		// First plaintext block
		p1 := []byte("comment1=cooking")
		fmt.Printf("-- First plaintext block is always '%s'.\n", string(p1))
		// i1 = p1 ^ c0
		i1, _ := set1.XOR([]byte(p1), iv)
		fmt.Printf("-- Intermediate value i1 = Decrypt(C1) = P1 xor IV is '%x'.\n", string(i1))
		// What we whish p1 to be equal to
		targetp1 := []byte(";admin=true;1234")
		fmt.Printf("-- We want P1 to be equal to '%s' after the decryption.\n", string(targetp1))
		// What the iv should be to have this plaintext
		craftedIV, _ := set1.XOR(targetp1, i1)
		fmt.Printf("-- We craft a new IV = targetP1 xor I1 = %x.\n", string(craftedIV))
		// craftedIV := iv
		fmt.Println("Testing...")
		fmt.Printf("Admin = %t\n", set2.Challenge16IsAdmin(c, craftedIV))
	default:
		fmt.Println(" - Unknown challenge number !!!")
		os.Exit(4)
	}
	os.Exit(0)
}
