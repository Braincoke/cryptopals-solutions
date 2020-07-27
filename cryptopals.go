package main

import (
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
