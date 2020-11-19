# Cryptopals Challenges

This repository contains the solutions for the [Cryptopals crypto challenges](https://cryptopals.com).
Each package contains the solutions to one set of challenges. You can look through the commits to see the incremental solutions to each challenge.

## Solutions explanation

I have written write-ups for the challenges I found the most interesting on my [blog](https://braincoke.fr/write-up/Cryptopals), check them out !

## Running the solutions

New challenges might requires the solutions you built previously.
For instance the solution for the fourth challenge of Set 1 might rely on the code written for the challenge 2 and 3.
The file `cryptopals.go` contains the solutions to each challenge, based on the code written in each package.

To run the solution build the program and call it with the challenge number `cryptopals <challenge_number>`

~~~bash
go build
./cryptopals 4
~~~

or

~~~bash
go run cryptopals 4
~~~
