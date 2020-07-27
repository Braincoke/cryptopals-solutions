# Cryptopals Challenges

This repository contains the solutions for the [Cryptopals crypto challenges](https://cryptopals.com).
Each package contains the solutions to one set of challenges. You can look through the commits to see the incremental solutions to each challenge.

## Running the solutions

New challenges might requires the solutions you built previously.
For instance the solution for the fourth challenge of Set 1 might rely on the code written for the challenge 2 and 3.
The file `cryptopals.go` contains the solutions to each challenge, based on the code written in each package.

To run the solution build the program and call it with the set number and challenge number `cryptopals <set_number> <challenge_number>`

~~~bash
go build
./cryptopals 1 4
~~~
