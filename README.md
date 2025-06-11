This product includes software developed by the Lattigo project
(https://github.com/ldsec/lattigo), licensed under the Apache License 2.0.



HOW TO INSTALL
==============
use "go mod tidy" 


HOW TO RUN UNITTEST
===================
1. go to target folder (e.g for the faster impelementation of ckks "cd fckks")
2. run go test command "go test" (x is the number of parties e.g for 2 parites set x to 2)


HOW TO RUN BENCHMARK
====================
1. go to target folder (e.g for the faster impelementation of ckks "cd fckks")
2. run go benchmark command "go test -bench=. -benchtime=10x -timeout=0" (This runs 10 repetition of benchmark and output average elapsed time)
