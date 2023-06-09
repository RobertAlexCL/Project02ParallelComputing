# Project 2 Parallel Computing
# Parallel Key Search using MPI

This repository contains an implementation of a parallel key search algorithm using the Message Passing Interface (MPI) framework. The program aims to find a specific key that can decrypt a given ciphertext created with DES encryption using a brute-force approach.

## Dependencies

To compile and run this program, you need to have the following dependencies installed:

- Crypto++ library: [https://www.cryptopp.com/](https://www.cryptopp.com/)
- MPI library: [https://www.open-mpi.org/](https://www.open-mpi.org/)

## Compilation

Use the following command to compile the programs:

``` bash
mpic++ bruteforceNaive.cpp -o desBrute -lcryptopp
```

``` bash
mpic++ bruteforceApproach01.cpp -o desBrute01 -lcryptopp
```

``` bash
mpic++ bruteforceApproach02.cpp -o desBrute02 -lcryptopp
```


## Execution

To run the programs, use the following command:
``` bash
mpiexec -n [number of processes] ./desBrute [key]
```
``` bash
mpiexec -n [number of processes] ./desBrute01 [key]
```
``` bash
mpiexec -n [number of processes] ./desBrute02 [key]
```
Replace `[number of processes]` with the desired number of MPI processes, and `[key]` with the key value you want to use for encryption and decryption.

## Authors

- Sebastián Maldonado Arnau 18003
- Alexis Renato Estrada Martinez 181099
- Roberto Alejandro Castillo de Leon 18546