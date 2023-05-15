/**
 * Filename: bruteforceApproach01.cpp
 * Description: Parallel Key Search using MPI
 * Authors:
 * - Sebastián Maldonado Arnau           18003
 * - Alexis Renato Estrada Martinez     181099
 * - Roberto Alejandro Castillo de Leon  18546
 * Date: 2023-05-14
 *
 * Compilation: mpic++ bruteforceApproach01.cpp -o desBrute01 -lcryptopp
 * Execution: mpiexec -n [number of processes] ./desBrute01 [key]
 * 
 * Dependencies:
 * - Crypto++ library: https://www.cryptopp.com/
 * - MPI library: https://www.open-mpi.org/
 */

#include <mpi.h>
#include <iostream>
#include <fstream>
#include <string>
#include <streambuf>
#include <cryptopp/des.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>

using namespace std;


/**
 * Converts a long value to a Crypto++ byte array representation.
 *
 * @param key The long value to be converted.
 * @param keyBytes A pointer to the byte array where the converted bytes will be stored.
 * @param keyLength The length of the byte array.
 *
*/
void longToByteArray(long key, CryptoPP::byte* keyBytes, size_t keyLength) {
    // shift key 1 bit left to avoid even/odd keys colliding
    long temp = key << 1;

    // for each DES byte take 7 bits of the long until finished (8th bit is parity (not used))
    for (size_t i = 0; i < keyLength; ++i) {
        keyBytes[i] = static_cast<CryptoPP::byte>((temp >> (7 * (keyLength - i - 1))) & 0xFE);
    }
}


/**
 * Reads the contents of a file and broadcasts it to all processes using MPI.
 *
 * @param filename The name of the file to be read.
 * @param rank The rank of the current process.
 * @return The contents of the file as a string.
 *
 */
string handleFile(string filename, int rank) {
    string fileContents;

    // Process 0 reads the file
    if (rank == 0) {
        ifstream inputFile(filename);

        if (inputFile.is_open()) {
            string line;
            while (getline(inputFile, line)) {
                // Append line to fileContents string
                fileContents += line + '\n';
            }

            inputFile.close();
        } else {
            cerr << "Error opening file. :(" << endl;
            // Abort MPI in all processes if file handling fails.
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
    }

    // Process 0 broadcasts fileContents to the rest
    int fileContentsSize = fileContents.size();
    MPI_Bcast(&fileContentsSize, 1, MPI_INT, 0, MPI_COMM_WORLD);
    fileContents.resize(fileContentsSize); // resize string to receive data
    MPI_Bcast(fileContents.data(), fileContentsSize, MPI_CHAR, 0, MPI_COMM_WORLD);
    
    return fileContents;
}

pair<long, long> split_range(long lower, long upper) {
    long middle = lower + (upper - lower) / 2;
    return make_pair(lower, middle);
}



/**
 * Encrypts the given plaintext using the provided key.
 *
 * @param key The encryption key as a long value.
 * @param plaintext The plaintext to be encrypted.
 * @return The ciphertext as a string.
 *
 */
string encrypt(long key, string plaintext) {
    const size_t keyLength = CryptoPP::DES::DEFAULT_KEYLENGTH;
    CryptoPP::byte keyBytes[keyLength];
    // convert long key to byte array
    longToByteArray(key, keyBytes, keyLength);

    // set encryption to DES
    CryptoPP::ECB_Mode<CryptoPP::DES>::Encryption encryption;
    encryption.SetKey(keyBytes, keyLength); // set key

    string ciphertext;
    CryptoPP::StringSource(plaintext, true,
        new CryptoPP::StreamTransformationFilter(encryption, // encrypt data
            new CryptoPP::HexEncoder(                        // then encode to hex
                new CryptoPP::StringSink(ciphertext)
            )
        )
    );

    return ciphertext;
}


/**
 * Decrypts the given ciphertext using the provided key.
 *
 * @param key The encryption key as a long value.
 * @param ciphertext The ciphertext to be encrypted.
 * @return The plaintext as a string.
 *
 */
string decrypt(long key, string ciphertext) {
    const size_t keyLength = CryptoPP::DES::DEFAULT_KEYLENGTH;
    CryptoPP::byte keyBytes[keyLength];
    // convert long key to byte array
    longToByteArray(key, keyBytes, keyLength);

    // set decryption to DES
    CryptoPP::ECB_Mode<CryptoPP::DES>::Decryption decryption;
    decryption.SetKey(keyBytes, keyLength); // set key
    try {
        string plaintext;
        CryptoPP::StringSource(ciphertext, true,
            new CryptoPP::HexDecoder(                                // first decode hex
                new CryptoPP::StreamTransformationFilter(decryption, // then decode data
                    new CryptoPP::StringSink(plaintext)
                )
            )
        );
        return plaintext;

    // if the key is invalid it just exits instead of throwing an exception
    } catch (const CryptoPP::InvalidCiphertext& e) {
        // nada :)
    }
    return "";

}


/**
 * Tries a given key to decrypt the ciphertext and checks if a specific search string is found in the resulting plaintext
 * to determine if it was successful.
 *
 * @param key The decryption key as a long value.
 * @param ciphertext The ciphertext to be decrypted.
 * @return A boolean indicating if the search string was found in the decrypted plaintext.
 *
 */
bool tryKey(long key, string ciphertext) {
    string search = "prueba de proyecto";
    string plaintext = decrypt(key, ciphertext);
    return plaintext.find(search) != string::npos;
}


int main(int argc, char *argv[]) {
    int N, rank;
    long upper = (1L << 56); // max size for DES key
    long the_key;
    long mylower, myupper;
    MPI_Status st;
    MPI_Request req;
    MPI_Comm comm = MPI_COMM_WORLD;

    // MPI initialization
    MPI_Init(NULL, NULL);
    MPI_Comm_size(comm, &N);
    MPI_Comm_rank(comm, &rank);

    // read key as parameter
    if (argc > 1) {
        try {
            the_key = stol(argv[1]); // convert parameter to long
        } catch (const invalid_argument& ex) {
            cerr << "Invalid parameter. Key could not be cast to long." << endl;
            MPI_Abort(MPI_COMM_WORLD, 1);
            return -1;
        }
    } else {
        cerr << "You need to pass the key as a command line argument." << endl;
        MPI_Abort(MPI_COMM_WORLD, 1);
        return -1;
    }

    // read plaintext from file
    string plaintext = handleFile("plaintext.txt", rank);

    string ciphertext = encrypt(the_key, plaintext);

    if (rank == 0) {
        cout << "Plaintext: " << plaintext << endl;
        cout << "Ciphertext: " << ciphertext << endl;
    }

    // Divide key range into subtrees
    long totalLower = 0;
    long totalUpper = upper;

    long myMiddle;
    tie(mylower, myMiddle) = split_range(totalLower + rank * (totalUpper - totalLower) / N,
                                      totalLower + (rank + 1) * (totalUpper - totalLower) / N);

    if (rank == N - 1) {
        // Compensate for remainder
        myMiddle = totalUpper;
    }

    cout << "Process " << rank << " -> lower: " << mylower << " upper: " << myMiddle << endl;

    long found = -1L;
    int ready;

    // Non blocking receive to check within for-loop if someone found the key
    MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);

    double start = MPI_Wtime(); // Start measuring execution time
    for (long i = mylower; i < myMiddle; i++) {
        MPI_Test(&req, &ready, MPI_STATUS_IGNORE);
        if (ready)
            break; // Someone found the key, exit the loop

        if (tryKey(i, ciphertext)) {
            found = i;
            cout << "Process " << rank << " found the key" << endl;
            // Inform others that the key was found
            for (int node = 0; node < N; node++) {
                MPI_Send(&found, 1, MPI_LONG, node, 0, comm);
            }
            break;
        }
    }

    double end = MPI_Wtime(); // Stop measuring execution time
    double delta = end - start;

    // Process 0 prints info
    if (rank == 0) {
        MPI_Wait(&req, &st);

        string decrypted = decrypt(found, ciphertext);
        cout << endl << "Key found = " << found << endl;
        cout << "Decrypted = " << decrypted << endl;
        cout << "Execution time: " << delta << endl;

    }

    cout << "Process " << rank << " exiting" << endl;

    // Finalize MPI environment
    MPI_Finalize();
    return 0;
}