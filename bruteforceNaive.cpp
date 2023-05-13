//bruteforceNaive.cpp
//Tambien cifra un texto cualquiera con un key arbitrario.
//OJO: asegurarse que la palabra a buscar sea lo suficientemente grande
//  evitando falsas soluciones ya que sera muy improbable que tal palabra suceda de
//  forma pseudoaleatoria en el descifrado.
//>> mpic++ bruteforceNaive.cpp -o desBrute -lcryptopp
//>> mpiexec -n <N> ./desBrute

#include <mpi.h>
#include <iostream>
#include <cryptopp/des.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <string>

using namespace std;

void longToByteArray(long key, CryptoPP::byte* keyBytes, size_t keyLength) {
    for (size_t i = 0; i < keyLength; ++i) {
        keyBytes[i] = static_cast<CryptoPP::byte>((key >> (7 * (keyLength - i - 1))) & 0xFE);
    }
}

string encrypt(long key, string plaintext) {
    const size_t keyLength = CryptoPP::DES::DEFAULT_KEYLENGTH;
    CryptoPP::byte keyBytes[keyLength];
    longToByteArray(key, keyBytes, keyLength);

    CryptoPP::ECB_Mode<CryptoPP::DES>::Encryption encryption;
    encryption.SetKey(keyBytes, keyLength);

    string ciphertext;
    CryptoPP::StringSource(plaintext, true,
        new CryptoPP::StreamTransformationFilter(encryption,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(ciphertext)
            )
        )
    );

    return ciphertext;
}

string decrypt(long key, string ciphertext) {
    const size_t keyLength = CryptoPP::DES::DEFAULT_KEYLENGTH;
    CryptoPP::byte keyBytes[keyLength];
    longToByteArray(key, keyBytes, keyLength);

    CryptoPP::ECB_Mode<CryptoPP::DES>::Decryption decryption;
    decryption.SetKey(keyBytes, keyLength);
    try {
        string plaintext;
        CryptoPP::StringSource(ciphertext, true,
            new CryptoPP::HexDecoder(
                new CryptoPP::StreamTransformationFilter(decryption,
                    new CryptoPP::StringSink(plaintext)
                )
            )
        );
        return plaintext;
    } catch (const CryptoPP::InvalidCiphertext& e) {
        // nada :)
    }
    return "";

}

bool tryKey(long key, string ciphertext) {
    string search = "prueba de proyecto";
    string plaintext = decrypt(key, ciphertext);
    return plaintext.find(search) != string::npos;
}

string eltexto = "Esta es una prueba de proyecto 2";
long the_key = 123456L;

int main(int argc, char *argv[]) {
    int N, rank;
    long upper = (1L << 56); 
    long mylower, myupper;
    MPI_Status st;
    MPI_Request req;
    MPI_Comm comm = MPI_COMM_WORLD;

    // Inicializar MPI
    MPI_Init(NULL, NULL);
    MPI_Comm_size(comm, &N);
    MPI_Comm_rank(comm, &rank);

    string ciphertext = encrypt(the_key, eltexto);

    if (rank == 0) {
        cout << "Plaintext: " << eltexto << endl;
        cout << "Ciphertext: " << ciphertext << endl;
    }

    // Distribuir trabajo de forma naive
    long range_per_node = upper / N;
    mylower = range_per_node * rank;
    myupper = range_per_node * (rank + 1) - 1;
    if (rank == N - 1) {
        // Compensar residuo
        myupper = upper;
    }
    cout << "Process " << rank << " -> lower: " << mylower << " upper: " << myupper << endl;

    long found = -1L;
    int ready;

    // Non blocking receive, revisar en el for si alguien ya encontró
    MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);

    for (long i = mylower; i < myupper; i++) {
        MPI_Test(&req, &ready, MPI_STATUS_IGNORE);
        if (ready)
            break; // Ya encontraron, salir


        if (tryKey(i, ciphertext)) {
            found = i;
            cout << "Process " << rank << " found the key" << endl;
            for (int node = 0; node < N; node++) {
                MPI_Send(&found, 1, MPI_LONG, node, 0, comm); // Avisar a otros
            }
            break;
        }
    }
    if (rank == 0) {
        MPI_Wait(&req, &st);

        string decrypted = decrypt(found, ciphertext);
        cout << "Key found = " << found << endl;
        cout << "Decrypted = " << decrypted << endl;

    }

    cout << "Process " << rank << " exiting" << endl;

    // Finalizar entorno MPI
    MPI_Finalize();
    return 0;
}