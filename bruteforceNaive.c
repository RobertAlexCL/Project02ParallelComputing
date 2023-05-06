//bruteforceNaive.c
//Tambien cifra un texto cualquiera con un key arbitrario.
//OJO: asegurarse que la palabra a buscar sea lo suficientemente grande
//  evitando falsas soluciones ya que sera muy improbable que tal palabra suceda de
//  forma pseudoaleatoria en el descifrado.
//>> mpicc bruteforce.c -o desBrute
//>> mpirun -np <N> desBrute

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <unistd.h>
#include <openssl/des.h>

void encrypt(const_DES_cblock *key, const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext) {
    DES_key_schedule schedule;
    DES_set_key_unchecked(key, &schedule);
    DES_ecb_encrypt((const_DES_cblock *)plaintext, (DES_cblock *)ciphertext, &schedule, DES_ENCRYPT);
}

void decrypt(const_DES_cblock *key, const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext) {
    DES_key_schedule schedule;
    DES_set_key_unchecked(key, &schedule);
    DES_ecb_encrypt((const_DES_cblock *)ciphertext, (DES_cblock *)plaintext, &schedule, DES_DECRYPT);
}

int tryKey(const_DES_cblock *key, const unsigned char *ciphertext, int ciphertext_len) {
    char search[] = "es una prueba de";
    unsigned char temp[ciphertext_len + 1];
    memcpy(temp, ciphertext, ciphertext_len);
    temp[ciphertext_len] = 0;
    decrypt(key, temp, ciphertext_len, temp);
    return strstr((char *)temp, search) != NULL;
}

unsigned char eltexto[] = "Esta es una prueba de proyecto 2";
long the_key = 123456L;

int main(int argc, char *argv[]) {
    int N, id;
    long upper = (1L << 56); 
    long mylower, myupper;
    MPI_Status st;
    MPI_Request req;

    int ciphlen = strlen((char *)eltexto);
    MPI_Comm comm = MPI_COMM_WORLD;

    // Cifrar el texto
    unsigned char ciphertext[ciphlen + 1];
    memcpy(ciphertext, eltexto, ciphlen);
    ciphertext[ciphlen] = 0;
    DES_key_schedule key;
    DES_set_key_unchecked((DES_cblock *)&the_key, &key);
    encrypt(&key, ciphertext, ciphlen, ciphertext);

    // Inicializar MPI
    MPI_Init(NULL, NULL);
    MPI_Comm_size(comm, &N);
    MPI_Comm_rank(comm, &id);

    long found = 0L;
    int ready = 0;

    // Distribuir trabajo de forma naive
    long range_per_node = upper / N;
    mylower = range_per_node * id;
    myupper = range_per_node * (id + 1) - 1;
    if (id == N - 1) {
        // Compensar residuo
        myupper = upper;
    }
    printf("Process %d lower %ld upper %ld\n", id, mylower, myupper);

    // Non blocking receive, revisar en el for si alguien ya encontró
    MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);

    for (long i = mylower; i < myupper; ++i) {
        MPI_Test(&req, &ready, MPI_STATUS_IGNORE);
        if (ready)
            break; // Ya encontraron, salir

        DES_key_schedule temp_key; // Cambiado a DES_key_schedule
        DES_set_key_unchecked((DES_cblock *)&i, &temp_key); // Cambiado a &temp_key
        printf("Process %d trying key %ld\n", id, i); // Mensaje de depuración

        if (tryKey(&temp_key, ciphertext, ciphlen)) {
            found = i;
            printf("Process %d found the key\n", id);
            for (int node = 0; node < N; node++) {
                MPI_Send(&found, 1, MPI_LONG, node, 0, comm); // Avisar a otros
            }
            break;
        }
    }

    // Wait y luego imprimir el texto
    if (id == 0) {
        MPI_Wait(&req, &st);
        DES_cblock found_key;
        DES_set_key_unchecked((DES_cblock *)&the_key, &key);
        decrypt(&found_key, ciphertext, ciphlen, ciphertext);
        printf("Key = %li\n\n", found);
        printf("%s\n", ciphertext);
    }
    printf("Process %d exiting\n", id);

    // Finalizar entorno MPI
    MPI_Finalize();
}