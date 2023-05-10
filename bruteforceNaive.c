//bruteforceNaive.c
//Tambien cifra un texto cualquiera con un key arbitrario.
//OJO: asegurarse que la palabra a buscar sea lo suficientemente grande
//  evitando falsas soluciones ya que sera muy improbable que tal palabra suceda de
//  forma pseudoaleatoria en el descifrado.
//>> mpicc bruteforceNaive.c -o desBrute -lcrypto
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
    DES_cblock ivec;
    memset(ivec, 0, sizeof(ivec)); // Inicializa el vector de inicialización a ceros
    DES_ncbc_encrypt(plaintext, ciphertext, plaintext_len, &schedule, &ivec, DES_ENCRYPT);
}

void decrypt(const_DES_cblock *key, const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext) {
    DES_key_schedule schedule;
    DES_set_key_unchecked(key, &schedule);
    DES_cblock ivec;
    memset(ivec, 0, sizeof(ivec)); // Inicializa el vector de inicialización a ceros
    DES_ncbc_encrypt(ciphertext, plaintext, ciphertext_len, &schedule, &ivec, DES_DECRYPT);
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
    int padding = 8 - (ciphlen % 8); // Calcular el relleno necesario
    int padded_ciphlen = ciphlen + padding; // Calcular la longitud del texto con relleno
    unsigned char padded_text[padded_ciphlen]; // Crear un arreglo para el texto con relleno
    memcpy(padded_text, eltexto, ciphlen); // Copiar el texto original al arreglo con relleno
    for (int i = 0; i < padding; i++) {
        padded_text[ciphlen + i] = padding; // Rellenar con el valor de padding
    }

    MPI_Comm comm = MPI_COMM_WORLD;

    // Cifrar el texto
    unsigned char ciphertext[padded_ciphlen];
    memcpy(ciphertext, padded_text, padded_ciphlen);
    DES_key_schedule key;
    DES_set_key_unchecked((DES_cblock *)&the_key, &key);
    encrypt(&key, padded_text, padded_ciphlen, ciphertext);

    // Inicializar MPI
    MPI_Init(NULL, NULL);
    MPI_Comm_size(comm, &N);
    MPI_Comm_rank(comm, &id);

    // Imprimir el texto cifrado
    if (id == 0) {
        printf("Texto cifrado: ");
        for (int i = 0; i < ciphlen; i++) {
            printf("%c", ciphertext[i]);
        }
        printf("\n");
    }

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
        // printf("Process %d trying key %ld\n", id, i); // Mensaje de depuración

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
        DES_key_schedule found_schedule; // Cambiado a DES_key_schedule
        DES_set_key_unchecked((DES_cblock *)&found, &found_schedule); // Utiliza la clave encontrada (found) en lugar de the_key
        unsigned char decrypted_text[padded_ciphlen]; // Crear un arreglo para el texto descifrado
        decrypt(&found_schedule, ciphertext, padded_ciphlen, decrypted_text); // Descifrar el texto con relleno
        int decrypted_len = padded_ciphlen - decrypted_text[padded_ciphlen - 1]; // Calcular la longitud del texto descifrado sin relleno
        decrypted_text[decrypted_len] = '\0'; // Añadir el caracter nulo al final del texto descifrado
        printf("Key = %li\n\n", found);
        printf("%s\n", decrypted_text);
    }
    printf("Process %d exiting\n", id);

    // Finalizar entorno MPI
    MPI_Finalize();
}