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
#include <openssl/des.h>

void decrypt(DES_cblock key, char *ciph, int len) {
  DES_key_schedule ks;
  DES_set_key_unchecked(&key, &ks);
  DES_ncbc_encrypt((unsigned char *)ciph, (unsigned char *)ciph, len, &ks, &key, DES_DECRYPT);
}

void encrypt(DES_cblock key, char *ciph, int len) {
  DES_key_schedule ks;
  DES_set_key_unchecked(&key, &ks);
  DES_ncbc_encrypt((unsigned char *)ciph, (unsigned char *)ciph, len, &ks, &key, DES_ENCRYPT);
}

int tryKey(DES_cblock key, char *ciph, int len) {
  char search[] = "es una prueba de";
  char temp[len + 1];
  memcpy(temp, ciph, len);
  temp[len] = 0;
  decrypt(key, temp, len);
  return strstr(temp, search) != NULL;
}

char eltexto[] = "Esta es una prueba de proyecto 2";
DES_cblock the_key = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

int main(int argc, char *argv[]) {
  int N, id;
  long upper = (1L << 56);
  long mylower, myupper;
  MPI_Status st;
  MPI_Request req;

  int ciphlen = strlen(eltexto);
  MPI_Comm comm = MPI_COMM_WORLD;

  char cipher[ciphlen + 1];
  memcpy(cipher, eltexto, ciphlen);
  cipher[ciphlen] = 0;
  encrypt(the_key, cipher, ciphlen);

  MPI_Init(NULL, NULL);
  MPI_Comm_size(comm, &N);
  MPI_Comm_rank(comm, &id);

  long found = 0L;
  int ready = 0;

  long range_per_node = upper / N;
  mylower = range_per_node * id;
  myupper = range_per_node * (id + 1) - 1;
  if (id == N - 1) {
    myupper = upper;
  }
  printf("Process %d lower %ld upper %ld\n", id, mylower, myupper);

  MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);

  for (long i = mylower; i < myupper; ++i) {
    DES_cblock key_candidate;
    for (int j = 0; j < 8; ++j) {
      key_candidate[j] = (i >> (56 - 8 * (j + 1))) & 0xff;
    }

    MPI_Test(&req, &ready, MPI_STATUS_IGNORE);
    if (ready)
      break;

    if (tryKey(key_candidate, cipher, ciphlen)) {
      found = i;
      printf("Process %d found the key\n", id);
      for (int node = 0; node < N; node++) {
        MPI_Send(&found, 1, MPI_LONG, node, 0, comm); //avisar a otros
      }
      break;
    }
  }

  if (id == 0) {
    MPI_Wait(&req, &st);
    for (int j = 0; j < 8; ++j) {
      the_key[j] = (found >> (56 - 8 * (j + 1))) & 0xff;
    }
    decrypt(the_key, cipher, ciphlen);
    printf("Key = %li\n\n", found);
    printf("Key bytes: ");
    for (int j = 0; j < 8; ++j) {
      printf("%02x ", the_key[j]);
    }
    printf("\n\n");
    printf("%s\n", cipher);
  }
  printf("Process %d exiting\n", id);

  MPI_Finalize();
}
