#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "fd_chacha20.h"

#define TEST_KEY_SIZE FD_CHACHA20_KEY_SIZE
#define TEST_NONCE_SIZE FD_CHACHA20_NONCE_SIZE

/* Test fd_chacha20_rng_init function */
void test_fd_chacha20_rng_init()
{
  unsigned char key[TEST_KEY_SIZE];
  unsigned char nonce[TEST_NONCE_SIZE];

  /* Generate key and nonce using /dev/urandom */
  FILE *fp = fopen("/dev/urandom", "rb");
  fread(key, sizeof(key), 1, fp);
  fread(nonce, sizeof(nonce), 1, fp);
  fclose(fp);

  /* Initialize the random number generator */
  assert(fd_chacha20_rng_init(key, nonce) == 0);
}

/* Test fd_chacha20_rng_get_uint32 function */
void test_fd_chacha20_rng_get_uint32()
{
  unsigned char key[TEST_KEY_SIZE];
  unsigned char nonce[TEST_NONCE_SIZE];
  fd_chacha20_rng_t num1, num2;

  /* Generate key and nonce using /dev/urandom */
  FILE *fp = fopen("/dev/urandom", "rb");
  fread(key, sizeof(key), 1, fp);
  fread(nonce, sizeof(nonce), 1, fp);
  fclose(fp);

  /* Initialize the random number generator */
  assert(fd_chacha20_rng_init(key, nonce) == 0);

  /* Generate two random numbers and make sure they are different */
  assert(fd_chacha20_rng_get_uint32(&num1) == 0);
  assert(fd_chacha20_rng_get_uint32(&num2) == 0);
  assert(num1 != num2);

  /* Print random numbers */
  printf("%u\n", num1);
  printf("%u\n", num2);
}

int main()
{
  test_fd_chacha20_rng_init();
  test_fd_chacha20_rng_get_uint32();

  printf("All fd_chacha20_rng tests passed!\n");

  return 0;
}
