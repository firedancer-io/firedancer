#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>
#include "fd_chacha20_rng.h"

#define TEST_KEY_SIZE FD_CHACHA20_KEY_SIZE
#define TEST_NONCE_SIZE FD_CHACHA20_NONCE_SIZE

/* Test fd_chacha20_rng_get_uint32 function */
void test_fd_chacha20_rng_get_uint32()
{
  fd_chacha20_rng_t result;

  // Test vector
  unsigned char key[TEST_KEY_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  unsigned char nonce[TEST_NONCE_SIZE] = {0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};

  // Expected test vector result value
  fd_chacha20_rng_t expected_value = 2194474613;

  /* Initialize the random number generator */
  assert(fd_chacha20_rng_init(key, nonce) == 0);

  /* Generate two random numbers and make sure they are different */
  assert(fd_chacha20_rng_get_uint32(&result) == 0);

  assert(result == expected_value);

  /* Print random number */
  printf("%u\n", result);
}

int main()
{
  test_fd_chacha20_rng_get_uint32();

  printf("All fd_chacha20_rng tests passed!\n");

  return 0;
}
