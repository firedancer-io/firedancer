#include <string.h>
#include <assert.h>
#include <openssl/evp.h>
#include "fd_chacha20_rng.h"

#define TEST_KEY_SIZE FD_CHACHA20_KEY_SIZE
#define TEST_NONCE_SIZE FD_CHACHA20_NONCE_SIZE

/* Test fd_chacha20_rng_get_uint32 function */
void test_fd_chacha20_generate_random_number()
{
  // uint where we store the generated random number
  fd_chacha20_rng_t result;

  // Test vector
  uchar key[TEST_KEY_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  uchar nonce[TEST_NONCE_SIZE] = {0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};

  // Expected test vector result value
  fd_chacha20_rng_t expected_value = 2194474613;

  assert(fd_chacha20_generate_random_number(key, nonce, &result) == 0);

  /* Print random number */
  printf("Random number generated: %u\n", result);

  assert(result == expected_value);
}

int main()
{
  test_fd_chacha20_generate_random_number();

  printf("All fd_chacha20_rng tests passed!\n");

  return 0;
}
