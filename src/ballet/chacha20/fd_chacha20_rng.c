#include <openssl/evp.h>
#include "fd_chacha20_rng.h"

int fd_chacha20_rng_init(EVP_CIPHER_CTX *ctx, unsigned char *key, unsigned char *nonce)
{
  if (ctx == NULL)
  {
    fprintf(stderr, "Error creating EVP_CIPHER_CTX\n");
    return 1;
  }

  // Initialize the ChaCha20 context with the key and nonce
  if (!EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce))
  {
    fprintf(stderr, "Error: EVP_EncryptInit_ex()\n");
    return 1;
  }

  return 0;
}

int fd_chacha20_generate_random_number(EVP_CIPHER_CTX *ctx, fd_chacha20_rng_t *num)
{
  unsigned char buf[4]; // 4 bytes -> 32 bits
  int outlen;

  // Generate a random 32-bit number
  // we pass NULL as plaintext to generate random numbers solely based on chacha20 internal state
  if (!EVP_EncryptUpdate(ctx, buf, &outlen, NULL, 0))
  {
    fprintf(stderr, "Error: EVP_EncryptUpdate()\n");
    return 1;
  }

  *num = *((unsigned int *)buf);

  return 0;
}
