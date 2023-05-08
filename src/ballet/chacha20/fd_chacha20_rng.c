#include <openssl/evp.h>
#include "fd_chacha20_rng.h"

int fd_chacha20_rng_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *nonce)
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

int fd_chacha20_rng_generate(EVP_CIPHER_CTX *ctx, fd_chacha20_rng_t *random_number)
{
  unsigned char buf[4]; // 4 bytes -> 32 bits
  int outlen;

  // Generate a random 32-bit number
  // We pass NULL as plaintext to generate random numbers solely based on chacha20 internal state
  if (!EVP_EncryptUpdate(ctx, buf, &outlen, NULL, 0))
  {
    fprintf(stderr, "Error: EVP_EncryptUpdate()\n");
    return 1;
  }

  *random_number = *((fd_chacha20_rng_t *)buf);

  return 0;
}

int fd_chacha20_generate_random_number(const unsigned char *key, const unsigned char *nonce, fd_chacha20_rng_t *random_number)
{
  // Create the ChaCha20 context
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  // Set chacha20 cipher context using key and nonce
  if (!fd_chacha20_rng_init(ctx, key, nonce))
  {
    fprintf(stderr, "Error: fd_chacha20_rng_init()\n");
    return 1;
  }

  // Generates random number using chacha20 cipher context
  if (!fd_chacha20_rng_generate(ctx, random_number))
  {
    fprintf(stderr, "Error: fd_chacha20_rng_generate()\n");
    return 1;
  }

  // Free cipher context from memory
  EVP_CIPHER_CTX_free(ctx);

  return 0;
}
