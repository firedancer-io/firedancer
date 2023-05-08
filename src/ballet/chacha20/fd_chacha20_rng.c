#include <openssl/evp.h>
#include "fd_chacha20_rng.h"

static EVP_CIPHER_CTX *ctx = NULL;

int fd_chacha20_rng_init(unsigned char *key, unsigned char *nonce)
{
  // Initialize the ChaCha20 context with the key and nonce
  if (!(ctx = EVP_CIPHER_CTX_new()) ||
      !EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce))
  {
    fprintf(stderr, "Error: EVP_EncryptInit_ex()\n");
    return 1;
  }

  return 0;
}

int fd_chacha20_rng_get_uint32(fd_chacha20_rng_t *num)
{
  unsigned char buf[4];
  int outlen;

  // Generate a random 32-bit number
  if (!EVP_EncryptUpdate(ctx, buf, &outlen, buf, sizeof(buf)))
  {
    fprintf(stderr, "Error: EVP_EncryptUpdate()\n");
    return 1;
  }

  *num = *((unsigned int *)buf);

  return 0;
}
