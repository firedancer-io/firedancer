#ifndef HEADER_fd_src_ballet_ed25519_fd_ed25519_openssl_h
#define HEADER_fd_src_ballet_ed25519_fd_ed25519_openssl_h
#ifdef FD_HAS_OPENSSL

#include <openssl/evp.h>

/* fd_ed25519_pkey_from_private wraps an Ed25519 private key in an
   OpenSSL EVP_PKEY object.

   private_key assumed to point to first byte of a 32-byte memory region
   private key.

   Returns a new EVP_PKEY object on success.  On failure, returns NULL.
   Reasons for failure include heap allocation fail or OpenSSL internal
   error. */

static inline EVP_PKEY *
fd_ed25519_pkey_from_private( void * private_key ) {
  return EVP_PKEY_new_raw_private_key( EVP_PKEY_ED25519, NULL, private_key, 32UL );
}

#endif /* FD_HAS_OPENSSL */
#endif /* HEADER_fd_src_ballet_ed25519_fd_ed25519_openssl_h */
