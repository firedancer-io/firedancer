#ifndef HEADER_fd_src_disco_keyguard_fd_keyguard_bls_h
#define HEADER_fd_src_disco_keyguard_fd_keyguard_bls_h

#include "fd_keyguard.h"
#include "../../ballet/bls/fd_bls.h"
#include "../../ballet/sha512/fd_sha512.h"

struct fd_keyguard_bls_key {
  fd_bls_sec_t secret_key;
  uchar        public_key[ FD_KEYGUARD_BLS_PUBKEY_SZ ]; /* canonical compressed encoding */
};
typedef struct fd_keyguard_bls_key fd_keyguard_bls_key_t;

FD_PROTOTYPES_BEGIN

/* fd_keyguard_bls_key_derive derives the Alpenglow BLS voting key of an
   ed25519 keypair.  The key is derived from the ed25519 signature of
   "bls-key-derive-alpenglow".  Terminates the process if the public key
   does not match the private key. */

void FD_FN_SENSITIVE
fd_keyguard_bls_key_derive( fd_keyguard_bls_key_t * key,
                            uchar const             ed25519_public_key[ static 32 ],
                            uchar const             ed25519_private_key[ static 32 ],
                            fd_sha512_t *           sha );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_keyguard_fd_keyguard_bls_h */
