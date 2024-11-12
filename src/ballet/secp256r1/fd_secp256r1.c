#include "fd_secp256r1.h"

#include <stdint.h>
#include <s2n-bignum.h>

int
fd_secp256r1_verify( uchar const   msg[], /* msg_sz */
                     ulong         msg_sz,
                     uchar const   sig[ 64 ],
                     uchar const   public_key[ 33 ],
                     fd_sha256_t * sha ) {
  (void)msg;
  (void)msg_sz;
  (void)sig;
  (void)public_key;
  (void)sha;

  //TODO

  return FD_SECP256R1_FAILURE;
}
