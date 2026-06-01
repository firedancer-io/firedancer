#ifndef HEADER_fd_src_ballet_bls_fd_bls12_381_kdf_h
#define HEADER_fd_src_ballet_bls_fd_bls12_381_kdf_h

#include "../fd_ballet_base.h"
#include "../sha512/fd_sha512.h"

FD_PROTOTYPES_BEGIN

#define FD_BLS_KEYPAIR_DERIVE_SEED ((uchar const *)"alpenglow")

/* fd_bls12_381_kdf derives a BLS12-381 keypair from an Ed25519
   identity keypair, matching Agave's BLSKeypair::derive_from_signer.

   On success:
   - bls_pk is set to the 48-byte compressed BLS public key (G1).
   - bls_sk is set to the 32-byte BLS secret key (LE scalar)
   Returns 0.

   Returns -1 on failure. */
int
fd_bls12_381_kdf( uchar         bls_pk[ 48 ],
                  uchar         bls_sk[ 32 ],
                  uchar const   ed25519_public_key[ 32 ],
                  uchar const   ed25519_private_key[ 32 ],
                  fd_sha512_t * sha );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_bls_fd_bls12_381_kdf_h */
