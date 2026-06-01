#include "fd_bls12_381_kdf.h"
#include "../ed25519/fd_ed25519.h"

#include <blst.h>

#define FD_BLS_KDF_PREFIX     "bls-key-derive-alpenglow"
#define FD_BLS_KDF_PREFIX_SZ  (sizeof(FD_BLS_KDF_PREFIX)-1)

int
fd_bls12_381_kdf( uchar         bls_pk[ 48 ],
                  uchar         bls_sk[ 32 ],
                  uchar const   ed25519_public_key[ 32 ],
                  uchar const   ed25519_private_key[ 32 ],
                  fd_sha512_t * sha ) {
  /* 1. Ed25519 sign the prefix.
    https://github.com/anza-xyz/solana-sdk/blob/bls-signatures%40v3.3.0/bls-signatures/src/secret_key.rs#L94-L98 */
  uchar sig[ 64 ];
  fd_ed25519_sign( sig, (uchar const *)FD_BLS_KDF_PREFIX, FD_BLS_KDF_PREFIX_SZ, ed25519_public_key, ed25519_private_key, sha );

  /* Agave checks whether the signature we've just computed is all-zeroes.
     We will skip this check, as this is not a feasible condition to reach.*/

  /* 2. Derive BLS secret key with blst_keygen(), using the Ed25519
    signature as the IKM.
    https://github.com/anza-xyz/solana-sdk/blob/bls-signatures%40v3.3.0/bls-signatures/src/secret_key.rs#L76-L85 */
  blst_scalar scalar[1];
  blst_keygen( scalar, sig, 64UL, NULL, 0 );

  /* Clear the signature from the stack. */
  fd_memzero_explicit( sig, 64UL );

  /* 3. Validate the scalar with blst_scalar_fr_check(). */
  if( FD_UNLIKELY( !blst_scalar_fr_check( scalar ) ) ) {
    fd_memzero_explicit( scalar, sizeof(blst_scalar) );
    return -1;
  }

  /* 4. Derive a BLS public key, pk = sk * G1 */
  blst_p1 pk[1];
  blst_sk_to_pk_in_g1( pk, scalar );

  /* 5. Serialize the result. */
  blst_p1_compress( bls_pk, pk );
  blst_lendian_from_scalar( bls_sk, scalar );

  fd_memzero_explicit( scalar, sizeof(blst_scalar) );
  return 0;
}
