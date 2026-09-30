#include "fd_keyguard_bls.h"
#include "../../ballet/ed25519/fd_ed25519.h"

FD_STATIC_ASSERT( FD_KEYGUARD_BLS_PUBKEY_SZ==FD_BLS_PUB_COMPRESSED_SZ, bls_public_key_size );
FD_STATIC_ASSERT( FD_KEYGUARD_BLS_SIG_SZ   ==FD_BLS_SIG_SZ,            bls_signature_size  );

void FD_FN_SENSITIVE
fd_keyguard_bls_key_derive( fd_keyguard_bls_key_t * key,
                            uchar const             ed25519_public_key[ static 32 ],
                            uchar const             ed25519_private_key[ static 32 ],
                            fd_sha512_t *           sha ) {
  uchar check_public_key[ 32 ];
  fd_ed25519_public_from_private( check_public_key, ed25519_private_key, sha );
  if( FD_UNLIKELY( memcmp( check_public_key, ed25519_public_key, 32UL ) ) )
    FD_LOG_EMERG(( "The public key in the key file does not match the public key derived from the private key. "
                   "Firedancer will not use the key pair to sign as it might leak the private key." ));

  static char const derive_msg[] = "bls-key-derive-alpenglow";

  uchar ikm[ FD_ED25519_SIG_SZ ];
  fd_ed25519_sign( ikm, (uchar const *)derive_msg, sizeof(derive_msg)-1UL, ed25519_public_key, ed25519_private_key, sha );
  fd_bls_sec_derive( &key->secret_key, ikm, sizeof(ikm) );
  fd_memzero_explicit( ikm, sizeof(ikm) );

  fd_bls_pub_t public_key[1];
  fd_bls_sec_to_pub( &key->secret_key, public_key );
  blst_p1_compress( key->public_key, public_key );
}
