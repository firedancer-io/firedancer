#include "fd_keyguard_bls.h"

void FD_FN_SENSITIVE
fd_keyguard_bls_key_derive( fd_keyguard_bls_key_t * key,
                            uchar const              ed25519_public_key[ static 32 ],
                            uchar const              ed25519_private_key[ static 32 ],
                            fd_sha512_t *            sha ) {
  static char const derive_msg[] = "bls-key-derive-alpenglow";

  uchar ikm[ FD_ED25519_SIG_SZ ];
  fd_ed25519_sign( ikm, (uchar const *)derive_msg, sizeof(derive_msg)-1UL, ed25519_public_key, ed25519_private_key, sha );
  fd_bls_sec_derive( &key->secret_key, ikm, sizeof(ikm) );
  fd_memzero_explicit( ikm, sizeof(ikm) );

  fd_bls_pub_t public_key[1];
  fd_bls_sec_to_pub( &key->secret_key, public_key );
  blst_p1_compress( key->public_key, public_key );
}

fd_keyguard_bls_key_t const *
fd_keyguard_bls_key_query( fd_keyguard_bls_key_t const * keys,
                           ulong                         key_cnt,
                           uchar const                   public_key[ static FD_KEYGUARD_BLS_PUBKEY_SZ ] ) {
  for( ulong i=0UL; i<key_cnt; i++ ) {
    if( FD_LIKELY( !memcmp( keys[ i ].public_key, public_key, FD_KEYGUARD_BLS_PUBKEY_SZ ) ) ) return &keys[ i ];
  }
  return NULL;
}

ulong
fd_keyguard_bls_request_encode( uchar *       request,
                                uchar const   public_key[ static FD_KEYGUARD_BLS_PUBKEY_SZ ],
                                uchar const * payload,
                                ulong         payload_sz ) {
  memcpy( request, public_key, FD_KEYGUARD_BLS_PUBKEY_SZ );
  memcpy( request+FD_KEYGUARD_BLS_PUBKEY_SZ, payload, payload_sz );
  return FD_KEYGUARD_BLS_PUBKEY_SZ+payload_sz;
}

int FD_FN_SENSITIVE
fd_keyguard_bls_sign_request( fd_keyguard_bls_key_t const * keys,
                              ulong                         key_cnt,
                              uchar const *                 request,
                              ulong                         request_sz,
                              fd_bls_sig_t *                signature ) {
  if( FD_UNLIKELY( request_sz<FD_KEYGUARD_BLS_PUBKEY_SZ ) ) return 0;
  fd_keyguard_bls_key_t const * key = fd_keyguard_bls_key_query( keys, key_cnt, request );
  if( FD_UNLIKELY( !key ) ) return 0;
  fd_bls_sec_sign( &key->secret_key,
                   request+FD_KEYGUARD_BLS_PUBKEY_SZ,
                   request_sz-FD_KEYGUARD_BLS_PUBKEY_SZ,
                   signature );
  return 1;
}
