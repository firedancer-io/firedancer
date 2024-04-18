#include "fd_secp256k1.h"

#include <secp256k1.h>
#include <secp256k1_recovery.h>

void *
fd_secp256k1_recover( void *       public_key,
                      void const * msg_hash,
                      void const * sig,
                      int          recovery_id ) {
  secp256k1_ecdsa_recoverable_signature recoverable_sig;
  secp256k1_pubkey internal_public_key;
  uchar serialized_public_key[ 65 ];
  size_t public_key_len = 65;

  // avoid panic in secp256k1_ecdsa_recoverable_signature_parse_compact
  // https://github.com/bitcoin-core/secp256k1/blob/v0.4.0/src/modules/recovery/main_impl.h#L46
  // ARG_CHECK(recid >= 0 && recid <= 3);
  if ( !(recovery_id >= 0 && recovery_id <= 3) ) {
    return NULL;
  }

  if( !secp256k1_ecdsa_recoverable_signature_parse_compact( secp256k1_context_static,
                                                            &recoverable_sig, (uchar const *) sig,
                                                            recovery_id ) ) {
    return NULL;
  }

  if( !secp256k1_ecdsa_recover( secp256k1_context_static, &internal_public_key,
                                &recoverable_sig, msg_hash ) ) {
    return NULL;
  }

  if( !secp256k1_ec_pubkey_serialize( secp256k1_context_static, serialized_public_key, &public_key_len,
                                      &internal_public_key, SECP256K1_EC_UNCOMPRESSED ) ) {
    return NULL;
  }

  // skip 1st byte: libsecp256k1 prepends 0x04 to the public key
  // https://github.com/bitcoin-core/secp256k1/blob/v0.4.0/src/eckey_impl.h#L49
  return fd_memcpy(public_key, &serialized_public_key[1], 64);
}
