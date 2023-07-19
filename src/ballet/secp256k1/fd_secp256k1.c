#include "fd_secp256k1.h"

#include <secp256k1.h>
#include <secp256k1_recovery.h>

void *
fd_secp256k1_recover( void *       public_key,
                      void const * msg_hash,
                      void const * sig,
                      int          recovery_id ) {
  secp256k1_ecdsa_recoverable_signature recoverable_sig;
  if( !secp256k1_ecdsa_recoverable_signature_parse_compact( secp256k1_context_static,
                                                            &recoverable_sig, (uchar const *) sig,
                                                            recovery_id ) ) {
    return NULL;
  }

  if( !secp256k1_ecdsa_recover( secp256k1_context_static, (secp256k1_pubkey *) public_key,
                                &recoverable_sig, msg_hash ) ) {
    return NULL;
  }

  return public_key;
}
