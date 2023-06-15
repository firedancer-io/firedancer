#include "fd_secp256k1.h"

#include <secp256k1.h>
#include <secp256k1_recovery.h>

void *
fd_secp256k1_public_from_private( void *       public_key,
                                  void const * private_key ) {
  // TODO: preallocate ctx
  // TODO: randomize context to prevent side channel attacks
  secp256k1_context * ctx = secp256k1_context_create( SECP256K1_CONTEXT_NONE );

  if( !secp256k1_ec_seckey_verify( ctx, private_key ) ) {
    return NULL;
  }

  if( !secp256k1_ec_pubkey_create( ctx, public_key, private_key ) ) {
    return NULL;
  }

  secp256k1_context_destroy( ctx );

  return public_key;
}

void *
fd_secp256k1_sign( void *       sig,
                   void const * msg_hash,
                   void const * private_key ) {
  // TODO: preallocate ctx
  // TODO: randomize context to prevent side channel attacks
  secp256k1_context * ctx = secp256k1_context_create( SECP256K1_CONTEXT_NONE );

  if( !secp256k1_ecdsa_sign( ctx, (secp256k1_ecdsa_signature *) sig, msg_hash, private_key, NULL, 
                             NULL ) ) {
    return NULL;
  }

  secp256k1_context_destroy( ctx );

  return sig;
}

int
fd_secp256k1_verify( void const * msg_hash,
                     void const * sig,
                     void const * public_key ) {
  if( !secp256k1_ecdsa_verify( secp256k1_context_static, (secp256k1_ecdsa_signature const *) sig, 
                               msg_hash, (secp256k1_pubkey const *) public_key ) ) {
    return FD_SECP256K1_ERR_SIG;
  }

  return FD_SECP256K1_SUCCESS;
  
}

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

char const *
fd_secp256k1_strerror( int err ) {
  switch( err ) {
  case FD_SECP256K1_SUCCESS:    return "success";
  case FD_SECP256K1_ERR_SIG:    return "bad signature";
  default: break;
  }
  return "unknown";
}
