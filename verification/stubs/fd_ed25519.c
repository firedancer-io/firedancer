/* fd_tls_crypto.c stubs cryptographic functions used by fd_tls */

#include <ballet/sha256/fd_sha256.h>
#include <ballet/sha512/fd_sha512.h>
#include <ballet/ed25519/fd_ed25519.h>

void *
fd_ed25519_sign( void *        sig,
                 void const *  msg,
                 ulong         sz,
                 void const *  public_key,
                 void const *  private_key,
                 fd_sha512_t * sha ) {
  __CPROVER_r_ok( msg,         sz                  );
  __CPROVER_r_ok( public_key,  32UL                );
  __CPROVER_r_ok( private_key, 32UL                );
  __CPROVER_r_ok( sha,         sizeof(fd_sha512_t) );

  __CPROVER_rw_ok( sig, 64UL );
  __CPROVER_havoc_slice( sig, 64UL );
  return sig;
}


int
fd_ed25519_verify( void const *  msg,
                   ulong         sz,
                   void const *  sig,
                   void const *  public_key,
                   fd_sha512_t * sha ) {

  __CPROVER_r_ok( msg,        sz                  );
  __CPROVER_r_ok( sig,        64UL                );
  __CPROVER_r_ok( public_key, 32UL                );
  __CPROVER_r_ok( sha,        sizeof(fd_sha512_t) );

  int retval;
  __CPROVER_assume( ( retval==FD_ED25519_SUCCESS    ) |
                    ( retval==FD_ED25519_ERR_SIG    ) |
                    ( retval==FD_ED25519_ERR_PUBKEY ) |
                    ( retval==FD_ED25519_ERR_MSG    ) );
  return retval;
}

void *
fd_x25519_exchange( void *       shared_secret,
                    void const * self_private_key,
                    void const * peer_public_key ) {
  __CPROVER_r_ok( self_private_key, 32UL );
  __CPROVER_r_ok( peer_public_key,  32UL  );
  __CPROVER_havoc_slice( shared_secret, 32UL );
  return shared_secret;
}
