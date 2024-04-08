/* stubs/fd_aes.c mocks the fd_aes API.  Output buffers are filled with
   undefined bytes. */

#include <assert.h>
#include <ballet/aes/fd_aes.h>
#include <ballet/aes/fd_aes_gcm.h>

int
fd_aes_ref_set_encrypt_key( uchar const *  user_key,
                            ulong          bits,
                            fd_aes_key_t * key ) {
  assert( bits==128UL );
  __CPROVER_r_ok( user_key, 16 );
  __CPROVER_w_ok( key, sizeof(fd_aes_key_t) );
  __CPROVER_havoc_slice( key, sizeof(fd_aes_key_t) );
}

void
fd_aes_ref_encrypt_core( uchar const *        in,
                         uchar *              out,
                         fd_aes_key_t const * key ) {
  __CPROVER_r_ok( in, 16 );
  __CPROVER_w_ok( out, 16 );
  __CPROVER_r_ok( key, sizeof(fd_aes_key_t) );
  __CPROVER_havoc_slice( out, 16 );
}

void
fd_aes_gcm_init( fd_aes_gcm_t * aes_gcm,
                 uchar const *  key,
                 ulong          key_len,
                 uchar const    iv[ static 12 ] ) {
  __CPROVER_rw_ok( aes_gcm, sizeof(fd_aes_gcm_t) );
  __CPROVER_r_ok( key, key_len );
  __CPROVER_r_ok( iv, 12 );
  __CPROVER_havoc_slice( aes_gcm, sizeof(fd_aes_gcm_t) );
}

int
fd_aes_gcm_aead_decrypt( fd_aes_gcm_t * aes_gcm,
                         uchar const *  c,
                         uchar *        p,
                         ulong          sz,
                         uchar const *  aad,
                         ulong          aad_sz,
                         uchar const    tag[ static 16 ] ) {
  __CPROVER_rw_ok( aes_gcm, sizeof(fd_aes_gcm_t) );
  __CPROVER_r_ok( c, sz       );
  __CPROVER_w_ok( p, sz       );
  __CPROVER_r_ok( aad, aad_sz );
  __CPROVER_r_ok( tag, 16     );
  __CPROVER_havoc_slice( aes_gcm, sizeof(fd_aes_gcm_t) );
  __CPROVER_havoc_slice( p, sz );
}
