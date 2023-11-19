#include <ballet/sha256/fd_sha256.h>

fd_sha256_t *
fd_sha256_init( fd_sha256_t * sha ) {
  __CPROVER_w_ok( sha, sizeof(fd_sha256_t) );
  __CPROVER_havoc_slice( sha, sizeof(fd_sha256_t) );
  return sha;
}

fd_sha256_t *
fd_sha256_append( fd_sha256_t * sha,
                  void const *  data,
                  ulong         sz ) {
  __CPROVER_rw_ok( sha, sizeof(fd_sha256_t) );
  __CPROVER_r_ok( data, sz );
  __CPROVER_havoc_slice( sha, sizeof(fd_sha256_t) );
  return sha;
}

void *
fd_sha256_fini( fd_sha256_t * sha,
                void *        hash ) {
  __CPROVER_rw_ok( sha, sizeof(fd_sha256_t) );
  __CPROVER_w_ok( hash, 32UL );
  __CPROVER_havoc_slice( sha, sizeof(fd_sha256_t) );
  __CPROVER_havoc_slice( hash, 32UL );
  return sha;
}

void *
fd_hmac_sha256( void const * data,
                ulong        data_sz,
                void const * key,
                ulong        key_sz,
                void *       hash ) {
  __CPROVER_r_ok( data, data_sz );
  __CPROVER_r_ok( key,  key_sz  );
  __CPROVER_havoc_slice( hash, 32UL );
}
