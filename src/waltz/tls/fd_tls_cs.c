#include "fd_tls_cs.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "../../ballet/sha512/fd_sha512.h"
#include "../../ballet/hmac/fd_hmac.h"

static void *
fd_tls_sha256_init( void * state ) {
  return fd_sha256_init( (fd_sha256_t *)state );
}

static void *
fd_tls_sha256_append( void *       state,
                      void const * data,
                      ulong        data_sz ) {
  return fd_sha256_append( (fd_sha256_t *)state, data, data_sz );
}

static void *
fd_tls_sha256_fini( void * state,
                    void * hash ) {
  return fd_sha256_fini( (fd_sha256_t *)state, hash );
}

static void *
fd_tls_sha384_init( void * state ) {
  return fd_sha384_init( (fd_sha512_t *)state );
}

static void *
fd_tls_sha384_append( void *       state,
                      void const * data,
                      ulong        data_sz ) {
  return fd_sha384_append( (fd_sha512_t *)state, data, data_sz );
}

static void *
fd_tls_sha384_fini( void * state,
                    void * hash ) {
  return fd_sha384_fini( (fd_sha512_t *)state, hash );
}

#define FD_TLS_CS_ENTRY( SUITE_ID, HASH_SZ, KEY_SZ, HASH, HMAC, STATE_T, NAME )   \
  { .suite_id = (SUITE_ID),                                                       \
    .hash_sz  = (HASH_SZ),                                                        \
    .key_sz   = (KEY_SZ),                                                         \
    .hmac_fn  = (HMAC),                                                           \
    .hash_vt  = {                                                                 \
      .init     = fd_tls_##HASH##_init,                                            \
      .append   = fd_tls_##HASH##_append,                                          \
      .fini     = fd_tls_##HASH##_fini,                                            \
      .state_sz = sizeof(STATE_T),                                                \
    },                                                                            \
    .name = (NAME),                                                               \
  }

fd_tls_cs_t const fd_tls_cs_table[ FD_TLS_CS_CNT ] = {
  [FD_TLS_CS_IDX_AES_128_GCM_SHA256] =
    FD_TLS_CS_ENTRY( 0x1301, 32, 16, sha256, fd_hmac_sha256, fd_sha256_t, "TLS_AES_128_GCM_SHA256" ),
  [FD_TLS_CS_IDX_AES_256_GCM_SHA384] =
    FD_TLS_CS_ENTRY( 0x1302, 48, 32, sha384, fd_hmac_sha384, fd_sha512_t, "TLS_AES_256_GCM_SHA384" ),
};

fd_tls_cs_t const *
fd_tls_cs_lookup( ushort suite_id ) {
  for( uint i=0; i<FD_TLS_CS_CNT; i++ )
    if( fd_tls_cs_table[i].suite_id == suite_id ) return &fd_tls_cs_table[i];
  return NULL;
}
