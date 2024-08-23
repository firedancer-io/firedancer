/* fd_aes_gcm_x86.c provides wrappers and AES key expansion for
   fd_aes_gcm_{aesni,avx10}.S */

#include "fd_aes_gcm.h"
#include "../../util/simd/fd_sse.h"

#if FD_HAS_AESNI

FD_FN_SENSITIVE static void
expand_aes_key( fd_aes_gcm_aesni_key_t * out,
                uchar const *            keyp ) {
  vb_t key = vb_ldu( keyp );

  /* Expand encryption key */

  vb_t v0, v1;
  vb_t enc[11];
# define ASSIST( out, gen ) do {                      \
    vb_t v2 = _mm_aeskeygenassist_si128( v0, (gen) ); \
    vb_t v3 = vu_permute2( v1, v0, 0, 0, 1, 0 );      \
    vb_t v4 = vu_xor     ( v0, v3 );                  \
         v1 = vu_permute2( v3, v4, 0, 3, 0, 2 );      \
    vb_t v5 = vu_xor     ( v4, v1 );                  \
    vb_t v6 = vu_permute ( v2,     3, 3, 3, 3 );      \
         v0 = vu_xor     ( v5, v6 );                  \
    (out) = v0;                                       \
  } while(0)
  v0 = key;
  v1 = vu_zero();
          enc[ 0] = v0;
  ASSIST( enc[ 1], 0x01 );
  ASSIST( enc[ 2], 0x02 );
  ASSIST( enc[ 3], 0x04 );
  ASSIST( enc[ 4], 0x08 );
  ASSIST( enc[ 5], 0x10 );
  ASSIST( enc[ 6], 0x20 );
  ASSIST( enc[ 7], 0x40 );
  ASSIST( enc[ 8], 0x80 );
  ASSIST( enc[ 9], 0x1B );
  ASSIST( enc[10], 0x36 );
# undef ASSIST

  vb_st( out->key_enc,        enc[ 0] );
  vb_st( out->key_enc + 0x10, enc[ 1] );
  vb_st( out->key_enc + 0x20, enc[ 2] );
  vb_st( out->key_enc + 0x30, enc[ 3] );
  vb_st( out->key_enc + 0x40, enc[ 4] );
  vb_st( out->key_enc + 0x50, enc[ 5] );
  vb_st( out->key_enc + 0x60, enc[ 6] );
  vb_st( out->key_enc + 0x70, enc[ 7] );
  vb_st( out->key_enc + 0x80, enc[ 8] );
  vb_st( out->key_enc + 0x90, enc[ 9] );
  vb_st( out->key_enc + 0xa0, enc[10] );

  /* Derive decryption key */

  vb_st( out->key_dec,                          enc[10]   );
  vb_st( out->key_dec + 0x10, _mm_aesimc_si128( enc[ 9] ) );
  vb_st( out->key_dec + 0x20, _mm_aesimc_si128( enc[ 8] ) );
  vb_st( out->key_dec + 0x30, _mm_aesimc_si128( enc[ 7] ) );
  vb_st( out->key_dec + 0x40, _mm_aesimc_si128( enc[ 6] ) );
  vb_st( out->key_dec + 0x50, _mm_aesimc_si128( enc[ 5] ) );
  vb_st( out->key_dec + 0x60, _mm_aesimc_si128( enc[ 4] ) );
  vb_st( out->key_dec + 0x70, _mm_aesimc_si128( enc[ 3] ) );
  vb_st( out->key_dec + 0x80, _mm_aesimc_si128( enc[ 2] ) );
  vb_st( out->key_dec + 0x90, _mm_aesimc_si128( enc[ 1] ) );
  vb_st( out->key_dec + 0xa0, _mm_aesimc_si128( enc[ 0] ) );

  out->key_sz = 16;
}

__attribute__((sysv_abi)) extern void
aes_gcm_precompute_aesni( fd_aes_gcm_aesni_t * key );

__attribute__((sysv_abi)) extern void
aes_gcm_aad_update_aesni( fd_aes_gcm_aesni_t const * key,
                          uchar                      ghash_acc[16],
                          uchar const *              aad,
                          int                        aadlen );

__attribute__((sysv_abi)) extern void
aes_gcm_enc_update_aesni( fd_aes_gcm_aesni_t const * key,
                          uint const                 le_ctr[4],
                          uchar                      ghash_acc[16],
                          uchar const *              src,
                          uchar *                    dst,
                          int                        datalen );

__attribute__((sysv_abi)) extern void
aes_gcm_enc_final_aesni( fd_aes_gcm_aesni_t const * key,
                         uint const                 le_ctr[4],
                         uchar                      ghash_acc[16],
                         ulong                      total_aadlen,
                         ulong                      total_datalen );

__attribute__((sysv_abi)) extern void
aes_gcm_dec_update_aesni( fd_aes_gcm_aesni_t const * key,
                          uint const                 le_ctr[4],
                          uchar                      ghash_acc[16],
                          uchar const *              src,
                          uchar *                    dst,
                          int                        datalen );

__attribute__((sysv_abi,warn_unused_result)) extern int
aes_gcm_dec_final_aesni( fd_aes_gcm_aesni_t const * key,
                         uint const                 le_ctr[4],
                         uchar const                ghash_acc[16],
                         ulong                      total_aadlen,
                         ulong                      total_datalen,
                         uchar const                tag[16],
                         int                        taglen );

void
fd_aes_128_gcm_init_aesni( fd_aes_gcm_aesni_t * aes_gcm,
                           uchar const          key[ 16 ],
                           uchar const          iv [ 12 ] ) {
  expand_aes_key( &aes_gcm->key, key );
  aes_gcm_precompute_aesni( aes_gcm );
  memcpy( aes_gcm->iv, iv, 12 );
}

static void
load_le_ctr( uint        le_ctr[4],
             uchar const iv[12] ) {
  le_ctr[0] = 2;
  le_ctr[1] = fd_uint_bswap( fd_uint_load_4_fast( iv+8 ) );
  le_ctr[2] = fd_uint_bswap( fd_uint_load_4_fast( iv+4 ) );
  le_ctr[3] = fd_uint_bswap( fd_uint_load_4_fast( iv   ) );
}

void
fd_aes_gcm_encrypt_aesni( fd_aes_gcm_aesni_t * aes_gcm,
                          uchar *              c,
                          uchar const *        p,
                          ulong                sz,
                          uchar const *        aad,
                          ulong                aad_sz,
                          uchar                tag[ 16 ] ) {
  uint le_ctr[4]; load_le_ctr( le_ctr, aes_gcm->iv );
  uchar ghash_acc[16] = {0};
  aes_gcm_aad_update_aesni( aes_gcm, ghash_acc, aad, (int)aad_sz );
  aes_gcm_enc_update_aesni( aes_gcm, le_ctr, ghash_acc, p, c, (int)sz );
  aes_gcm_enc_final_aesni ( aes_gcm, le_ctr, ghash_acc, aad_sz, sz );
  memcpy( tag, ghash_acc, 16 );
}

int
fd_aes_gcm_decrypt_aesni( fd_aes_gcm_aesni_t * aes_gcm,
                          uchar const *        c,
                          uchar *              p,
                          ulong                sz,
                          uchar const *        aad,
                          ulong                aad_sz,
                          uchar const          tag[ 16 ] ) {
  uint le_ctr[4]; load_le_ctr( le_ctr, aes_gcm->iv );
  uchar ghash_acc[16] = {0};
  aes_gcm_aad_update_aesni( aes_gcm, ghash_acc, aad, (int)aad_sz );
  aes_gcm_dec_update_aesni( aes_gcm, le_ctr, ghash_acc, c, p, (int)sz );
  return aes_gcm_dec_final_aesni( aes_gcm, le_ctr, ghash_acc, aad_sz, sz, tag, 16 );
}

#endif /* FD_HAS_AESNI */

#if FD_HAS_AVX && FD_HAS_AESNI

__attribute__((sysv_abi)) extern void
aes_gcm_precompute_aesni_avx( fd_aes_gcm_aesni_t * key );

__attribute__((sysv_abi)) extern void
aes_gcm_aad_update_aesni_avx( fd_aes_gcm_aesni_t * key,
                              uchar                ghash_acc[16],
                              uchar const *        aad,
                              int                  aadlen );

__attribute__((sysv_abi)) extern void
aes_gcm_enc_update_aesni_avx( fd_aes_gcm_aesni_t * key,
                              uint const           le_ctr[4],
                              uchar                ghash_acc[16],
                              uchar const *        src,
                              uchar *              dst,
                              int                  datalen );

__attribute__((sysv_abi)) extern void
aes_gcm_enc_final_aesni_avx( fd_aes_gcm_aesni_t * key,
                             uint const           le_ctr[4],
                             uchar                ghash_acc[16],
                             ulong                total_aadlen,
                             ulong                total_datalen );

__attribute__((sysv_abi)) extern void
aes_gcm_dec_update_aesni_avx( fd_aes_gcm_aesni_t const * key,
                              uint const                 le_ctr[4],
                              uchar                      ghash_acc[16],
                              uchar const *              src,
                              uchar *                    dst,
                              int                        datalen );

__attribute__((sysv_abi,warn_unused_result)) extern int
aes_gcm_dec_final_aesni_avx( fd_aes_gcm_aesni_t const * key,
                             uint const                 le_ctr[4],
                             uchar const                ghash_acc[16],
                             ulong                      total_aadlen,
                             ulong                      total_datalen,
                             uchar const                tag[16],
                             int                        taglen );

void
fd_aes_128_gcm_init_avx2( fd_aes_gcm_aesni_t * aes_gcm,
                          uchar const          key[ 16 ],
                          uchar const          iv [ 12 ] ) {
  expand_aes_key( fd_type_pun( &aes_gcm->key ), key );
  aes_gcm_precompute_aesni_avx( aes_gcm );
  memcpy( aes_gcm->iv, iv, 12 );
}

void
fd_aes_gcm_encrypt_avx2( fd_aes_gcm_aesni_t * aes_gcm,
                         uchar *              c,
                         uchar const *        p,
                         ulong                sz,
                         uchar const *        aad,
                         ulong                aad_sz,
                         uchar                tag[ 16 ] ) {
  uint le_ctr[4]; load_le_ctr( le_ctr, aes_gcm->iv );
  uchar ghash_acc[16] = {0};
  aes_gcm_aad_update_aesni_avx( aes_gcm, ghash_acc, aad, (int)aad_sz );
  aes_gcm_enc_update_aesni_avx( aes_gcm, le_ctr, ghash_acc, p, c, (int)sz );
  aes_gcm_enc_final_aesni_avx ( aes_gcm, le_ctr, ghash_acc, aad_sz, sz );
  memcpy( tag, ghash_acc, 16 );
}

int
fd_aes_gcm_decrypt_avx2( fd_aes_gcm_aesni_t * aes_gcm,
                         uchar const *        c,
                         uchar *              p,
                         ulong                sz,
                         uchar const *        aad,
                         ulong                aad_sz,
                         uchar const          tag[ 16 ] ) {
  uint le_ctr[4]; load_le_ctr( le_ctr, aes_gcm->iv );
  uchar ghash_acc[16] = {0};
  aes_gcm_aad_update_aesni_avx( aes_gcm, ghash_acc, aad, (int)aad_sz );
  aes_gcm_dec_update_aesni_avx( aes_gcm, le_ctr, ghash_acc, c, p, (int)sz );
  return aes_gcm_dec_final_aesni_avx( aes_gcm, le_ctr, ghash_acc, aad_sz, sz, tag, 16 );
}

#endif /* FD_HAS_AVX && FD_HAS_AESNI */

#if FD_HAS_AVX512 && FD_HAS_GFNI && FD_HAS_AESNI

__attribute__((sysv_abi)) extern void
aes_gcm_precompute_vaes_avx10_512( fd_aes_gcm_avx10_t * key );

__attribute__((sysv_abi)) extern void
aes_gcm_aad_update_vaes_avx10( fd_aes_gcm_avx10_t const * key,
                               uchar                ghash_acc[16],
                               uchar const *        aad,
                               int                  aadlen );

__attribute__((sysv_abi)) extern void
aes_gcm_enc_update_vaes_avx10_512( fd_aes_gcm_avx10_t * key,
                                   uint const           le_ctr[4],
                                   uchar                ghash_acc[16],
                                   uchar const *        src,
                                   uchar *              dst,
                                   int                  datalen );

__attribute__((sysv_abi)) extern void
aes_gcm_enc_final_vaes_avx10( fd_aes_gcm_avx10_t * key,
                              uint const           le_ctr[4],
                              uchar                ghash_acc[16],
                              ulong                total_aadlen,
                              ulong                total_datalen );

__attribute__((sysv_abi)) extern void
aes_gcm_dec_update_vaes_avx10_512( fd_aes_gcm_avx10_t const * key,
                                   uint const                 le_ctr[4],
                                   uchar                      ghash_acc[16],
                                   uchar const *              src,
                                   uchar *                    dst,
                                   int                        datalen );

__attribute__((sysv_abi,warn_unused_result)) extern int
aes_gcm_dec_final_vaes_avx10( fd_aes_gcm_avx10_t const * key,
                              uint const                 le_ctr[4],
                              uchar const                ghash_acc[16],
                              ulong                      total_aadlen,
                              ulong                      total_datalen,
                              uchar const                tag[16],
                              int                        taglen );

void
fd_aes_128_gcm_init_avx10( fd_aes_gcm_avx10_t * aes_gcm,
                           uchar const          key[ 16 ],
                           uchar const          iv [ 12 ] ) {
  expand_aes_key( &aes_gcm->key, key );
  aes_gcm_precompute_vaes_avx10_512( aes_gcm );
  memcpy( aes_gcm->iv, iv, 12 );
}

void
fd_aes_128_gcm_init_avx10_512( fd_aes_gcm_avx10_t * aes_gcm,
                               uchar const          key[ 16 ],
                               uchar const          iv [ 12 ] ) {
  expand_aes_key( &aes_gcm->key, key );
  aes_gcm_precompute_vaes_avx10_512( aes_gcm );
  memcpy( aes_gcm->iv, iv, 12 );
}

void
fd_aes_gcm_encrypt_avx10_512( fd_aes_gcm_avx10_t * aes_gcm,
                              uchar *              c,
                              uchar const *        p,
                              ulong                sz,
                              uchar const *        aad,
                              ulong                aad_sz,
                              uchar                tag[ 16 ] ) {
  uint le_ctr[4]; load_le_ctr( le_ctr, aes_gcm->iv );
  uchar ghash_acc[16] = {0};
  aes_gcm_aad_update_vaes_avx10    ( aes_gcm, ghash_acc, aad, (int)aad_sz );
  aes_gcm_enc_update_vaes_avx10_512( aes_gcm, le_ctr, ghash_acc, p, c, (int)sz );
  aes_gcm_enc_final_vaes_avx10     ( aes_gcm, le_ctr, ghash_acc, aad_sz, sz );
  memcpy( tag, ghash_acc, 16 );
}

int
fd_aes_gcm_decrypt_avx10_512( fd_aes_gcm_avx10_t * aes_gcm,
                              uchar const *        c,
                              uchar *              p,
                              ulong                sz,
                              uchar const *        aad,
                              ulong                aad_sz,
                              uchar const          tag[ 16 ] ) {
  uint le_ctr[4]; load_le_ctr( le_ctr, aes_gcm->iv );
  uchar ghash_acc[16] = {0};
  aes_gcm_aad_update_vaes_avx10      ( aes_gcm, ghash_acc, aad, (int)aad_sz );
  aes_gcm_dec_update_vaes_avx10_512  ( aes_gcm, le_ctr, ghash_acc, c, p, (int)sz );
  return aes_gcm_dec_final_vaes_avx10( aes_gcm, le_ctr, ghash_acc, aad_sz, sz, tag, 16 );
}

#endif /* FD_HAS_AVX512 && FD_HAS_GFNI && FD_HAS_AESNI */
