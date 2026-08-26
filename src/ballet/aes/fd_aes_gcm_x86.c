/* fd_aes_gcm_x86.c provides wrappers and AES key expansion for
   fd_aes_gcm_{aesni,avx10}.S */

#include "fd_aes_gcm.h"
#include "../../util/sanitize/fd_msan.h"

#if FD_HAS_AESNI

#include "../../util/simd/fd_sse.h"

FD_FN_SENSITIVE static void
expand_aes_key( fd_aes_gcm_aesni_key_t * out,
                uchar const *            keyp,
                ulong                    key_sz ) {
  vb_t v0 = vb_ldu( keyp );
  vb_t v1;

# define EXPAND_A( gen, shuffle ) do {                \
    vb_t v2 = _mm_aeskeygenassist_si128( v1, (gen) ); \
         v2 = _mm_shuffle_epi32( v2, (shuffle) );     \
    vb_t v3 = _mm_slli_si128( v0, 4 );                \
         v0 = vu_xor( v0, v3 );                       \
         v3 = _mm_slli_si128( v3, 4 );                \
         v0 = vu_xor( v0, v3 );                       \
         v3 = _mm_slli_si128( v3, 4 );                \
         v0 = vu_xor( v0, v3 );                       \
         v0 = vu_xor( v0, v2 );                       \
  } while(0)

  ulong nr;
  switch( key_sz ) {
  case 16UL:
    v1 = v0;
    vb_st( out->key_enc, v0 );
#   define EXPAND_128( off, gen ) do {   \
      EXPAND_A( (gen), 0xff );           \
      vb_st( out->key_enc + (off), v0 ); \
      v1 = v0;                           \
    } while(0)
    EXPAND_128( 0x10, 0x01 );
    EXPAND_128( 0x20, 0x02 );
    EXPAND_128( 0x30, 0x04 );
    EXPAND_128( 0x40, 0x08 );
    EXPAND_128( 0x50, 0x10 );
    EXPAND_128( 0x60, 0x20 );
    EXPAND_128( 0x70, 0x40 );
    EXPAND_128( 0x80, 0x80 );
    EXPAND_128( 0x90, 0x1b );
    EXPAND_128( 0xa0, 0x36 );
#   undef EXPAND_128
    nr = 10UL;
    break;
  case 24UL:
    v1 = _mm_loadl_epi64( (__m128i const *)(keyp+16) );
    vb_st ( out->key_enc,    v0 );
    _mm_storel_epi64( (__m128i *)(out->key_enc+16), v1 );
#   define EXPAND_192( off, gen ) do {                            \
      EXPAND_A( (gen), 0x55 );                                    \
      vb_t v2 = _mm_shuffle_epi32( v0, 0xff );                    \
      v1 = vu_xor( v1, _mm_slli_si128( v1, 4 ) );                 \
      v1 = vu_xor( v1, v2 );                                      \
      vb_stu( out->key_enc + (off), v0 );                         \
      _mm_storel_epi64( (__m128i *)(out->key_enc+(off)+16), v1 ); \
    } while(0)
    EXPAND_192(  24, 0x01 );
    EXPAND_192(  48, 0x02 );
    EXPAND_192(  72, 0x04 );
    EXPAND_192(  96, 0x08 );
    EXPAND_192( 120, 0x10 );
    EXPAND_192( 144, 0x20 );
    EXPAND_192( 168, 0x40 );
#   undef EXPAND_192
    EXPAND_A( 0x80, 0x55 );
    vb_st( out->key_enc + 192, v0 );
    nr = 12UL;
    break;
  case 32UL:
    v1 = vb_ldu( keyp+16 );
    vb_st( out->key_enc,      v0 );
    vb_st( out->key_enc+0x10, v1 );
#   define EXPAND_256_A( off, gen ) do {               \
      EXPAND_A( (gen), 0xff );                         \
      vb_st( out->key_enc + (off), v0 );               \
    } while(0)
#   define EXPAND_256_B( off ) do {                    \
      vb_t v2 = _mm_aeskeygenassist_si128( v0, 0x00 ); \
           v2 = _mm_shuffle_epi32( v2, 0xaa );         \
      vb_t v3 = _mm_slli_si128( v1, 4 );               \
           v1 = vu_xor( v1, v3 );                      \
           v3 = _mm_slli_si128( v3, 4 );               \
           v1 = vu_xor( v1, v3 );                      \
           v3 = _mm_slli_si128( v3, 4 );               \
           v1 = vu_xor( v1, v3 );                      \
           v1 = vu_xor( v1, v2 );                      \
      vb_st( out->key_enc + (off), v1 );               \
    } while(0)
    EXPAND_256_A( 0x20, 0x01 ); EXPAND_256_B( 0x30 );
    EXPAND_256_A( 0x40, 0x02 ); EXPAND_256_B( 0x50 );
    EXPAND_256_A( 0x60, 0x04 ); EXPAND_256_B( 0x70 );
    EXPAND_256_A( 0x80, 0x08 ); EXPAND_256_B( 0x90 );
    EXPAND_256_A( 0xa0, 0x10 ); EXPAND_256_B( 0xb0 );
    EXPAND_256_A( 0xc0, 0x20 ); EXPAND_256_B( 0xd0 );
    EXPAND_256_A( 0xe0, 0x40 );
#   undef EXPAND_256_B
#   undef EXPAND_256_A
    nr = 14UL;
    break;
  default:
    FD_LOG_CRIT(( "invalid key_sz %lu", key_sz ));
  }
# undef EXPAND_A

  vb_st( out->key_dec, vb_ld( out->key_enc + nr*16UL ) );
  for( ulong i=1UL; i<nr; i++ ) {
    vb_t enc_key = vb_ld( out->key_enc + i*16UL );
    vb_st( out->key_dec + (nr-i)*16UL, _mm_aesimc_si128( enc_key ) );
  }
  vb_st( out->key_dec + nr*16UL, vb_ld( out->key_enc ) );
  out->key_sz = (uint)key_sz;
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
fd_aes_gcm_init_aesni( fd_aes_gcm_aesni_t * aes_gcm,
                       uchar const *        key,
                       ulong                key_sz,
                       uchar const          iv[ 12 ] ) {
  expand_aes_key( &aes_gcm->key, key, key_sz );
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
  fd_msan_unpoison( c, sz );
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
  fd_msan_unpoison( p, sz );
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
fd_aes_gcm_init_avx2( fd_aes_gcm_aesni_t * aes_gcm,
                      uchar const *        key,
                      ulong                key_sz,
                      uchar const          iv[ 12 ] ) {
  expand_aes_key( &aes_gcm->key, key, key_sz );
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
  fd_msan_unpoison( c, sz );
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
  fd_msan_unpoison( p, sz );
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
fd_aes_gcm_init_avx10_512( fd_aes_gcm_avx10_t * aes_gcm,
                           uchar const *        key,
                           ulong                key_sz,
                           uchar const          iv[ 12 ] ) {
  expand_aes_key( &aes_gcm->key, key, key_sz );
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
  fd_msan_unpoison( c, sz );
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
  fd_msan_unpoison( p, sz );
  return aes_gcm_dec_final_vaes_avx10( aes_gcm, le_ctr, ghash_acc, aad_sz, sz, tag, 16 );
}

#endif /* FD_HAS_AVX512 && FD_HAS_GFNI && FD_HAS_AESNI */
