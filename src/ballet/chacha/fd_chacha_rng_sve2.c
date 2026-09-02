#include "fd_chacha_rng.h"
#include <arm_sve.h>

#define QR( a, b, c, d ) do {           \
    (a) = svadd_u32_x( pg, (a), (b) );  \
    (d) = svxar_n_u32( (d), (a), 16 );  \
    (c) = svadd_u32_x( pg, (c), (d) );  \
    (b) = svxar_n_u32( (b), (c), 20 );  \
    (a) = svadd_u32_x( pg, (a), (b) );  \
    (d) = svxar_n_u32( (d), (a), 24 );  \
    (c) = svadd_u32_x( pg, (c), (d) );  \
    (b) = svxar_n_u32( (b), (c), 25 );  \
  } while(0)

#define STORE_4X4_128( pg4, out0, out1, out2, out3, a, b, c, d ) do {                   \
    svuint32_t ab0 = svtrn1_u32( (a), (b) );                                            \
    svuint32_t ab1 = svtrn2_u32( (a), (b) );                                            \
    svuint32_t cd0 = svtrn1_u32( (c), (d) );                                            \
    svuint32_t cd1 = svtrn2_u32( (c), (d) );                                            \
                                                                                        \
    svuint64_t ab0_64 = svreinterpret_u64_u32( ab0 );                                   \
    svuint64_t ab1_64 = svreinterpret_u64_u32( ab1 );                                   \
    svuint64_t cd0_64 = svreinterpret_u64_u32( cd0 );                                   \
    svuint64_t cd1_64 = svreinterpret_u64_u32( cd1 );                                   \
                                                                                        \
    svst1_u32( (pg4), (out0), svreinterpret_u32_u64( svzip1_u64( ab0_64, cd0_64 ) ) );  \
    svst1_u32( (pg4), (out1), svreinterpret_u32_u64( svzip1_u64( ab1_64, cd1_64 ) ) );  \
    svst1_u32( (pg4), (out2), svreinterpret_u32_u64( svzip2_u64( ab0_64, cd0_64 ) ) );  \
    svst1_u32( (pg4), (out3), svreinterpret_u32_u64( svzip2_u64( ab1_64, cd1_64 ) ) );  \
  } while(0)

#define STORE_4X4_VLA( pg4, out0, out1, out2, out3, a, b, c, d ) do {                   \
    svuint64_t ab0 = svreinterpret_u64_u32( svtrn1_u32( (a), (b) ) );                   \
    svuint64_t ab1 = svreinterpret_u64_u32( svtrn2_u32( (a), (b) ) );                   \
    svuint64_t cd0 = svreinterpret_u64_u32( svtrn1_u32( (c), (d) ) );                   \
    svuint64_t cd1 = svreinterpret_u64_u32( svtrn2_u32( (c), (d) ) );                   \
                                                                                        \
    svst1_u32( (pg4), (out0),                                                           \
               svreinterpret_u32_u64( svtrn1_u64( ab0, cd0 ) ) );                       \
    svst1_u32( (pg4), (out1),                                                           \
               svreinterpret_u32_u64( svtrn1_u64( ab1, cd1 ) ) );                       \
    svst1_u32( (pg4), (out2),                                                           \
               svreinterpret_u32_u64( svtrn2_u64( ab0, cd0 ) ) );                       \
    svst1_u32( (pg4), (out3),                                                           \
               svreinterpret_u32_u64( svtrn2_u64( ab1, cd1 ) ) );                       \
  } while(0)

static void
fd_chacha_rng_refill_sve2( fd_chacha_rng_t * rng,
                           ulong             rnd2_cnt ) {
  uint const * key = (uint const *)rng->key;
  ulong idx = rng->buf_fill >> 6;

  svbool_t const pg  = svptrue_b32();
  svbool_t const pg4 = svwhilelt_b32_u64( 0UL, 4UL );

  svuint32_t x0  = svdup_n_u32( 0x61707865U );
  svuint32_t x1  = svdup_n_u32( 0x3320646eU );
  svuint32_t x2  = svdup_n_u32( 0x79622d32U );
  svuint32_t x3  = svdup_n_u32( 0x6b206574U );
  svuint32_t x4  = svdup_n_u32( key[0] );
  svuint32_t x5  = svdup_n_u32( key[1] );
  svuint32_t x6  = svdup_n_u32( key[2] );
  svuint32_t x7  = svdup_n_u32( key[3] );
  svuint32_t x8  = svdup_n_u32( key[4] );
  svuint32_t x9  = svdup_n_u32( key[5] );
  svuint32_t x10 = svdup_n_u32( key[6] );
  svuint32_t x11 = svdup_n_u32( key[7] );
  svuint32_t x12 = svdupq_n_u32( (uint)(idx+0UL), (uint)(idx+1UL), (uint)(idx+2UL), (uint)(idx+3UL) );
  svuint32_t x13 = svdupq_n_u32( (uint)((idx+0UL)>>32), (uint)((idx+1UL)>>32),
                                 (uint)((idx+2UL)>>32), (uint)((idx+3UL)>>32) );
  svuint32_t x14 = svdup_n_u32( 0U );
  svuint32_t x15 = svdup_n_u32( 0U );

  for( ulong i=0UL; i<rnd2_cnt; i++ ) {
    QR( x0, x4, x8,  x12 );
    QR( x1, x5, x9,  x13 );
    QR( x2, x6, x10, x14 );
    QR( x3, x7, x11, x15 );
    QR( x0, x5, x10, x15 );
    QR( x1, x6, x11, x12 );
    QR( x2, x7, x8,  x13 );
    QR( x3, x4, x9,  x14 );
  }

  x0  = svadd_n_u32_x( pg, x0,  0x61707865U );
  x1  = svadd_n_u32_x( pg, x1,  0x3320646eU );
  x2  = svadd_n_u32_x( pg, x2,  0x79622d32U );
  x3  = svadd_n_u32_x( pg, x3,  0x6b206574U );
  x4  = svadd_n_u32_x( pg, x4,  key[0] );
  x5  = svadd_n_u32_x( pg, x5,  key[1] );
  x6  = svadd_n_u32_x( pg, x6,  key[2] );
  x7  = svadd_n_u32_x( pg, x7,  key[3] );
  x8  = svadd_n_u32_x( pg, x8,  key[4] );
  x9  = svadd_n_u32_x( pg, x9,  key[5] );
  x10 = svadd_n_u32_x( pg, x10, key[6] );
  x11 = svadd_n_u32_x( pg, x11, key[7] );
  x12 = svadd_u32_x( pg, x12, svdupq_n_u32( (uint)(  idx+0UL      ), (uint)(  idx+1UL      ),
                                            (uint)(  idx+2UL      ), (uint)(  idx+3UL      ) ) );
  x13 = svadd_u32_x( pg, x13, svdupq_n_u32( (uint)( (idx+0UL)>>32 ), (uint)( (idx+1UL)>>32 ),
                                            (uint)( (idx+2UL)>>32 ), (uint)( (idx+3UL)>>32 ) ) );

  uint * out = (uint *)rng->buf;
  if( FD_LIKELY( svcntw()==4UL ) ) {
    STORE_4X4_128( pg4, out+ 0, out+16, out+32, out+48, x0,  x1,  x2,  x3  );
    STORE_4X4_128( pg4, out+ 4, out+20, out+36, out+52, x4,  x5,  x6,  x7  );
    STORE_4X4_128( pg4, out+ 8, out+24, out+40, out+56, x8,  x9,  x10, x11 );
    STORE_4X4_128( pg4, out+12, out+28, out+44, out+60, x12, x13, x14, x15 );
  } else {
    STORE_4X4_VLA( pg4, out+ 0, out+16, out+32, out+48, x0,  x1,  x2,  x3  );
    STORE_4X4_VLA( pg4, out+ 4, out+20, out+36, out+52, x4,  x5,  x6,  x7  );
    STORE_4X4_VLA( pg4, out+ 8, out+24, out+40, out+56, x8,  x9,  x10, x11 );
    STORE_4X4_VLA( pg4, out+12, out+28, out+44, out+60, x12, x13, x14, x15 );
  }

  rng->buf_fill += 4UL*FD_CHACHA_BLOCK_SZ;
}

#undef STORE_4X4_VLA
#undef STORE_4X4_128
#undef QR

void
fd_chacha8_rng_refill_sve2( fd_chacha_rng_t * rng ) {
  fd_chacha_rng_refill_sve2( rng, 4UL );
}

void
fd_chacha20_rng_refill_sve2( fd_chacha_rng_t * rng ) {
  fd_chacha_rng_refill_sve2( rng, 10UL );
}
