
#include "fd_sha256.h"
#include "fd_sha256_constants.h"
#include <arm_neon.h>

/* SHA-256 using ARMv8 FEAT_SHA256 Crypto Extensions. */

static void
fd_sha256_core_arm( uint *        state,
                    uchar const * block,
                    ulong         block_cnt ) {

#define SHA256_ROUNDS( MSG, KIDX ) do {                                    \
    uint32x4_t wk = vaddq_u32( (MSG), vld1q_u32( fd_sha256_K + (KIDX) ) ); \
    uint32x4_t abcd_prev = abcd;                                           \
    abcd = vsha256hq_u32(  abcd, efgh, wk );                               \
    efgh = vsha256h2q_u32( efgh, abcd_prev, wk );                          \
  } while( 0 )

  do {
    uint32x4_t abcd      = vld1q_u32( state   );
    uint32x4_t efgh      = vld1q_u32( state+4 );
    uint32x4_t abcd_init = abcd;
    uint32x4_t efgh_init = efgh;

    uint32x4_t msg0 = vreinterpretq_u32_u8( vrev32q_u8( vld1q_u8( block    ) ) );
    uint32x4_t msg1 = vreinterpretq_u32_u8( vrev32q_u8( vld1q_u8( block+16 ) ) );
    uint32x4_t msg2 = vreinterpretq_u32_u8( vrev32q_u8( vld1q_u8( block+32 ) ) );
    uint32x4_t msg3 = vreinterpretq_u32_u8( vrev32q_u8( vld1q_u8( block+48 ) ) );

    SHA256_ROUNDS( msg0,  0 );
    msg0 = vsha256su0q_u32( msg0, msg1 );
    SHA256_ROUNDS( msg1,  4 );
    msg1 = vsha256su0q_u32( msg1, msg2 );
    msg0 = vsha256su1q_u32( msg0, msg2, msg3 );
    SHA256_ROUNDS( msg2,  8 );
    msg2 = vsha256su0q_u32( msg2, msg3 );
    msg1 = vsha256su1q_u32( msg1, msg3, msg0 );
    SHA256_ROUNDS( msg3, 12 );
    msg3 = vsha256su0q_u32( msg3, msg0 );
    msg2 = vsha256su1q_u32( msg2, msg0, msg1 );

    SHA256_ROUNDS( msg0, 16 );
    msg0 = vsha256su0q_u32( msg0, msg1 );
    msg3 = vsha256su1q_u32( msg3, msg1, msg2 );
    SHA256_ROUNDS( msg1, 20 );
    msg1 = vsha256su0q_u32( msg1, msg2 );
    msg0 = vsha256su1q_u32( msg0, msg2, msg3 );
    SHA256_ROUNDS( msg2, 24 );
    msg2 = vsha256su0q_u32( msg2, msg3 );
    msg1 = vsha256su1q_u32( msg1, msg3, msg0 );
    SHA256_ROUNDS( msg3, 28 );
    msg3 = vsha256su0q_u32( msg3, msg0 );
    msg2 = vsha256su1q_u32( msg2, msg0, msg1 );

    SHA256_ROUNDS( msg0, 32 );
    msg0 = vsha256su0q_u32( msg0, msg1 );
    msg3 = vsha256su1q_u32( msg3, msg1, msg2 );
    SHA256_ROUNDS( msg1, 36 );
    msg1 = vsha256su0q_u32( msg1, msg2 );
    msg0 = vsha256su1q_u32( msg0, msg2, msg3 );
    SHA256_ROUNDS( msg2, 40 );
    msg2 = vsha256su0q_u32( msg2, msg3 );
    msg1 = vsha256su1q_u32( msg1, msg3, msg0 );
    SHA256_ROUNDS( msg3, 44 );
    msg3 = vsha256su0q_u32( msg3, msg0 );
    msg2 = vsha256su1q_u32( msg2, msg0, msg1 );

    SHA256_ROUNDS( msg0, 48 );
    msg0 = vsha256su0q_u32( msg0, msg1 );
    msg3 = vsha256su1q_u32( msg3, msg1, msg2 );
    SHA256_ROUNDS( msg1, 52 );
    msg1 = vsha256su0q_u32( msg1, msg2 );
    msg0 = vsha256su1q_u32( msg0, msg2, msg3 );
    SHA256_ROUNDS( msg2, 56 );
    SHA256_ROUNDS( msg3, 60 );

    vst1q_u32( state,   vaddq_u32( abcd, abcd_init ) );
    vst1q_u32( state+4, vaddq_u32( efgh, efgh_init ) );
    block += FD_SHA256_BLOCK_SZ;
  } while( --block_cnt );

#undef SHA256_ROUNDS
}

static void
fd_sha256_hash_32_repeated_arm( uchar const * data,
                                uchar *       hash,
                                ulong         cnt ) {
  uint32x4_t msg0 = vreinterpretq_u32_u8( vrev32q_u8( vld1q_u8( data      ) ) );
  uint32x4_t msg1 = vreinterpretq_u32_u8( vrev32q_u8( vld1q_u8( data+16UL ) ) );
  uint32x4_t const pad0 = { 0x80000000U, 0U, 0U,   0U };
  uint32x4_t const pad1 = {          0U, 0U, 0U, 256U };
  uint32x4_t const initialABCD = { FD_SHA256_INITIAL_A, FD_SHA256_INITIAL_B,
                                   FD_SHA256_INITIAL_C, FD_SHA256_INITIAL_D };
  uint32x4_t const initialEFGH = { FD_SHA256_INITIAL_E, FD_SHA256_INITIAL_F,
                                   FD_SHA256_INITIAL_G, FD_SHA256_INITIAL_H };

#define SHA256_REPEATED_ROUNDS( MSG, KIDX ) do {                            \
    uint32x4_t wk = vaddq_u32( (MSG), vld1q_u32( fd_sha256_K + (KIDX) ) ); \
    uint32x4_t abcd_prev = abcd;                                           \
    abcd = vsha256hq_u32(  abcd, efgh, wk );                               \
    efgh = vsha256h2q_u32( efgh, abcd_prev, wk );                          \
  } while( 0 )

  for( ulong iter=0UL; iter<cnt; iter++ ) {
    uint32x4_t abcd = initialABCD;
    uint32x4_t efgh = initialEFGH;
    uint32x4_t w0 = msg0;
    uint32x4_t w1 = msg1;
    uint32x4_t w2 = pad0;
    uint32x4_t w3 = pad1;

    SHA256_REPEATED_ROUNDS( w0,  0 ); w0 = vsha256su0q_u32( w0, w1 );
    SHA256_REPEATED_ROUNDS( w1,  4 ); w1 = vsha256su0q_u32( w1, w2 ); w0 = vsha256su1q_u32( w0, w2, w3 );
    SHA256_REPEATED_ROUNDS( w2,  8 ); w2 = vsha256su0q_u32( w2, w3 ); w1 = vsha256su1q_u32( w1, w3, w0 );
    SHA256_REPEATED_ROUNDS( w3, 12 ); w3 = vsha256su0q_u32( w3, w0 ); w2 = vsha256su1q_u32( w2, w0, w1 );

    SHA256_REPEATED_ROUNDS( w0, 16 ); w0 = vsha256su0q_u32( w0, w1 ); w3 = vsha256su1q_u32( w3, w1, w2 );
    SHA256_REPEATED_ROUNDS( w1, 20 ); w1 = vsha256su0q_u32( w1, w2 ); w0 = vsha256su1q_u32( w0, w2, w3 );
    SHA256_REPEATED_ROUNDS( w2, 24 ); w2 = vsha256su0q_u32( w2, w3 ); w1 = vsha256su1q_u32( w1, w3, w0 );
    SHA256_REPEATED_ROUNDS( w3, 28 ); w3 = vsha256su0q_u32( w3, w0 ); w2 = vsha256su1q_u32( w2, w0, w1 );

    SHA256_REPEATED_ROUNDS( w0, 32 ); w0 = vsha256su0q_u32( w0, w1 ); w3 = vsha256su1q_u32( w3, w1, w2 );
    SHA256_REPEATED_ROUNDS( w1, 36 ); w1 = vsha256su0q_u32( w1, w2 ); w0 = vsha256su1q_u32( w0, w2, w3 );
    SHA256_REPEATED_ROUNDS( w2, 40 ); w2 = vsha256su0q_u32( w2, w3 ); w1 = vsha256su1q_u32( w1, w3, w0 );
    SHA256_REPEATED_ROUNDS( w3, 44 ); w3 = vsha256su0q_u32( w3, w0 ); w2 = vsha256su1q_u32( w2, w0, w1 );

    SHA256_REPEATED_ROUNDS( w0, 48 ); w0 = vsha256su0q_u32( w0, w1 ); w3 = vsha256su1q_u32( w3, w1, w2 );
    SHA256_REPEATED_ROUNDS( w1, 52 ); w1 = vsha256su0q_u32( w1, w2 ); w0 = vsha256su1q_u32( w0, w2, w3 );
    SHA256_REPEATED_ROUNDS( w2, 56 );
    SHA256_REPEATED_ROUNDS( w3, 60 );

    msg0 = vaddq_u32( abcd, initialABCD );
    msg1 = vaddq_u32( efgh, initialEFGH );
  }
  vst1q_u8( hash,      vrev32q_u8( vreinterpretq_u8_u32( msg0 ) ) );
  vst1q_u8( hash+16UL, vrev32q_u8( vreinterpretq_u8_u32( msg1 ) ) );
}

#define LANE_RND( l, W ) {                              \
    uint32x4_t wk        = vaddq_u32( W##_##l, k );     \
    uint32x4_t abcd_prev = abcd##l;                     \
    abcd##l = vsha256hq_u32(  abcd##l, efgh##l, wk );   \
    efgh##l = vsha256h2q_u32( efgh##l, abcd_prev, wk ); \
  }

#define RND( W, KIDX ) do {                             \
    uint32x4_t k = vld1q_u32( fd_sha256_K + (KIDX) );   \
    LANE_RND( 0, W )                                    \
    LANE_RND( 1, W )                                    \
  } while( 0 )

#define SU0( A, B ) do {                                \
    A##_0 = vsha256su0q_u32( A##_0, B##_0 );            \
    A##_1 = vsha256su0q_u32( A##_1, B##_1 );            \
  } while( 0 )

#define SU1( A, B, C ) do {                             \
    A##_0 = vsha256su1q_u32( A##_0, B##_0, C##_0 );     \
    A##_1 = vsha256su1q_u32( A##_1, B##_1, C##_1 );     \
  } while( 0 )

static void
fd_sha256_repeat_lanes_x2( uint32x4_t * msg,   /* [4] */
                           ulong        cnt ) {

  uint32x4_t const pad0 = { 0x80000000U, 0U, 0U,   0U };
  uint32x4_t const pad1 = {          0U, 0U, 0U, 256U };
  uint32x4_t const initialABCD = { FD_SHA256_INITIAL_A, FD_SHA256_INITIAL_B,
                                   FD_SHA256_INITIAL_C, FD_SHA256_INITIAL_D };
  uint32x4_t const initialEFGH = { FD_SHA256_INITIAL_E, FD_SHA256_INITIAL_F,
                                   FD_SHA256_INITIAL_G, FD_SHA256_INITIAL_H };

  uint32x4_t m0_0 = msg[ 0 ]; uint32x4_t m1_0 = msg[ 1 ];
  uint32x4_t m0_1 = msg[ 2 ]; uint32x4_t m1_1 = msg[ 3 ];

  for( ulong iter=0UL; iter<cnt; iter++ ) {
    uint32x4_t abcd0 = initialABCD; uint32x4_t efgh0 = initialEFGH;
    uint32x4_t w0_0  = m0_0;        uint32x4_t w1_0  = m1_0;
    uint32x4_t w2_0  = pad0;        uint32x4_t w3_0  = pad1;

    uint32x4_t abcd1 = initialABCD; uint32x4_t efgh1 = initialEFGH;
    uint32x4_t w0_1  = m0_1;        uint32x4_t w1_1  = m1_1;
    uint32x4_t w2_1  = pad0;        uint32x4_t w3_1  = pad1;

    RND( w0,  0 ); SU0( w0, w1 );
    RND( w1,  4 ); SU0( w1, w2 ); SU1( w0, w2, w3 );
    RND( w2,  8 ); SU0( w2, w3 ); SU1( w1, w3, w0 );
    RND( w3, 12 ); SU0( w3, w0 ); SU1( w2, w0, w1 );

    RND( w0, 16 ); SU0( w0, w1 ); SU1( w3, w1, w2 );
    RND( w1, 20 ); SU0( w1, w2 ); SU1( w0, w2, w3 );
    RND( w2, 24 ); SU0( w2, w3 ); SU1( w1, w3, w0 );
    RND( w3, 28 ); SU0( w3, w0 ); SU1( w2, w0, w1 );

    RND( w0, 32 ); SU0( w0, w1 ); SU1( w3, w1, w2 );
    RND( w1, 36 ); SU0( w1, w2 ); SU1( w0, w2, w3 );
    RND( w2, 40 ); SU0( w2, w3 ); SU1( w1, w3, w0 );
    RND( w3, 44 ); SU0( w3, w0 ); SU1( w2, w0, w1 );

    RND( w0, 48 ); SU0( w0, w1 ); SU1( w3, w1, w2 );
    RND( w1, 52 ); SU0( w1, w2 ); SU1( w0, w2, w3 );
    RND( w2, 56 );
    RND( w3, 60 );

    m0_0 = vaddq_u32( abcd0, initialABCD ); m1_0 = vaddq_u32( efgh0, initialEFGH );
    m0_1 = vaddq_u32( abcd1, initialABCD ); m1_1 = vaddq_u32( efgh1, initialEFGH );
  }

  msg[ 0 ] = m0_0; msg[ 1 ] = m1_0;
  msg[ 2 ] = m0_1; msg[ 3 ] = m1_1;
}

#undef SU1
#undef SU0
#undef RND
#undef LANE_RND

static inline void
repbatch_lane_load( uint32x4_t  msg[4],
                    ulong       lane,
                    uchar const in[32] ) {
  msg[ 2UL*lane      ] = vreinterpretq_u32_u8( vrev32q_u8( vld1q_u8( in      ) ) );
  msg[ 2UL*lane+1UL  ] = vreinterpretq_u32_u8( vrev32q_u8( vld1q_u8( in+16UL ) ) );
}

static inline void
repbatch_lane_store( uchar            out[32],
                     uint32x4_t const msg[4],
                     ulong            lane ) {
  vst1q_u8( out,      vrev32q_u8( vreinterpretq_u8_u32( msg[ 2UL*lane     ] ) ) );
  vst1q_u8( out+16UL, vrev32q_u8( vreinterpretq_u8_u32( msg[ 2UL*lane+1UL ] ) ) );
}

void
fd_sha256_hash_32_repeated_batch_arm( uchar const * hash_in,
                                      uchar *       hash,
                                      ulong const * cnt,
                                      ulong         batch_cnt ) {

  uint32x4_t msg [ 4 ];
  ulong      slot[ 2 ];
  ulong      rem [ 2 ];
  int        live[ 2 ] = { 0, 0 };
  ulong      next      = 0UL;

  for(;;) {

    for( ulong l=0UL; l<2UL; l++ ) {
      while( !live[ l ] && next<batch_cnt ) {
        ulong e = next++;
        if( FD_UNLIKELY( !cnt[ e ] ) ) {
          memcpy( hash+32UL*e, hash_in+32UL*e, 32UL );
          continue;
        }
        repbatch_lane_load( msg, l, hash_in+32UL*e );
        slot[ l ] = e;
        rem [ l ] = cnt[ e ];
        live[ l ] = 1;
      }
    }

    if( FD_UNLIKELY( !live[ 0 ] && !live[ 1 ] ) ) break;

    if( FD_LIKELY( live[ 0 ] && live[ 1 ] ) ) {
      ulong step = fd_ulong_min( rem[ 0 ], rem[ 1 ] );
      fd_sha256_repeat_lanes_x2( msg, step );
      rem[ 0 ] -= step;
      rem[ 1 ] -= step;

      for( ulong l=0UL; l<2UL; l++ ) {
        if( !rem[ l ] ) {
          repbatch_lane_store( hash+32UL*slot[ l ], msg, l );
          live[ l ] = 0;
        }
      }
    } else {
      ulong l   = live[ 0 ] ? 0UL : 1UL;
      ulong out = 32UL*slot[ l ];
      repbatch_lane_store( hash+out, msg, l );
      fd_sha256_hash_32_repeated_arm( hash+out, hash+out, rem[ l ] );
      live[ l ] = 0;
    }
  }
}
