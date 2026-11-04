
#include "fd_sha256.h"
#include "fd_sha256_constants.h"
#include <arm_neon.h>

/* SHA-256 using ARMv8 FEAT_SHA256 Crypto Extensions. */

void
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
