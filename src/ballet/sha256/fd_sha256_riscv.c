#include "fd_sha256.h"
#include "fd_sha256_constants.h"

#if !FD_HAS_RISCV_SHA256
#error "fd_sha256_riscv requires FD_HAS_RISCV_SHA256"
#endif

#if !defined(__riscv) || (__riscv_xlen!=64)
#error "fd_sha256_riscv requires RV64"
#endif

#if !defined(__riscv_zvkb) || (!defined(__riscv_zvknha) && !defined(__riscv_zvknhb))
#error "fd_sha256_riscv requires Zvkb and Zvknha or Zvknhb"
#endif

#if !defined(__riscv_zvl128b)
#error "fd_sha256_riscv requires VLEN >= 128"
#endif

#include <riscv_vector.h>

/* The SHA-2 vector instructions operate on four rounds at a time.  They
   expect the state as {fe,b,a},{h,g,d,c}, while message vectors remain in
   the natural W[t:t+3] order. */

#define FD_SHA256_RISCV_VL (4UL)

#define FD_SHA256_RISCV_DECLARE_CONSTANTS()                                              \
  vuint32m1_t const k00 = __riscv_vle32_v_u32m1( fd_sha256_K     , FD_SHA256_RISCV_VL ); \
  vuint32m1_t const k01 = __riscv_vle32_v_u32m1( fd_sha256_K+ 4UL, FD_SHA256_RISCV_VL ); \
  vuint32m1_t const k02 = __riscv_vle32_v_u32m1( fd_sha256_K+ 8UL, FD_SHA256_RISCV_VL ); \
  vuint32m1_t const k03 = __riscv_vle32_v_u32m1( fd_sha256_K+12UL, FD_SHA256_RISCV_VL ); \
  vuint32m1_t const k04 = __riscv_vle32_v_u32m1( fd_sha256_K+16UL, FD_SHA256_RISCV_VL ); \
  vuint32m1_t const k05 = __riscv_vle32_v_u32m1( fd_sha256_K+20UL, FD_SHA256_RISCV_VL ); \
  vuint32m1_t const k06 = __riscv_vle32_v_u32m1( fd_sha256_K+24UL, FD_SHA256_RISCV_VL ); \
  vuint32m1_t const k07 = __riscv_vle32_v_u32m1( fd_sha256_K+28UL, FD_SHA256_RISCV_VL ); \
  vuint32m1_t const k08 = __riscv_vle32_v_u32m1( fd_sha256_K+32UL, FD_SHA256_RISCV_VL ); \
  vuint32m1_t const k09 = __riscv_vle32_v_u32m1( fd_sha256_K+36UL, FD_SHA256_RISCV_VL ); \
  vuint32m1_t const k10 = __riscv_vle32_v_u32m1( fd_sha256_K+40UL, FD_SHA256_RISCV_VL ); \
  vuint32m1_t const k11 = __riscv_vle32_v_u32m1( fd_sha256_K+44UL, FD_SHA256_RISCV_VL ); \
  vuint32m1_t const k12 = __riscv_vle32_v_u32m1( fd_sha256_K+48UL, FD_SHA256_RISCV_VL ); \
  vuint32m1_t const k13 = __riscv_vle32_v_u32m1( fd_sha256_K+52UL, FD_SHA256_RISCV_VL ); \
  vuint32m1_t const k14 = __riscv_vle32_v_u32m1( fd_sha256_K+56UL, FD_SHA256_RISCV_VL ); \
  vuint32m1_t const k15 = __riscv_vle32_v_u32m1( fd_sha256_K+60UL, FD_SHA256_RISCV_VL )

#define FD_SHA256_RISCV_ROUND( k, w ) do {                                         \
    vuint32m1_t _wk = __riscv_vadd_vv_u32m1( (k), (w), FD_SHA256_RISCV_VL );       \
    state1 = __riscv_vsha2cl_vv_u32m1( state1, state0, _wk, FD_SHA256_RISCV_VL );  \
    state0 = __riscv_vsha2ch_vv_u32m1( state0, state1, _wk, FD_SHA256_RISCV_VL );  \
  } while( 0 )

/* vsha2ms needs {W[t-12],W[t-7:t-5]} in its middle operand.  The lane-zero
   merge supplies W[t-12] without disturbing the other three lanes. */
#define FD_SHA256_RISCV_SCHEDULE( dst, middle, lane0_src, last ) do {                 \
    vuint32m1_t _middle = __riscv_vmerge_vvm_u32m1( (middle), (lane0_src), lane0,     \
                                                    FD_SHA256_RISCV_VL );             \
    (dst) = __riscv_vsha2ms_vv_u32m1( (dst), _middle, (last), FD_SHA256_RISCV_VL );   \
  } while( 0 )

#define FD_SHA256_RISCV_ROUNDS() do {           \
    FD_SHA256_RISCV_ROUND( k00, w0 );           \
    FD_SHA256_RISCV_SCHEDULE( w0, w2, w1, w3 ); \
    FD_SHA256_RISCV_ROUND( k01, w1 );           \
    FD_SHA256_RISCV_SCHEDULE( w1, w3, w2, w0 ); \
    FD_SHA256_RISCV_ROUND( k02, w2 );           \
    FD_SHA256_RISCV_SCHEDULE( w2, w0, w3, w1 ); \
    FD_SHA256_RISCV_ROUND( k03, w3 );           \
    FD_SHA256_RISCV_SCHEDULE( w3, w1, w0, w2 ); \
    FD_SHA256_RISCV_ROUND( k04, w0 );           \
    FD_SHA256_RISCV_SCHEDULE( w0, w2, w1, w3 ); \
    FD_SHA256_RISCV_ROUND( k05, w1 );           \
    FD_SHA256_RISCV_SCHEDULE( w1, w3, w2, w0 ); \
    FD_SHA256_RISCV_ROUND( k06, w2 );           \
    FD_SHA256_RISCV_SCHEDULE( w2, w0, w3, w1 ); \
    FD_SHA256_RISCV_ROUND( k07, w3 );           \
    FD_SHA256_RISCV_SCHEDULE( w3, w1, w0, w2 ); \
    FD_SHA256_RISCV_ROUND( k08, w0 );           \
    FD_SHA256_RISCV_SCHEDULE( w0, w2, w1, w3 ); \
    FD_SHA256_RISCV_ROUND( k09, w1 );           \
    FD_SHA256_RISCV_SCHEDULE( w1, w3, w2, w0 ); \
    FD_SHA256_RISCV_ROUND( k10, w2 );           \
    FD_SHA256_RISCV_SCHEDULE( w2, w0, w3, w1 ); \
    FD_SHA256_RISCV_ROUND( k11, w3 );           \
    FD_SHA256_RISCV_SCHEDULE( w3, w1, w0, w2 ); \
    FD_SHA256_RISCV_ROUND( k12, w0 );           \
    FD_SHA256_RISCV_ROUND( k13, w1 );           \
    FD_SHA256_RISCV_ROUND( k14, w2 );           \
    FD_SHA256_RISCV_ROUND( k15, w3 );           \
  } while( 0 )

static uint const fd_sha256_riscv_state_idx[4] __attribute__((aligned(16))) = {
  20U, 16U, 4U, 0U
};

static uint const fd_sha256_riscv_initial0[4] __attribute__((aligned(16))) = {
  FD_SHA256_INITIAL_F, FD_SHA256_INITIAL_E, FD_SHA256_INITIAL_B, FD_SHA256_INITIAL_A
};

static uint const fd_sha256_riscv_initial1[4] __attribute__((aligned(16))) = {
  FD_SHA256_INITIAL_H, FD_SHA256_INITIAL_G, FD_SHA256_INITIAL_D, FD_SHA256_INITIAL_C
};

static uint const fd_sha256_riscv_padding0[4] __attribute__((aligned(16))) = {
  0x80000000U, 0U, 0U, 0U
};

static uint const fd_sha256_riscv_padding1[4] __attribute__((aligned(16))) = {
  0U, 0U, 0U, 256U
};

static uint const fd_sha256_riscv_reverse_idx[4] __attribute__((aligned(16))) = {
  3U, 2U, 1U, 0U
};

void
fd_sha256_core_riscv( uint *        state,
                      uchar const * block,
                      ulong         block_cnt ) {
  FD_SHA256_RISCV_DECLARE_CONSTANTS();

  vuint32m1_t const idx = __riscv_vle32_v_u32m1( fd_sha256_riscv_state_idx,
                                                 FD_SHA256_RISCV_VL );
  vuint32m1_t state0 = __riscv_vluxei32_v_u32m1( state,     idx, FD_SHA256_RISCV_VL );
  vuint32m1_t state1 = __riscv_vluxei32_v_u32m1( state+2UL, idx, FD_SHA256_RISCV_VL );
  vuint32m1_t const lane_ids = __riscv_vid_v_u32m1( FD_SHA256_RISCV_VL );
  vbool32_t const lane0 = __riscv_vmseq_vx_u32m1_b32( lane_ids, 0U, FD_SHA256_RISCV_VL );

  do {
    vuint32m1_t w0 = __riscv_vreinterpret_v_u8m1_u32m1( __riscv_vle8_v_u8m1( block,      16UL ) );
    vuint32m1_t w1 = __riscv_vreinterpret_v_u8m1_u32m1( __riscv_vle8_v_u8m1( block+16UL, 16UL ) );
    vuint32m1_t w2 = __riscv_vreinterpret_v_u8m1_u32m1( __riscv_vle8_v_u8m1( block+32UL, 16UL ) );
    vuint32m1_t w3 = __riscv_vreinterpret_v_u8m1_u32m1( __riscv_vle8_v_u8m1( block+48UL, 16UL ) );
    w0 = __riscv_vrev8_v_u32m1( w0, FD_SHA256_RISCV_VL );
    w1 = __riscv_vrev8_v_u32m1( w1, FD_SHA256_RISCV_VL );
    w2 = __riscv_vrev8_v_u32m1( w2, FD_SHA256_RISCV_VL );
    w3 = __riscv_vrev8_v_u32m1( w3, FD_SHA256_RISCV_VL );

    vuint32m1_t const state0_save = state0;
    vuint32m1_t const state1_save = state1;
    FD_SHA256_RISCV_ROUNDS();
    state0 = __riscv_vadd_vv_u32m1( state0, state0_save, FD_SHA256_RISCV_VL );
    state1 = __riscv_vadd_vv_u32m1( state1, state1_save, FD_SHA256_RISCV_VL );
    block += FD_SHA256_BLOCK_SZ;
  } while( --block_cnt );

  __riscv_vsuxei32_v_u32m1( state,     idx, state0, FD_SHA256_RISCV_VL );
  __riscv_vsuxei32_v_u32m1( state+2UL, idx, state1, FD_SHA256_RISCV_VL );
}

void
fd_sha256_hash_32_repeated_riscv( uchar const * data,
                                  uchar *       hash,
                                  ulong         cnt ) {
  FD_SHA256_RISCV_DECLARE_CONSTANTS();

  vuint32m1_t w0 = __riscv_vle32_v_u32m1( (uint const *)data,      FD_SHA256_RISCV_VL );
  vuint32m1_t w1 = __riscv_vle32_v_u32m1( (uint const *)(data+16), FD_SHA256_RISCV_VL );
  w0 = __riscv_vrev8_v_u32m1( w0, FD_SHA256_RISCV_VL );
  w1 = __riscv_vrev8_v_u32m1( w1, FD_SHA256_RISCV_VL );

  vuint32m1_t const initial0 = __riscv_vle32_v_u32m1( fd_sha256_riscv_initial0, FD_SHA256_RISCV_VL );
  vuint32m1_t const initial1 = __riscv_vle32_v_u32m1( fd_sha256_riscv_initial1, FD_SHA256_RISCV_VL );
  vuint32m1_t const padding0 = __riscv_vle32_v_u32m1( fd_sha256_riscv_padding0, FD_SHA256_RISCV_VL );
  vuint32m1_t const padding1 = __riscv_vle32_v_u32m1( fd_sha256_riscv_padding1, FD_SHA256_RISCV_VL );
  vuint32m1_t const reverse_idx = __riscv_vle32_v_u32m1( fd_sha256_riscv_reverse_idx, FD_SHA256_RISCV_VL );
  vuint32m1_t const lane_ids = __riscv_vid_v_u32m1( FD_SHA256_RISCV_VL );
  vbool32_t const lane0 = __riscv_vmseq_vx_u32m1_b32( lane_ids, 0U, FD_SHA256_RISCV_VL );

  for( ulong iter=0UL; iter<cnt; iter++ ) {
    vuint32m1_t w2 = padding0;
    vuint32m1_t w3 = padding1;
    vuint32m1_t state0 = initial0;
    vuint32m1_t state1 = initial1;

    FD_SHA256_RISCV_ROUNDS();
    state0 = __riscv_vadd_vv_u32m1( state0, initial0, FD_SHA256_RISCV_VL );
    state1 = __riscv_vadd_vv_u32m1( state1, initial1, FD_SHA256_RISCV_VL );

    /* Convert {f,e,b,a},{h,g,d,c} directly to {a,b,c,d},{e,f,g,h} for
       the next iteration, without a scalar or memory round trip. */
    state0 = __riscv_vrgather_vv_u32m1( state0, reverse_idx, FD_SHA256_RISCV_VL );
    state1 = __riscv_vrgather_vv_u32m1( state1, reverse_idx, FD_SHA256_RISCV_VL );
    w0 = __riscv_vslideup_vx_u32m1_tu( state0, state1, 2UL, FD_SHA256_RISCV_VL );
    state0 = __riscv_vslidedown_vx_u32m1( state0, 2UL, FD_SHA256_RISCV_VL );
    state1 = __riscv_vslidedown_vx_u32m1( state1, 2UL, FD_SHA256_RISCV_VL );
    w1 = __riscv_vslideup_vx_u32m1_tu( state0, state1, 2UL, FD_SHA256_RISCV_VL );
  }

  w0 = __riscv_vrev8_v_u32m1( w0, FD_SHA256_RISCV_VL );
  w1 = __riscv_vrev8_v_u32m1( w1, FD_SHA256_RISCV_VL );
  __riscv_vse8_v_u8m1( hash,    __riscv_vreinterpret_v_u32m1_u8m1( w0 ), 16UL );
  __riscv_vse8_v_u8m1( hash+16, __riscv_vreinterpret_v_u32m1_u8m1( w1 ), 16UL );
}

#undef FD_SHA256_RISCV_ROUNDS
#undef FD_SHA256_RISCV_SCHEDULE
#undef FD_SHA256_RISCV_ROUND
#undef FD_SHA256_RISCV_DECLARE_CONSTANTS
#undef FD_SHA256_RISCV_VL
