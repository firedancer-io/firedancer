#include "fd_sha512.h"

#if !FD_HAS_RISCV_SHA512
#error "fd_sha512_riscv requires FD_HAS_RISCV_SHA512"
#endif

#if !defined(__riscv) || (__riscv_xlen!=64)
#error "fd_sha512_riscv requires RV64"
#endif

#if !defined(__riscv_zvkb) || !defined(__riscv_zvknhb)
#error "fd_sha512_riscv requires Zvkb and Zvknhb"
#endif

#if !defined(__riscv_zvl128b)
#error "fd_sha512_riscv requires VLEN >= 128"
#endif

#include <riscv_vector.h>

/* This implementation follows OpenSSL's sha512-riscv64-zvkb-zvknhb.pl
   (Apache-2.0 or BSD-2-Clause).  The SHA-2 vector instructions operate on
   four rounds at a time.  They expect the state as
   {f,e,b,a},{h,g,d,c}, while message vectors remain in W[t:t+3] order. */

#define FD_SHA512_RISCV_VL (4UL)

static ulong const fd_sha512_riscv_K[80] __attribute__((aligned(64))) = {
  0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
  0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
  0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
  0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
  0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
  0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
  0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
  0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
  0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
  0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
  0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
  0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
  0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
  0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
  0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
  0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
  0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
  0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
  0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
  0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
};

static uint const fd_sha512_riscv_state_idx[4] __attribute__((aligned(16))) = {
  40U, 32U, 8U, 0U
};

#define FD_SHA512_RISCV_ROUND( w ) do {                                                \
    /* Keep GCC from hoisting all 20 constant vectors and spilling them. */             \
    FD_COMPILER_MFENCE();                                                               \
    vuint64m2_t _wk = __riscv_vle64_v_u64m2( round_const, FD_SHA512_RISCV_VL );         \
    round_const += 4UL;                                                                \
    _wk = __riscv_vadd_vv_u64m2( _wk, (w), FD_SHA512_RISCV_VL );                       \
    state1 = __riscv_vsha2cl_vv_u64m2( state1, state0, _wk, FD_SHA512_RISCV_VL );      \
    state0 = __riscv_vsha2ch_vv_u64m2( state0, state1, _wk, FD_SHA512_RISCV_VL );      \
  } while( 0 )

/* vsha2ms needs {W[t-12],W[t-7:t-5]} in its middle operand. */
#define FD_SHA512_RISCV_SCHEDULE( dst, middle, lane0_src, last ) do {                 \
    vuint64m2_t _middle = __riscv_vmerge_vvm_u64m2( (middle), (lane0_src), lane0,    \
                                                    FD_SHA512_RISCV_VL );             \
    (dst) = __riscv_vsha2ms_vv_u64m2( (dst), _middle, (last), FD_SHA512_RISCV_VL ); \
  } while( 0 )

#define FD_SHA512_RISCV_ROUND_CYCLE() do {        \
    FD_SHA512_RISCV_ROUND( w0 );                  \
    FD_SHA512_RISCV_SCHEDULE( w0, w2, w1, w3 );  \
    FD_SHA512_RISCV_ROUND( w1 );                  \
    FD_SHA512_RISCV_SCHEDULE( w1, w3, w2, w0 );  \
    FD_SHA512_RISCV_ROUND( w2 );                  \
    FD_SHA512_RISCV_SCHEDULE( w2, w0, w3, w1 );  \
    FD_SHA512_RISCV_ROUND( w3 );                  \
    FD_SHA512_RISCV_SCHEDULE( w3, w1, w0, w2 );  \
  } while( 0 )

#define FD_SHA512_RISCV_ROUNDS() do { \
    FD_SHA512_RISCV_ROUND_CYCLE();    \
    FD_SHA512_RISCV_ROUND_CYCLE();    \
    FD_SHA512_RISCV_ROUND_CYCLE();    \
    FD_SHA512_RISCV_ROUND_CYCLE();    \
    FD_SHA512_RISCV_ROUND( w0 );      \
    FD_SHA512_RISCV_ROUND( w1 );      \
    FD_SHA512_RISCV_ROUND( w2 );      \
    FD_SHA512_RISCV_ROUND( w3 );      \
  } while( 0 )

void
fd_sha512_core_riscv( ulong *       state,
                      uchar const * block,
                      ulong         block_cnt ) {
  vuint32m1_t const idx = __riscv_vle32_v_u32m1( fd_sha512_riscv_state_idx,
                                                 FD_SHA512_RISCV_VL );
  vuint64m2_t state0 = __riscv_vluxei32_v_u64m2( state,     idx, FD_SHA512_RISCV_VL );
  vuint64m2_t state1 = __riscv_vluxei32_v_u64m2( state+2UL, idx, FD_SHA512_RISCV_VL );
  vuint64m2_t const lane_ids = __riscv_vid_v_u64m2( FD_SHA512_RISCV_VL );
  vbool32_t const lane0 = __riscv_vmseq_vx_u64m2_b32( lane_ids, 0UL, FD_SHA512_RISCV_VL );

  do {
    vuint64m2_t w0 = __riscv_vle64_v_u64m2( (ulong const *)(block     ), FD_SHA512_RISCV_VL );
    vuint64m2_t w1 = __riscv_vle64_v_u64m2( (ulong const *)(block+32UL), FD_SHA512_RISCV_VL );
    vuint64m2_t w2 = __riscv_vle64_v_u64m2( (ulong const *)(block+64UL), FD_SHA512_RISCV_VL );
    vuint64m2_t w3 = __riscv_vle64_v_u64m2( (ulong const *)(block+96UL), FD_SHA512_RISCV_VL );
    w0 = __riscv_vrev8_v_u64m2( w0, FD_SHA512_RISCV_VL );
    w1 = __riscv_vrev8_v_u64m2( w1, FD_SHA512_RISCV_VL );
    w2 = __riscv_vrev8_v_u64m2( w2, FD_SHA512_RISCV_VL );
    w3 = __riscv_vrev8_v_u64m2( w3, FD_SHA512_RISCV_VL );

    vuint64m2_t const state0_save = state0;
    vuint64m2_t const state1_save = state1;
    ulong const * round_const = fd_sha512_riscv_K;
    FD_COMPILER_UNPREDICTABLE( round_const );
    FD_SHA512_RISCV_ROUNDS();
    state0 = __riscv_vadd_vv_u64m2( state0, state0_save, FD_SHA512_RISCV_VL );
    state1 = __riscv_vadd_vv_u64m2( state1, state1_save, FD_SHA512_RISCV_VL );
    block += FD_SHA512_BLOCK_SZ;
  } while( --block_cnt );

  __riscv_vsuxei32_v_u64m2( state,     idx, state0, FD_SHA512_RISCV_VL );
  __riscv_vsuxei32_v_u64m2( state+2UL, idx, state1, FD_SHA512_RISCV_VL );
}

#undef FD_SHA512_RISCV_ROUNDS
#undef FD_SHA512_RISCV_ROUND_CYCLE
#undef FD_SHA512_RISCV_SCHEDULE
#undef FD_SHA512_RISCV_ROUND
#undef FD_SHA512_RISCV_VL
