#include "fd_lthash2.h"
#include "../keccak256/fd_keccak256_avx512_internal.h"
#include "../keccak256/fd_keccak256.h"
#include <string.h>

/* Round constants are the same as standard Keccak-f[1600]; we just use
   rounds 12..23 for Keccak-p[1600,12] (KangarooTwelve convention).
   Pull from fd_keccak256_rc which is exported from fd_keccak256.c. */
extern ulong const fd_keccak256_rc[24];

/* Rate = 17 lanes (1088 bits = 136 bytes), capacity = 8 lanes (512 bits).
   Counter is XORed into lane 17 (first capacity lane).  Padding suffix
   = 0x07 (K12-style domain separator) + 0x80 trailing bit. */
#define LTHASH2_RATE_LANES   (17UL)
#define LTHASH2_RATE_BYTES  (136UL)        /* = 17 * 8 */
#define LTHASH2_CTR_LANE     (17)          /* first capacity lane */
#define LTHASH2_PAD_DSBYTE   (0x07)        /* K12 domain separator */

#if FD_HAS_AVX512

/* ---- Sequential absorb (1 state) ---------------------------------------
   Standard sponge absorb: XOR input rate-block-by-rate-block into the
   state and permute.  Final partial block is padded with 0x07 ... 0x80
   then permuted.  Uses fd_keccak256_avx512_keccak1_f1600_12r for the
   inner permutation (scalar 64-bit; ~150 ns/call). */

static void
fd_lthash2_absorb_1( ulong         state[25],
                     void const *  input,
                     ulong         input_sz ) {
  uchar const * p   = (uchar const *)input;
  ulong         rem = input_sz;

  /* Full rate blocks. */
  while( rem >= LTHASH2_RATE_BYTES ) {
    for( ulong z=0; z<LTHASH2_RATE_LANES; z++ ) {
      ulong w; memcpy( &w, p + 8*z, 8 );
      state[ z ] ^= w;
    }
    fd_keccak256_avx512_keccak1_f1600_12r( state, fd_keccak256_rc );
    p   += LTHASH2_RATE_BYTES;
    rem -= LTHASH2_RATE_BYTES;
  }

  /* Final partial block. */
  uchar buf[ LTHASH2_RATE_BYTES ] __attribute__((aligned(64)));
  memcpy( buf, p, rem );
  memset( buf + rem, 0, LTHASH2_RATE_BYTES - rem );
  buf[ rem                    ] ^= LTHASH2_PAD_DSBYTE;
  buf[ LTHASH2_RATE_BYTES - 1 ] ^= 0x80;
  for( ulong z=0; z<LTHASH2_RATE_LANES; z++ ) {
    ulong w; memcpy( &w, buf + 8*z, 8 );
    state[ z ] ^= w;
  }
  fd_keccak256_avx512_keccak1_f1600_12r( state, fd_keccak256_rc );
}

/* ---- Counter-mode squeeze (8 ctrs in parallel via keccak8) -----------
   Given the absorbed state S, derive 8 states { S ⊕ ctr_i into lane 17
   for ctr_i = ctrs[0..7] }, permute all 8 in parallel via keccak8 12r,
   and write each lane's first 136 bytes of rate into out[i].

   tmp_buf is a 136-byte scratch used when an out[i] would overrun a
   smaller user buffer (caller may pass a stack buffer of 136 B as
   out[i] for the last ctr to truncate the 2048 B total). */

static void
fd_lthash2_squeeze_8( ulong const   base_state[25],
                      ulong const * ctrs,
                      void *        out_buffers[8] ) {
  /* SoA state: 25 zmm = 1600 bytes contiguous. */
  ulong soa[ 200 ] __attribute__((aligned(64)));
  fd_keccak256_avx512_keccak8_broadcast_state( soa, base_state );
  fd_keccak256_avx512_keccak8_xor_into_lane( soa, LTHASH2_CTR_LANE, ctrs );
  fd_keccak256_avx512_keccak8_f1600_12r_raw( soa, fd_keccak256_rc );
  fd_keccak256_avx512_keccak8_extract_rate( out_buffers, soa, LTHASH2_RATE_BYTES );
}

void
fd_lthash2_compute( void const *         input,
                    ulong                input_sz,
                    fd_lthash2_value_t * out ) {

  /* Absorb. */
  ulong state[ 25 ] __attribute__((aligned(64)));
  memset( state, 0, sizeof(state) );
  fd_lthash2_absorb_1( state, input, input_sz );

  /* Squeeze: 16 counters, 2 batches of 8.  Output is 2048 bytes total.
     16 * 136 = 2176 B per batch-of-16, so the LAST 8 bytes of ctr=15's
     rate are dropped — write that ctr's output to a stack scratch and
     copy only what fits in `out`. */

  void * out_b1[ 8 ];
  for( int i=0; i<8; i++ ) out_b1[ i ] = out->bytes + (ulong)i * LTHASH2_RATE_BYTES;
  ulong ctrs_lo[ 8 ] = { 0,1,2,3,4,5,6,7 };
  fd_lthash2_squeeze_8( state, ctrs_lo, out_b1 );

  /* Batch 2: ctrs 8..15.  ctr=15's output starts at offset 15*136 = 2040,
     so we have 2048-2040 = 8 bytes left in `out`.  Use a temp buffer for
     ctr=15 then copy 8 bytes. */
  uchar tail_buf[ LTHASH2_RATE_BYTES ] __attribute__((aligned(64)));
  void * out_b2[ 8 ];
  for( int i=0; i<7; i++ ) out_b2[ i ] = out->bytes + (8UL+(ulong)i) * LTHASH2_RATE_BYTES;
  out_b2[ 7 ] = tail_buf;  /* ctr=15 lands here */
  ulong ctrs_hi[ 8 ] = { 8,9,10,11,12,13,14,15 };
  fd_lthash2_squeeze_8( state, ctrs_hi, out_b2 );

  /* Copy the 8 surviving bytes of the truncated last block. */
  memcpy( out->bytes + 15UL*LTHASH2_RATE_BYTES,
          tail_buf,
          FD_LTHASH2_LEN_BYTES - 15UL*LTHASH2_RATE_BYTES );
}

/* ===================================================================== */
/* batch16: 16 lthashes computed in parallel.  Best amortized cost.      */
/* ===================================================================== */

/* Build the b-th rate block of an input message into `block`, applying
   K12 padding (0x07 + 0x80) at the trailing block.  After the trailing
   block, returns a zero block (idempotent — repeating the call past the
   trailing index keeps producing zeros, which is a no-op when XOR'd
   into the state).  Caller is responsible for not running past the
   maximum needed b. */
static inline void
fd_lthash2_build_block( uchar        block[ LTHASH2_RATE_BYTES ],
                        void const * input,
                        ulong        sz,
                        ulong        b ) {
  ulong const start = b * LTHASH2_RATE_BYTES;
  if( start >= sz + 1UL ) {
    /* Past trailing block — zero (no-op when XOR'd). */
    memset( block, 0, LTHASH2_RATE_BYTES );
    return;
  }
  if( start + LTHASH2_RATE_BYTES <= sz ) {
    /* Full data block. */
    memcpy( block, (uchar const *)input + start, LTHASH2_RATE_BYTES );
    return;
  }
  /* Trailing block: partial data + pad. */
  ulong const remaining = sz - start;
  memcpy( block, (uchar const *)input + start, remaining );
  memset( block + remaining, 0, LTHASH2_RATE_BYTES - remaining );
  block[ remaining               ] ^= LTHASH2_PAD_DSBYTE;
  block[ LTHASH2_RATE_BYTES - 1  ] ^= 0x80;
}

/* batch8: same algorithm as batch16 but with one SoA buffer (8 lanes). */
void
fd_lthash2_batch8( void const *               inputs[8],
                   uint const                 sizes[8],
                   fd_lthash2_value_t * const outputs[8] ) {

  ulong ssa[ 200 ] __attribute__((aligned(64)));
  memset( ssa, 0, sizeof(ssa) );

  ulong n_perms[ 8 ];
  ulong n_max_blocks = 0;
  for( int i=0; i<8; i++ ) {
    n_perms[ i ] = (ulong)sizes[ i ] / LTHASH2_RATE_BYTES + 1UL;
    if( n_perms[ i ] > n_max_blocks ) n_max_blocks = n_perms[ i ];
  }

  ulong saved [ 8 ][ 25 ] __attribute__((aligned(64)));
  int   frozen[ 8 ];
  for( int i=0; i<8; i++ ) frozen[ i ] = 0;

  for( ulong b=0UL; b<n_max_blocks; b++ ) {
    uchar blocks[ 8 ][ LTHASH2_RATE_BYTES ] __attribute__((aligned(64)));
    for( int i=0; i<8; i++ ) {
      fd_lthash2_build_block( blocks[ i ], inputs[ i ], sizes[ i ], b );
    }
    void const * ba[ 8 ]; for( int s=0; s<8; s++ ) ba[ s ] = blocks[ s ];
    fd_keccak256_avx512_keccak8_xor_block_into_state( ssa, ba, LTHASH2_RATE_LANES );
    fd_keccak256_avx512_keccak8_f1600_12r_raw( ssa, fd_keccak256_rc );

    for( int i=0; i<8; i++ ) {
      if( !frozen[ i ] && b + 1UL == n_perms[ i ] ) {
        fd_keccak256_avx512_keccak8_extract_lane( saved[ i ], ssa, i );
        frozen[ i ] = 1;
      } else if( frozen[ i ] ) {
        fd_keccak256_avx512_keccak8_inject_lane( ssa, i, saved[ i ] );
      }
    }
  }

  for( ulong ctr=0UL; ctr<16UL; ctr++ ) {
    ulong ssa_w[ 200 ] __attribute__((aligned(64)));
    memcpy( ssa_w, ssa, sizeof(ssa) );

    ulong ctrs[ 8 ] = { ctr,ctr,ctr,ctr, ctr,ctr,ctr,ctr };
    fd_keccak256_avx512_keccak8_xor_into_lane( ssa_w, LTHASH2_CTR_LANE, ctrs );
    fd_keccak256_avx512_keccak8_f1600_12r_raw( ssa_w, fd_keccak256_rc );

    if( ctr < 15 ) {
      void * out_a[ 8 ]; for( int s=0; s<8; s++ ) out_a[ s ] = outputs[ s ]->bytes + ctr * LTHASH2_RATE_BYTES;
      fd_keccak256_avx512_keccak8_extract_rate( out_a, ssa_w, LTHASH2_RATE_BYTES );
    } else {
      uchar tmp_a[ 8 ][ LTHASH2_RATE_BYTES ] __attribute__((aligned(64)));
      void * out_a[ 8 ]; for( int s=0; s<8; s++ ) out_a[ s ] = tmp_a[ s ];
      fd_keccak256_avx512_keccak8_extract_rate( out_a, ssa_w, LTHASH2_RATE_BYTES );
      ulong const tail = FD_LTHASH2_LEN_BYTES - 15UL * LTHASH2_RATE_BYTES;
      for( int s=0; s<8; s++ ) {
        memcpy( outputs[ s ]->bytes + 15UL*LTHASH2_RATE_BYTES, tmp_a[ s ], tail );
      }
    }
  }
}

void
fd_lthash2_batch16( void const *               inputs[16],
                    uint const                 sizes[16],
                    fd_lthash2_value_t * const outputs[16] ) {

  /* Two SoA states: ssa for lanes 0..7, ssb for lanes 8..15. */
  ulong ssa[ 200 ] __attribute__((aligned(64)));
  ulong ssb[ 200 ] __attribute__((aligned(64)));
  memset( ssa, 0, sizeof(ssa) );
  memset( ssb, 0, sizeof(ssb) );

  /* ---- Parallel absorb. ---------------------------------------------
     Process the union of all inputs' rate blocks.  If a lane has fewer
     blocks than the max, its later iterations XOR zeros into the SoA
     (no-op in state), so the math is still correct — at the cost of
     some wasted permutation work for lanes that already finished. */

  ulong n_perms[ 16 ];
  ulong n_max_blocks = 0;
  for( int i=0; i<16; i++ ) {
    /* +1 because the pad block is always needed (final block at offset
       `sz` carries the 0x07 dom-sep + 0x80 trailing bit). */
    n_perms[ i ] = (ulong)sizes[ i ] / LTHASH2_RATE_BYTES + 1UL;
    if( n_perms[ i ] > n_max_blocks ) n_max_blocks = n_perms[ i ];
  }

  /* Freeze/restore: when a lane finishes its required number of perms,
     snapshot its 25-u64 state.  After every later perm in the batch,
     overwrite the perturbed slot with the snapshot.  Cost is small: a
     finished lane is restored once per remaining permutation, ~25 u64
     stores. */
  ulong saved [ 16 ][ 25 ] __attribute__((aligned(64)));
  int   frozen[ 16 ];
  for( int i=0; i<16; i++ ) frozen[ i ] = 0;

  for( ulong b=0UL; b<n_max_blocks; b++ ) {
    /* Build 16 per-lane rate blocks. */
    uchar blocks[ 16 ][ LTHASH2_RATE_BYTES ] __attribute__((aligned(64)));
    for( int i=0; i<16; i++ ) {
      fd_lthash2_build_block( blocks[ i ], inputs[ i ], sizes[ i ], b );
    }
    /* XOR into SoA — split across the two 8-state batches. */
    void const * ba[ 8 ]; for( int s=0; s<8; s++ ) ba[ s ] = blocks[     s ];
    void const * bb[ 8 ]; for( int s=0; s<8; s++ ) bb[ s ] = blocks[ 8 + s ];
    fd_keccak256_avx512_keccak8_xor_block_into_state( ssa, ba, LTHASH2_RATE_LANES );
    fd_keccak256_avx512_keccak8_xor_block_into_state( ssb, bb, LTHASH2_RATE_LANES );
    fd_keccak256_avx512_keccak8_f1600_12r_raw( ssa, fd_keccak256_rc );
    fd_keccak256_avx512_keccak8_f1600_12r_raw( ssb, fd_keccak256_rc );

    /* Snapshot lanes finishing this iteration; restore lanes already frozen. */
    for( int i=0; i<16; i++ ) {
      void * soa = (i<8) ? ssa : ssb;
      int    ll  = (i<8) ? i : i-8;
      if( !frozen[ i ] && b + 1UL == n_perms[ i ] ) {
        fd_keccak256_avx512_keccak8_extract_lane( saved[ i ], soa, ll );
        frozen[ i ] = 1;
      } else if( frozen[ i ] ) {
        fd_keccak256_avx512_keccak8_inject_lane( soa, ll, saved[ i ] );
      }
    }
  }

  /* ---- Counter-mode squeeze. -----------------------------------------
     For each ctr 0..15: clone the absorbed SoA state, XOR ctr into
     lane 17 of every state, permute, extract 136 B per lane into the
     right position of each output buffer. */

  for( ulong ctr=0UL; ctr<16UL; ctr++ ) {
    ulong ssa_w[ 200 ] __attribute__((aligned(64)));
    ulong ssb_w[ 200 ] __attribute__((aligned(64)));
    memcpy( ssa_w, ssa, sizeof(ssa) );
    memcpy( ssb_w, ssb, sizeof(ssb) );

    ulong ctrs[ 8 ] = { ctr,ctr,ctr,ctr, ctr,ctr,ctr,ctr };
    fd_keccak256_avx512_keccak8_xor_into_lane( ssa_w, LTHASH2_CTR_LANE, ctrs );
    fd_keccak256_avx512_keccak8_xor_into_lane( ssb_w, LTHASH2_CTR_LANE, ctrs );

    fd_keccak256_avx512_keccak8_f1600_12r_raw( ssa_w, fd_keccak256_rc );
    fd_keccak256_avx512_keccak8_f1600_12r_raw( ssb_w, fd_keccak256_rc );

    if( ctr < 15 ) {
      /* Direct write into each output's correct offset. */
      void * out_a[ 8 ]; for( int s=0; s<8; s++ ) out_a[ s ] = outputs[     s ]->bytes + ctr * LTHASH2_RATE_BYTES;
      void * out_b[ 8 ]; for( int s=0; s<8; s++ ) out_b[ s ] = outputs[ 8 + s ]->bytes + ctr * LTHASH2_RATE_BYTES;
      fd_keccak256_avx512_keccak8_extract_rate( out_a, ssa_w, LTHASH2_RATE_BYTES );
      fd_keccak256_avx512_keccak8_extract_rate( out_b, ssb_w, LTHASH2_RATE_BYTES );
    } else {
      /* Last ctr: only the first 8 bytes of the rate fit in each output.
         Stage to a 16x136 byte temp, then copy 8 bytes per output. */
      uchar tmp_a[ 8 ][ LTHASH2_RATE_BYTES ] __attribute__((aligned(64)));
      uchar tmp_b[ 8 ][ LTHASH2_RATE_BYTES ] __attribute__((aligned(64)));
      void * out_a[ 8 ]; for( int s=0; s<8; s++ ) out_a[ s ] = tmp_a[ s ];
      void * out_b[ 8 ]; for( int s=0; s<8; s++ ) out_b[ s ] = tmp_b[ s ];
      fd_keccak256_avx512_keccak8_extract_rate( out_a, ssa_w, LTHASH2_RATE_BYTES );
      fd_keccak256_avx512_keccak8_extract_rate( out_b, ssb_w, LTHASH2_RATE_BYTES );
      ulong const tail = FD_LTHASH2_LEN_BYTES - 15UL * LTHASH2_RATE_BYTES; /* 8 bytes */
      for( int s=0; s<8; s++ ) {
        memcpy( outputs[     s ]->bytes + 15UL*LTHASH2_RATE_BYTES, tmp_a[ s ], tail );
        memcpy( outputs[ 8 + s ]->bytes + 15UL*LTHASH2_RATE_BYTES, tmp_b[ s ], tail );
      }
    }
  }
}

#else /* !FD_HAS_AVX512: use a scalar fallback */

void
fd_lthash2_compute( void const *         input,
                    ulong                input_sz,
                    fd_lthash2_value_t * out ) {
  (void)input; (void)input_sz; (void)out;
  /* TODO: scalar fallback for non-AVX-512 builds. */
}

#endif /* FD_HAS_AVX512 */
