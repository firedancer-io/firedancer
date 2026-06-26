#include "fd_lthash2.h"
#include "../keccak256/fd_keccak256_avx512_internal.h"
#include "../keccak256/fd_keccak256.h"
#include <string.h>

/* Round constants are the same as standard Keccak-f[1600]; we use rounds
   12..23 for Keccak-p[1600,12] (KangarooTwelve convention).  Pulled from
   fd_keccak256_rc, exported from fd_keccak256.c. */
extern ulong const fd_keccak256_rc[24];

/* KTP12 = KangarooTwelve construction on Keccak-p[1600,12] with a
   counter-mode parallel squeeze.

   - Hash function: KangarooTwelve (KT128) — TurboSHAKE128 (rate 21 lanes =
     168 B, capacity 256 bits) with the 8192-byte chunk tree.  Inputs <=
     8192 B are a single node (domain 0x07); larger inputs split into
     8192-B chunks, the leaf chunks (1..n-1) are hashed in parallel (domain
     0x0B) to 32-byte chaining values, and the final node (chunk 0 ||
     0x03 00.. || CVs || right_encode(n-1) || 0xFF 0xFF, domain 0x06) is
     absorbed sequentially.  The leaf parallelism gives the absorb the full
     8-wide keccak8 throughput (vs a serial single-lane sponge).
   - Squeeze: counter XORed into capacity lane 21, 8 counters per keccak8
     permutation; 13 blocks -> 2048 B.  Parallel (lane = counter) in
     `compute`, parallel (lane = account) in `batch8`. */
#define LTHASH2_RATE_LANES   (21UL)
#define LTHASH2_RATE_BYTES  (168UL)        /* = 21 * 8 */
#define LTHASH2_CTR_LANE     (21)          /* first capacity lane */
#define LTHASH2_FULL_BLOCKS  (12UL)        /* squeeze blocks 0..11 full 168 B */
#define LTHASH2_LAST_BYTES   (32UL)        /* squeeze block 12 contributes 32 B */
#define LTHASH2_NSQ          (13UL)        /* total squeeze blocks */

#define K12_CHUNK            (8192UL)      /* KangarooTwelve chunk size B */
#define K12_CV_BYTES           (32UL)      /* chaining value length (256 bits) */
#define K12_DS_SINGLE          (0x07)      /* single-node domain */
#define K12_DS_LEAF            (0x0B)      /* leaf-node domain */
#define K12_DS_FINAL           (0x06)      /* final-node domain */

#if FD_HAS_AVX512

/* ====================================================================== */
/* Scalar single-state sponge (for the sequential final-node / single-node */
/* absorb).  TurboSHAKE128 rate = 168 B, Keccak-p[1600,12].                */
/* ====================================================================== */

typedef struct { ulong s[25]; uchar buf[ LTHASH2_RATE_BYTES ]; ulong blen; } k12_sponge_t;

static inline void
sp_init( k12_sponge_t * sp ) { memset( sp->s, 0, sizeof(sp->s) ); sp->blen = 0UL; }

static inline void
sp_permute_block( k12_sponge_t * sp ) {
  for( ulong z=0; z<LTHASH2_RATE_LANES; z++ ) {
    ulong w; memcpy( &w, sp->buf + 8*z, 8 ); sp->s[ z ] ^= w;
  }
  fd_keccak256_avx512_keccak1_f1600_12r( sp->s, fd_keccak256_rc );
  sp->blen = 0UL;
}

static void
sp_absorb( k12_sponge_t * sp, void const * data, ulong len ) {
  uchar const * d = (uchar const *)data;
  while( len ) {
    ulong take = LTHASH2_RATE_BYTES - sp->blen; if( take>len ) take = len;
    memcpy( sp->buf + sp->blen, d, take );
    sp->blen += take; d += take; len -= take;
    if( sp->blen==LTHASH2_RATE_BYTES ) sp_permute_block( sp );
  }
}

static void
sp_finalize( k12_sponge_t * sp, uchar ds ) {
  memset( sp->buf + sp->blen, 0, LTHASH2_RATE_BYTES - sp->blen );
  sp->buf[ sp->blen                 ] = (uchar)( sp->buf[ sp->blen ] ^ ds );
  sp->buf[ LTHASH2_RATE_BYTES - 1UL ] = (uchar)( sp->buf[ LTHASH2_RATE_BYTES-1UL ] ^ 0x80 );
  for( ulong z=0; z<LTHASH2_RATE_LANES; z++ ) {
    ulong w; memcpy( &w, sp->buf + 8*z, 8 ); sp->s[ z ] ^= w;
  }
  fd_keccak256_avx512_keccak1_f1600_12r( sp->s, fd_keccak256_rc );
}

/* right_encode(x): big-endian minimal-byte x followed by the byte count.
   right_encode(0) = {0x00,0x01}.  Returns the encoded length. */
static ulong
right_encode( uchar out[9], ulong x ) {
  ulong n=1UL, t=x; while( t>=256UL ) { t>>=8; n++; }
  if( n>8UL ) n = 8UL;                       /* x is a u64: n in 1..8 */
  uchar be[8];
  for( ulong i=0; i<8; i++ ) be[ i ] = (uchar)( x >> (8*(7-i)) );  /* fixed 8-byte BE */
  memcpy( out, be + (8UL-n), n );
  out[ n ] = (uchar)n;
  return n+1UL;
}

/* ====================================================================== */
/* Parallel absorb (up to 8 inputs, lane-major) into one keccak8 SoA      */
/* state, with domain-separator dsbyte.  Lanes >= n are fed zero blocks.  */
/* ====================================================================== */

static inline void
fd_lthash2_build_block( uchar        block[ LTHASH2_RATE_BYTES ],
                        void const * input,
                        ulong        sz,
                        ulong        b,
                        uchar        dsbyte ) {
  ulong const start = b * LTHASH2_RATE_BYTES;
  if( start >= sz + 1UL ) { memset( block, 0, LTHASH2_RATE_BYTES ); return; }
  if( start + LTHASH2_RATE_BYTES <= sz ) {
    memcpy( block, (uchar const *)input + start, LTHASH2_RATE_BYTES ); return;
  }
  ulong const remaining = sz - start;
  memcpy( block, (uchar const *)input + start, remaining );
  memset( block + remaining, 0, LTHASH2_RATE_BYTES - remaining );
  block[ remaining               ] = (uchar)( block[ remaining ] ^ dsbyte );
  block[ LTHASH2_RATE_BYTES - 1  ] = (uchar)( block[ LTHASH2_RATE_BYTES-1 ] ^ 0x80 );
}

static void
fd_lthash2_pabsorb( ulong        ssa[200],
                    void const * inputs[8],
                    uint const   sizes[8],
                    ulong        n,
                    uchar        dsbyte ) {
  ulong n_perms[8]; ulong n_max=0;
  for( ulong i=0; i<8; i++ ) {
    n_perms[i] = (i<n) ? ((ulong)sizes[i]/LTHASH2_RATE_BYTES + 1UL) : 0UL;
    if( n_perms[i] > n_max ) n_max = n_perms[i];
  }
  ulong saved[8][25] __attribute__((aligned(64)));
  int   frozen[8]; for( ulong i=0; i<8; i++ ) frozen[i] = (i>=n);
  for( ulong i=0; i<8; i++ ) if( i>=n ) memset( saved[i], 0, sizeof(saved[i]) );

  for( ulong b=0; b<n_max; b++ ) {
    uchar blocks[8][ LTHASH2_RATE_BYTES ] __attribute__((aligned(64)));
    for( ulong i=0; i<8; i++ ) {
      if( i<n && !frozen[i] ) fd_lthash2_build_block( blocks[i], inputs[i], sizes[i], b, dsbyte );
      else                    memset( blocks[i], 0, LTHASH2_RATE_BYTES );
    }
    void const * ba[8]; for( ulong s=0; s<8; s++ ) ba[s] = blocks[s];
    fd_keccak256_avx512_keccak8_xor_block_into_state( ssa, ba, LTHASH2_RATE_LANES );
    fd_keccak256_avx512_keccak8_f1600_12r_raw( ssa, fd_keccak256_rc );
    for( ulong i=0; i<8; i++ ) {
      if( !frozen[i] && b+1UL==n_perms[i] ) {
        fd_keccak256_avx512_keccak8_extract_lane( saved[i], ssa, (int)i ); frozen[i]=1;
      } else if( frozen[i] ) {
        fd_keccak256_avx512_keccak8_inject_lane( ssa, (int)i, saved[i] );
      }
    }
  }
}

/* ====================================================================== */
/* KangarooTwelve tree absorb -> final absorbed scalar state[25].          */
/* ====================================================================== */

/* Hash up to 8 leaf chunks in parallel (domain 0x0B) into 32-byte CVs. */
static void
fd_lthash2_leaves8( uchar        cv[8][ K12_CV_BYTES ],
                    void const * chunks[8],
                    uint const   sizes[8],
                    ulong        nleaf ) {
  ulong ssa[200] __attribute__((aligned(64)));
  memset( ssa, 0, sizeof(ssa) );
  fd_lthash2_pabsorb( ssa, chunks, sizes, nleaf, K12_DS_LEAF );
  void * outs[8]; for( ulong s=0; s<8; s++ ) outs[s] = cv[s];
  fd_keccak256_avx512_keccak8_extract_rate( outs, ssa, K12_CV_BYTES );  /* first 32 B = CV */
}

static void
fd_lthash2_absorb_tree( ulong state[25], void const * input, ulong sz ) {
  uchar const * p = (uchar const *)input;

  if( sz <= K12_CHUNK ) {
    /* single node */
    k12_sponge_t sp; sp_init( &sp );
    sp_absorb( &sp, p, sz );
    sp_finalize( &sp, K12_DS_SINGLE );
    memcpy( state, sp.s, sizeof(sp.s) );
    return;
  }

  /* tree: n chunks of 8192 B (last possibly shorter) */
  ulong const n     = (sz + K12_CHUNK - 1UL) / K12_CHUNK;
  ulong const nleaf = n - 1UL;

  k12_sponge_t sp; sp_init( &sp );
  sp_absorb( &sp, p, K12_CHUNK );                 /* chunk 0 */
  uchar const sep[8] = { 0x03,0,0,0,0,0,0,0 };
  sp_absorb( &sp, sep, 8UL );                     /* chunk-separator */

  for( ulong base=0; base<nleaf; base+=8UL ) {
    ulong cnt = nleaf-base; if( cnt>8UL ) cnt = 8UL;
    void const * chunks[8]; uint sizes[8];
    for( ulong j=0; j<cnt; j++ ) {
      ulong ci  = 1UL + base + j;                 /* chunk index */
      ulong off = ci * K12_CHUNK;
      ulong csz = (off + K12_CHUNK <= sz) ? K12_CHUNK : (sz - off);
      chunks[j] = p + off; sizes[j] = (uint)csz;
    }
    for( ulong j=cnt; j<8UL; j++ ) { chunks[j] = p; sizes[j] = 1U; } /* unused */
    uchar cv[8][ K12_CV_BYTES ] __attribute__((aligned(64)));
    fd_lthash2_leaves8( cv, chunks, sizes, cnt );
    for( ulong j=0; j<cnt; j++ ) sp_absorb( &sp, cv[j], K12_CV_BYTES );
  }

  uchar re[9]; ulong relen = right_encode( re, nleaf );
  sp_absorb( &sp, re, relen );
  uchar const ff[2] = { 0xFF, 0xFF };
  sp_absorb( &sp, ff, 2UL );
  sp_finalize( &sp, K12_DS_FINAL );
  memcpy( state, sp.s, sizeof(sp.s) );
}

/* ====================================================================== */
/* Counter-mode parallel squeeze (shared by both variants).               */
/* ====================================================================== */

static inline void
fd_lthash2_emit_block( void const *               base_soa,
                       ulong                      blk,
                       fd_lthash2_value_t * const outs[8],
                       ulong                      n ) {
  ulong ctrs[8] = { blk,blk,blk,blk, blk,blk,blk,blk };
  if( blk < LTHASH2_FULL_BLOCKS ) {
    uchar scratch[8][ LTHASH2_RATE_BYTES ] __attribute__((aligned(64)));
    void * o[8];
    for( ulong s=0; s<8; s++ ) o[s] = (s<n) ? (void*)(outs[s]->bytes + blk*LTHASH2_RATE_BYTES) : (void*)scratch[s];
    fd_keccak256_avx512_keccak8_squeeze_ctr21( base_soa, ctrs, o, LTHASH2_RATE_BYTES, fd_keccak256_rc );
  } else {
    uchar tmp[8][ LTHASH2_RATE_BYTES ] __attribute__((aligned(64)));
    void * o[8]; for( ulong s=0; s<8; s++ ) o[s] = tmp[s];
    fd_keccak256_avx512_keccak8_squeeze_ctr21( base_soa, ctrs, o, LTHASH2_RATE_BYTES, fd_keccak256_rc );
    for( ulong s=0; s<n; s++ )
      memcpy( outs[s]->bytes + LTHASH2_FULL_BLOCKS*LTHASH2_RATE_BYTES, tmp[s], LTHASH2_LAST_BYTES );
  }
}

/* ---- variant (b): single account, lane = counter ---------------------- */
void
fd_lthash2_compute( void const *         input,
                    ulong                input_sz,
                    fd_lthash2_value_t * out ) {
  ulong state[ 25 ] __attribute__((aligned(64)));
  fd_lthash2_absorb_tree( state, input, input_sz );

  ulong base_soa[ 200 ] __attribute__((aligned(64)));
  fd_keccak256_avx512_keccak8_broadcast_state( base_soa, state );

  ulong c0[8] = { 0,1,2,3,4,5,6,7 };
  void * o0[8]; for( ulong i=0; i<8; i++ ) o0[i] = out->bytes + i*LTHASH2_RATE_BYTES;
  fd_keccak256_avx512_keccak8_squeeze_ctr21( base_soa, c0, o0, LTHASH2_RATE_BYTES, fd_keccak256_rc );

  ulong c1[8] = { 8,9,10,11,12,13,14,15 };
  uchar scr[8][ LTHASH2_RATE_BYTES ] __attribute__((aligned(64)));
  void * o1[8];
  for( ulong i=0; i<4; i++ ) o1[i] = out->bytes + (8UL+i)*LTHASH2_RATE_BYTES;  /* blocks 8..11 */
  for( ulong i=4; i<8; i++ ) o1[i] = scr[i];                                   /* block 12 + unused */
  fd_keccak256_avx512_keccak8_squeeze_ctr21( base_soa, c1, o1, LTHASH2_RATE_BYTES, fd_keccak256_rc );
  memcpy( out->bytes + LTHASH2_FULL_BLOCKS*LTHASH2_RATE_BYTES, scr[4], LTHASH2_LAST_BYTES );
}

/* ---- variant (a): N (1..8) accounts in parallel, lane = account -------- *
   For small accounts (<= one chunk) this is the fast path; large accounts
   should use compute() (which has the tree absorb).  Absorb here is the
   single-node TurboSHAKE128 (domain 0x07) — callers must ensure each
   input is <= K12_CHUNK if exact KangarooTwelve agreement with compute()
   is required (compute() single-node path uses the same 0x07 domain). */
void
fd_lthash2_batch8( void const *               inputs[8],
                   uint const                 sizes[8],
                   fd_lthash2_value_t * const outputs[8],
                   ulong                      n ) {
  if( FD_UNLIKELY( n==0UL ) ) return;
  if( FD_UNLIKELY( n>8UL  ) ) n = 8UL;
  ulong ssa[200] __attribute__((aligned(64)));
  memset( ssa, 0, sizeof(ssa) );
  fd_lthash2_pabsorb( ssa, inputs, sizes, n, K12_DS_SINGLE );
  for( ulong blk=0; blk<LTHASH2_NSQ; blk++ ) fd_lthash2_emit_block( ssa, blk, outputs, n );
}

#else /* !FD_HAS_AVX512 */

void
fd_lthash2_compute( void const * input, ulong input_sz, fd_lthash2_value_t * out ) {
  (void)input; (void)input_sz; (void)out;
}

#endif /* FD_HAS_AVX512 */
