/* falcon_ref_ktp256.c - non-standard variant of the Pornin round 3
 *                       reference, modified per the paper to drive
 *                       hash-to-point with the KTP256 construction:
 *                       TurboSHAKE256 (12-round Keccak-p[1600]) plus
 *                       an 8-way parallel squeeze on top of the XKCP
 *                       `KeccakP1600times8_AVX512` permutation.
 *
 * The change is confined to hash-to-point.  Public-key parsing,
 * signature decoding (`comp_decode`), Montgomery NTT and `verify_raw`
 * are reused unmodified from vendor/falcon-round3/.../vrfy.c.
 *
 * Algorithm (cf. paper Algorithm "Parallel-squeeze hash-to-point with
 * parameter K"):
 *
 *  (1) Absorb the input  m = nonce || msg  into one TurboSHAKE256 state
 *      `S` with reduced-round (12) Keccak-p[1600], standard SHAKE256
 *      padding (0x1F .. 0x80).  Do *not* apply the final permutation
 *      (it is performed in step 3).
 *  (2) Initialize 8 instances S_0..S_7 of the times8 layout to copies
 *      of `S`.  XOR the counter `i` into a fixed capacity lane (lane 17)
 *      of each instance S_i.
 *  (3) Apply `KeccakP1600times8_AVX512_Permute_12rounds` to all 8
 *      states in parallel.
 *  (4) Extract one rate-sized block (136 bytes) from each instance and
 *      concatenate them to obtain 8*136 = 1088 bytes.
 *  (5) Run rejection sampling on the concatenated stream until the 512
 *      coefficients are produced.  If 1088 bytes are not enough, repeat
 *      from step (2) with the counter increased by 8.
 *
 * The output `c` differs from standard SHAKE256 hash-to-point, so this
 * variant cannot verify Falcon round 3 signatures.  The point of the
 * file is to measure the wall-clock speed of the parallel-squeeze
 * approach end-to-end (parse + new hash-to-point + verify_raw) so that
 * `bench` can report it next to the standard `falcon_ref` and
 * `falcon_ref_xkcp` rows.
 *
 * Public domain.
 */

#include "falcon.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define NONCELEN     40
#define N            FALCON_N
#define LOGN         FALCON_LOGN
#define Q            FALCON_Q
#define K_REJ        ( ( 1 << 16 ) / Q ) /* 5 */
#define SHAKE_RATE   136                 /* (1600 - 2*256) / 8 */
#define COUNTER_LANE 17                  /* a capacity lane (rate ends at lane 16.something) */

/* --- Pornin internals (vendor/falcon-round3) --- */
extern size_t falcon_inner_modq_decode  ( uint16_t * x, unsigned logn,
                                          void const * in, size_t max_in_len );
extern size_t falcon_inner_comp_decode  ( int16_t  * x, unsigned logn,
                                          void const * in, size_t max_in_len );
extern void   falcon_inner_to_ntt_monty ( uint16_t * h, unsigned logn );
extern int    falcon_inner_verify_raw   ( uint16_t const * c0,
                                          int16_t  const * s2,
                                          uint16_t const * h,
                                          unsigned logn, uint8_t * tmp );

#if defined(__AVX512F__) && defined(__AVX512BW__) && defined(__AVX512DQ__)
#define HAVE_AVX512 1
#else
#define HAVE_AVX512 0
#endif

#if HAVE_AVX512

#include <immintrin.h>

/* --- XKCP plain64 Keccak-p[1600] (single state, used to build `S`). --- */

typedef struct { uint64_t A[ 25 ]; } kp1600_state_t;

extern void KeccakP1600_plain64_Initialize        ( kp1600_state_t * st );
extern void KeccakP1600_plain64_AddBytes          ( kp1600_state_t * st,
                                                    unsigned char const * data,
                                                    unsigned int offset,
                                                    unsigned int length );
extern void KeccakP1600_plain64_Permute_12rounds  ( kp1600_state_t * st );

/* --- XKCP times8 AVX-512 Keccak-p[1600] (8 parallel states).
 * State is 25 lanes of __m512i, with lane[L][instance i] at byte offset
 * L*64 + i*8. */

typedef struct { __m512i A[ 25 ]; } kp1600_x8_state_t;

extern void KeccakP1600times8_AVX512_InitializeAll      ( kp1600_x8_state_t * st );
extern void KeccakP1600times8_AVX512_AddBytes           ( kp1600_x8_state_t * st,
                                                          unsigned int instanceIndex,
                                                          unsigned char const * data,
                                                          unsigned int offset,
                                                          unsigned int length );
extern void KeccakP1600times8_AVX512_PermuteAll_12rounds( kp1600_x8_state_t * st );
extern void KeccakP1600times8_AVX512_ExtractBytes       ( kp1600_x8_state_t const * st,
                                                          unsigned int instanceIndex,
                                                          unsigned char * data,
                                                          unsigned int offset,
                                                          unsigned int length );

/* KTP256 = "Keccak-Turbo-Parallel-256" hash-to-point.  Exposed
 * (non-static) so the AVX-512 verifier pipelines can reuse the same
 * implementation; see falcon_avx512.c, falcon_avx512_barrett.c, and
 * falcon_x86.c for the corresponding `_ktp256_crypto_sign_open`
 * entry points.
 *
 * Construction:
 *   (1) Build base sponge S with TurboSHAKE256-style absorb: rate
 *       136 B, padding 0x1F..0x80, but Keccak-p[1600,12] (12 rounds
 *       instead of SHAKE's 24).  The trailing permutation is fused
 *       with the parallel squeeze in step (3).
 *   (2) Make 8 copies of S, XOR counters 0..7 into capacity lane 17
 *       of each.  Inline AVX-512: broadcast each of the 25 base
 *       lanes with `vpbroadcastq` and XOR the counter vector into
 *       lane 17 with a single `vpxorq`.
 *   (3) Apply Keccak-p[1600,12] to all 8 states in parallel via
 *       XKCP `KeccakP1600times8_AVX512_PermuteAll_12rounds`.
 *   (4) Extract instance-by-instance lazily and run hash-to-point
 *       rejection sampling, bailing out the moment `remaining`
 *       reaches 0 so we never read the lanes we don't need.
 *   (5) If 8 instances aren't enough (~57% of inputs need a second
 *       batch to satisfy the 512-coefficient demand), advance the
 *       counter base by 8 and repeat (2)-(4). */
void
fa512_hash_to_point_ktp256( uint16_t * out, uint8_t const * in, size_t in_len ) {
  /* (1) Build base. */
  kp1600_state_t base;
  KeccakP1600_plain64_Initialize( &base );
  while( in_len >= SHAKE_RATE ) {
    KeccakP1600_plain64_AddBytes( &base, in, 0, SHAKE_RATE );
    KeccakP1600_plain64_Permute_12rounds( &base );
    in += SHAKE_RATE; in_len -= SHAKE_RATE;
  }
  if( in_len ) KeccakP1600_plain64_AddBytes( &base, in, 0, (unsigned)in_len );
  unsigned char ds  = 0x1F;
  unsigned char fin = 0x80;
  KeccakP1600_plain64_AddBytes( &base, &ds,  (unsigned)in_len, 1 );
  KeccakP1600_plain64_AddBytes( &base, &fin, SHAKE_RATE - 1,    1 );

  unsigned remaining    = N;
  unsigned counter_base = 0;

  while( remaining ) {
    /* (2) Inline SoA setup: broadcast each base lane to 8 instances
     * then XOR a vector of 8 counters into lane 17.  No per-lane
     * AddBytes calls. */
    __m512i st[25] __attribute__((aligned(64)));
    for( int L=0; L<25; L++ ) st[L] = _mm512_set1_epi64( (long long)base.A[L] );
    __m512i ctrs = _mm512_setr_epi64(
        (long long)(counter_base + 0), (long long)(counter_base + 1),
        (long long)(counter_base + 2), (long long)(counter_base + 3),
        (long long)(counter_base + 4), (long long)(counter_base + 5),
        (long long)(counter_base + 6), (long long)(counter_base + 7) );
    st[ COUNTER_LANE ] = _mm512_xor_epi64( st[ COUNTER_LANE ], ctrs );

    /* (3) Permute 8 instances in parallel; XKCP's state struct is
     * { V512 A[25] }, exactly our `st`. */
    KeccakP1600times8_AVX512_PermuteAll_12rounds( (kp1600_x8_state_t *)st );

    /* (4) Lazy extract: walk instances 0..7, reading just the 17
     * rate lanes of each (lane L of instance i is at
     * `((uint64_t*)st)[L*8 + i]`), and stop as soon as
     * `remaining` is 0. */
    uint64_t const * lanes = (uint64_t const *)st;
    for( unsigned i=0; i<8 && remaining > 0; i++ ) {
      uint64_t rate_lanes[ 17 ];
      for( int L=0; L<17; L++ ) rate_lanes[ L ] = lanes[ L*8 + i ];
      uint8_t const * buf = (uint8_t const *)rate_lanes;
      for( size_t j=0; j+1 < SHAKE_RATE && remaining > 0; j += 2 ) {
        uint32_t w = ( (uint32_t)buf[ j ] << 8 ) | (uint32_t)buf[ j+1 ];
        if( w < (uint32_t)( K_REJ * Q ) ) { /* 5*Q = 61445 */
          while( w >= Q ) w -= Q;
          *out++ = (uint16_t)w;
          remaining--;
        }
      }
    }
    counter_base += 8;
  }
}

int
falcon_ref_ktp256_crypto_sign_open( uint8_t       * m,  size_t * mlen,
                                    uint8_t const * sm, size_t   smlen,
                                    uint8_t const * pk ) {
  uint8_t  tmp[ 2 * 512 ];
  uint16_t h[ 512 ], c0[ 512 ];
  int16_t  sig[ 512 ];

  if( pk[ 0 ] != 0x00 + LOGN ) return -1;
  if( falcon_inner_modq_decode( h, LOGN, pk + 1,
                                FALCON_PUBKEY_SIZE - 1 )
      != FALCON_PUBKEY_SIZE - 1 ) return -1;
  falcon_inner_to_ntt_monty( h, LOGN );

  if( smlen < 2 + NONCELEN ) return -1;
  size_t sig_len = ( (size_t)sm[ 0 ] << 8 ) | (size_t)sm[ 1 ];
  if( sig_len > smlen - 2 - NONCELEN ) return -1;
  size_t msg_len = smlen - 2 - NONCELEN - sig_len;

  uint8_t const * esig = sm + 2 + NONCELEN + msg_len;
  if( sig_len < 1 || esig[ 0 ] != 0x20 + LOGN ) return -1;
  if( falcon_inner_comp_decode( sig, LOGN, esig + 1,
                                sig_len - 1 ) != sig_len - 1 ) return -1;

  fa512_hash_to_point_ktp256( c0, sm + 2, NONCELEN + msg_len );

  /* `verify_raw` always runs to completion: the result is "signature is
   * short" 0/1, and even when 0 (which is the expected outcome for
   * standard test vectors, since `c0` is computed with a different
   * hash) the function performs the full NTT pipeline.  This makes the
   * timing measured here the right end-to-end cost of the variant. */
  int ok = falcon_inner_verify_raw( c0, sig, h, LOGN, tmp );

  memmove( m, sm + 2 + NONCELEN, msg_len );
  if( mlen ) *mlen = msg_len;
  return ok ? 0 : -1;
}

#else /* !HAVE_AVX512 */

int
falcon_ref_ktp256_crypto_sign_open( uint8_t       * m,  size_t * mlen,
                                    uint8_t const * sm, size_t   smlen,
                                    uint8_t const * pk ) {
  /* No AVX-512 available: fall back to the standard reference so the
   * harness still produces a meaningful row.  The fallback obviously
   * does not exercise the parallel-squeeze code path. */
  return falcon_ref_xkcp_crypto_sign_open( m, mlen, sm, smlen, pk );
}

#endif /* HAVE_AVX512 */
