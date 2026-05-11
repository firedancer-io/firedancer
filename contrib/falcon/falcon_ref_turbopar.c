/* falcon_ref_turbopar.c - non-standard variant of the Pornin round 3
 *                          reference, modified per the paper to drive
 *                          hash-to-point with TurboSHAKE256 (12 rounds)
 *                          and an 8-way parallel squeeze on top of the
 *                          XKCP `KeccakP1600times8_AVX512` permutation.
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

/* Exposed (non-static) so the AVX-512 variants can reuse the same
 * hash-to-point with their own NTT pipelines.  See falcon_avx512.c /
 * falcon_avx512.c for the `_turbopar_crypto_sign_open` entry points. */
void
fa512_hash_to_point_turbopar( uint16_t * out, uint8_t const * in, size_t in_len ) {
  /* (1) Build `S` with TurboSHAKE256-style padding, but using
   * Keccak-p[1600] with only 12 rounds.  The padding follows SHAKE256
   * (0x1F .. 0x80) so that the construction matches the description in
   * the paper; `0x07` would be an alternative (RFC TurboSHAKE) but it
   * does not change the security argument.  The final permutation is
   * delayed: it is performed in parallel in step 3. */
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

  /* Loop until 512 coefficients have been produced.  Each iteration
   * runs a single parallel permutation over 8 instances and yields
   * 8*136 = 1088 rate bytes (= 544 16-bit candidates), so for Falcon-512
   * a single iteration is almost always enough. */
  unsigned counter_base = 0;
  unsigned remaining    = N;
  uint8_t  buf[ 8 * SHAKE_RATE ];

  while( remaining ) {
    /* (2) Make 8 copies of `base` and XOR the counter into lane 17 of
     * each.  We use an 8-byte little-endian counter. */
    kp1600_x8_state_t st;
    KeccakP1600times8_AVX512_InitializeAll( &st );
    for( unsigned i=0; i<8; i++ ) {
      KeccakP1600times8_AVX512_AddBytes( &st, i,
                                         (unsigned char const *)base.A,
                                         0, sizeof base.A );
      uint64_t c = (uint64_t)( counter_base + i );
      KeccakP1600times8_AVX512_AddBytes( &st, i,
                                         (unsigned char const *)&c,
                                         COUNTER_LANE * 8, 8 );
    }

    /* (3) Permute all 8 in parallel with 12 rounds. */
    KeccakP1600times8_AVX512_PermuteAll_12rounds( &st );

    /* (4) Extract 1 rate block from each instance, concatenated. */
    for( unsigned i=0; i<8; i++ ) {
      KeccakP1600times8_AVX512_ExtractBytes( &st, i,
                                             buf + i * SHAKE_RATE,
                                             0, SHAKE_RATE );
    }

    /* (5) Rejection sampling. */
    for( size_t j=0; j+1 < sizeof buf && remaining > 0; j += 2 ) {
      uint32_t w = ( (uint32_t)buf[ j ] << 8 ) | (uint32_t)buf[ j+1 ];
      if( w < (uint32_t)( K_REJ * Q ) ) { /* 5*Q = 61445 */
        while( w >= Q ) w -= Q;
        *out++ = (uint16_t)w;
        remaining--;
      }
    }
    counter_base += 8;
  }
}

int
falcon_ref_turbopar_crypto_sign_open( uint8_t       * m,  size_t * mlen,
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

  fa512_hash_to_point_turbopar( c0, sm + 2, NONCELEN + msg_len );

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
falcon_ref_turbopar_crypto_sign_open( uint8_t       * m,  size_t * mlen,
                                      uint8_t const * sm, size_t   smlen,
                                      uint8_t const * pk ) {
  /* No AVX-512 available: fall back to the standard reference so the
   * harness still produces a meaningful row.  The fallback obviously
   * does not exercise the parallel-squeeze code path. */
  return falcon_ref_xkcp_crypto_sign_open( m, mlen, sm, smlen, pk );
}

#endif /* HAVE_AVX512 */
