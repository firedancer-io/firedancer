/* falcon_ref_xkcp.c - Falcon-512 verification using the unmodified
 *                     parsers / NTT / verify_raw from the Pornin round 3
 *                     reference (vendor/falcon-round3) but with hash-to-
 *                     point driven by XKCP's SHAKE256 instead of Pornin's
 *                     `inner_shake256_*` from vendor/falcon-round3/shake.c.
 *
 * Standard SHAKE256 is uniquely defined (FIPS 202), so the byte stream
 * produced by XKCP and by Pornin is identical.  This file therefore
 * verifies the same signatures as `falcon_ref_crypto_sign_open`, only
 * the SHAKE backend differs.  The XKCP backend used here is the scalar
 * `plain64` Keccak-p[1600], the fastest single-stream SHAKE256 we
 * measured (faster than Pornin's, the AVX-512 single-stream variant, and
 * s2n-bignum; see contrib/falcon/bench).
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
#define SHAKE_RATE   136                   /* (1600 - 2*256) / 8 */

/* --- Pornin internals (vendor/falcon-round3) ---
 * The vendored reference compiles with default `FALCON_PREFIX = falcon_inner`
 * so all of the symbols below resolve to the .o files built from
 * vendor/falcon-round3/Reference_Implementation/falcon512/falcon512int. */

extern size_t falcon_inner_modq_decode  ( uint16_t * x, unsigned logn,
                                          void const * in, size_t max_in_len );
extern size_t falcon_inner_comp_decode  ( int16_t  * x, unsigned logn,
                                          void const * in, size_t max_in_len );
extern void   falcon_inner_to_ntt_monty ( uint16_t * h, unsigned logn );
extern int    falcon_inner_verify_raw   ( uint16_t const * c0,
                                          int16_t  const * s2,
                                          uint16_t const * h,
                                          unsigned logn, uint8_t * tmp );

/* --- XKCP plain64 Keccak-p[1600] (vendor/xkcp/lib/low/KeccakP-1600/plain-64bits) --- */

typedef struct { uint64_t A[ 25 ]; } kp1600_state_t;

extern void KeccakP1600_plain64_Initialize       ( kp1600_state_t * st );
extern void KeccakP1600_plain64_AddBytes         ( kp1600_state_t * st,
                                                   unsigned char const * data,
                                                   unsigned int offset,
                                                   unsigned int length );
extern void KeccakP1600_plain64_Permute_24rounds ( kp1600_state_t * st );
extern void KeccakP1600_plain64_ExtractBytes     ( kp1600_state_t const * st,
                                                   unsigned char * data,
                                                   unsigned int offset,
                                                   unsigned int length );

/* SHAKE256-driven hash-to-point.  Identical algorithm to Pornin's
 * `Zf(hash_to_point_vartime)`, but with XKCP as the SHAKE backend.  We
 * extract one rate-sized block per permutation and run rejection sampling
 * inside the block, which avoids materializing a large output buffer.
 *
 * Exposed (non-static) so the subcomponent bench can call it directly. */
void
hash_to_point_xkcp( uint16_t * out, uint8_t const * in, size_t in_len ) {
  kp1600_state_t st;
  KeccakP1600_plain64_Initialize( &st );

  /* Absorb full rate-sized blocks. */
  while( in_len >= SHAKE_RATE ) {
    KeccakP1600_plain64_AddBytes( &st, in, 0, SHAKE_RATE );
    KeccakP1600_plain64_Permute_24rounds( &st );
    in += SHAKE_RATE; in_len -= SHAKE_RATE;
  }
  /* Absorb trailing partial block + SHAKE256 padding (0x1F .. 0x80). */
  if( in_len ) KeccakP1600_plain64_AddBytes( &st, in, 0, (unsigned)in_len );
  unsigned char ds  = 0x1F;
  unsigned char fin = 0x80;
  KeccakP1600_plain64_AddBytes( &st, &ds,  (unsigned)in_len,    1 );
  KeccakP1600_plain64_AddBytes( &st, &fin, SHAKE_RATE - 1,       1 );
  KeccakP1600_plain64_Permute_24rounds( &st );

  /* Squeeze one rate-sized block at a time and run rejection sampling
   * inside it.  The rate (136) is even, so 16-bit candidates never span
   * a permutation boundary; the byte stream therefore matches Pornin's
   * lazy `inner_shake256_extract`. */
  unsigned       remaining = N;
  uint8_t        blk[ SHAKE_RATE ];
  for( ;; ) {
    KeccakP1600_plain64_ExtractBytes( &st, blk, 0, SHAKE_RATE );
    for( unsigned j=0; j+1 < SHAKE_RATE && remaining > 0; j += 2 ) {
      uint32_t w = ( (uint32_t)blk[ j ] << 8 ) | (uint32_t)blk[ j+1 ];
      if( w < (uint32_t)( K_REJ * Q ) ) { /* 5*Q = 61445 */
        while( w >= Q ) w -= Q;
        *out++ = (uint16_t)w;
        remaining--;
      }
    }
    if( !remaining ) break;
    KeccakP1600_plain64_Permute_24rounds( &st );
  }
}

int
falcon_ref_xkcp_crypto_sign_open( uint8_t       * m,  size_t * mlen,
                                  uint8_t const * sm, size_t   smlen,
                                  uint8_t const * pk ) {
  uint8_t  tmp[ 2 * 512 ];
  uint16_t h[ 512 ], c0[ 512 ];
  int16_t  sig[ 512 ];

  /* Public-key parsing: same as nist.c in the vendored ref. */
  if( pk[ 0 ] != 0x00 + LOGN ) return -1;
  if( falcon_inner_modq_decode( h, LOGN, pk + 1,
                                FALCON_PUBKEY_SIZE - 1 )
      != FALCON_PUBKEY_SIZE - 1 ) return -1;
  falcon_inner_to_ntt_monty( h, LOGN );

  /* Find nonce, signature, message length within `sm`. */
  if( smlen < 2 + NONCELEN ) return -1;
  size_t sig_len = ( (size_t)sm[ 0 ] << 8 ) | (size_t)sm[ 1 ];
  if( sig_len > smlen - 2 - NONCELEN ) return -1;
  size_t msg_len = smlen - 2 - NONCELEN - sig_len;

  uint8_t const * esig = sm + 2 + NONCELEN + msg_len;
  if( sig_len < 1 || esig[ 0 ] != 0x20 + LOGN ) return -1;
  if( falcon_inner_comp_decode( sig, LOGN, esig + 1,
                                sig_len - 1 ) != sig_len - 1 ) return -1;

  /* Hash-to-point over (nonce || msg) with XKCP SHAKE256. */
  hash_to_point_xkcp( c0, sm + 2, NONCELEN + msg_len );

  if( !falcon_inner_verify_raw( c0, sig, h, LOGN, tmp ) ) return -1;

  memmove( m, sm + 2 + NONCELEN, msg_len );
  if( mlen ) *mlen = msg_len;
  return 0;
}
