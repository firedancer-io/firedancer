/* xkcp_shake.c - thin SHAKE256 wrappers around the low-level
 *                Keccak-p[1600] permutations from XKCP.
 *
 * We keep the construction (sponge with rate=136, padding 0x1F||0x80)
 * here in plain C and instantiate it twice, once with the plain64
 * permutation (`KeccakP1600_plain64_*`) and once with the AVX-512
 * permutation (`KeccakP1600_AVX512_*`).  Both permutations share the
 * same state layout (`KeccakP1600_plain64_state` = 25 lanes of 64
 * bits), so the wrappers differ only in which Permute / Add / Extract
 * functions they call.
 *
 * The XKCP source files we link against are unmodified; see
 * vendor/xkcp/lib/low/KeccakP-1600/{plain-64bits,AVX512}.
 *
 * Public domain. */

#include "xkcp_shake.h"

#include <stdint.h>
#include <stddef.h>

/* The state struct happens to be defined in the plain64 header. */
typedef struct { uint64_t A[ 25 ]; } kstate_t;

/* plain64 permutation entry points (vendor/xkcp/lib/low/KeccakP-1600/plain-64bits). */
extern void KeccakP1600_plain64_Initialize        ( kstate_t * st );
extern void KeccakP1600_plain64_AddBytes          ( kstate_t * st,
                                                    unsigned char const * data,
                                                    unsigned int offset,
                                                    unsigned int length );
extern void KeccakP1600_plain64_Permute_24rounds  ( kstate_t * st );
extern void KeccakP1600_plain64_ExtractBytes      ( kstate_t const * st,
                                                    unsigned char * data,
                                                    unsigned int offset,
                                                    unsigned int length );

/* AVX-512 permutation entry points (vendor/xkcp/lib/low/KeccakP-1600/AVX512). */
extern void KeccakP1600_AVX512_Initialize         ( kstate_t * st );
extern void KeccakP1600_AVX512_AddBytes           ( kstate_t * st,
                                                    unsigned char const * data,
                                                    unsigned int offset,
                                                    unsigned int length );
extern void KeccakP1600_AVX512_Permute_24rounds   ( kstate_t * st );
extern void KeccakP1600_AVX512_ExtractBytes       ( kstate_t const * st,
                                                    unsigned char * data,
                                                    unsigned int offset,
                                                    unsigned int length );

#define SHAKE256_RATE 136 /* (1600 - 2*256) / 8 */

#define DEFINE_SHAKE256( SUFFIX )                                              \
void xkcp_shake256_##SUFFIX( uint8_t const * in,  size_t in_len,               \
                             uint8_t       * out, size_t out_len ) {           \
  kstate_t st;                                                                 \
  KeccakP1600_##SUFFIX##_Initialize( &st );                                    \
                                                                                \
  /* Absorb full rate-sized blocks. */                                         \
  while( in_len >= SHAKE256_RATE ) {                                           \
    KeccakP1600_##SUFFIX##_AddBytes( &st, in, 0, SHAKE256_RATE );              \
    KeccakP1600_##SUFFIX##_Permute_24rounds( &st );                            \
    in += SHAKE256_RATE; in_len -= SHAKE256_RATE;                              \
  }                                                                            \
  /* Absorb the trailing partial block plus SHAKE256 padding. */               \
  if( in_len ) KeccakP1600_##SUFFIX##_AddBytes( &st, in, 0,                    \
                                                (unsigned int)in_len );        \
  unsigned char ds  = 0x1F;                                                    \
  unsigned char fin = 0x80;                                                    \
  KeccakP1600_##SUFFIX##_AddBytes( &st, &ds,  (unsigned int)in_len, 1 );       \
  KeccakP1600_##SUFFIX##_AddBytes( &st, &fin, SHAKE256_RATE - 1,    1 );       \
  KeccakP1600_##SUFFIX##_Permute_24rounds( &st );                              \
                                                                                \
  /* Squeeze. */                                                               \
  while( out_len >= SHAKE256_RATE ) {                                          \
    KeccakP1600_##SUFFIX##_ExtractBytes( &st, out, 0, SHAKE256_RATE );         \
    KeccakP1600_##SUFFIX##_Permute_24rounds( &st );                            \
    out += SHAKE256_RATE; out_len -= SHAKE256_RATE;                            \
  }                                                                            \
  if( out_len ) KeccakP1600_##SUFFIX##_ExtractBytes( &st, out, 0,              \
                                                     (unsigned int)out_len );  \
}

DEFINE_SHAKE256( plain64 )
DEFINE_SHAKE256( AVX512  )
